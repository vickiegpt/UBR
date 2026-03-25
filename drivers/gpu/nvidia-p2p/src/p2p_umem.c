/*
 * SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: MIT
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

/*
 * Generic P2P UMEM Support
 *
 * Provides unified DMA support for:
 * - CXL memory expanders
 * - AF_XDP UMEM (zero-copy networking)
 * - Generic user memory regions
 *
 * Supports both directions:
 * - GPU DMA to/from external memory (CXL, UMEM)
 * - GPU memory exported as UMEM backing store
 */

#include "core/core.h"
#include "gpu/gpu.h"
#include "mem_mgr/p2p.h"
#include "os/os.h"
#include "nvport/nvport.h"
#include "gpu/mem_mgr/mem_mgr.h"
#include "gpu/mem_mgr/mem_desc.h"
#include "gpu/mem_mgr/ce_utils.h"
#include "gpu/bus/kern_bus.h"

// Buffer type enumeration (must match nv-p2p.c)
typedef enum {
    NV_P2P_BUFFER_TYPE_GENERIC = 0,
    NV_P2P_BUFFER_TYPE_CXL,
    NV_P2P_BUFFER_TYPE_XDP_UMEM,
    NV_P2P_BUFFER_TYPE_GPU_EXPORT,
} NV_P2P_BUFFER_TYPE;

// DMA direction flags
#define P2P_DMA_FLAG_TO_GPU      0x1
#define P2P_DMA_FLAG_FROM_GPU    0x0
#define P2P_DMA_FLAG_ASYNC       0x2

// Page size constants
#define P2P_PAGE_SIZE_4K         (4ULL * 1024)
#define P2P_PAGE_SIZE_2M         (2ULL * 1024 * 1024)
#define P2P_DEFAULT_PAGE_SIZE    P2P_PAGE_SIZE_2M

// Forward declarations for kernel pinning interface (generic)
extern NV_STATUS nv_pin_cxl_buffer(NvU64, NvU64, void **);
extern NV_STATUS nv_unpin_cxl_buffer(void *);
extern NV_STATUS nv_get_cxl_buffer_pages(void *, NvU64 **, NvU32 *);
extern NV_STATUS nv_pin_cxl_buffer_hugepages(NvU64, NvU64, NvU32, void **);
extern NV_STATUS nv_get_cxl_buffer_hugepages(void *, NvU64 **, NvU32 *, NvU32 *);

// AF_XDP UMEM interface
extern NV_STATUS nv_pin_xdp_umem(NvU64, NvU64, NvU32, void **);
extern NV_STATUS nv_unpin_xdp_umem(void *);
extern NV_STATUS nv_get_xdp_umem_pages(void *, NvU64, NvU64, NvU64 **, NvU32 *, NvU32 *);
extern NV_STATUS nv_register_gpu_umem(void *, NvU64, NvU64, NvU32, void **);
extern NV_STATUS nv_unregister_gpu_umem(void *);
extern NV_STATUS nv_get_umem_buffer_info(void *, NvU32 *, NvU64 *, NvU32 *, NvU32 *, NvBool *);

// CXL device enumeration
typedef struct {
    NvU32   numDevices;
    NvU32   numMemoryDevices;
    NvBool  bLinkUp;
    NvU32   cxlVersion;
} P2P_SYSTEM_INFO;

extern NV_STATUS nv_enumerate_cxl_devices(P2P_SYSTEM_INFO *pInfo);

//
// Unified P2P Buffer Handle
//
typedef struct P2P_UMEM_BUFFER_HANDLE
{
    void               *pKernelHandle;     // Kernel pinning handle
    NvU64               baseAddress;       // Base virtual address
    NvU64               size;              // Size in bytes
    NvU32               bufferType;        // NV_P2P_BUFFER_TYPE
    NvU64              *pPageArray;        // Physical page addresses
    NvU32               pageCount;         // Number of pages
    NvU32               pageSize;          // Page size (4K or 2M)
    NvU32               frameSize;         // XDP frame size (for UMEM)
    NvBool              bRegistered;       // Registration state
    NvBool              bHugePages;        // Using huge pages
    NvBool              bGpuBacked;        // GPU memory backing
    // GPU state
    void               *gpuMemHandle;      // GPU memory handle (for export)
    NvU64               gpuOffset;         // GPU memory offset
    MEMORY_DESCRIPTOR  *pMemDesc;          // Persistent memory descriptor
} P2P_UMEM_BUFFER_HANDLE;

// Global tracking
#define P2P_MAX_BUFFER_SIZE         (1ULL << 40)  // 1TB
#define P2P_MAX_REGISTERED_BUFFERS  256

static NvU32 g_p2pRegisteredBufferCount = 0;
static NvU64 g_p2pTotalRegisteredSize = 0;

//
// Helper: Check if address range is 2MB aligned
//
static NvBool
_p2pCanUseHugePages
(
    NvU64 baseAddress,
    NvU64 size
)
{
    return ((baseAddress & (P2P_PAGE_SIZE_2M - 1)) == 0) &&
           ((size & (P2P_PAGE_SIZE_2M - 1)) == 0) &&
           (size >= P2P_PAGE_SIZE_2M);
}

//
// Helper: Create memory descriptor for external memory
//
static NV_STATUS
_p2pCreateMemDesc
(
    OBJGPU *pGpu,
    P2P_UMEM_BUFFER_HANDLE *pHandle
)
{
    NV_STATUS status;
    MEMORY_DESCRIPTOR *pMemDesc = NULL;
    RmPhysAddr *pPteArray = NULL;
    NvU32 i;

    if (pHandle->pPageArray == NULL || pHandle->pageCount == 0)
    {
        NV_PRINTF(LEVEL_ERROR, "P2P UMEM: No page array available\n");
        return NV_ERR_INVALID_STATE;
    }

    status = memdescCreate(&pMemDesc, pGpu, pHandle->size, 0, NV_FALSE, ADDR_SYSMEM,
                           NV_MEMORY_UNCACHED, MEMDESC_FLAGS_NONE);
    if (status != NV_OK)
    {
        NV_PRINTF(LEVEL_ERROR, "P2P UMEM: Failed to create memdesc: 0x%x\n", status);
        return status;
    }

    pPteArray = portMemAllocNonPaged(pHandle->pageCount * sizeof(RmPhysAddr));
    if (pPteArray == NULL)
    {
        memdescDestroy(pMemDesc);
        return NV_ERR_NO_MEMORY;
    }

    for (i = 0; i < pHandle->pageCount; i++)
    {
        pPteArray[i] = (RmPhysAddr)pHandle->pPageArray[i];
    }

    memdescFillPages(pMemDesc, 0, pPteArray, pHandle->pageCount, pHandle->pageSize);
    memdescSetPageSize(pMemDesc, AT_GPU, pHandle->pageSize);

    pHandle->pMemDesc = pMemDesc;
    portMemFree(pPteArray);

    NV_PRINTF(LEVEL_INFO, "P2P UMEM: Created memdesc - %u pages of %u bytes (type=%u)\n",
              pHandle->pageCount, pHandle->pageSize, pHandle->bufferType);

    return NV_OK;
}

//
// RmP2PGetSystemInfo
//
// Gets P2P system capabilities (CXL devices, etc.)
//
NV_STATUS
RmP2PGetSystemInfo
(
    NvU32  *pNumDevices,
    NvU32  *pNumMemDevices,
    NvBool *pbLinkUp,
    NvU32  *pVersion
)
{
    P2P_SYSTEM_INFO info;
    NV_STATUS status;

    portMemSet(&info, 0, sizeof(info));

    status = nv_enumerate_cxl_devices(&info);
    if (status != NV_OK)
    {
        info.numDevices = 0;
        info.numMemoryDevices = 0;
        info.bLinkUp = NV_FALSE;
        info.cxlVersion = 2;
    }

    if (pNumDevices)    *pNumDevices = info.numDevices;
    if (pNumMemDevices) *pNumMemDevices = info.numMemoryDevices;
    if (pbLinkUp)       *pbLinkUp = info.bLinkUp;
    if (pVersion)       *pVersion = info.cxlVersion;

    return NV_OK;
}

// Backward compatibility alias
NV_STATUS RmP2PGetCxlSystemInfo(NvU32 *a, NvU32 *b, NvBool *c, NvU32 *d)
{
    return RmP2PGetSystemInfo(a, b, c, d);
}

//
// RmP2PRegisterUmemBuffer
//
// Unified registration for all buffer types.
//
NV_STATUS
RmP2PRegisterUmemBuffer
(
    NvU32   bufferType,
    NvU64   baseAddress,
    NvU64   size,
    NvU32   frameSize,
    void   *gpuMemHandle,
    NvU64   gpuOffset,
    void  **ppBufferHandle
)
{
    P2P_UMEM_BUFFER_HANDLE *pHandle = NULL;
    NV_STATUS status;
    void *pKernelHandle = NULL;
    NvU64 *pPhysAddrs = NULL;
    NvU32 pageCount = 0;
    NvU32 actualPageSize = P2P_PAGE_SIZE_4K;
    NvBool bUseHugePages;

    if (size == 0 || ppBufferHandle == NULL)
    {
        NV_PRINTF(LEVEL_ERROR, "P2P Register: invalid args\n");
        return NV_ERR_INVALID_ARGUMENT;
    }

    if (size > P2P_MAX_BUFFER_SIZE)
    {
        NV_PRINTF(LEVEL_ERROR, "P2P Register: buffer too large\n");
        return NV_ERR_INVALID_ARGUMENT;
    }

    if (g_p2pRegisteredBufferCount >= P2P_MAX_REGISTERED_BUFFERS)
    {
        NV_PRINTF(LEVEL_ERROR, "P2P Register: max buffers reached\n");
        return NV_ERR_INSUFFICIENT_RESOURCES;
    }

    pHandle = portMemAllocNonPaged(sizeof(P2P_UMEM_BUFFER_HANDLE));
    if (pHandle == NULL)
        return NV_ERR_NO_MEMORY;

    portMemSet(pHandle, 0, sizeof(P2P_UMEM_BUFFER_HANDLE));
    pHandle->bufferType = bufferType;
    pHandle->frameSize = frameSize ? frameSize : P2P_PAGE_SIZE_4K;

    switch (bufferType)
    {
        case NV_P2P_BUFFER_TYPE_CXL:
        case NV_P2P_BUFFER_TYPE_GENERIC:
            // Try huge pages for CXL/generic
            bUseHugePages = _p2pCanUseHugePages(baseAddress, size);
            if (bUseHugePages)
            {
                status = nv_pin_cxl_buffer_hugepages(baseAddress, size,
                                                     P2P_PAGE_SIZE_2M, &pKernelHandle);
                if (status == NV_OK)
                {
                    status = nv_get_cxl_buffer_hugepages(pKernelHandle, &pPhysAddrs,
                                                         &pageCount, &actualPageSize);
                    if (status == NV_OK && pageCount > 0)
                    {
                        pHandle->bHugePages = NV_TRUE;
                    }
                    else
                    {
                        nv_unpin_cxl_buffer(pKernelHandle);
                        pKernelHandle = NULL;
                        bUseHugePages = NV_FALSE;
                    }
                }
                else
                {
                    bUseHugePages = NV_FALSE;
                }
            }
            // Fall back to 4K
            if (!bUseHugePages)
            {
                status = nv_pin_cxl_buffer(baseAddress, size, &pKernelHandle);
                if (status != NV_OK)
                {
                    portMemFree(pHandle);
                    return status;
                }
                status = nv_get_cxl_buffer_pages(pKernelHandle, &pPhysAddrs, &pageCount);
                if (status != NV_OK || pageCount == 0)
                {
                    nv_unpin_cxl_buffer(pKernelHandle);
                    portMemFree(pHandle);
                    return (status != NV_OK) ? status : NV_ERR_INVALID_STATE;
                }
                actualPageSize = P2P_PAGE_SIZE_4K;
            }
            break;

        case NV_P2P_BUFFER_TYPE_XDP_UMEM:
            // AF_XDP UMEM registration
            status = nv_pin_xdp_umem(baseAddress, size, pHandle->frameSize, &pKernelHandle);
            if (status != NV_OK)
            {
                NV_PRINTF(LEVEL_ERROR, "P2P Register: XDP UMEM pin failed: 0x%x\n", status);
                portMemFree(pHandle);
                return status;
            }
            status = nv_get_xdp_umem_pages(pKernelHandle, 0, size,
                                           &pPhysAddrs, &pageCount, NULL);
            if (status != NV_OK || pageCount == 0)
            {
                nv_unpin_xdp_umem(pKernelHandle);
                portMemFree(pHandle);
                return (status != NV_OK) ? status : NV_ERR_INVALID_STATE;
            }
            actualPageSize = P2P_PAGE_SIZE_4K;
            break;

        case NV_P2P_BUFFER_TYPE_GPU_EXPORT:
            // GPU memory exported as UMEM
            if (gpuMemHandle == NULL)
            {
                NV_PRINTF(LEVEL_ERROR, "P2P Register: GPU export requires gpu handle\n");
                portMemFree(pHandle);
                return NV_ERR_INVALID_ARGUMENT;
            }
            status = nv_register_gpu_umem(gpuMemHandle, gpuOffset, size,
                                          pHandle->frameSize, &pKernelHandle);
            if (status != NV_OK)
            {
                portMemFree(pHandle);
                return status;
            }
            pHandle->gpuMemHandle = gpuMemHandle;
            pHandle->gpuOffset = gpuOffset;
            pHandle->bGpuBacked = NV_TRUE;
            pageCount = (NvU32)(size / pHandle->frameSize);
            actualPageSize = pHandle->frameSize;
            break;

        default:
            NV_PRINTF(LEVEL_ERROR, "P2P Register: unknown buffer type %u\n", bufferType);
            portMemFree(pHandle);
            return NV_ERR_INVALID_ARGUMENT;
    }

    pHandle->pKernelHandle = pKernelHandle;
    pHandle->baseAddress = baseAddress;
    pHandle->size = size;
    pHandle->pPageArray = pPhysAddrs;
    pHandle->pageCount = pageCount;
    pHandle->pageSize = actualPageSize;
    pHandle->bRegistered = NV_TRUE;
    pHandle->pMemDesc = NULL;

    g_p2pRegisteredBufferCount++;
    g_p2pTotalRegisteredSize += size;

    *ppBufferHandle = pHandle;

    NV_PRINTF(LEVEL_INFO, "P2P Register: type=%u, size=0x%llx, pages=%u, pageSize=%u\n",
              bufferType, size, pageCount, actualPageSize);

    return NV_OK;
}

// Backward compatibility wrapper
NV_STATUS RmP2PRegisterCxlBuffer(void *dev, NvU64 addr, NvU64 size, NvU32 ver, void **h)
{
    (void)ver;  // Version unused in generic path
    return RmP2PRegisterUmemBuffer(NV_P2P_BUFFER_TYPE_CXL, addr, size, 0, NULL, 0, h);
}

//
// RmP2PUnregisterUmemBuffer
//
NV_STATUS
RmP2PUnregisterUmemBuffer
(
    void *pBufferHandle
)
{
    P2P_UMEM_BUFFER_HANDLE *pHandle = (P2P_UMEM_BUFFER_HANDLE *)pBufferHandle;
    NvU64 savedSize;

    if (pHandle == NULL)
        return NV_ERR_INVALID_ARGUMENT;

    if (!pHandle->bRegistered)
        return NV_ERR_INVALID_STATE;

    savedSize = pHandle->size;
    pHandle->bRegistered = NV_FALSE;

    // Clean up memory descriptor
    if (pHandle->pMemDesc != NULL)
    {
        memdescDestroy(pHandle->pMemDesc);
        pHandle->pMemDesc = NULL;
    }

    // Unpin based on type
    if (pHandle->pKernelHandle != NULL)
    {
        switch (pHandle->bufferType)
        {
            case NV_P2P_BUFFER_TYPE_CXL:
            case NV_P2P_BUFFER_TYPE_GENERIC:
                nv_unpin_cxl_buffer(pHandle->pKernelHandle);
                break;
            case NV_P2P_BUFFER_TYPE_XDP_UMEM:
                nv_unpin_xdp_umem(pHandle->pKernelHandle);
                break;
            case NV_P2P_BUFFER_TYPE_GPU_EXPORT:
                nv_unregister_gpu_umem(pHandle->pKernelHandle);
                break;
        }
    }

    portMemFree(pHandle);

    if (g_p2pRegisteredBufferCount > 0)
        g_p2pRegisteredBufferCount--;
    if (g_p2pTotalRegisteredSize >= savedSize)
        g_p2pTotalRegisteredSize -= savedSize;

    return NV_OK;
}

// Backward compatibility
NV_STATUS RmP2PUnregisterCxlBuffer(void *h)
{
    return RmP2PUnregisterUmemBuffer(h);
}

//
// RmP2PGetUmemPages
//
NV_STATUS
RmP2PGetUmemPages
(
    void   *pBufferHandle,
    NvU64   offset,
    NvU64   size,
    NvU64  *pPhysAddrs,
    NvU32  *pPageCount,
    NvU32  *pPageSize
)
{
    P2P_UMEM_BUFFER_HANDLE *pHandle = (P2P_UMEM_BUFFER_HANDLE *)pBufferHandle;
    NvU32 startPage, numPages, i;

    if (pHandle == NULL || pPhysAddrs == NULL || pPageCount == NULL || pPageSize == NULL)
        return NV_ERR_INVALID_ARGUMENT;

    if (!pHandle->bRegistered)
        return NV_ERR_INVALID_STATE;

    if (offset + size > pHandle->size)
        return NV_ERR_INVALID_ARGUMENT;

    if (pHandle->bGpuBacked)
    {
        // GPU-backed doesn't have page array, return frame info
        *pPageCount = (NvU32)(size / pHandle->frameSize);
        *pPageSize = pHandle->frameSize;
        return NV_OK;
    }

    startPage = (NvU32)(offset / pHandle->pageSize);
    numPages = (NvU32)((offset + size + pHandle->pageSize - 1) / pHandle->pageSize) - startPage;

    if (startPage + numPages > pHandle->pageCount)
        return NV_ERR_INVALID_ARGUMENT;

    for (i = 0; i < numPages; i++)
    {
        pPhysAddrs[i] = pHandle->pPageArray[startPage + i];
    }

    *pPageCount = numPages;
    *pPageSize = pHandle->pageSize;

    return NV_OK;
}

// Backward compatibility
NV_STATUS RmP2PGetCxlPages(void *h, NvU64 o, NvU64 s, NvU64 *p, NvU32 *c, NvU32 *z)
{
    return RmP2PGetUmemPages(h, o, s, p, c, z);
}

NV_STATUS RmP2PPutCxlPages(void *h, NvU64 o, NvU64 s)
{
    (void)h; (void)o; (void)s;
    return NV_OK;  // No-op for now
}

//
// RmP2PUmemDmaRequest
//
// Unified DMA request for all buffer types.
// Supports GPU <-> external memory transfers.
//
NV_STATUS
RmP2PUmemDmaRequest
(
    OBJGPU *pGpu,
    void   *pBufferHandle,
    NvU64   gpuOffset,
    NvU64   umemOffset,
    NvU64   size,
    NvU32   flags
)
{
    P2P_UMEM_BUFFER_HANDLE *pHandle = (P2P_UMEM_BUFFER_HANDLE *)pBufferHandle;
    NV_STATUS status = NV_OK;
    MemoryManager *pMemoryManager;
    KernelBus *pKernelBus;
    NvBool bToGpu = (flags & P2P_DMA_FLAG_TO_GPU) != 0;
    MEMORY_DESCRIPTOR *pGpuMemDesc = NULL;
    TRANSFER_SURFACE srcSurf = {0};
    TRANSFER_SURFACE dstSurf = {0};
    NvU64 transferSize;

    if (pGpu == NULL)
    {
        NV_PRINTF(LEVEL_ERROR, "P2P DMA: NULL GPU\n");
        return NV_ERR_INVALID_ARGUMENT;
    }

    if (pHandle == NULL || !pHandle->bRegistered)
    {
        NV_PRINTF(LEVEL_ERROR, "P2P DMA: Invalid buffer handle\n");
        return NV_ERR_INVALID_ARGUMENT;
    }

    if (size == 0)
    {
        NV_PRINTF(LEVEL_ERROR, "P2P DMA: Zero size\n");
        return NV_ERR_INVALID_ARGUMENT;
    }

    if (umemOffset > pHandle->size || size > pHandle->size - umemOffset)
    {
        NV_PRINTF(LEVEL_ERROR, "P2P DMA: OOB access\n");
        return NV_ERR_INVALID_ARGUMENT;
    }

    pMemoryManager = GPU_GET_MEMORY_MANAGER(pGpu);
    pKernelBus = GPU_GET_KERNEL_BUS(pGpu);

    if (pMemoryManager == NULL || pKernelBus == NULL)
    {
        NV_PRINTF(LEVEL_ERROR, "P2P DMA: NULL managers\n");
        return NV_ERR_INVALID_STATE;
    }

    // Create memory descriptor on first use (for non-GPU-backed buffers)
    if (pHandle->pMemDesc == NULL && !pHandle->bGpuBacked)
    {
        status = _p2pCreateMemDesc(pGpu, pHandle);
        if (status != NV_OK)
        {
            NV_PRINTF(LEVEL_ERROR, "P2P DMA: Failed to create memdesc: 0x%x\n", status);
            return status;
        }
    }

    // Validate GPU
    if (pGpu->bIsSOC || pGpu->getProperty(pGpu, PDB_PROP_GPU_IS_LOST))
    {
        NV_PRINTF(LEVEL_ERROR, "P2P DMA: GPU not available\n");
        return NV_ERR_GPU_IS_LOST;
    }

    // Create GPU memory descriptor
    status = memdescCreate(&pGpuMemDesc, pGpu, size, 0, NV_TRUE, ADDR_FBMEM,
                           NV_MEMORY_UNCACHED, MEMDESC_FLAGS_NONE);
    if (status != NV_OK)
    {
        NV_PRINTF(LEVEL_ERROR, "P2P DMA: Failed to create GPU memdesc: 0x%x\n", status);
        return status;
    }

    memdescDescribe(pGpuMemDesc, ADDR_FBMEM, gpuOffset, size);

    transferSize = size;
    if (transferSize > (NvU64)NV_U32_MAX)
    {
        NV_PRINTF(LEVEL_ERROR, "P2P DMA: transfer size 0x%llx exceeds NvU32 max\n", transferSize);
        memdescDestroy(pGpuMemDesc);
        return NV_ERR_INVALID_ARGUMENT;
    }

    // Set up transfer based on direction
    if (bToGpu)
    {
        // External -> GPU
        srcSurf.pMemDesc = pHandle->pMemDesc;
        srcSurf.offset = umemOffset;
        dstSurf.pMemDesc = pGpuMemDesc;
        dstSurf.offset = 0;

        NV_PRINTF(LEVEL_INFO, "P2P DMA: %s->GPU, size=0x%llx, type=%u\n",
                  pHandle->bufferType == NV_P2P_BUFFER_TYPE_XDP_UMEM ? "UMEM" : "EXT",
                  transferSize, pHandle->bufferType);
    }
    else
    {
        // GPU -> External
        srcSurf.pMemDesc = pGpuMemDesc;
        srcSurf.offset = 0;
        dstSurf.pMemDesc = pHandle->pMemDesc;
        dstSurf.offset = umemOffset;

        NV_PRINTF(LEVEL_INFO, "P2P DMA: GPU->%s, size=0x%llx, type=%u\n",
                  pHandle->bufferType == NV_P2P_BUFFER_TYPE_XDP_UMEM ? "UMEM" : "EXT",
                  transferSize, pHandle->bufferType);
    }

    // Execute DMA via Copy Engine
    status = memmgrMemCopy(pMemoryManager, &dstSurf, &srcSurf, (NvU32)transferSize,
                           TRANSFER_FLAGS_PREFER_CE);

    if (status != NV_OK)
    {
        NV_PRINTF(LEVEL_ERROR, "P2P DMA: CE copy failed: 0x%x\n", status);
    }

    memdescDestroy(pGpuMemDesc);

    return status;
}

// Backward compatibility
NV_STATUS RmP2PCxlDmaRequest(OBJGPU *g, void *h, NvU64 go, NvU64 co, NvU64 s, NvU32 f)
{
    return RmP2PUmemDmaRequest(g, h, go, co, s, f);
}

//
// RmP2PUmemDmaRequestDirect
//
// Direct DMA request that constructs a temporary buffer handle from
// raw physical page addresses.  This is the entry point for the
// kernel-open ioctl path (NV_ESC_P2P_DMA_XFER) which already has
// pinned pages from nv_pin_xdp_umem() but no RM-level registration.
//
NV_STATUS
RmP2PUmemDmaRequestDirect
(
    OBJGPU *pGpu,
    NvU64  *pPhysAddrs,
    NvU32   pageCount,
    NvU32   pageSize,
    NvU64   bufferSize,
    NvU64   gpuOffset,
    NvU64   umemOffset,
    NvU64   size,
    NvU32   flags
)
{
    P2P_UMEM_BUFFER_HANDLE tempHandle;
    NV_STATUS status;

    if (pGpu == NULL || pPhysAddrs == NULL || pageCount == 0)
    {
        NV_PRINTF(LEVEL_ERROR, "P2P DMA Direct: invalid args\n");
        return NV_ERR_INVALID_ARGUMENT;
    }

    portMemSet(&tempHandle, 0, sizeof(tempHandle));
    tempHandle.pPageArray   = pPhysAddrs;
    tempHandle.pageCount    = pageCount;
    tempHandle.pageSize     = pageSize;
    tempHandle.size         = bufferSize;
    tempHandle.bufferType   = NV_P2P_BUFFER_TYPE_XDP_UMEM;
    tempHandle.bRegistered  = NV_TRUE;
    tempHandle.bGpuBacked   = NV_FALSE;
    tempHandle.pMemDesc     = NULL;

    status = RmP2PUmemDmaRequest(pGpu, &tempHandle, gpuOffset,
                                  umemOffset, size, flags);

    // Destroy the transient memory descriptor created by RmP2PUmemDmaRequest
    if (tempHandle.pMemDesc != NULL)
    {
        memdescDestroy(tempHandle.pMemDesc);
        tempHandle.pMemDesc = NULL;
    }

    return status;
}

//
// RmP2PGetBufferInfo
//
// Returns information about a registered buffer.
//
NV_STATUS
RmP2PGetBufferInfo
(
    void   *pBufferHandle,
    NvU32  *pBufferType,
    NvU64  *pSize,
    NvU32  *pPageSize,
    NvU32  *pFrameSize,
    NvBool *pIsGpuBacked
)
{
    P2P_UMEM_BUFFER_HANDLE *pHandle = (P2P_UMEM_BUFFER_HANDLE *)pBufferHandle;

    if (pHandle == NULL)
        return NV_ERR_INVALID_ARGUMENT;

    if (pBufferType)  *pBufferType = pHandle->bufferType;
    if (pSize)        *pSize = pHandle->size;
    if (pPageSize)    *pPageSize = pHandle->pageSize;
    if (pFrameSize)   *pFrameSize = pHandle->frameSize;
    if (pIsGpuBacked) *pIsGpuBacked = pHandle->bGpuBacked;

    return NV_OK;
}
