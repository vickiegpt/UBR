/*
 * SPDX-FileCopyrightText: Copyright (c) 2011-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#define  __NO_VERSION__

#include "os-interface.h"
#include "nv-linux.h"
#include "nv-rsync.h"

#include "nv-p2p.h"
#include "rmp2pdefines.h"

#include "nvmisc.h"

#include <linux/vmalloc.h>

typedef enum nv_p2p_page_table_type {
    NV_P2P_PAGE_TABLE_TYPE_NON_PERSISTENT = 0,
    NV_P2P_PAGE_TABLE_TYPE_PERSISTENT,
} nv_p2p_page_table_type_t;

typedef struct nv_p2p_dma_mapping {
    struct list_head list_node;
    struct nvidia_p2p_dma_mapping *dma_mapping;
} nv_p2p_dma_mapping_t;

typedef struct nv_p2p_mem_info {
    void (*free_callback)(void *data);
    void *data;
    struct nvidia_p2p_page_table page_table;
    struct {
        struct list_head list_head;
        struct semaphore lock;
    } dma_mapping_list;
    void *private;
    void *mig_info;
    NvBool force_pcie;
} nv_p2p_mem_info_t;

// declared and created in nv.c
extern void *nvidia_p2p_page_t_cache;

static struct nvidia_status_mapping {
    NV_STATUS status;
    int error;
} nvidia_status_mappings[] = {
    { NV_ERR_GENERIC,                -EIO      },
    { NV_ERR_INSUFFICIENT_RESOURCES, -ENOMEM   },
    { NV_ERR_NO_MEMORY,              -ENOMEM   },
    { NV_ERR_INVALID_ARGUMENT,       -EINVAL   },
    { NV_ERR_INVALID_OBJECT_HANDLE,  -EINVAL   },
    { NV_ERR_INVALID_STATE,          -EIO      },
    { NV_ERR_NOT_SUPPORTED,          -ENOTSUPP },
    { NV_ERR_OBJECT_NOT_FOUND,       -EINVAL   },
    { NV_ERR_STATE_IN_USE,           -EBUSY    },
    { NV_ERR_GPU_UUID_NOT_FOUND,     -ENODEV   },
    { NV_OK,                          0        },
};

#define NVIDIA_STATUS_MAPPINGS \
    NV_ARRAY_ELEMENTS(nvidia_status_mappings)

static int nvidia_p2p_map_status(NV_STATUS status)
{
    int error = -EIO;
    uint8_t i;

    for (i = 0; i < NVIDIA_STATUS_MAPPINGS; i++)
    {
        if (nvidia_status_mappings[i].status == status)
        {
            error = nvidia_status_mappings[i].error;
            break;
        }
    }
    return error;
}

static NvU32 nvidia_p2p_page_size_mappings[NVIDIA_P2P_PAGE_SIZE_COUNT] = {
    NVRM_P2P_PAGESIZE_SMALL_4K, NVRM_P2P_PAGESIZE_BIG_64K, NVRM_P2P_PAGESIZE_BIG_128K
};

static NV_STATUS nvidia_p2p_map_page_size(NvU32 page_size, NvU32 *page_size_index)
{
    NvU32 i;

    for (i = 0; i < NVIDIA_P2P_PAGE_SIZE_COUNT; i++)
    {
        if (nvidia_p2p_page_size_mappings[i] == page_size)
        {
            *page_size_index = i;
            break;
        }
    }

    if (i == NVIDIA_P2P_PAGE_SIZE_COUNT)
        return NV_ERR_GENERIC;

    return NV_OK;
}

static NV_STATUS nv_p2p_insert_dma_mapping(
    struct nv_p2p_mem_info *mem_info,
    struct nvidia_p2p_dma_mapping *dma_mapping
)
{
    NV_STATUS status;
    struct nv_p2p_dma_mapping *node;

    status = os_alloc_mem((void**)&node, sizeof(*node));
    if (status != NV_OK)
    {
        return status;
    }

    down(&mem_info->dma_mapping_list.lock);

    node->dma_mapping = dma_mapping;
    list_add_tail(&node->list_node, &mem_info->dma_mapping_list.list_head);

    up(&mem_info->dma_mapping_list.lock);

    return NV_OK;
}

static struct nvidia_p2p_dma_mapping* nv_p2p_remove_dma_mapping(
    struct nv_p2p_mem_info *mem_info,
    struct nvidia_p2p_dma_mapping *dma_mapping
)
{
    struct nv_p2p_dma_mapping *cur;
    struct nvidia_p2p_dma_mapping *ret_dma_mapping = NULL;

    down(&mem_info->dma_mapping_list.lock);

    list_for_each_entry(cur, &mem_info->dma_mapping_list.list_head, list_node)
    {
        if (dma_mapping == NULL || dma_mapping == cur->dma_mapping)
        {
            ret_dma_mapping = cur->dma_mapping;
            list_del(&cur->list_node);
            os_free_mem(cur);
            break;
        }
    }

    up(&mem_info->dma_mapping_list.lock);

    return ret_dma_mapping;
}

static void nv_p2p_free_dma_mapping(
    struct nvidia_p2p_dma_mapping *dma_mapping
)
{
    nv_dma_device_t peer_dma_dev = {{ 0 }};
    NvU32 page_size;
    NV_STATUS status;

    peer_dma_dev.dev = &dma_mapping->pci_dev->dev;
    peer_dma_dev.addressable_range.limit = dma_mapping->pci_dev->dma_mask;

    page_size = nvidia_p2p_page_size_mappings[dma_mapping->page_size_type];

    if (dma_mapping->private != NULL)
    {
        /*
         * If OS page size is smaller than P2P page size,
         * page inflation logic applies for DMA unmapping too.
         * Bigger P2P page needs to be split in smaller OS pages.
         */
        if (page_size > PAGE_SIZE)
        {
            NvU64 *os_dma_addresses = NULL;
            NvU32 os_pages_per_p2p_page = page_size;
            NvU32 os_page_count;
            NvU32 index, i, j;

            do_div(os_pages_per_p2p_page, PAGE_SIZE);

            os_page_count = os_pages_per_p2p_page * dma_mapping->entries;

            status = os_alloc_mem((void **)&os_dma_addresses,
                        (os_page_count * sizeof(NvU64)));
            if(WARN_ON(status != NV_OK))
            {
                goto failed;
            }

            index = 0;
            for (i = 0; i < dma_mapping->entries; i++)
            {
                os_dma_addresses[index] = dma_mapping->dma_addresses[i];
                index++;

                for (j = 1; j < os_pages_per_p2p_page; j++)
                {
                    os_dma_addresses[index] = os_dma_addresses[index - 1] + PAGE_SIZE;
                    index++;
                }
            }

            status = nv_dma_unmap_alloc(&peer_dma_dev,
                                        os_page_count,
                                        os_dma_addresses,
                                        &dma_mapping->private);
            WARN_ON(status != NV_OK);

            os_free_mem(os_dma_addresses);
        }
        else
        {
            WARN_ON(page_size != PAGE_SIZE);

            status = nv_dma_unmap_alloc(&peer_dma_dev,
                                        dma_mapping->entries,
                                        dma_mapping->dma_addresses,
                                        &dma_mapping->private);
            WARN_ON(status != NV_OK);
        }
    }
    else
    {
        NvU32 i;
        for (i = 0; i < dma_mapping->entries; i++)
        {
            nv_dma_unmap_peer(&peer_dma_dev, page_size / PAGE_SIZE,
                              dma_mapping->dma_addresses[i]);
        }
    }

failed:
    os_free_mem(dma_mapping->dma_addresses);

    os_free_mem(dma_mapping);
}

static void nv_p2p_free_page_table(
    struct nvidia_p2p_page_table *page_table
)
{
    NvU32 i;
    struct nvidia_p2p_dma_mapping *dma_mapping;
    struct nv_p2p_mem_info *mem_info = NULL;

    mem_info = container_of(page_table, nv_p2p_mem_info_t, page_table);

    dma_mapping = nv_p2p_remove_dma_mapping(mem_info, NULL);
    while (dma_mapping != NULL)
    {
        nv_p2p_free_dma_mapping(dma_mapping);

        dma_mapping = nv_p2p_remove_dma_mapping(mem_info, NULL);
    }

    for (i = 0; i < page_table->entries; i++)
    {
        NV_KMEM_CACHE_FREE(page_table->pages[i], nvidia_p2p_page_t_cache);
    }

    if (page_table->gpu_uuid != NULL)
    {
        os_free_mem(page_table->gpu_uuid);
    }

    if (page_table->pages != NULL)
    {
        os_free_mem(page_table->pages);
    }

    os_free_mem(mem_info);
}

static NV_STATUS nv_p2p_put_pages(
    nv_p2p_page_table_type_t pt_type,
    nvidia_stack_t * sp,
    uint64_t p2p_token,
    uint32_t va_space,
    uint64_t virtual_address,
    struct nvidia_p2p_page_table **page_table
)
{
    NV_STATUS status;

    /*
     * rm_p2p_put_pages returns NV_OK if the page_table was found and
     * got unlinked from the RM's tracker (atomically). This ensures that
     * RM's tear-down path does not race with this path.
     *
     * rm_p2p_put_pages returns NV_ERR_OBJECT_NOT_FOUND if the page_table
     * was already unlinked.
     */
    if (pt_type == NV_P2P_PAGE_TABLE_TYPE_PERSISTENT)
    {
        struct nv_p2p_mem_info *mem_info = NULL;

        /*
         * It is safe to access persistent page_table as there is no async
         * callback which can free it unlike non-persistent page_table.
         */
        mem_info = container_of(*page_table, nv_p2p_mem_info_t, page_table);
        status = rm_p2p_put_pages_persistent(sp, mem_info->private, *page_table, mem_info->mig_info);
    }
    else
    {
        status = rm_p2p_put_pages(sp, p2p_token, va_space,
                                  virtual_address, *page_table);
    }

    if (status == NV_OK)
    {
        nv_p2p_free_page_table(*page_table);
        *page_table = NULL;
    }
    else if ((pt_type == NV_P2P_PAGE_TABLE_TYPE_NON_PERSISTENT) &&
             (status == NV_ERR_OBJECT_NOT_FOUND))
    {
        status = NV_OK;
        *page_table = NULL;
    }
    else
    {
        WARN_ON(status != NV_OK);
    }

    return status;
}

void NV_API_CALL nv_p2p_free_platform_data(
    void *data
)
{
    if (data == NULL)
    {
        WARN_ON(data == NULL);
        return;
    }

    nv_p2p_free_page_table((struct nvidia_p2p_page_table*)data);
}

int nvidia_p2p_init_mapping(
    uint64_t p2p_token,
    struct nvidia_p2p_params *params,
    void (*destroy_callback)(void *data),
    void *data
)
{
    return -ENOTSUPP;
}

NV_EXPORT_SYMBOL(nvidia_p2p_init_mapping);

int nvidia_p2p_destroy_mapping(uint64_t p2p_token)
{
    return -ENOTSUPP;
}

NV_EXPORT_SYMBOL(nvidia_p2p_destroy_mapping);

static void nv_p2p_mem_info_free_callback(void *data)
{
    nv_p2p_mem_info_t *mem_info = (nv_p2p_mem_info_t*) data;

    mem_info->free_callback(mem_info->data);

    nv_p2p_free_platform_data(&mem_info->page_table);
}

static int nv_p2p_get_pages(
    nv_p2p_page_table_type_t pt_type,
    uint64_t p2p_token,
    uint32_t va_space,
    uint64_t virtual_address,
    uint64_t length,
    uint8_t  flags,
    struct nvidia_p2p_page_table **page_table,
    void (*free_callback)(void * data),
    void *data
)
{
    NV_STATUS status;
    nvidia_stack_t *sp = NULL;
    struct nvidia_p2p_page *page;
    struct nv_p2p_mem_info *mem_info = NULL;
    NvU32 entries;
    NvU32 *wreqmb_h = NULL;
    NvU32 *rreqmb_h = NULL;
    NvU64 *physical_addresses = NULL;
    NvU32 page_count;
    NvU32 i = 0;
    NvBool bGetPages = NV_FALSE;
    NvBool bGetUuid = NV_FALSE;
    NvU32 page_size = NVRM_P2P_PAGESIZE_BIG_64K;
    NvU32 page_size_index;
    NvU64 temp_length;
    NvU8 *gpu_uuid = NULL;
    NvU8 uuid[NVIDIA_P2P_GPU_UUID_LEN] = {0};
    NvBool force_pcie = !!(flags & NVIDIA_P2P_FLAGS_FORCE_BAR1_MAPPING);
    NvBool cpu_cacheable;
    int rc;

    if (!NV_IS_ALIGNED64(virtual_address, NVRM_P2P_PAGESIZE_BIG_64K) ||
        !NV_IS_ALIGNED64(length, NVRM_P2P_PAGESIZE_BIG_64K))
    {
        nv_printf(NV_DBG_ERRORS,
                  "NVRM: Invalid argument in nv_p2p_get_pages,"
                  "address or length are not aligned "
                  "address=0x%llx, length=0x%llx\n",
                  virtual_address, length);
        return -EINVAL;
    }

    // Forced PCIe mappings are not supported for non-persistent APIs
    if ((free_callback != NULL) && force_pcie)
    {
        return -ENOTSUPP;
    }

    rc = nv_kmem_cache_alloc_stack(&sp);
    if (rc != 0)
    {
        return rc;
    }

    *page_table = NULL;
    status = os_alloc_mem((void **)&mem_info, sizeof(*mem_info));
    if (status != NV_OK)
    {
        goto failed;
    }

    memset(mem_info, 0, sizeof(*mem_info));

    INIT_LIST_HEAD(&mem_info->dma_mapping_list.list_head);
    NV_INIT_MUTEX(&mem_info->dma_mapping_list.lock);

    mem_info->force_pcie = force_pcie;

    *page_table = &(mem_info->page_table);

    /*
     * assign length to temporary variable since do_div macro does in-place
     * division
     */
    temp_length = length;
    do_div(temp_length, page_size);
    page_count = temp_length;

    if (length & (page_size - 1))
    {
        page_count++;
    }

    status = os_alloc_mem((void **)&physical_addresses,
            (page_count * sizeof(NvU64)));
    if (status != NV_OK)
    {
        goto failed;
    }
    status = os_alloc_mem((void **)&wreqmb_h, (page_count * sizeof(NvU32)));
    if (status != NV_OK)
    {
        goto failed;
    }
    status = os_alloc_mem((void **)&rreqmb_h, (page_count * sizeof(NvU32)));
    if (status != NV_OK)
    {
        goto failed;
    }

    if (pt_type == NV_P2P_PAGE_TABLE_TYPE_PERSISTENT)
    {
        void *gpu_info = NULL;

        if ((p2p_token != 0) || (va_space != 0))
        {
            status = -ENOTSUPP;
            goto failed;
        }

        status = rm_p2p_get_gpu_info(sp, virtual_address, length,
                                     &gpu_uuid, &gpu_info);
        if (status != NV_OK)
        {
            goto failed;
        }

        (*page_table)->gpu_uuid = gpu_uuid;

        rc = nvidia_dev_get_uuid(gpu_uuid, sp);
        if (rc != 0)
        {
            status = NV_ERR_GPU_UUID_NOT_FOUND;
            goto failed;
        }

        os_mem_copy(uuid, gpu_uuid, NVIDIA_P2P_GPU_UUID_LEN);

        bGetUuid = NV_TRUE;

        status = rm_p2p_get_pages_persistent(sp, virtual_address, length,
                                             &mem_info->private,
                                             physical_addresses, &entries,
                                             force_pcie, *page_table, gpu_info,
                                             &mem_info->mig_info, &cpu_cacheable);
        if (status != NV_OK)
        {
            goto failed;
        }
    }
    else
    {
        // Get regular old-style, non-persistent mappings
        status = rm_p2p_get_pages(sp, p2p_token, va_space,
                virtual_address, length, physical_addresses, wreqmb_h,
                rreqmb_h, &entries, &gpu_uuid, *page_table, &cpu_cacheable);
        if (status != NV_OK)
        {
            goto failed;
        }

        (*page_table)->gpu_uuid = gpu_uuid;
    }

    bGetPages = NV_TRUE;

    status = os_alloc_mem((void *)&(*page_table)->pages,
             (entries * sizeof(page)));
    if (status != NV_OK)
    {
        goto failed;
    }

    (*page_table)->version = NVIDIA_P2P_PAGE_TABLE_VERSION;

    for (i = 0; i < entries; i++)
    {
        page = NV_KMEM_CACHE_ALLOC(nvidia_p2p_page_t_cache);
        if (page == NULL)
        {
            status = NV_ERR_NO_MEMORY;
            goto failed;
        }

        memset(page, 0, sizeof(*page));

        page->physical_address = physical_addresses[i];
        page->registers.fermi.wreqmb_h = wreqmb_h[i];
        page->registers.fermi.rreqmb_h = rreqmb_h[i];

        (*page_table)->pages[i] = page;
        (*page_table)->entries++;
    }

    status = nvidia_p2p_map_page_size(page_size, &page_size_index);
    if (status != NV_OK)
    {
        goto failed;
    }

    (*page_table)->page_size = page_size_index;

    if (cpu_cacheable)
    {
        (*page_table)->flags |= NVIDIA_P2P_PAGE_TABLE_FLAGS_CPU_CACHEABLE;
    }

    os_free_mem(physical_addresses);
    physical_addresses = NULL;

    os_free_mem(wreqmb_h);
    wreqmb_h = NULL;

    os_free_mem(rreqmb_h);
    rreqmb_h = NULL;

    if (free_callback != NULL)
    {
        mem_info->free_callback = free_callback;
        mem_info->data          = data;

        status = rm_p2p_register_callback(sp, p2p_token, virtual_address, length,
                                          *page_table, nv_p2p_mem_info_free_callback, mem_info);
        if (status != NV_OK)
        {
            goto failed;
        }
    }

    nv_kmem_cache_free_stack(sp);

    return nvidia_p2p_map_status(status);

failed:
    if (physical_addresses != NULL)
    {
        os_free_mem(physical_addresses);
    }

    if (wreqmb_h != NULL)
    {
        os_free_mem(wreqmb_h);
    }

    if (rreqmb_h != NULL)
    {
        os_free_mem(rreqmb_h);
    }

    if (bGetPages)
    {
        (void)nv_p2p_put_pages(pt_type, sp, p2p_token, va_space,
                               virtual_address, page_table);
    }

    if (bGetUuid)
    {
        nvidia_dev_put_uuid(uuid, sp);
    }

    if (*page_table != NULL)
    {
        nv_p2p_free_page_table(*page_table);
    }

    nv_kmem_cache_free_stack(sp);

    return nvidia_p2p_map_status(status);
}

int nvidia_p2p_get_pages(
    uint64_t p2p_token,
    uint32_t va_space,
    uint64_t virtual_address,
    uint64_t length,
    struct nvidia_p2p_page_table **page_table,
    void (*free_callback)(void * data),
    void *data
)
{
    if (free_callback == NULL)
    {
        return -EINVAL;
    }

    return nv_p2p_get_pages(NV_P2P_PAGE_TABLE_TYPE_NON_PERSISTENT,
                            p2p_token, va_space, virtual_address,
                            length, NVIDIA_P2P_FLAGS_DEFAULT,
                            page_table, free_callback, data);
}
NV_EXPORT_SYMBOL(nvidia_p2p_get_pages);

int nvidia_p2p_get_pages_persistent(
    uint64_t virtual_address,
    uint64_t length,
    struct nvidia_p2p_page_table **page_table,
    uint32_t flags
)
{
    return nv_p2p_get_pages(NV_P2P_PAGE_TABLE_TYPE_PERSISTENT, 0, 0,
                            virtual_address, length, flags, page_table,
                            NULL, NULL);
}
NV_EXPORT_SYMBOL(nvidia_p2p_get_pages_persistent);

/*
 * This function is a no-op, but is left in place (for now), in order to allow
 * third-party callers to build and run without errors or warnings. This is OK,
 * because the missing functionality is provided by nv_p2p_free_platform_data,
 * which is being called as part of the RM's cleanup path.
 */
int nvidia_p2p_free_page_table(struct nvidia_p2p_page_table *page_table)
{
    return 0;
}

NV_EXPORT_SYMBOL(nvidia_p2p_free_page_table);

int nvidia_p2p_put_pages(
    uint64_t p2p_token,
    uint32_t va_space,
    uint64_t virtual_address,
    struct nvidia_p2p_page_table *page_table
)
{
    NV_STATUS status;
    nvidia_stack_t *sp = NULL;
    int rc = 0;

    if (page_table == NULL)
    {
        return 0;
    }

    rc = nv_kmem_cache_alloc_stack(&sp);
    if (rc != 0)
    {
        return -ENOMEM;
    }

    status = nv_p2p_put_pages(NV_P2P_PAGE_TABLE_TYPE_NON_PERSISTENT,
                              sp, p2p_token, va_space,
                              virtual_address, &page_table);
    nv_kmem_cache_free_stack(sp);

    return nvidia_p2p_map_status(status);
}
NV_EXPORT_SYMBOL(nvidia_p2p_put_pages);

int nvidia_p2p_put_pages_persistent(
    uint64_t virtual_address,
    struct nvidia_p2p_page_table *page_table,
    uint32_t flags
)
{
    NvU8 uuid[NVIDIA_P2P_GPU_UUID_LEN] = {0};
    NV_STATUS status;
    nvidia_stack_t *sp = NULL;
    int rc = 0;

    if (flags != 0)
    {
        return -EINVAL;
    }

    if (page_table == NULL)
    {
        return 0;
    }

    rc = nv_kmem_cache_alloc_stack(&sp);
    if (rc != 0)
    {
        return -ENOMEM;
    }

    os_mem_copy(uuid, page_table->gpu_uuid, NVIDIA_P2P_GPU_UUID_LEN);

    status = nv_p2p_put_pages(NV_P2P_PAGE_TABLE_TYPE_PERSISTENT,
                              sp, 0, 0, virtual_address, &page_table);

    nvidia_dev_put_uuid(uuid, sp);

    nv_kmem_cache_free_stack(sp);

    return nvidia_p2p_map_status(status);
}
NV_EXPORT_SYMBOL(nvidia_p2p_put_pages_persistent);

int nvidia_p2p_dma_map_pages(
    struct pci_dev *peer,
    struct nvidia_p2p_page_table *page_table,
    struct nvidia_p2p_dma_mapping **dma_mapping
)
{
    NV_STATUS status;
    nv_dma_device_t peer_dma_dev = {{ 0 }};
    nvidia_stack_t *sp = NULL;
    NvU64 *dma_addresses = NULL;
    NvU32 page_count;
    NvU32 page_size;
    enum nvidia_p2p_page_size_type page_size_type;
    struct nv_p2p_mem_info *mem_info = NULL;
    NvU32 i;
    void *priv;
    int rc;

    if (peer == NULL || page_table == NULL || dma_mapping == NULL ||
        page_table->gpu_uuid == NULL)
    {
        return -EINVAL;
    }

    mem_info = container_of(page_table, nv_p2p_mem_info_t, page_table);

    //
    // Only CPU mappings are supported for forced PCIe config through
    // nv-p2p APIs. IO mappings will not be supported.
    //
    if (mem_info->force_pcie)
    {
        return -ENOTSUPP;
    }

    rc = nv_kmem_cache_alloc_stack(&sp);
    if (rc != 0)
    {
        return rc;
    }

    *dma_mapping = NULL;
    status = os_alloc_mem((void **)dma_mapping, sizeof(**dma_mapping));
    if (status != NV_OK)
    {
        goto failed;
    }
    memset(*dma_mapping, 0, sizeof(**dma_mapping));

    page_count = page_table->entries;

    status = os_alloc_mem((void **)&dma_addresses,
            (page_count * sizeof(NvU64)));
    if (status != NV_OK)
    {
        goto failed;
    }

    page_size_type = page_table->page_size;

    BUG_ON((page_size_type <= NVIDIA_P2P_PAGE_SIZE_4KB) ||
           (page_size_type >= NVIDIA_P2P_PAGE_SIZE_COUNT));

    peer_dma_dev.dev = &peer->dev;
    peer_dma_dev.addressable_range.limit = peer->dma_mask;

    page_size = nvidia_p2p_page_size_mappings[page_size_type];

    for (i = 0; i < page_count; i++)
    {
        dma_addresses[i] = page_table->pages[i]->physical_address;
    }

    status = rm_p2p_dma_map_pages(sp, &peer_dma_dev,
            page_table->gpu_uuid, page_size, page_count, dma_addresses, &priv);
    if (status != NV_OK)
    {
        goto failed;
    }

    (*dma_mapping)->version = NVIDIA_P2P_DMA_MAPPING_VERSION;
    (*dma_mapping)->page_size_type = page_size_type;
    (*dma_mapping)->entries = page_count;
    (*dma_mapping)->dma_addresses = dma_addresses;
    (*dma_mapping)->private = priv;
    (*dma_mapping)->pci_dev = peer;

    /*
     * All success, it is safe to insert dma_mapping now.
     */
    status = nv_p2p_insert_dma_mapping(mem_info, *dma_mapping);
    if (status != NV_OK)
    {
        goto failed_insert;
    }

    nv_kmem_cache_free_stack(sp);

    return 0;

failed_insert:
    nv_p2p_free_dma_mapping(*dma_mapping);
    dma_addresses = NULL;
    *dma_mapping = NULL;

failed:
    if (dma_addresses != NULL)
    {
        os_free_mem(dma_addresses);
    }

    if (*dma_mapping != NULL)
    {
        os_free_mem(*dma_mapping);
        *dma_mapping = NULL;
    }

    nv_kmem_cache_free_stack(sp);

    return nvidia_p2p_map_status(status);
}

NV_EXPORT_SYMBOL(nvidia_p2p_dma_map_pages);

int nvidia_p2p_dma_unmap_pages(
    struct pci_dev *peer,
    struct nvidia_p2p_page_table *page_table,
    struct nvidia_p2p_dma_mapping *dma_mapping
)
{
    struct nv_p2p_mem_info *mem_info = NULL;

    if (peer == NULL || dma_mapping == NULL || page_table == NULL)
    {
        return -EINVAL;
    }

    mem_info = container_of(page_table, nv_p2p_mem_info_t, page_table);

    /*
     * nv_p2p_remove_dma_mapping returns dma_mapping if the dma_mapping was
     * found and got unlinked from the mem_info->dma_mapping_list (atomically).
     * This ensures that the RM's tear-down path does not race with this path.
     *
     * nv_p2p_remove_dma_mappings returns NULL if the dma_mapping was already
     * unlinked.
     */
    if (nv_p2p_remove_dma_mapping(mem_info, dma_mapping) == NULL)
    {
        return 0;
    }

    WARN_ON(peer != dma_mapping->pci_dev);

    BUG_ON((dma_mapping->page_size_type <= NVIDIA_P2P_PAGE_SIZE_4KB) ||
           (dma_mapping->page_size_type >= NVIDIA_P2P_PAGE_SIZE_COUNT));

    nv_p2p_free_dma_mapping(dma_mapping);

    return 0;
}

NV_EXPORT_SYMBOL(nvidia_p2p_dma_unmap_pages);

/*
 * This function is a no-op, but is left in place (for now), in order to allow
 * third-party callers to build and run without errors or warnings. This is OK,
 * because the missing functionality is provided by nv_p2p_free_platform_data,
 * which is being called as part of the RM's cleanup path.
 */
int nvidia_p2p_free_dma_mapping(
    struct nvidia_p2p_dma_mapping *dma_mapping
)
{
    return 0;
}

NV_EXPORT_SYMBOL(nvidia_p2p_free_dma_mapping);

int nvidia_p2p_register_rsync_driver(
    nvidia_p2p_rsync_driver_t *driver,
    void *data
)
{
    if (driver == NULL)
    {
        return -EINVAL;
    }

    if (!NVIDIA_P2P_RSYNC_DRIVER_VERSION_COMPATIBLE(driver))
    {
        return -EINVAL;
    }

    if (driver->get_relaxed_ordering_mode == NULL ||
        driver->put_relaxed_ordering_mode == NULL ||
        driver->wait_for_rsync == NULL)
    {
        return -EINVAL;
    }

    return nv_register_rsync_driver(driver->get_relaxed_ordering_mode,
                                    driver->put_relaxed_ordering_mode,
                                    driver->wait_for_rsync, data);
}

NV_EXPORT_SYMBOL(nvidia_p2p_register_rsync_driver);

void nvidia_p2p_unregister_rsync_driver(
    nvidia_p2p_rsync_driver_t *driver,
    void *data
)
{
    if (driver == NULL)
    {
        WARN_ON(1);
        return;
    }

    if (!NVIDIA_P2P_RSYNC_DRIVER_VERSION_COMPATIBLE(driver))
    {
        WARN_ON(1);
        return;
    }

    if (driver->get_relaxed_ordering_mode == NULL ||
        driver->put_relaxed_ordering_mode == NULL ||
        driver->wait_for_rsync == NULL)
    {
        WARN_ON(1);
        return;
    }

    nv_unregister_rsync_driver(driver->get_relaxed_ordering_mode,
                               driver->put_relaxed_ordering_mode,
                               driver->wait_for_rsync, data);
}

NV_EXPORT_SYMBOL(nvidia_p2p_unregister_rsync_driver);

int nvidia_p2p_get_rsync_registers(
    nvidia_p2p_rsync_reg_info_t **reg_info
)
{
    // TODO: Remove this interface.
    return -ENODEV;
}

NV_EXPORT_SYMBOL(nvidia_p2p_get_rsync_registers);

void nvidia_p2p_put_rsync_registers(
    nvidia_p2p_rsync_reg_info_t *reg_info
)
{
    // TODO: Remove this interface.  There is nothing to do because
    // nvidia_p2p_get_rsync_registers always fails.
}

NV_EXPORT_SYMBOL(nvidia_p2p_put_rsync_registers);

/*
 * Generic P2P UMEM Buffer Support
 *
 * Provides unified page pinning and DMA support for:
 * - CXL memory expanders
 * - AF_XDP UMEM (zero-copy networking)
 * - Generic user memory regions for GPU DMA
 *
 * Supports both directions:
 * - GPU DMA to/from UMEM (Copy Engine transfers)
 * - GPU memory registered as UMEM backing store
 */

#include <linux/sched/signal.h>
#include <linux/netdevice.h>

// Try to include AF_XDP headers if available
#if defined(CONFIG_XDP_SOCKETS) || defined(CONFIG_XDP_SOCKETS_MODULE)
#include <net/xdp_sock_drv.h>
#define NV_XDP_UMEM_SUPPORT 1
#else
#define NV_XDP_UMEM_SUPPORT 0
#endif

// Buffer type enumeration
typedef enum {
    NV_P2P_BUFFER_TYPE_GENERIC = 0,    // Generic user memory
    NV_P2P_BUFFER_TYPE_CXL,            // CXL memory expander
    NV_P2P_BUFFER_TYPE_XDP_UMEM,       // AF_XDP UMEM
    NV_P2P_BUFFER_TYPE_GPU_EXPORT,     // GPU memory exported as UMEM
} nv_p2p_buffer_type_t;

// Global tracking for pinned buffers (generic)
typedef struct {
    spinlock_t      lock;
    NvU64           totalPinnedBytes;      // Total bytes currently pinned
    NvU64           totalPinnedPages;      // Total pages currently pinned
    NvU32           numBuffers;            // Number of active buffers
    NvU64           maxPinnedBytes;        // Maximum allowed pinned bytes (0 = no limit)
    NvU32           maxBuffers;            // Maximum number of buffers (0 = no limit)
    NvBool          bInitialized;
} nv_p2p_umem_tracker_t;

static nv_p2p_umem_tracker_t g_p2pUmemTracker = {
    .totalPinnedBytes = 0,
    .totalPinnedPages = 0,
    .numBuffers = 0,
    .maxPinnedBytes = 0,           // Will be set based on system memory
    .maxBuffers = 256,             // Default max buffers
    .bInitialized = NV_FALSE
};

// Per-buffer structure (generic for all buffer types)
typedef struct {
    NvU64                   userVirtAddr;
    NvU64                   size;
    NvU32                   pageCount;
    NvU32                   pageSize;       // Track actual page size (4K or 2M)
    NvU32                   frameSize;      // XDP frame size (for UMEM)
    NvU64                  *physAddrs;
    struct page           **pages;
    NvBool                  bHugePages;     // Whether huge pages are used
    NvU32                   refCount;       // Reference count for buffer reuse
    nv_p2p_buffer_type_t    bufferType;     // Type of buffer
    struct list_head        listNode;       // For tracking in global list
    // XDP-specific fields
#if NV_XDP_UMEM_SUPPORT
    struct xdp_umem        *xdpUmem;        // XDP UMEM reference (if applicable)
    struct xsk_buff_pool   *xskPool;        // XSK buffer pool (if applicable)
#endif
    void                   *gpuMemHandle;   // GPU memory handle (for GPU export)
    NvU64                   gpuOffset;      // GPU memory offset
    NvBool                  bGpuBacked;     // Whether backed by GPU memory
} nv_p2p_umem_buffer_t;

// Backwards compatibility typedef
typedef nv_p2p_umem_buffer_t cxl_pinned_buffer_t;

// Initialize the global tracker (called on first use)
static void nv_p2p_umem_init_tracker(void)
{
    struct sysinfo si;

    if (g_p2pUmemTracker.bInitialized)
        return;

    spin_lock_init(&g_p2pUmemTracker.lock);

    // Get system memory info to set reasonable limits
    si_meminfo(&si);

    // Default: allow pinning up to 90% of total system RAM for P2P workloads
    g_p2pUmemTracker.maxPinnedBytes = (NvU64)si.totalram * si.mem_unit * 9 / 10;
    g_p2pUmemTracker.bInitialized = NV_TRUE;
}

// Check if we can pin more memory (fast path)
static inline NV_STATUS nv_p2p_umem_check_limits(NvU64 size, NvU32 pageCount)
{
    unsigned long flags;

    nv_p2p_umem_init_tracker();

    spin_lock_irqsave(&g_p2pUmemTracker.lock, flags);

    // Check buffer count limit
    if (g_p2pUmemTracker.maxBuffers > 0 &&
        g_p2pUmemTracker.numBuffers >= g_p2pUmemTracker.maxBuffers)
    {
        spin_unlock_irqrestore(&g_p2pUmemTracker.lock, flags);
        return NV_ERR_INSUFFICIENT_RESOURCES;
    }

    // Check total pinned bytes limit
    if (g_p2pUmemTracker.maxPinnedBytes > 0 &&
        g_p2pUmemTracker.totalPinnedBytes + size > g_p2pUmemTracker.maxPinnedBytes)
    {
        spin_unlock_irqrestore(&g_p2pUmemTracker.lock, flags);
        return NV_ERR_INSUFFICIENT_RESOURCES;
    }

    spin_unlock_irqrestore(&g_p2pUmemTracker.lock, flags);
    return NV_OK;
}

// Update tracker after successful pin (inline for performance)
static inline void nv_p2p_umem_track_pin(NvU64 size, NvU32 pageCount)
{
    unsigned long flags;

    spin_lock_irqsave(&g_p2pUmemTracker.lock, flags);
    g_p2pUmemTracker.totalPinnedBytes += size;
    g_p2pUmemTracker.totalPinnedPages += pageCount;
    g_p2pUmemTracker.numBuffers++;
    spin_unlock_irqrestore(&g_p2pUmemTracker.lock, flags);
}

// Update tracker after unpin (inline for performance)
static inline void nv_p2p_umem_track_unpin(NvU64 size, NvU32 pageCount)
{
    unsigned long flags;

    spin_lock_irqsave(&g_p2pUmemTracker.lock, flags);
    if (g_p2pUmemTracker.totalPinnedBytes >= size)
        g_p2pUmemTracker.totalPinnedBytes -= size;
    if (g_p2pUmemTracker.totalPinnedPages >= pageCount)
        g_p2pUmemTracker.totalPinnedPages -= pageCount;
    if (g_p2pUmemTracker.numBuffers > 0)
        g_p2pUmemTracker.numBuffers--;
    spin_unlock_irqrestore(&g_p2pUmemTracker.lock, flags);
}

// Backward compatibility aliases
#define cxl_init_tracker        nv_p2p_umem_init_tracker
#define cxl_check_pin_limits    nv_p2p_umem_check_limits
#define cxl_track_pin           nv_p2p_umem_track_pin
#define cxl_track_unpin         nv_p2p_umem_track_unpin

NV_STATUS NV_API_CALL nv_pin_cxl_buffer(
    NvU64   userVirtAddr,
    NvU64   size,
    void  **ppHandle
)
{
    cxl_pinned_buffer_t *pBuffer = NULL;
    unsigned long startAddr;
    NvU32 pageCount;
    int ret;
    NvU32 i;
    NV_STATUS status;
    NvBool bLargeAlloc;

    if (unlikely(size == 0 || ppHandle == NULL))
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: CXL pin: invalid argument (size=%llu, ppHandle=%p)\n",
                  (unsigned long long)size, ppHandle);
        return NV_ERR_INVALID_ARGUMENT;
    }

    // Check for overflow
    if (unlikely(userVirtAddr > ULONG_MAX - size))
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: CXL pin: address overflow (addr=0x%llx, size=0x%llx)\n",
                  (unsigned long long)userVirtAddr, (unsigned long long)size);
        return NV_ERR_INVALID_ARGUMENT;
    }

    startAddr = userVirtAddr & PAGE_MASK;
    pageCount = ((userVirtAddr + size - 1) >> PAGE_SHIFT) - (startAddr >> PAGE_SHIFT) + 1;

    // Sanity check (max ~1TB)
    if (unlikely(pageCount == 0 || pageCount > (1UL << 28)))
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: CXL pin: invalid page count %u (size=0x%llx)\n",
                  pageCount, (unsigned long long)size);
        return NV_ERR_INVALID_ARGUMENT;
    }

    // Check limits before allocating
    status = cxl_check_pin_limits(size, pageCount);
    if (unlikely(status != NV_OK))
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: CXL pin: resource limit exceeded (size=0x%llx, pages=%u)\n",
                  (unsigned long long)size, pageCount);
        return status;
    }

    pBuffer = kzalloc(sizeof(*pBuffer), GFP_KERNEL);
    if (unlikely(pBuffer == NULL))
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: CXL pin: failed to allocate buffer struct\n");
        return NV_ERR_NO_MEMORY;
    }

    // Use vmalloc for large arrays (>512 entries)
    bLargeAlloc = (pageCount > 512);

    if (bLargeAlloc)
    {
        pBuffer->pages = vmalloc(pageCount * sizeof(struct page *));
        pBuffer->physAddrs = vmalloc(pageCount * sizeof(NvU64));
    }
    else
    {
        pBuffer->pages = kmalloc(pageCount * sizeof(struct page *), GFP_KERNEL);
        pBuffer->physAddrs = kmalloc(pageCount * sizeof(NvU64), GFP_KERNEL);
    }

    if (unlikely(pBuffer->pages == NULL || pBuffer->physAddrs == NULL))
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: CXL pin: failed to allocate page arrays (%u pages)\n", pageCount);
        goto fail_alloc;
    }

    // Pin user pages
    nv_mmap_read_lock(current->mm);
    ret = NV_PIN_USER_PAGES(startAddr, pageCount, FOLL_WRITE, pBuffer->pages);
    nv_mmap_read_unlock(current->mm);

    if (unlikely(ret != pageCount))
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: CXL pin: page pinning failed - got %d, expected %u (addr=0x%lx)\n",
                  ret, pageCount, startAddr);
        if (ret > 0)
        {
            for (i = 0; i < ret; i++)
                NV_UNPIN_USER_PAGE(pBuffer->pages[i]);
        }
        goto fail_alloc;
    }

    // Convert to physical addresses with validation
    for (i = 0; i < pageCount; i++)
    {
        if (unlikely(pBuffer->pages[i] == NULL))
        {
            nv_printf(NV_DBG_ERRORS, "NVRM: CXL pin: NULL page at index %u\n", i);
            // Unpin pages we've processed so far
            for (; i > 0; i--)
                NV_UNPIN_USER_PAGE(pBuffer->pages[i - 1]);
            goto fail_alloc;
        }
        pBuffer->physAddrs[i] = page_to_phys(pBuffer->pages[i]);

        // Sanity check physical address
        if (unlikely(pBuffer->physAddrs[i] == 0))
        {
            nv_printf(NV_DBG_ERRORS, "NVRM: CXL pin: zero physical address at page %u\n", i);
        }
    }

    pBuffer->userVirtAddr = userVirtAddr;
    pBuffer->size = size;
    pBuffer->pageCount = pageCount;
    pBuffer->pageSize = PAGE_SIZE;
    pBuffer->refCount = 1;
    pBuffer->bHugePages = NV_FALSE;

    cxl_track_pin(size, pageCount);
    *ppHandle = pBuffer;
    return NV_OK;

fail_alloc:
    if (pBuffer->physAddrs)
    {
        if (bLargeAlloc)
            vfree(pBuffer->physAddrs);
        else
            kfree(pBuffer->physAddrs);
    }
    if (pBuffer->pages)
    {
        if (bLargeAlloc)
            vfree(pBuffer->pages);
        else
            kfree(pBuffer->pages);
    }
    kfree(pBuffer);
    return NV_ERR_NO_MEMORY;
}

NV_STATUS NV_API_CALL nv_unpin_cxl_buffer(void *pHandle)
{
    cxl_pinned_buffer_t *pBuffer = (cxl_pinned_buffer_t *)pHandle;
    NvU32 i;
    NvU64 savedSize;
    NvU32 savedPageCount;
    NvBool bLargeAlloc;

    if (unlikely(pBuffer == NULL))
        return NV_ERR_INVALID_ARGUMENT;

    savedSize = pBuffer->size;
    savedPageCount = pBuffer->pageCount;
    bLargeAlloc = (savedPageCount > 512);

    // Unpin pages
    if (pBuffer->pages)
    {
        for (i = 0; i < savedPageCount; i++)
        {
            if (pBuffer->pages[i])
                NV_UNPIN_USER_PAGE(pBuffer->pages[i]);
        }

        if (bLargeAlloc)
            vfree(pBuffer->pages);
        else
            kfree(pBuffer->pages);
    }

    if (pBuffer->physAddrs)
    {
        if (bLargeAlloc)
            vfree(pBuffer->physAddrs);
        else
            kfree(pBuffer->physAddrs);
    }

    kfree(pBuffer);
    cxl_track_unpin(savedSize, savedPageCount);

    return NV_OK;
}

NV_STATUS NV_API_CALL nv_get_cxl_buffer_pages(
    void    *pHandle,
    NvU64  **ppPhysAddrs,
    NvU32   *pPageCount
)
{
    cxl_pinned_buffer_t *pBuffer = (cxl_pinned_buffer_t *)pHandle;

    if (unlikely(pBuffer == NULL || ppPhysAddrs == NULL || pPageCount == NULL))
        return NV_ERR_INVALID_ARGUMENT;

    if (unlikely(pBuffer->physAddrs == NULL || pBuffer->pageCount == 0))
        return NV_ERR_INVALID_STATE;

    *ppPhysAddrs = pBuffer->physAddrs;
    *pPageCount = pBuffer->pageCount;

    return NV_OK;
}

/*
 * CXL Buffer Huge Page Pinning (2MB pages)
 *
 * Pins user pages using huge pages (2MB) for CXL buffer DMA.
 * Huge pages significantly reduce page table overhead for large transfers.
 */
#define CXL_HUGEPAGE_SIZE       (2ULL * 1024 * 1024)  // 2MB
#define CXL_HUGEPAGE_SHIFT      21

NV_STATUS NV_API_CALL nv_pin_cxl_buffer_hugepages(
    NvU64   userVirtAddr,
    NvU64   size,
    NvU32   requestedPageSize,
    void  **ppHandle
)
{
    cxl_pinned_buffer_t *pBuffer = NULL;
    unsigned long startAddr;
    NvU32 pageCount;
    NvU32 actualPageSize;
    int ret;
    NvU32 i;
    NV_STATUS status;
    NvBool bLargeAlloc;
    NvBool bUseHugePages = NV_FALSE;

    if (unlikely(size == 0 || ppHandle == NULL))
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: CXL hugepage pin: invalid argument\n");
        return NV_ERR_INVALID_ARGUMENT;
    }

    // Check if we can use huge pages (both address and size must be 2MB aligned)
    if (requestedPageSize == CXL_HUGEPAGE_SIZE &&
        (userVirtAddr & (CXL_HUGEPAGE_SIZE - 1)) == 0 &&
        (size & (CXL_HUGEPAGE_SIZE - 1)) == 0 &&
        size >= CXL_HUGEPAGE_SIZE)
    {
        bUseHugePages = NV_TRUE;
        actualPageSize = CXL_HUGEPAGE_SIZE;
        startAddr = userVirtAddr;
        pageCount = (NvU32)(size >> CXL_HUGEPAGE_SHIFT);
        nv_printf(NV_DBG_INFO, "NVRM: CXL hugepage pin: using 2MB pages (%u pages)\n", pageCount);
    }
    else
    {
        // Fall back to 4K pages
        actualPageSize = PAGE_SIZE;
        startAddr = userVirtAddr & PAGE_MASK;
        pageCount = ((userVirtAddr + size - 1) >> PAGE_SHIFT) - (startAddr >> PAGE_SHIFT) + 1;
        nv_printf(NV_DBG_INFO, "NVRM: CXL hugepage pin: falling back to 4K pages (%u pages)\n", pageCount);
    }

    // Check limits
    status = cxl_check_pin_limits(size, pageCount);
    if (status != NV_OK)
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: CXL hugepage pin: resource limit exceeded\n");
        return status;
    }

    // Allocate buffer structure
    pBuffer = kzalloc(sizeof(cxl_pinned_buffer_t), GFP_KERNEL);
    if (pBuffer == NULL)
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: CXL hugepage pin: failed to allocate buffer struct\n");
        return NV_ERR_NO_MEMORY;
    }

    pBuffer->userVirtAddr = userVirtAddr;
    pBuffer->size = size;
    pBuffer->pageCount = pageCount;
    pBuffer->pageSize = actualPageSize;
    pBuffer->bHugePages = bUseHugePages;
    pBuffer->refCount = 1;

    bLargeAlloc = (pageCount > 512);

    // Allocate page tracking arrays
    if (bLargeAlloc)
    {
        pBuffer->physAddrs = vmalloc(pageCount * sizeof(NvU64));
        pBuffer->pages = vmalloc(pageCount * sizeof(struct page *));
    }
    else
    {
        pBuffer->physAddrs = kmalloc(pageCount * sizeof(NvU64), GFP_KERNEL);
        pBuffer->pages = kmalloc(pageCount * sizeof(struct page *), GFP_KERNEL);
    }

    if (pBuffer->physAddrs == NULL || pBuffer->pages == NULL)
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: CXL hugepage pin: failed to allocate arrays\n");
        goto fail_alloc;
    }

    memset(pBuffer->pages, 0, pageCount * sizeof(struct page *));
    memset(pBuffer->physAddrs, 0, pageCount * sizeof(NvU64));

    // Pin pages using pin_user_pages
    // NV_PIN_USER_PAGES macro handles the vmas argument internally based on kernel version
    ret = NV_PIN_USER_PAGES(startAddr, pageCount, FOLL_LONGTERM | FOLL_WRITE,
                           pBuffer->pages);
    if (ret != pageCount)
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: CXL hugepage pin: failed - got %d, expected %u\n",
                  ret, pageCount);
        // Unpin any pages that were pinned
        if (ret > 0)
        {
            for (i = 0; i < (NvU32)ret; i++)
            {
                if (pBuffer->pages[i])
                    NV_UNPIN_USER_PAGE(pBuffer->pages[i]);
            }
        }
        goto fail_alloc;
    }

    // Convert page pointers to physical addresses
    for (i = 0; i < pageCount; i++)
    {
        if (pBuffer->pages[i] == NULL)
        {
            nv_printf(NV_DBG_ERRORS, "NVRM: CXL hugepage pin: NULL page at index %u\n", i);
            goto fail_unpin;
        }
        pBuffer->physAddrs[i] = page_to_phys(pBuffer->pages[i]);
        if (pBuffer->physAddrs[i] == 0)
        {
            nv_printf(NV_DBG_ERRORS, "NVRM: CXL hugepage pin: zero phys addr at page %u\n", i);
            goto fail_unpin;
        }
    }

    cxl_track_pin(size, pageCount);
    *ppHandle = pBuffer;

    nv_printf(NV_DBG_INFO, "NVRM: CXL hugepage pin: success - %u %s pages, size=0x%llx\n",
              pageCount, bUseHugePages ? "2MB" : "4K", (unsigned long long)size);

    return NV_OK;

fail_unpin:
    for (i = 0; i < pageCount; i++)
    {
        if (pBuffer->pages[i])
            NV_UNPIN_USER_PAGE(pBuffer->pages[i]);
    }

fail_alloc:
    if (pBuffer->physAddrs)
    {
        if (bLargeAlloc)
            vfree(pBuffer->physAddrs);
        else
            kfree(pBuffer->physAddrs);
    }
    if (pBuffer->pages)
    {
        if (bLargeAlloc)
            vfree(pBuffer->pages);
        else
            kfree(pBuffer->pages);
    }
    kfree(pBuffer);
    return NV_ERR_NO_MEMORY;
}

NV_STATUS NV_API_CALL nv_get_cxl_buffer_hugepages(
    void    *pHandle,
    NvU64  **ppPhysAddrs,
    NvU32   *pPageCount,
    NvU32   *pPageSize
)
{
    cxl_pinned_buffer_t *pBuffer = (cxl_pinned_buffer_t *)pHandle;

    if (unlikely(pBuffer == NULL || ppPhysAddrs == NULL ||
                 pPageCount == NULL || pPageSize == NULL))
        return NV_ERR_INVALID_ARGUMENT;

    if (unlikely(pBuffer->physAddrs == NULL || pBuffer->pageCount == 0))
        return NV_ERR_INVALID_STATE;

    *ppPhysAddrs = pBuffer->physAddrs;
    *pPageCount = pBuffer->pageCount;
    *pPageSize = pBuffer->pageSize;

    return NV_OK;
}

/*
 * ============================================================================
 * AF_XDP UMEM Support for GPU P2P DMA
 * ============================================================================
 *
 * Provides zero-copy networking support via AF_XDP sockets.
 * Enables direct GPU DMA to/from XDP UMEM frames.
 *
 * Two modes of operation:
 * 1. User UMEM -> GPU: Pin user's UMEM and enable GPU DMA access
 * 2. GPU -> UMEM: Export GPU memory as UMEM backing for zero-copy TX
 */

// XDP frame size constants
#define NV_XDP_FRAME_SIZE_2K     2048
#define NV_XDP_FRAME_SIZE_4K     4096
#define NV_XDP_DEFAULT_HEADROOM  256

/*
 * nv_pin_xdp_umem
 *
 * Pins an AF_XDP UMEM region for GPU DMA access.
 * The UMEM must already be registered with the kernel via XSK socket.
 *
 * Parameters:
 *   umemAddr     [IN]  - User virtual address of UMEM region
 *   size         [IN]  - Size of UMEM in bytes
 *   frameSize    [IN]  - Size of each XDP frame (typically 2K or 4K)
 *   ppHandle     [OUT] - Returns handle for subsequent operations
 */
NV_STATUS NV_API_CALL nv_pin_xdp_umem(
    NvU64   umemAddr,
    NvU64   size,
    NvU32   frameSize,
    void  **ppHandle
)
{
    nv_p2p_umem_buffer_t *pBuffer = NULL;
    unsigned long startAddr;
    NvU32 pageCount;
    int ret;
    NvU32 i;
    NV_STATUS status;
    NvBool bLargeAlloc;

    if (unlikely(size == 0 || ppHandle == NULL))
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: XDP UMEM pin: invalid argument\n");
        return NV_ERR_INVALID_ARGUMENT;
    }

    // Validate frame size (must be power of 2, typically 2K or 4K)
    if (frameSize == 0 || (frameSize & (frameSize - 1)) != 0)
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: XDP UMEM pin: invalid frame size %u\n", frameSize);
        return NV_ERR_INVALID_ARGUMENT;
    }

    // UMEM size must be multiple of frame size
    if (size % frameSize != 0)
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: XDP UMEM pin: size 0x%llx not multiple of frame %u\n",
                  (unsigned long long)size, frameSize);
        return NV_ERR_INVALID_ARGUMENT;
    }

    startAddr = umemAddr & PAGE_MASK;
    pageCount = ((umemAddr + size - 1) >> PAGE_SHIFT) - (startAddr >> PAGE_SHIFT) + 1;

    // Check limits
    status = nv_p2p_umem_check_limits(size, pageCount);
    if (status != NV_OK)
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: XDP UMEM pin: resource limit exceeded\n");
        return status;
    }

    pBuffer = kzalloc(sizeof(*pBuffer), GFP_KERNEL);
    if (pBuffer == NULL)
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: XDP UMEM pin: failed to allocate buffer struct\n");
        return NV_ERR_NO_MEMORY;
    }

    pBuffer->bufferType = NV_P2P_BUFFER_TYPE_XDP_UMEM;
    pBuffer->frameSize = frameSize;
    pBuffer->bGpuBacked = NV_FALSE;

    bLargeAlloc = (pageCount > 512);

    if (bLargeAlloc)
    {
        pBuffer->pages = vmalloc(pageCount * sizeof(struct page *));
        pBuffer->physAddrs = vmalloc(pageCount * sizeof(NvU64));
    }
    else
    {
        pBuffer->pages = kmalloc(pageCount * sizeof(struct page *), GFP_KERNEL);
        pBuffer->physAddrs = kmalloc(pageCount * sizeof(NvU64), GFP_KERNEL);
    }

    if (pBuffer->pages == NULL || pBuffer->physAddrs == NULL)
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: XDP UMEM pin: failed to allocate arrays\n");
        goto fail_alloc;
    }

    // Pin UMEM pages with FOLL_LONGTERM for persistent DMA access.
    // Do NOT hold mmap_read_lock with FOLL_LONGTERM — on kernel 5.10+
    // this can trigger lockdep warnings or fail for certain memory types
    // (e.g., huge pages).  Matches the CXL hugepage pin path above.
    ret = NV_PIN_USER_PAGES(startAddr, pageCount, FOLL_LONGTERM | FOLL_WRITE, pBuffer->pages);

    if (ret != pageCount)
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: XDP UMEM pin: failed - got %d, expected %u\n",
                  ret, pageCount);
        if (ret > 0)
        {
            for (i = 0; i < (NvU32)ret; i++)
                NV_UNPIN_USER_PAGE(pBuffer->pages[i]);
        }
        goto fail_alloc;
    }

    // Convert to physical addresses
    for (i = 0; i < pageCount; i++)
    {
        if (pBuffer->pages[i] == NULL)
        {
            nv_printf(NV_DBG_ERRORS, "NVRM: XDP UMEM pin: NULL page at index %u\n", i);
            goto fail_unpin;
        }
        pBuffer->physAddrs[i] = page_to_phys(pBuffer->pages[i]);
    }

    pBuffer->userVirtAddr = umemAddr;
    pBuffer->size = size;
    pBuffer->pageCount = pageCount;
    pBuffer->pageSize = PAGE_SIZE;
    pBuffer->refCount = 1;

    nv_p2p_umem_track_pin(size, pageCount);
    *ppHandle = pBuffer;

    nv_printf(NV_DBG_INFO, "NVRM: XDP UMEM pin: success - %u pages, %llu frames of %u bytes\n",
              pageCount, (unsigned long long)(size / frameSize), frameSize);

    return NV_OK;

fail_unpin:
    for (i = 0; i < pageCount; i++)
    {
        if (pBuffer->pages[i])
            NV_UNPIN_USER_PAGE(pBuffer->pages[i]);
    }

fail_alloc:
    if (pBuffer->physAddrs)
    {
        if (bLargeAlloc)
            vfree(pBuffer->physAddrs);
        else
            kfree(pBuffer->physAddrs);
    }
    if (pBuffer->pages)
    {
        if (bLargeAlloc)
            vfree(pBuffer->pages);
        else
            kfree(pBuffer->pages);
    }
    kfree(pBuffer);
    return NV_ERR_NO_MEMORY;
}

/*
 * nv_unpin_xdp_umem
 *
 * Unpins a previously pinned XDP UMEM region.
 */
NV_STATUS NV_API_CALL nv_unpin_xdp_umem(void *pHandle)
{
    nv_p2p_umem_buffer_t *pBuffer = (nv_p2p_umem_buffer_t *)pHandle;
    NvU32 i;
    NvU64 savedSize;
    NvU32 savedPageCount;
    NvBool bLargeAlloc;

    if (pBuffer == NULL)
        return NV_ERR_INVALID_ARGUMENT;

    if (pBuffer->bufferType != NV_P2P_BUFFER_TYPE_XDP_UMEM)
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: XDP UMEM unpin: wrong buffer type %d\n",
                  pBuffer->bufferType);
        return NV_ERR_INVALID_ARGUMENT;
    }

    savedSize = pBuffer->size;
    savedPageCount = pBuffer->pageCount;
    bLargeAlloc = (savedPageCount > 512);

    if (pBuffer->pages)
    {
        for (i = 0; i < savedPageCount; i++)
        {
            if (pBuffer->pages[i])
                NV_UNPIN_USER_PAGE(pBuffer->pages[i]);
        }
        if (bLargeAlloc)
            vfree(pBuffer->pages);
        else
            kfree(pBuffer->pages);
    }

    if (pBuffer->physAddrs)
    {
        if (bLargeAlloc)
            vfree(pBuffer->physAddrs);
        else
            kfree(pBuffer->physAddrs);
    }

    kfree(pBuffer);
    nv_p2p_umem_track_unpin(savedSize, savedPageCount);

    return NV_OK;
}

/*
 * nv_xdp_umem_dma_xfer
 *
 * Performs a GPU Copy Engine DMA transfer between a pinned XDP UMEM
 * region and GPU framebuffer memory.  This is the kernel-open entry
 * point for the NV_ESC_P2P_DMA_XFER ioctl.
 *
 * The gpuVA parameter is a CUDA virtual address (from cudaMalloc).
 * We use nvidia_p2p_get_pages_persistent() to resolve it to physical
 * GPU VRAM page addresses, then pass those to the RM CE DMA engine.
 *
 * Parameters:
 *   pHandle     [IN]  - Handle from nv_pin_xdp_umem()
 *   gpuVA       [IN]  - CUDA virtual address (from cudaMalloc)
 *   umemOffset  [IN]  - Byte offset in UMEM
 *   size        [IN]  - Transfer size in bytes
 *   direction   [IN]  - 0 = GPU->UMEM, 1 = UMEM->GPU
 */
NV_STATUS NV_API_CALL nv_xdp_umem_dma_xfer(
    void   *pHandle,
    NvU64   gpuVA,
    NvU64   umemOffset,
    NvU64   size,
    NvU32   direction
)
{
    nv_p2p_umem_buffer_t *pBuffer = (nv_p2p_umem_buffer_t *)pHandle;
    nvidia_stack_t *sp = NULL;
    struct nvidia_p2p_page_table *gpu_page_table = NULL;
    NV_STATUS status;
    NvU64 gpu_phys_offset;
    NvU64 page_size_bytes;
    NvU64 page_offset;
    int rc;

    if (pBuffer == NULL)
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: XDP DMA xfer: NULL handle\n");
        return NV_ERR_INVALID_ARGUMENT;
    }

    if (pBuffer->bufferType != NV_P2P_BUFFER_TYPE_XDP_UMEM)
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: XDP DMA xfer: wrong buffer type %u\n",
                  pBuffer->bufferType);
        return NV_ERR_INVALID_ARGUMENT;
    }

    if (size == 0)
        return NV_OK;

    if (umemOffset + size > pBuffer->size)
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: XDP DMA xfer: OOB (off=0x%llx sz=0x%llx buf=0x%llx)\n",
                  (unsigned long long)umemOffset, (unsigned long long)size,
                  (unsigned long long)pBuffer->size);
        return NV_ERR_INVALID_ARGUMENT;
    }

    if (pBuffer->physAddrs == NULL || pBuffer->pageCount == 0)
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: XDP DMA xfer: no pinned pages\n");
        return NV_ERR_INVALID_STATE;
    }

    /*
     * Resolve CUDA VA -> physical GPU VRAM pages.
     * nvidia_p2p_get_pages_persistent pins the GPU allocation backing
     * this VA range and returns physical page addresses.
     */
    rc = nvidia_p2p_get_pages_persistent(gpuVA, size, &gpu_page_table, 0);
    if (rc != 0)
    {
        nv_printf(NV_DBG_ERRORS,
                  "NVRM: XDP DMA xfer: nvidia_p2p_get_pages_persistent(VA=0x%llx, sz=0x%llx) failed: %d\n",
                  (unsigned long long)gpuVA, (unsigned long long)size, rc);
        return NV_ERR_INVALID_ADDRESS;
    }

    if (gpu_page_table == NULL || gpu_page_table->entries == 0 ||
        gpu_page_table->pages == NULL)
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: XDP DMA xfer: empty GPU page table\n");
        status = NV_ERR_INVALID_STATE;
        goto cleanup_pages;
    }

    /*
     * Extract the physical VRAM base address from the first GPU page.
     * The physical_address field is the actual FBMEM offset that the
     * CE DMA engine can access directly (bypassing GPU MMU).
     *
     * For contiguous allocations (cudaMalloc default), all pages are
     * sequential.  We compute the offset within the first page from
     * the VA alignment.
     */
    switch (gpu_page_table->page_size) {
    case NVIDIA_P2P_PAGE_SIZE_4KB:   page_size_bytes = 4096ULL; break;
    case NVIDIA_P2P_PAGE_SIZE_64KB:  page_size_bytes = 65536ULL; break;
    case NVIDIA_P2P_PAGE_SIZE_128KB: page_size_bytes = 131072ULL; break;
    default:                         page_size_bytes = 65536ULL; break;
    }

    page_offset = gpuVA & (page_size_bytes - 1);
    gpu_phys_offset = gpu_page_table->pages[0]->physical_address + page_offset;

    nv_printf(NV_DBG_INFO,
              "NVRM: XDP DMA xfer: VA=0x%llx -> phys=0x%llx (pages=%u, page_size=0x%llx)\n",
              (unsigned long long)gpuVA,
              (unsigned long long)gpu_phys_offset,
              gpu_page_table->entries,
              (unsigned long long)page_size_bytes);

    rc = nv_kmem_cache_alloc_stack(&sp);
    if (rc != 0)
    {
        status = NV_ERR_NO_MEMORY;
        goto cleanup_pages;
    }

    status = rm_p2p_umem_dma_request(sp,
                                      pBuffer->physAddrs,
                                      pBuffer->pageCount,
                                      pBuffer->pageSize,
                                      pBuffer->size,
                                      gpu_phys_offset,
                                      umemOffset,
                                      size,
                                      direction,
                                      0);

    nv_kmem_cache_free_stack(sp);

cleanup_pages:
    if (gpu_page_table != NULL)
    {
        nvidia_p2p_put_pages_persistent(gpuVA, gpu_page_table, 0);
    }
    return status;
}

/*
 * nv_get_xdp_umem_pages
 *
 * Gets physical page addresses for a range within the UMEM.
 * Useful for setting up GPU DMA descriptors.
 */
NV_STATUS NV_API_CALL nv_get_xdp_umem_pages(
    void    *pHandle,
    NvU64    offset,
    NvU64    size,
    NvU64  **ppPhysAddrs,
    NvU32   *pPageCount,
    NvU32   *pFrameSize
)
{
    nv_p2p_umem_buffer_t *pBuffer = (nv_p2p_umem_buffer_t *)pHandle;
    NvU32 startPage, endPage;

    if (pBuffer == NULL || ppPhysAddrs == NULL || pPageCount == NULL)
        return NV_ERR_INVALID_ARGUMENT;

    if (offset + size > pBuffer->size)
        return NV_ERR_INVALID_ARGUMENT;

    startPage = (NvU32)(offset / pBuffer->pageSize);
    endPage = (NvU32)((offset + size + pBuffer->pageSize - 1) / pBuffer->pageSize);

    if (endPage > pBuffer->pageCount)
        return NV_ERR_INVALID_ARGUMENT;

    *ppPhysAddrs = &pBuffer->physAddrs[startPage];
    *pPageCount = endPage - startPage;
    if (pFrameSize)
        *pFrameSize = pBuffer->frameSize;

    return NV_OK;
}

/*
 * nv_register_gpu_umem
 *
 * Registers GPU memory to be used as UMEM backing store.
 * This enables zero-copy TX where packets are composed directly in GPU memory.
 *
 * Parameters:
 *   gpuMemHandle  [IN]  - Handle to allocated GPU memory
 *   gpuOffset     [IN]  - Offset within GPU memory
 *   size          [IN]  - Size of region to expose
 *   frameSize     [IN]  - XDP frame size
 *   ppHandle      [OUT] - Returns handle for UMEM operations
 */
NV_STATUS NV_API_CALL nv_register_gpu_umem(
    void   *gpuMemHandle,
    NvU64   gpuOffset,
    NvU64   size,
    NvU32   frameSize,
    void  **ppHandle
)
{
    nv_p2p_umem_buffer_t *pBuffer = NULL;
    NV_STATUS status;
    NvU32 frameCount;

    if (gpuMemHandle == NULL || ppHandle == NULL || size == 0)
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: GPU UMEM register: invalid argument\n");
        return NV_ERR_INVALID_ARGUMENT;
    }

    if (frameSize == 0 || (frameSize & (frameSize - 1)) != 0)
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: GPU UMEM register: invalid frame size %u\n", frameSize);
        return NV_ERR_INVALID_ARGUMENT;
    }

    frameCount = (NvU32)(size / frameSize);
    if (frameCount == 0)
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: GPU UMEM register: size too small for frame\n");
        return NV_ERR_INVALID_ARGUMENT;
    }

    status = nv_p2p_umem_check_limits(size, frameCount);
    if (status != NV_OK)
        return status;

    pBuffer = kzalloc(sizeof(*pBuffer), GFP_KERNEL);
    if (pBuffer == NULL)
        return NV_ERR_NO_MEMORY;

    pBuffer->bufferType = NV_P2P_BUFFER_TYPE_GPU_EXPORT;
    pBuffer->gpuMemHandle = gpuMemHandle;
    pBuffer->gpuOffset = gpuOffset;
    pBuffer->size = size;
    pBuffer->frameSize = frameSize;
    pBuffer->pageCount = frameCount;  // Using frames as "pages"
    pBuffer->pageSize = frameSize;
    pBuffer->bGpuBacked = NV_TRUE;
    pBuffer->refCount = 1;

    // Physical addresses will be resolved via GPU BAR1 mapping
    // The actual BAR1 offset calculation happens in the RM layer
    pBuffer->physAddrs = NULL;
    pBuffer->pages = NULL;

    nv_p2p_umem_track_pin(size, frameCount);
    *ppHandle = pBuffer;

    nv_printf(NV_DBG_INFO, "NVRM: GPU UMEM register: success - %u frames, gpuOffset=0x%llx\n",
              frameCount, (unsigned long long)gpuOffset);

    return NV_OK;
}

/*
 * nv_unregister_gpu_umem
 *
 * Unregisters GPU memory previously registered as UMEM backing.
 */
NV_STATUS NV_API_CALL nv_unregister_gpu_umem(void *pHandle)
{
    nv_p2p_umem_buffer_t *pBuffer = (nv_p2p_umem_buffer_t *)pHandle;
    NvU64 savedSize;
    NvU32 savedPageCount;

    if (pBuffer == NULL)
        return NV_ERR_INVALID_ARGUMENT;

    if (pBuffer->bufferType != NV_P2P_BUFFER_TYPE_GPU_EXPORT)
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: GPU UMEM unregister: wrong buffer type\n");
        return NV_ERR_INVALID_ARGUMENT;
    }

    savedSize = pBuffer->size;
    savedPageCount = pBuffer->pageCount;

    kfree(pBuffer);
    nv_p2p_umem_track_unpin(savedSize, savedPageCount);

    return NV_OK;
}

/*
 * nv_get_umem_buffer_info
 *
 * Gets information about a registered UMEM buffer (generic).
 * Works for both user UMEM and GPU-backed UMEM.
 */
NV_STATUS NV_API_CALL nv_get_umem_buffer_info(
    void   *pHandle,
    NvU32  *pBufferType,
    NvU64  *pSize,
    NvU32  *pFrameSize,
    NvU32  *pFrameCount,
    NvBool *pIsGpuBacked
)
{
    nv_p2p_umem_buffer_t *pBuffer = (nv_p2p_umem_buffer_t *)pHandle;

    if (pBuffer == NULL)
        return NV_ERR_INVALID_ARGUMENT;

    if (pBufferType)
        *pBufferType = pBuffer->bufferType;
    if (pSize)
        *pSize = pBuffer->size;
    if (pFrameSize)
        *pFrameSize = pBuffer->frameSize;
    if (pFrameCount)
        *pFrameCount = pBuffer->size / pBuffer->frameSize;
    if (pIsGpuBacked)
        *pIsGpuBacked = pBuffer->bGpuBacked;

    return NV_OK;
}

/*
 * CXL Device Enumeration
 *
 * Enumerates CXL devices in the system using the Linux PCI subsystem.
 * CXL memory devices have PCI class 0x0502 (Memory Controller / CXL)
 */

// CXL System Info structure (must match definition in p2p_cxl.c)
typedef struct {
    NvU32   numDevices;
    NvU32   numMemoryDevices;
    NvBool  bLinkUp;
    NvU32   cxlVersion;
} cxl_system_info_t;

// PCI class for CXL memory devices
#define PCI_CLASS_MEMORY_CXL  0x0502

NV_STATUS NV_API_CALL nv_enumerate_cxl_devices(void *pInfo)
{
    cxl_system_info_t *info = (cxl_system_info_t *)pInfo;
    struct pci_dev *pdev = NULL;
    NvU32 numDevices = 0;
    NvU32 numMemDevices = 0;
    NvBool bLinkUp = NV_FALSE;
    NvU32 cxlVersion = 2;
    u16 linkStatus;
    int ret;

    if (info == NULL)
        return NV_ERR_INVALID_ARGUMENT;

    // Enumerate all PCI devices looking for CXL memory devices
    for_each_pci_dev(pdev)
    {
        // Check for CXL memory device class (0x0502xx)
        if ((pdev->class >> 8) == PCI_CLASS_MEMORY_CXL)
        {
            numDevices++;
            numMemDevices++;

            // Check if PCIe link is up by reading link status
            ret = pcie_capability_read_word(pdev, PCI_EXP_LNKSTA, &linkStatus);
            if (ret == 0)
            {
                // For endpoints, link is up if speed > 0 and width > 0
                u16 speed = linkStatus & PCI_EXP_LNKSTA_CLS;
                u16 width = (linkStatus & PCI_EXP_LNKSTA_NLW) >> PCI_EXP_LNKSTA_NLW_SHIFT;

                if (speed > 0 && width > 0)
                {
                    bLinkUp = NV_TRUE;
                }

                // Check link speed for CXL version estimation
                // Gen5 (32 GT/s) typically means CXL 2.0+
                if (speed >= 5)  // Gen5 or higher
                    cxlVersion = 2;
                else if (speed >= 4)  // Gen4
                    cxlVersion = 1;
            }

        }
    }

    info->numDevices = numDevices;
    info->numMemoryDevices = numMemDevices;
    info->bLinkUp = bLinkUp;
    info->cxlVersion = cxlVersion;

    return NV_OK;
}
