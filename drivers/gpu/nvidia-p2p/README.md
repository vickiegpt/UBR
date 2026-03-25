# NVIDIA GPU P2P DMA for AF_XDP UMEM

This directory contains the modified files from NVIDIA open-gpu-kernel-modules
580.126.09 (branch chainio-p2p-dma) that implement GPU ↔ UMEM P2P DMA.

These are NOT standalone buildable sources — they are patches on top of the
NVIDIA 580.126.09 driver. To build:

1. Clone nvidia/open-gpu-kernel-modules at tag 580.126.09
2. Apply gpu_p2p_dma.patch
3. Build against the UBR kernel: make modules -j$(nproc)

## Files

### kernel-open/ (kernel-facing driver layer)
- nv-ioctl-numbers.h — NV_ESC_P2P_PIN/UNPIN/DMA_XFER ioctl numbers (219-221)
- nv-ioctl.h — ioctl parameter structures
- nv.h — rm_p2p_umem_dma_request() declaration
- nv.c — ioctl dispatch to nv_pin/unpin/dma_xfer functions
- nv-p2p.c — UMEM page pinning + CUDA VA resolution + CE DMA entry point
- nv-p2p.h — function declarations

### src/ (NVIDIA Resource Manager layer)
- osapi.c — rm_p2p_umem_dma_request() bridge (acquires RM lock, calls RM)
- p2p_umem.c — RmP2PUmemDmaRequest/Direct: memdesc + memmgrMemCopy via CE
- p2p.h — RM-side declarations
- srcs.mk — build list
- exports_link_command.txt — linker exports

### samples/
- gpu_xdp_p2p.c — Full demo: AF_XDP RX → GPU DMA → process → GPU DMA → AF_XDP TX
- gpu_xdp_p2p_nocuda.c — No-CUDA variant (limited, some ioctls unimplemented)

## Data path
```
ioctl(NV_ESC_P2P_DMA_XFER)
  → nv.c dispatch
  → nv_xdp_umem_dma_xfer() [nv-p2p.c]
    → nvidia_p2p_get_pages_persistent(CUDA VA) → phys VRAM addr
    → rm_p2p_umem_dma_request() [osapi.c]
      → RmP2PUmemDmaRequestDirect() [p2p_umem.c]
        → memmgrMemCopy(TRANSFER_FLAGS_PREFER_CE)  ← GPU Copy Engine HW DMA
```
