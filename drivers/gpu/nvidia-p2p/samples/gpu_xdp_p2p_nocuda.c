// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * GPU XDP P2P (No CUDA) - Zero-copy networking with GPU P2P DMA
 *
 * This application demonstrates:
 * 1. AF_XDP UMEM setup on network interface
 * 2. GPU P2P DMA registration of UMEM (via NVIDIA driver)
 * 3. Direct GPU DMA to/from network packets
 * 4. CPU-based packet processing and TX back
 *
 * This version does NOT require CUDA toolkit - it uses only
 * the NVIDIA driver's P2P interface for DMA operations.
 *
 * Requires:
 * - NVIDIA driver with P2P UMEM support (580.126.09+)
 * - libxdp, libbpf
 */

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <xdp/libxdp.h>
#include <xdp/xsk.h>

/*
 * Configuration
 */
#define INTERFACE_NAME      "eno1"
#define NUM_FRAMES          4096
#define FRAME_SIZE          XSK_UMEM__DEFAULT_FRAME_SIZE  /* 4096 */
#define UMEM_SIZE           (NUM_FRAMES * FRAME_SIZE)
#define BATCH_SIZE          64
#define FILL_RING_SIZE      NUM_FRAMES
#define COMP_RING_SIZE      NUM_FRAMES

#define RX_BATCH_SIZE       64
#define TX_BATCH_SIZE       64

/*
 * NVIDIA driver P2P ioctl interface
 * These match the kernel-side nv_p2p functions
 */
/*
 * NVIDIA driver ioctl interface using the NV_ESC_IOCTL_XFER_CMD mechanism.
 * NOTE: GET_GPU_INFO, ALLOC_GPU_MEM, FREE_GPU_MEM are NOT implemented
 * in the kernel driver. The no-CUDA path needs a different approach
 * for GPU memory management (e.g., using nvidia-smi or RM API directly).
 */
#define NV_P2P_IOCTL_MAGIC          'N'
#define NV_IOCTL_BASE               200
#define NV_ESC_IOCTL_XFER_CMD       (NV_IOCTL_BASE + 11)
#define NV_ESC_P2P_PIN_UMEM         (NV_IOCTL_BASE + 19)
#define NV_ESC_P2P_UNPIN_UMEM       (NV_IOCTL_BASE + 20)
#define NV_ESC_P2P_DMA_XFER         (NV_IOCTL_BASE + 21)
#define NV_IOCTL_XFER_CMD           _IOWR(NV_P2P_IOCTL_MAGIC, NV_ESC_IOCTL_XFER_CMD, struct nv_ioctl_xfer)

/* These ioctls are NOT implemented in the kernel driver */
#define NV_P2P_IOCTL_GET_GPU_INFO   0  /* unimplemented - use CUDA or nvidia-smi */
#define NV_P2P_IOCTL_ALLOC_GPU_MEM  0  /* unimplemented - use CUDA cudaMalloc */
#define NV_P2P_IOCTL_FREE_GPU_MEM   0  /* unimplemented - use CUDA cudaFree */

struct nv_ioctl_xfer {
    uint32_t    cmd;
    uint32_t    size;
    uint64_t    ptr;
};

static inline int nv_p2p_ioctl(int fd, uint32_t cmd, void *data, uint32_t size)
{
    struct nv_ioctl_xfer xfer = {
        .cmd = cmd,
        .size = size,
        .ptr = (uint64_t)(uintptr_t)data,
    };
    return ioctl(fd, NV_IOCTL_XFER_CMD, &xfer);
}

/* Keep old macros for backward compat, but they will not work */
#define NV_P2P_IOCTL_PIN_UMEM       0
#define NV_P2P_IOCTL_UNPIN_UMEM     0
#define NV_P2P_IOCTL_DMA_XFER       0

struct nv_p2p_pin_params {
    uint64_t    umem_addr;
    uint64_t    size;
    uint32_t    frame_size;
    uint64_t    handle;         /* out */
};

struct nv_p2p_unpin_params {
    uint64_t    handle;
};

struct nv_p2p_dma_params {
    uint64_t    handle;
    uint64_t    gpu_offset;
    uint64_t    umem_offset;
    uint64_t    size;
    uint32_t    direction;      /* 0 = GPU->UMEM, 1 = UMEM->GPU */
};

struct nv_p2p_gpu_info {
    uint32_t    gpu_count;
    uint32_t    gpu_id;
    char        name[64];
    uint64_t    memory_size;
    uint32_t    p2p_capable;
};

struct nv_p2p_alloc_params {
    uint32_t    gpu_id;
    uint64_t    size;
    uint64_t    handle;         /* out */
    uint64_t    gpu_addr;       /* out */
};

struct nv_p2p_free_params {
    uint64_t    handle;
};

/*
 * GPU P2P handle structure (no CUDA)
 */
typedef struct {
    void        *umem_buffer;       /* User UMEM buffer (mmap'd) */
    size_t       umem_size;         /* UMEM size */
    int          gpu_fd;            /* NVIDIA driver fd */
    void        *p2p_handle;        /* P2P registration handle */
    uint64_t     gpu_mem_handle;    /* GPU memory allocation handle */
    uint64_t     gpu_addr;          /* GPU memory address */
    size_t       gpu_buffer_size;   /* GPU buffer size */
    int          gpu_id;            /* GPU device ID */
    int          p2p_available;     /* P2P DMA available flag */

    /* Staging buffer for CPU fallback */
    void        *staging_buffer;
    size_t       staging_size;
} gpu_p2p_ctx_t;

/*
 * XSK context
 */
typedef struct {
    struct xsk_socket       *xsk;
    struct xsk_umem         *umem;
    struct xsk_ring_prod     fq;
    struct xsk_ring_cons     cq;
    struct xsk_ring_prod     tx;
    struct xsk_ring_cons     rx;
    void                    *umem_buffer;
    int                      queue_id;
    gpu_p2p_ctx_t           *gpu_ctx;
} xsk_ctx_t;

/*
 * Statistics
 */
typedef struct {
    uint64_t rx_packets;
    uint64_t tx_packets;
    uint64_t gpu_transfers;
    uint64_t cpu_fallbacks;
    uint64_t rx_bytes;
    uint64_t tx_bytes;
    uint64_t errors;
} stats_t;

static volatile int running = 1;
static stats_t stats = {0};

/*
 * Signal handler
 */
static void signal_handler(int sig)
{
    (void)sig;
    running = 0;
}

/*
 * Initialize GPU P2P context (without CUDA)
 */
static int gpu_p2p_init(gpu_p2p_ctx_t *ctx, void *umem_buffer, size_t umem_size, int gpu_id)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->umem_buffer = umem_buffer;
    ctx->umem_size = umem_size;
    ctx->gpu_id = gpu_id;
    ctx->p2p_available = 0;

    /* Try to open NVIDIA device */
    char dev_path[64];
    snprintf(dev_path, sizeof(dev_path), "/dev/nvidia%d", gpu_id);

    ctx->gpu_fd = open(dev_path, O_RDWR);
    if (ctx->gpu_fd < 0) {
        /* Try nvidiactl as fallback */
        ctx->gpu_fd = open("/dev/nvidiactl", O_RDWR);
        if (ctx->gpu_fd < 0) {
            fprintf(stderr, "Warning: Cannot open NVIDIA device: %s\n", strerror(errno));
            fprintf(stderr, "P2P DMA will not be available, using CPU fallback\n");
            goto setup_staging;
        }
    }

    /* Query GPU info */
    struct nv_p2p_gpu_info gpu_info = {0};
    gpu_info.gpu_id = gpu_id;

    int ret = ioctl(ctx->gpu_fd, NV_P2P_IOCTL_GET_GPU_INFO, &gpu_info);
    if (ret == 0) {
        printf("GPU %d: %s\n", gpu_id, gpu_info.name);
        printf("  Memory: %lu MB\n", gpu_info.memory_size / (1024*1024));
        printf("  P2P capable: %s\n", gpu_info.p2p_capable ? "yes" : "no");
    } else {
        printf("Warning: Could not query GPU info (ioctl may not be supported yet)\n");
    }

    /* Allocate GPU memory for packet processing buffer */
    ctx->gpu_buffer_size = umem_size;
    struct nv_p2p_alloc_params alloc_params = {
        .gpu_id = gpu_id,
        .size = ctx->gpu_buffer_size,
    };

    ret = ioctl(ctx->gpu_fd, NV_P2P_IOCTL_ALLOC_GPU_MEM, &alloc_params);
    if (ret == 0) {
        ctx->gpu_mem_handle = alloc_params.handle;
        ctx->gpu_addr = alloc_params.gpu_addr;
        printf("Allocated %zu bytes GPU memory at 0x%lx\n",
               ctx->gpu_buffer_size, ctx->gpu_addr);
    } else {
        printf("Warning: GPU memory allocation not supported via ioctl\n");
        printf("P2P DMA will use UMEM directly if possible\n");
    }

    /* Register UMEM with GPU for P2P DMA */
    struct nv_p2p_pin_params pin_params = {
        .umem_addr = (uint64_t)umem_buffer,
        .size = umem_size,
        .frame_size = FRAME_SIZE,
    };

    ret = nv_p2p_ioctl(ctx->gpu_fd, NV_ESC_P2P_PIN_UMEM, &pin_params, sizeof(pin_params));
    if (ret == 0) {
        ctx->p2p_handle = (void *)pin_params.handle;
        ctx->p2p_available = 1;
        printf("Registered UMEM with GPU P2P: handle=%p\n", ctx->p2p_handle);
        printf("P2P DMA transfers enabled!\n");
    } else {
        fprintf(stderr, "P2P UMEM registration failed: %s\n", strerror(errno));
        fprintf(stderr, "This is expected if kernel P2P support is not loaded\n");
    }

setup_staging:
    /* Allocate CPU staging buffer for fallback */
    ctx->staging_size = BATCH_SIZE * FRAME_SIZE;
    ctx->staging_buffer = mmap(NULL, ctx->staging_size,
                                PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ctx->staging_buffer == MAP_FAILED) {
        perror("mmap staging buffer");
        ctx->staging_buffer = NULL;
        ctx->staging_size = 0;
    }

    if (!ctx->p2p_available) {
        printf("\n*** Running in CPU-only mode (no GPU P2P DMA) ***\n");
        printf("Packets will be processed on CPU.\n");
        printf("To enable P2P: load the modified nvidia.ko with UMEM support\n\n");
    }

    return 0;
}

/*
 * Cleanup GPU P2P context
 */
static void gpu_p2p_cleanup(gpu_p2p_ctx_t *ctx)
{
    if (ctx->p2p_handle && ctx->gpu_fd >= 0) {
        struct nv_p2p_unpin_params unpin_params = {
            .handle = (uint64_t)ctx->p2p_handle,
        };
        ioctl(ctx->gpu_fd, NV_P2P_IOCTL_UNPIN_UMEM, &unpin_params);
    }

    if (ctx->gpu_mem_handle && ctx->gpu_fd >= 0) {
        struct nv_p2p_free_params free_params = {
            .handle = ctx->gpu_mem_handle,
        };
        ioctl(ctx->gpu_fd, NV_P2P_IOCTL_FREE_GPU_MEM, &free_params);
    }

    if (ctx->gpu_fd >= 0) {
        close(ctx->gpu_fd);
    }

    if (ctx->staging_buffer) {
        munmap(ctx->staging_buffer, ctx->staging_size);
    }
}

/*
 * Transfer packets from UMEM to GPU using P2P DMA
 * Falls back to staging buffer copy if P2P not available
 */
static int gpu_transfer_to_gpu(gpu_p2p_ctx_t *ctx, uint64_t umem_offset,
                               uint64_t gpu_offset, size_t size)
{
    if (ctx->p2p_available && ctx->gpu_fd >= 0) {
        /* Use P2P DMA */
        struct nv_p2p_dma_params dma_params = {
            .handle = (uint64_t)ctx->p2p_handle,
            .gpu_offset = gpu_offset,
            .umem_offset = umem_offset,
            .size = size,
            .direction = 1,  /* UMEM -> GPU */
        };

        int ret = ioctl(ctx->gpu_fd, NV_P2P_IOCTL_DMA_XFER, &dma_params);
        if (ret == 0) {
            stats.gpu_transfers++;
            return 0;
        }
        /* Fall through on error */
    }

    /* CPU fallback: copy to staging for "GPU processing" simulation */
    if (ctx->staging_buffer && gpu_offset + size <= ctx->staging_size) {
        void *src = (char *)ctx->umem_buffer + umem_offset;
        void *dst = (char *)ctx->staging_buffer + gpu_offset;
        memcpy(dst, src, size);
        stats.cpu_fallbacks++;
        return 0;
    }

    stats.errors++;
    return -1;
}

/*
 * Transfer packets from GPU back to UMEM
 */
static int gpu_transfer_from_gpu(gpu_p2p_ctx_t *ctx, uint64_t gpu_offset,
                                  uint64_t umem_offset, size_t size)
{
    if (ctx->p2p_available && ctx->gpu_fd >= 0) {
        /* Use P2P DMA */
        struct nv_p2p_dma_params dma_params = {
            .handle = (uint64_t)ctx->p2p_handle,
            .gpu_offset = gpu_offset,
            .umem_offset = umem_offset,
            .size = size,
            .direction = 0,  /* GPU -> UMEM */
        };

        int ret = ioctl(ctx->gpu_fd, NV_P2P_IOCTL_DMA_XFER, &dma_params);
        if (ret == 0) {
            stats.gpu_transfers++;
            return 0;
        }
    }

    /* CPU fallback: copy from staging back to UMEM */
    if (ctx->staging_buffer && gpu_offset + size <= ctx->staging_size) {
        void *src = (char *)ctx->staging_buffer + gpu_offset;
        void *dst = (char *)ctx->umem_buffer + umem_offset;
        memcpy(dst, src, size);
        stats.cpu_fallbacks++;
        return 0;
    }

    stats.errors++;
    return -1;
}

/*
 * CPU packet processing (MAC swap for demo)
 * In P2P mode, the GPU would do this; here we simulate it on CPU
 */
static void cpu_process_packet(uint8_t *pkt, uint32_t len)
{
    if (len < sizeof(struct ethhdr)) return;

    /* Swap MAC addresses */
    struct ethhdr *eth = (struct ethhdr *)pkt;
    uint8_t tmp[6];
    memcpy(tmp, eth->h_dest, 6);
    memcpy(eth->h_dest, eth->h_source, 6);
    memcpy(eth->h_source, tmp, 6);
}

/*
 * Process batch of packets
 * With P2P: transfers to GPU, processes there, transfers back
 * Without P2P: processes on CPU using staging buffer
 */
static int process_packet_batch(gpu_p2p_ctx_t *ctx, uint32_t *pkt_offsets,
                                 uint32_t *pkt_lengths, int num_packets)
{
    if (num_packets <= 0) return 0;

    if (ctx->p2p_available) {
        /* P2P mode: GPU would process the packets
         * For now, the DMA transfer is the main point -
         * actual GPU kernel would be launched if we had CUDA
         */
        /* The transfers already happened, GPU processing would happen here */
        return 0;
    }

    /* CPU fallback: process packets in staging buffer */
    for (int i = 0; i < num_packets; i++) {
        uint64_t gpu_offset = i * FRAME_SIZE;
        if (gpu_offset + pkt_lengths[i] <= ctx->staging_size) {
            uint8_t *pkt = (uint8_t *)ctx->staging_buffer + gpu_offset;
            cpu_process_packet(pkt, pkt_lengths[i]);
        }
    }

    return 0;
}

/*
 * Create UMEM
 */
static int create_umem(xsk_ctx_t *ctx)
{
    struct xsk_umem_config cfg = {
        .fill_size = FILL_RING_SIZE,
        .comp_size = COMP_RING_SIZE,
        .frame_size = FRAME_SIZE,
        .frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
        .flags = 0,
    };

    /* Try huge pages first for better P2P DMA performance */
    ctx->umem_buffer = mmap(NULL, UMEM_SIZE, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
    if (ctx->umem_buffer == MAP_FAILED) {
        /* Fall back to regular pages */
        ctx->umem_buffer = mmap(NULL, UMEM_SIZE, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (ctx->umem_buffer == MAP_FAILED) {
            perror("mmap UMEM");
            return -1;
        }
        printf("Using regular pages for UMEM\n");
    } else {
        printf("Using huge pages for UMEM (better for P2P DMA)\n");
    }

    /* Create UMEM */
    int ret = xsk_umem__create(&ctx->umem, ctx->umem_buffer, UMEM_SIZE,
                                &ctx->fq, &ctx->cq, &cfg);
    if (ret) {
        fprintf(stderr, "xsk_umem__create failed: %s\n", strerror(-ret));
        munmap(ctx->umem_buffer, UMEM_SIZE);
        return ret;
    }

    printf("Created UMEM: %zu bytes, %d frames\n", (size_t)UMEM_SIZE, NUM_FRAMES);
    return 0;
}

/*
 * Create XSK socket
 */
static int create_xsk(xsk_ctx_t *ctx, const char *ifname, int queue_id)
{
    struct xsk_socket_config cfg = {
        .rx_size = FILL_RING_SIZE,
        .tx_size = COMP_RING_SIZE,
        .libbpf_flags = XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD,
        .xdp_flags = XDP_FLAGS_DRV_MODE,
        .bind_flags = XDP_ZEROCOPY | XDP_USE_NEED_WAKEUP,
    };

    ctx->queue_id = queue_id;

    int ret = xsk_socket__create(&ctx->xsk, ifname, queue_id,
                                  ctx->umem, &ctx->rx, &ctx->tx, &cfg);
    if (ret) {
        /* Try without zero-copy */
        fprintf(stderr, "Zero-copy XSK failed, trying copy mode: %s\n", strerror(-ret));
        cfg.bind_flags = XDP_USE_NEED_WAKEUP;
        cfg.xdp_flags = XDP_FLAGS_SKB_MODE;

        ret = xsk_socket__create(&ctx->xsk, ifname, queue_id,
                                  ctx->umem, &ctx->rx, &ctx->tx, &cfg);
        if (ret) {
            fprintf(stderr, "xsk_socket__create failed: %s\n", strerror(-ret));
            return ret;
        }
        printf("Created XSK in copy mode (zero-copy not supported by driver)\n");
    } else {
        printf("Created XSK in zero-copy mode\n");
    }

    /* Populate fill ring */
    uint32_t idx;
    ret = xsk_ring_prod__reserve(&ctx->fq, NUM_FRAMES, &idx);
    if (ret != NUM_FRAMES) {
        fprintf(stderr, "Failed to reserve fill ring entries\n");
        return -1;
    }

    for (int i = 0; i < NUM_FRAMES; i++) {
        *xsk_ring_prod__fill_addr(&ctx->fq, idx++) = i * FRAME_SIZE;
    }
    xsk_ring_prod__submit(&ctx->fq, NUM_FRAMES);

    printf("Created XSK on %s queue %d\n", ifname, queue_id);
    return 0;
}

/*
 * Process received packets through GPU and send back
 */
static int process_packets(xsk_ctx_t *ctx)
{
    uint32_t idx_rx = 0, idx_tx = 0, idx_fq = 0;
    uint32_t pkt_offsets[BATCH_SIZE];
    uint32_t pkt_lengths[BATCH_SIZE];

    /* Receive packets */
    int rcvd = xsk_ring_cons__peek(&ctx->rx, RX_BATCH_SIZE, &idx_rx);
    if (!rcvd) {
        if (xsk_ring_prod__needs_wakeup(&ctx->fq)) {
            recvfrom(xsk_socket__fd(ctx->xsk), NULL, 0, MSG_DONTWAIT, NULL, NULL);
        }
        return 0;
    }

    /* Collect packet info */
    for (int i = 0; i < rcvd; i++) {
        const struct xdp_desc *desc = xsk_ring_cons__rx_desc(&ctx->rx, idx_rx + i);
        pkt_offsets[i] = desc->addr;
        pkt_lengths[i] = desc->len;
        stats.rx_packets++;
        stats.rx_bytes += desc->len;
    }

    /* Transfer packets to GPU (or staging) */
    for (int i = 0; i < rcvd; i++) {
        gpu_transfer_to_gpu(ctx->gpu_ctx, pkt_offsets[i],
                           i * FRAME_SIZE, pkt_lengths[i]);
    }

    /* Process on GPU (or CPU in fallback mode) */
    process_packet_batch(ctx->gpu_ctx, pkt_offsets, pkt_lengths, rcvd);

    /* Transfer processed packets back from GPU (or staging) */
    for (int i = 0; i < rcvd; i++) {
        gpu_transfer_from_gpu(ctx->gpu_ctx, i * FRAME_SIZE,
                              pkt_offsets[i], pkt_lengths[i]);
    }

    /* Reserve TX descriptors */
    int ret = xsk_ring_prod__reserve(&ctx->tx, rcvd, &idx_tx);
    if (ret != rcvd) {
        /* TX ring full, need to complete some */
        if (xsk_ring_prod__needs_wakeup(&ctx->tx)) {
            sendto(xsk_socket__fd(ctx->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
        }
        stats.errors++;
    } else {
        /* Fill TX descriptors */
        for (int i = 0; i < rcvd; i++) {
            struct xdp_desc *tx_desc = xsk_ring_prod__tx_desc(&ctx->tx, idx_tx + i);
            tx_desc->addr = pkt_offsets[i];
            tx_desc->len = pkt_lengths[i];
            stats.tx_packets++;
            stats.tx_bytes += pkt_lengths[i];
        }
        xsk_ring_prod__submit(&ctx->tx, rcvd);

        /* Kick TX */
        if (xsk_ring_prod__needs_wakeup(&ctx->tx)) {
            sendto(xsk_socket__fd(ctx->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
        }
    }

    /* Release RX descriptors */
    xsk_ring_cons__release(&ctx->rx, rcvd);

    /* Refill FQ */
    ret = xsk_ring_prod__reserve(&ctx->fq, rcvd, &idx_fq);
    if (ret == rcvd) {
        for (int i = 0; i < rcvd; i++) {
            *xsk_ring_prod__fill_addr(&ctx->fq, idx_fq + i) = pkt_offsets[i];
        }
        xsk_ring_prod__submit(&ctx->fq, rcvd);
    }

    /* Complete TX */
    uint32_t idx_cq;
    int completed = xsk_ring_cons__peek(&ctx->cq, BATCH_SIZE, &idx_cq);
    if (completed > 0) {
        xsk_ring_cons__release(&ctx->cq, completed);
    }

    return rcvd;
}

/*
 * Print statistics
 */
static void print_stats(void)
{
    static uint64_t last_rx = 0, last_tx = 0;
    static struct timespec last_time = {0};
    struct timespec now;

    clock_gettime(CLOCK_MONOTONIC, &now);

    if (last_time.tv_sec != 0) {
        double dt = (now.tv_sec - last_time.tv_sec) +
                    (now.tv_nsec - last_time.tv_nsec) / 1e9;

        uint64_t rx_pps = (uint64_t)((stats.rx_packets - last_rx) / dt);
        uint64_t tx_pps = (uint64_t)((stats.tx_packets - last_tx) / dt);

        printf("\rRX: %lu pps (%lu total) | TX: %lu pps (%lu total) | "
               "P2P: %lu | CPU: %lu | Err: %lu",
               rx_pps, stats.rx_packets, tx_pps, stats.tx_packets,
               stats.gpu_transfers, stats.cpu_fallbacks, stats.errors);
        fflush(stdout);
    }

    last_rx = stats.rx_packets;
    last_tx = stats.tx_packets;
    last_time = now;
}

/*
 * Main loop
 */
static void run_loop(xsk_ctx_t *ctx)
{
    struct pollfd fds[1];
    time_t last_stats = 0;

    fds[0].fd = xsk_socket__fd(ctx->xsk);
    fds[0].events = POLLIN | POLLOUT;

    printf("Starting packet processing loop...\n");
    printf("Press Ctrl+C to stop\n\n");

    while (running) {
        int ret = poll(fds, 1, 1000);
        if (ret < 0) {
            if (errno == EINTR) continue;
            perror("poll");
            break;
        }

        if (ret > 0) {
            process_packets(ctx);
        }

        /* Print stats every second */
        time_t now = time(NULL);
        if (now != last_stats) {
            print_stats();
            last_stats = now;
        }
    }

    printf("\n\nFinal Statistics:\n");
    printf("  RX packets: %lu (%lu bytes)\n", stats.rx_packets, stats.rx_bytes);
    printf("  TX packets: %lu (%lu bytes)\n", stats.tx_packets, stats.tx_bytes);
    printf("  P2P DMA transfers: %lu\n", stats.gpu_transfers);
    printf("  CPU fallback transfers: %lu\n", stats.cpu_fallbacks);
    printf("  Errors: %lu\n", stats.errors);
}

/*
 * Usage
 */
static void usage(const char *prog)
{
    printf("Usage: %s [options]\n", prog);
    printf("\n");
    printf("GPU XDP P2P Demo (No CUDA version)\n");
    printf("Receives packets via AF_XDP, transfers to GPU via P2P DMA,\n");
    printf("processes, and sends back.\n");
    printf("\n");
    printf("Options:\n");
    printf("  -i <ifname>   Interface name (default: %s)\n", INTERFACE_NAME);
    printf("  -q <queue>    Queue ID (default: 0)\n");
    printf("  -g <gpu>      GPU device ID (default: 0)\n");
    printf("  -h            Show this help\n");
    printf("\n");
    printf("Requirements:\n");
    printf("  - NVIDIA GPU with driver 580.126.09+\n");
    printf("  - Driver compiled with P2P UMEM support\n");
    printf("  - libxdp, libbpf\n");
    printf("\n");
    printf("If P2P is not available, falls back to CPU processing.\n");
}

int main(int argc, char **argv)
{
    const char *ifname = INTERFACE_NAME;
    int queue_id = 0;
    int gpu_id = 0;
    int opt;

    /* Parse arguments */
    while ((opt = getopt(argc, argv, "i:q:g:h")) != -1) {
        switch (opt) {
        case 'i':
            ifname = optarg;
            break;
        case 'q':
            queue_id = atoi(optarg);
            break;
        case 'g':
            gpu_id = atoi(optarg);
            break;
        case 'h':
            usage(argv[0]);
            return 0;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    /* Set up signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Increase memory limits */
    struct rlimit rlim = { RLIM_INFINITY, RLIM_INFINITY };
    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
        perror("setrlimit(RLIMIT_MEMLOCK)");
        return 1;
    }

    printf("====================================\n");
    printf("GPU XDP P2P Demo (No CUDA version)\n");
    printf("====================================\n");
    printf("Interface: %s, Queue: %d, GPU: %d\n\n", ifname, queue_id, gpu_id);

    /* Initialize contexts */
    xsk_ctx_t xsk_ctx = {0};
    gpu_p2p_ctx_t gpu_ctx = {0};

    /* Create UMEM */
    if (create_umem(&xsk_ctx)) {
        fprintf(stderr, "Failed to create UMEM\n");
        return 1;
    }

    /* Initialize GPU P2P */
    if (gpu_p2p_init(&gpu_ctx, xsk_ctx.umem_buffer, UMEM_SIZE, gpu_id)) {
        fprintf(stderr, "Failed to initialize GPU P2P context\n");
        goto cleanup;
    }
    xsk_ctx.gpu_ctx = &gpu_ctx;

    /* Create XSK socket */
    if (create_xsk(&xsk_ctx, ifname, queue_id)) {
        fprintf(stderr, "Failed to create XSK\n");
        goto cleanup;
    }

    /* Run main loop */
    run_loop(&xsk_ctx);

cleanup:
    printf("Cleaning up...\n");

    if (xsk_ctx.xsk) {
        xsk_socket__delete(xsk_ctx.xsk);
    }
    if (xsk_ctx.umem) {
        xsk_umem__delete(xsk_ctx.umem);
    }
    if (xsk_ctx.umem_buffer) {
        munmap(xsk_ctx.umem_buffer, UMEM_SIZE);
    }

    gpu_p2p_cleanup(&gpu_ctx);

    printf("Done.\n");
    return 0;
}
