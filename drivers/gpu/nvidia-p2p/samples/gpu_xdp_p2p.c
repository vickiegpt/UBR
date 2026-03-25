// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * GPU XDP P2P - Zero-copy networking with GPU acceleration
 *
 * This application demonstrates:
 * 1. AF_XDP UMEM setup on eno1
 * 2. GPU P2P DMA registration of UMEM
 * 3. Direct GPU DMA to/from network packets
 * 4. GPU processing and TX back
 *
 * Requires:
 * - NVIDIA driver with P2P UMEM support (580.126.09+)
 * - libxdp, libbpf
 * - CUDA toolkit (for GPU kernels)
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

/* CUDA includes */
#include <cuda.h>
#include <cuda_runtime.h>

/* NVIDIA driver interface for P2P */
#include <nvidia-p2p.h>

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
#define GPU_BUFFER_SIZE     UMEM_SIZE

#define RX_BATCH_SIZE       64
#define TX_BATCH_SIZE       64

/*
 * GPU P2P handle structure
 */
typedef struct {
    void        *umem_buffer;       /* User UMEM buffer (mmap'd) */
    size_t       umem_size;         /* UMEM size */
    void        *gpu_buffer;        /* GPU device memory */
    size_t       gpu_buffer_size;   /* GPU buffer size */
    CUdeviceptr  gpu_dptr;          /* CUDA device pointer */
    int          gpu_fd;            /* NVIDIA driver fd */
    void        *p2p_handle;        /* P2P registration handle */
    int          gpu_id;            /* GPU device ID */
    cudaStream_t stream;            /* CUDA stream for async ops */
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
 * CUDA error checking macro
 */
#define CUDA_CHECK(call) do { \
    cudaError_t err = call; \
    if (err != cudaSuccess) { \
        fprintf(stderr, "CUDA error at %s:%d: %s\n", \
                __FILE__, __LINE__, cudaGetErrorString(err)); \
        return -1; \
    } \
} while(0)

#define CU_CHECK(call) do { \
    CUresult err = call; \
    if (err != CUDA_SUCCESS) { \
        const char *errStr; \
        cuGetErrorString(err, &errStr); \
        fprintf(stderr, "CUDA driver error at %s:%d: %s\n", \
                __FILE__, __LINE__, errStr); \
        return -1; \
    } \
} while(0)

/*
 * NVIDIA driver ioctl interface
 * These match the kernel-side nv_p2p functions
 */
/*
 * NVIDIA driver ioctl interface using the NV_ESC_IOCTL_XFER_CMD mechanism.
 * The NVIDIA driver dispatches high-numbered commands (>= NV_IOCTL_BASE)
 * through a two-level ioctl: first NV_ESC_IOCTL_XFER_CMD carries the
 * nv_ioctl_xfer_t structure, which then contains the real command number.
 */
#define NV_P2P_IOCTL_MAGIC          'N'
#define NV_IOCTL_BASE               200
#define NV_ESC_IOCTL_XFER_CMD       (NV_IOCTL_BASE + 11)
#define NV_ESC_P2P_PIN_UMEM         (NV_IOCTL_BASE + 19)
#define NV_ESC_P2P_UNPIN_UMEM       (NV_IOCTL_BASE + 20)
#define NV_ESC_P2P_DMA_XFER         (NV_IOCTL_BASE + 21)
#define NV_IOCTL_XFER_CMD           _IOWR(NV_P2P_IOCTL_MAGIC, NV_ESC_IOCTL_XFER_CMD, struct nv_ioctl_xfer)

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

/* Compatibility macros - redirect old _IOWR-style calls to xfer mechanism */
#define NV_P2P_IOCTL_PIN_UMEM       0  /* unused, use nv_p2p_ioctl() */
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

/*
 * Initialize GPU P2P context
 */
static int gpu_p2p_init(gpu_p2p_ctx_t *ctx, void *umem_buffer, size_t umem_size, int gpu_id)
{
    int num_devices;

    memset(ctx, 0, sizeof(*ctx));
    ctx->umem_buffer = umem_buffer;
    ctx->umem_size = umem_size;
    ctx->gpu_id = gpu_id;

    /* Initialize CUDA */
    CUDA_CHECK(cudaGetDeviceCount(&num_devices));
    if (gpu_id >= num_devices) {
        fprintf(stderr, "GPU %d not found (have %d GPUs)\n", gpu_id, num_devices);
        return -1;
    }

    CUDA_CHECK(cudaSetDevice(gpu_id));

    /* Get device properties */
    struct cudaDeviceProp props;
    CUDA_CHECK(cudaGetDeviceProperties(&props, gpu_id));
    printf("Using GPU %d: %s (SM %d.%d)\n", gpu_id, props.name,
           props.major, props.minor);

    /* Check for P2P DMA capability */
    int p2p_capable = 0;
    CU_CHECK(cuDeviceGetAttribute(&p2p_capable,
             CU_DEVICE_ATTRIBUTE_GPU_DIRECT_RDMA_SUPPORTED, gpu_id));
    if (!p2p_capable) {
        fprintf(stderr, "Warning: GPU does not advertise GPUDirect RDMA support\n");
    }

    /* Allocate GPU buffer for packet processing */
    ctx->gpu_buffer_size = GPU_BUFFER_SIZE;
    CUDA_CHECK(cudaMalloc(&ctx->gpu_buffer, ctx->gpu_buffer_size));
    ctx->gpu_dptr = (CUdeviceptr)ctx->gpu_buffer;
    printf("Allocated %zu bytes GPU buffer at %p\n",
           ctx->gpu_buffer_size, ctx->gpu_buffer);

    /* Create CUDA stream for async operations */
    CUDA_CHECK(cudaStreamCreate(&ctx->stream));

    /* Open NVIDIA control device for P2P operations */
    ctx->gpu_fd = open("/dev/nvidia0", O_RDWR);
    if (ctx->gpu_fd < 0) {
        /* Try nvidia-uvm or nvidiactl */
        ctx->gpu_fd = open("/dev/nvidiactl", O_RDWR);
        if (ctx->gpu_fd < 0) {
            fprintf(stderr, "Failed to open NVIDIA device: %s\n", strerror(errno));
            fprintf(stderr, "Note: P2P UMEM requires driver support - using fallback\n");
            ctx->gpu_fd = -1;
        }
    }

    /* Register UMEM with GPU for P2P DMA */
    if (ctx->gpu_fd >= 0) {
        struct nv_p2p_pin_params pin_params = {
            .umem_addr = (uint64_t)umem_buffer,
            .size = umem_size,
            .frame_size = FRAME_SIZE,
        };

        int ret = nv_p2p_ioctl(ctx->gpu_fd, NV_ESC_P2P_PIN_UMEM, &pin_params, sizeof(pin_params));
        if (ret == 0) {
            ctx->p2p_handle = (void *)pin_params.handle;
            printf("Registered UMEM with GPU P2P: handle=%p\n", ctx->p2p_handle);
        } else {
            fprintf(stderr, "P2P UMEM registration failed (expected if not supported): %s\n",
                    strerror(errno));
            ctx->p2p_handle = NULL;
        }
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
        nv_p2p_ioctl(ctx->gpu_fd, NV_ESC_P2P_UNPIN_UMEM, &unpin_params, sizeof(unpin_params));
    }

    if (ctx->gpu_fd >= 0) {
        close(ctx->gpu_fd);
    }

    if (ctx->stream) {
        cudaStreamDestroy(ctx->stream);
    }

    if (ctx->gpu_buffer) {
        cudaFree(ctx->gpu_buffer);
    }
}

/*
 * Transfer packets from UMEM to GPU
 * Uses P2P DMA if available, falls back to cudaMemcpy
 */
static int gpu_transfer_to_gpu(gpu_p2p_ctx_t *ctx, uint64_t umem_offset,
                               uint64_t gpu_offset, size_t size)
{
    if (ctx->p2p_handle && ctx->gpu_fd >= 0) {
        /* Use P2P DMA */
        struct nv_p2p_dma_params dma_params = {
            .handle = (uint64_t)ctx->p2p_handle,
            .gpu_offset = (uint64_t)ctx->gpu_buffer + gpu_offset,
            .umem_offset = umem_offset,
            .size = size,
            .direction = 1,  /* UMEM -> GPU */
        };

        int ret = nv_p2p_ioctl(ctx->gpu_fd, NV_ESC_P2P_DMA_XFER, &dma_params, sizeof(dma_params));
        if (ret == 0) {
            stats.gpu_transfers++;
            return 0;
        }
        /* Fall through to cudaMemcpy on failure */
    }

    /* Fallback: use CUDA memcpy */
    void *src = (char *)ctx->umem_buffer + umem_offset;
    void *dst = (char *)ctx->gpu_buffer + gpu_offset;

    cudaError_t err = cudaMemcpyAsync(dst, src, size,
                                       cudaMemcpyHostToDevice, ctx->stream);
    if (err != cudaSuccess) {
        stats.errors++;
        return -1;
    }

    stats.gpu_transfers++;
    return 0;
}

/*
 * Transfer packets from GPU back to UMEM
 */
static int gpu_transfer_from_gpu(gpu_p2p_ctx_t *ctx, uint64_t gpu_offset,
                                  uint64_t umem_offset, size_t size)
{
    if (ctx->p2p_handle && ctx->gpu_fd >= 0) {
        /* Use P2P DMA */
        struct nv_p2p_dma_params dma_params = {
            .handle = (uint64_t)ctx->p2p_handle,
            .gpu_offset = (uint64_t)ctx->gpu_buffer + gpu_offset,
            .umem_offset = umem_offset,
            .size = size,
            .direction = 0,  /* GPU -> UMEM */
        };

        int ret = nv_p2p_ioctl(ctx->gpu_fd, NV_ESC_P2P_DMA_XFER, &dma_params, sizeof(dma_params));
        if (ret == 0) {
            stats.gpu_transfers++;
            return 0;
        }
    }

    /* Fallback */
    void *src = (char *)ctx->gpu_buffer + gpu_offset;
    void *dst = (char *)ctx->umem_buffer + umem_offset;

    cudaError_t err = cudaMemcpyAsync(dst, src, size,
                                       cudaMemcpyDeviceToHost, ctx->stream);
    if (err != cudaSuccess) {
        stats.errors++;
        return -1;
    }

    stats.gpu_transfers++;
    return 0;
}

/*
 * GPU packet processing kernel (simple MAC swap for demo)
 */
__global__ void gpu_process_packets(uint8_t *packets, uint32_t *lengths,
                                     int num_packets, int frame_size)
{
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= num_packets) return;

    uint8_t *pkt = packets + (idx * frame_size);
    uint32_t len = lengths[idx];

    if (len < sizeof(struct ethhdr)) return;

    /* Swap MAC addresses */
    struct ethhdr *eth = (struct ethhdr *)pkt;
    uint8_t tmp[6];
    memcpy(tmp, eth->h_dest, 6);
    memcpy(eth->h_dest, eth->h_source, 6);
    memcpy(eth->h_source, tmp, 6);

    /* Could add more processing here:
     * - Checksum recalculation
     * - Payload modification
     * - Encryption/decryption
     * - ML inference
     */
}

/*
 * Launch GPU processing kernel
 */
static int gpu_process_batch(gpu_p2p_ctx_t *ctx, uint32_t *pkt_offsets,
                              uint32_t *pkt_lengths, int num_packets)
{
    static uint32_t *d_lengths = NULL;
    static int max_packets = 0;

    if (num_packets <= 0) return 0;

    /* Allocate device memory for lengths if needed */
    if (num_packets > max_packets) {
        if (d_lengths) cudaFree(d_lengths);
        CUDA_CHECK(cudaMalloc(&d_lengths, num_packets * sizeof(uint32_t)));
        max_packets = num_packets;
    }

    /* Copy lengths to device */
    CUDA_CHECK(cudaMemcpyAsync(d_lengths, pkt_lengths,
                                num_packets * sizeof(uint32_t),
                                cudaMemcpyHostToDevice, ctx->stream));

    /* Launch kernel */
    int threads = 256;
    int blocks = (num_packets + threads - 1) / threads;

    gpu_process_packets<<<blocks, threads, 0, ctx->stream>>>(
        (uint8_t *)ctx->gpu_buffer, d_lengths, num_packets, FRAME_SIZE);

    /* Sync */
    CUDA_CHECK(cudaStreamSynchronize(ctx->stream));

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

    /* Allocate UMEM buffer */
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
        printf("Using huge pages for UMEM\n");
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
        fprintf(stderr, "xsk_socket__create failed: %s\n", strerror(-ret));
        return ret;
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

    /* Transfer packets to GPU */
    for (int i = 0; i < rcvd; i++) {
        gpu_transfer_to_gpu(ctx->gpu_ctx, pkt_offsets[i],
                           i * FRAME_SIZE, pkt_lengths[i]);
    }

    /* Process on GPU */
    gpu_process_batch(ctx->gpu_ctx, pkt_offsets, pkt_lengths, rcvd);

    /* Transfer processed packets back from GPU */
    for (int i = 0; i < rcvd; i++) {
        gpu_transfer_from_gpu(ctx->gpu_ctx, i * FRAME_SIZE,
                              pkt_offsets[i], pkt_lengths[i]);
    }

    /* Sync GPU operations */
    cudaStreamSynchronize(ctx->gpu_ctx->stream);

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

        uint64_t rx_pps = (stats.rx_packets - last_rx) / dt;
        uint64_t tx_pps = (stats.tx_packets - last_tx) / dt;

        printf("\rRX: %'lu pps (%'lu total) | TX: %'lu pps (%'lu total) | "
               "GPU xfers: %'lu | Errors: %lu",
               rx_pps, stats.rx_packets, tx_pps, stats.tx_packets,
               stats.gpu_transfers, stats.errors);
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
    printf("  RX packets: %'lu (%'lu bytes)\n", stats.rx_packets, stats.rx_bytes);
    printf("  TX packets: %'lu (%'lu bytes)\n", stats.tx_packets, stats.tx_bytes);
    printf("  GPU transfers: %'lu\n", stats.gpu_transfers);
    printf("  Errors: %lu\n", stats.errors);
}

/*
 * Usage
 */
static void usage(const char *prog)
{
    printf("Usage: %s [options]\n", prog);
    printf("Options:\n");
    printf("  -i <ifname>   Interface name (default: %s)\n", INTERFACE_NAME);
    printf("  -q <queue>    Queue ID (default: 0)\n");
    printf("  -g <gpu>      GPU device ID (default: 0)\n");
    printf("  -h            Show this help\n");
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

    printf("GPU XDP P2P Demo\n");
    printf("================\n");
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
        fprintf(stderr, "Failed to initialize GPU P2P\n");
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
