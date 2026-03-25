/*
 * NVMe to AF_XDP Pipeline using io_uring unified ops
 *
 * Uses IORING_OP_URING_CMD to issue NVMe passthrough commands directly,
 * performs userspace computation, and transmits via AF_XDP UMEM.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <linux/io_uring.h>
#include <linux/nvme_ioctl.h>
#include <sys/syscall.h>
#include <net/if.h>
#include <poll.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

/* Configuration */
#define QUEUE_DEPTH         256
#define NVME_BLOCK_SIZE     4096
#define NUM_BLOCKS          64
#define UMEM_SIZE           (NUM_BLOCKS * NVME_BLOCK_SIZE)
#define NUM_FRAMES          NUM_BLOCKS
#define FRAME_SIZE          NVME_BLOCK_SIZE
#define INVALID_UMEM_FRAME  UINT64_MAX

/* Room for ETH+IP+UDP headers before NVMe payload in UMEM frame */
#define PKT_HEADER_ROOM     64

/* LBA size in bytes; overridable via -b <lba_size> command line option */
static uint32_t g_lba_size = 512;

/* NVMe opcodes */
#define NVME_CMD_READ       0x02
#define NVME_CMD_WRITE      0x01

/* XDP Ring sizes */
#define XDP_RING_SIZE       256
#define FILL_RING_SIZE      XDP_RING_SIZE
#define COMP_RING_SIZE      XDP_RING_SIZE
#define TX_RING_SIZE        XDP_RING_SIZE
#define RX_RING_SIZE        XDP_RING_SIZE

/* io_uring opcodes from kernel */
#ifndef IORING_OP_URING_CMD
#define IORING_OP_URING_CMD 46
#endif

/* Syscall number for io_uring_sched_hints */
#ifndef __NR_io_uring_sched_hints
#define __NR_io_uring_sched_hints 468
#endif

/* Scheduler hint flags */
#define IO_URING_SCHED_HINT_LATENCY     (1U << 0)
#define IO_URING_SCHED_HINT_THROUGHPUT  (1U << 1)
#define IO_URING_SCHED_HINT_REALTIME    (1U << 2)
#define IO_URING_SCHED_HINT_NVME_XDP    (1U << 3)

/* Scheduler hints structure */
struct io_uring_sched_hints {
    uint64_t read_freq_ns;
    uint64_t send_freq_ns;
    uint32_t batch_size;
    uint32_t flags;
    uint64_t __resv[2];
};

/* Syscall wrapper for io_uring_sched_hints */
static int io_uring_sched_hints_set(struct io_uring_sched_hints *hints)
{
    return syscall(__NR_io_uring_sched_hints, 0, hints, 0);
}

static int io_uring_sched_hints_get(struct io_uring_sched_hints *hints)
{
    return syscall(__NR_io_uring_sched_hints, 1, hints, 0);
}

static int io_uring_sched_hints_record(int op_type)
{
    return syscall(__NR_io_uring_sched_hints, 2, NULL, op_type);
}

/* io_uring syscall wrappers */
static int io_uring_setup(unsigned entries, struct io_uring_params *p)
{
    return syscall(__NR_io_uring_setup, entries, p);
}

static int io_uring_enter(int fd, unsigned to_submit, unsigned min_complete,
                          unsigned flags, sigset_t *sig)
{
    return syscall(__NR_io_uring_enter, fd, to_submit, min_complete, flags, sig, 0);
}

/* io_uring context for 128-byte SQE (needed for URING_CMD) */
struct uring_ctx {
    int ring_fd;
    void *sq_ptr;
    void *cq_ptr;
    struct io_uring_sqe *sqes;
    unsigned *sq_head;
    unsigned *sq_tail;
    unsigned *sq_mask;
    unsigned *sq_array;
    unsigned *cq_head;
    unsigned *cq_tail;
    unsigned *cq_mask;
    struct io_uring_cqe *cqes;
    size_t sq_ring_sz;
    size_t cq_ring_sz;
    size_t sqe_size;
};

/* XDP socket context */
struct xsk_ctx {
    int xsk_fd;
    void *umem_area;

    /* UMEM fill ring */
    struct {
        unsigned int *producer;
        unsigned int *consumer;
        unsigned int *ring;
        unsigned int mask;
    } fill;

    /* UMEM completion ring */
    struct {
        unsigned int *producer;
        unsigned int *consumer;
        unsigned int *ring;
        unsigned int mask;
    } comp;

    /* TX ring */
    struct {
        unsigned int *producer;
        unsigned int *consumer;
        struct xdp_desc *ring;
        unsigned int mask;
    } tx;

    /* RX ring */
    struct {
        unsigned int *producer;
        unsigned int *consumer;
        struct xdp_desc *ring;
        unsigned int mask;
    } rx;

    /* Frame management */
    uint64_t umem_frame_addr[NUM_FRAMES];
    uint32_t umem_frame_free;
};

/* Pipeline context */
struct pipeline_ctx {
    struct uring_ctx uring;
    struct xsk_ctx xsk;
    int nvme_fd;
    char *nvme_device;
    char *net_iface;
    int ifindex;
    int queue_id;
    uint32_t nsid;  /* NVMe namespace ID */

    /* Remote destination */
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint32_t dst_ip;
    uint32_t src_ip;
    uint16_t dst_port;
    uint16_t src_port;
};

/* Initialize io_uring with 128-byte SQE support for URING_CMD */
static int init_io_uring(struct uring_ctx *ctx)
{
    struct io_uring_params params;
    void *ptr;

    memset(&params, 0, sizeof(params));
    /* Enable 128-byte SQE for URING_CMD which needs space for nvme_uring_cmd */
    params.flags = IORING_SETUP_SQE128;

    ctx->ring_fd = io_uring_setup(QUEUE_DEPTH, &params);
    if (ctx->ring_fd < 0) {
        perror("io_uring_setup with SQE128");
        return -1;
    }

    ctx->sqe_size = 128;  /* 128-byte SQEs */

    /* Map submission queue ring */
    ctx->sq_ring_sz = params.sq_off.array + params.sq_entries * sizeof(unsigned);
    ctx->sq_ptr = mmap(NULL, ctx->sq_ring_sz, PROT_READ | PROT_WRITE,
                       MAP_SHARED | MAP_POPULATE, ctx->ring_fd,
                       IORING_OFF_SQ_RING);
    if (ctx->sq_ptr == MAP_FAILED) {
        perror("mmap sq_ring");
        close(ctx->ring_fd);
        return -1;
    }

    /* Map completion queue ring */
    ctx->cq_ring_sz = params.cq_off.cqes + params.cq_entries * sizeof(struct io_uring_cqe);
    ctx->cq_ptr = mmap(NULL, ctx->cq_ring_sz, PROT_READ | PROT_WRITE,
                       MAP_SHARED | MAP_POPULATE, ctx->ring_fd,
                       IORING_OFF_CQ_RING);
    if (ctx->cq_ptr == MAP_FAILED) {
        perror("mmap cq_ring");
        munmap(ctx->sq_ptr, ctx->sq_ring_sz);
        close(ctx->ring_fd);
        return -1;
    }

    /* Map SQEs (128 bytes each) */
    ctx->sqes = mmap(NULL, params.sq_entries * ctx->sqe_size,
                     PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
                     ctx->ring_fd, IORING_OFF_SQES);
    if (ctx->sqes == MAP_FAILED) {
        perror("mmap sqes");
        munmap(ctx->cq_ptr, ctx->cq_ring_sz);
        munmap(ctx->sq_ptr, ctx->sq_ring_sz);
        close(ctx->ring_fd);
        return -1;
    }

    /* Set up ring pointers */
    ctx->sq_head = ctx->sq_ptr + params.sq_off.head;
    ctx->sq_tail = ctx->sq_ptr + params.sq_off.tail;
    ctx->sq_mask = ctx->sq_ptr + params.sq_off.ring_mask;
    ctx->sq_array = ctx->sq_ptr + params.sq_off.array;

    ctx->cq_head = ctx->cq_ptr + params.cq_off.head;
    ctx->cq_tail = ctx->cq_ptr + params.cq_off.tail;
    ctx->cq_mask = ctx->cq_ptr + params.cq_off.ring_mask;
    ctx->cqes = ctx->cq_ptr + params.cq_off.cqes;

    return 0;
}

/* Allocate UMEM frame */
static uint64_t xsk_alloc_umem_frame(struct xsk_ctx *xsk)
{
    if (xsk->umem_frame_free == 0)
        return INVALID_UMEM_FRAME;

    return xsk->umem_frame_addr[--xsk->umem_frame_free];
}

/* Free UMEM frame */
static void xsk_free_umem_frame(struct xsk_ctx *xsk, uint64_t addr)
{
    xsk->umem_frame_addr[xsk->umem_frame_free++] = addr;
}

/* Initialize AF_XDP socket with UMEM */
static int init_xsk(struct xsk_ctx *xsk, int ifindex, int queue_id)
{
    struct sockaddr_xdp sxdp;
    struct xdp_umem_reg umem_reg;
    struct xdp_mmap_offsets offsets;
    socklen_t optlen;
    void *map;
    int opt;

    /* Create XDP socket */
    xsk->xsk_fd = socket(AF_XDP, SOCK_RAW, 0);
    if (xsk->xsk_fd < 0) {
        perror("socket(AF_XDP)");
        return -1;
    }

    /* Allocate UMEM area */
    xsk->umem_area = mmap(NULL, UMEM_SIZE, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
    if (xsk->umem_area == MAP_FAILED) {
        /* Fallback without huge pages */
        xsk->umem_area = mmap(NULL, UMEM_SIZE, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (xsk->umem_area == MAP_FAILED) {
            perror("mmap umem");
            close(xsk->xsk_fd);
            return -1;
        }
    }

    /* Initialize frame addresses */
    for (int i = 0; i < NUM_FRAMES; i++)
        xsk->umem_frame_addr[i] = i * FRAME_SIZE;
    xsk->umem_frame_free = NUM_FRAMES;

    /* Register UMEM */
    memset(&umem_reg, 0, sizeof(umem_reg));
    umem_reg.addr = (unsigned long)xsk->umem_area;
    umem_reg.len = UMEM_SIZE;
    umem_reg.chunk_size = FRAME_SIZE;
    umem_reg.headroom = 0;

    if (setsockopt(xsk->xsk_fd, SOL_XDP, XDP_UMEM_REG, &umem_reg, sizeof(umem_reg)) < 0) {
        perror("setsockopt XDP_UMEM_REG");
        goto err;
    }

    /* Set ring sizes */
    opt = FILL_RING_SIZE;
    if (setsockopt(xsk->xsk_fd, SOL_XDP, XDP_UMEM_FILL_RING, &opt, sizeof(opt)) < 0) {
        perror("setsockopt XDP_UMEM_FILL_RING");
        goto err;
    }

    opt = COMP_RING_SIZE;
    if (setsockopt(xsk->xsk_fd, SOL_XDP, XDP_UMEM_COMPLETION_RING, &opt, sizeof(opt)) < 0) {
        perror("setsockopt XDP_UMEM_COMPLETION_RING");
        goto err;
    }

    opt = TX_RING_SIZE;
    if (setsockopt(xsk->xsk_fd, SOL_XDP, XDP_TX_RING, &opt, sizeof(opt)) < 0) {
        perror("setsockopt XDP_TX_RING");
        goto err;
    }

    opt = RX_RING_SIZE;
    if (setsockopt(xsk->xsk_fd, SOL_XDP, XDP_RX_RING, &opt, sizeof(opt)) < 0) {
        perror("setsockopt XDP_RX_RING");
        goto err;
    }

    /* Get ring offsets */
    optlen = sizeof(offsets);
    if (getsockopt(xsk->xsk_fd, SOL_XDP, XDP_MMAP_OFFSETS, &offsets, &optlen) < 0) {
        perror("getsockopt XDP_MMAP_OFFSETS");
        goto err;
    }

    /* Map fill ring */
    map = mmap(NULL, offsets.fr.desc + FILL_RING_SIZE * sizeof(uint64_t),
               PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
               xsk->xsk_fd, XDP_UMEM_PGOFF_FILL_RING);
    if (map == MAP_FAILED) {
        perror("mmap fill ring");
        goto err;
    }
    xsk->fill.producer = map + offsets.fr.producer;
    xsk->fill.consumer = map + offsets.fr.consumer;
    xsk->fill.ring = map + offsets.fr.desc;
    xsk->fill.mask = FILL_RING_SIZE - 1;

    /* Map completion ring */
    map = mmap(NULL, offsets.cr.desc + COMP_RING_SIZE * sizeof(uint64_t),
               PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
               xsk->xsk_fd, XDP_UMEM_PGOFF_COMPLETION_RING);
    if (map == MAP_FAILED) {
        perror("mmap completion ring");
        goto err;
    }
    xsk->comp.producer = map + offsets.cr.producer;
    xsk->comp.consumer = map + offsets.cr.consumer;
    xsk->comp.ring = map + offsets.cr.desc;
    xsk->comp.mask = COMP_RING_SIZE - 1;

    /* Map TX ring */
    map = mmap(NULL, offsets.tx.desc + TX_RING_SIZE * sizeof(struct xdp_desc),
               PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
               xsk->xsk_fd, XDP_PGOFF_TX_RING);
    if (map == MAP_FAILED) {
        perror("mmap tx ring");
        goto err;
    }
    xsk->tx.producer = map + offsets.tx.producer;
    xsk->tx.consumer = map + offsets.tx.consumer;
    xsk->tx.ring = map + offsets.tx.desc;
    xsk->tx.mask = TX_RING_SIZE - 1;

    /* Map RX ring */
    map = mmap(NULL, offsets.rx.desc + RX_RING_SIZE * sizeof(struct xdp_desc),
               PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
               xsk->xsk_fd, XDP_PGOFF_RX_RING);
    if (map == MAP_FAILED) {
        perror("mmap rx ring");
        goto err;
    }
    xsk->rx.producer = map + offsets.rx.producer;
    xsk->rx.consumer = map + offsets.rx.consumer;
    xsk->rx.ring = map + offsets.rx.desc;
    xsk->rx.mask = RX_RING_SIZE - 1;

    /* Bind socket to interface */
    memset(&sxdp, 0, sizeof(sxdp));
    sxdp.sxdp_family = AF_XDP;
    sxdp.sxdp_ifindex = ifindex;
    sxdp.sxdp_queue_id = queue_id;
    sxdp.sxdp_flags = XDP_USE_NEED_WAKEUP;

    if (bind(xsk->xsk_fd, (struct sockaddr *)&sxdp, sizeof(sxdp)) < 0) {
        perror("bind AF_XDP");
        goto err;
    }

    return 0;

err:
    munmap(xsk->umem_area, UMEM_SIZE);
    close(xsk->xsk_fd);
    return -1;
}

/* Get SQE pointer for 128-byte SQE */
static struct io_uring_sqe *get_sqe(struct uring_ctx *ctx, unsigned index)
{
    return (struct io_uring_sqe *)((char *)ctx->sqes + index * ctx->sqe_size);
}

/* Submit NVMe read using IORING_OP_URING_CMD (unified ops) */
static int submit_nvme_read_cmd(struct pipeline_ctx *ctx, void *buf, size_t len,
                                 uint64_t slba, uint64_t user_data)
{
    struct uring_ctx *uring = &ctx->uring;
    unsigned tail = *uring->sq_tail;
    unsigned index = tail & *uring->sq_mask;
    struct io_uring_sqe *sqe = get_sqe(uring, index);
    struct nvme_uring_cmd *cmd;

    /* Clear SQE */
    memset(sqe, 0, uring->sqe_size);

    /* Set up URING_CMD operation */
    sqe->opcode = IORING_OP_URING_CMD;
    sqe->fd = ctx->nvme_fd;
    sqe->cmd_op = NVME_URING_CMD_IO;
    sqe->user_data = user_data;

    /* NVMe command is embedded in the SQE's cmd field */
    cmd = (struct nvme_uring_cmd *)sqe->cmd;

    /* Build NVMe Read command */
    cmd->opcode = NVME_CMD_READ;
    cmd->nsid = ctx->nsid;
    cmd->addr = (uint64_t)buf;
    cmd->data_len = len;

    /* CDW10-11: Starting LBA (64-bit) */
    cmd->cdw10 = slba & 0xFFFFFFFF;
    cmd->cdw11 = (slba >> 32) & 0xFFFFFFFF;

    /* CDW12: Number of logical blocks (0-based) */
    uint32_t nlb = (len / g_lba_size) - 1;  /* LBA size set via -b option */
    cmd->cdw12 = nlb;

    uring->sq_array[index] = index;
    __atomic_store_n(uring->sq_tail, tail + 1, __ATOMIC_RELEASE);

    return io_uring_enter(uring->ring_fd, 1, 0, 0, NULL);
}

/* Wait for io_uring completion */
static int wait_nvme_completion(struct pipeline_ctx *ctx, uint64_t *user_data, int *result)
{
    struct uring_ctx *uring = &ctx->uring;
    unsigned head;
    struct io_uring_cqe *cqe;
    int ret;

    /* Wait for completion */
    ret = io_uring_enter(uring->ring_fd, 0, 1, IORING_ENTER_GETEVENTS, NULL);
    if (ret < 0)
        return ret;

    head = *uring->cq_head;
    if (head == *uring->cq_tail)
        return -EAGAIN;

    cqe = &uring->cqes[head & *uring->cq_mask];
    *user_data = cqe->user_data;
    *result = cqe->res;

    __atomic_store_n(uring->cq_head, head + 1, __ATOMIC_RELEASE);

    return 0;
}

/* Compute checksum */
static uint16_t compute_checksum(void *data, int len)
{
    uint32_t sum = 0;
    uint16_t *ptr = data;

    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }

    if (len == 1)
        sum += *(uint8_t *)ptr;

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    return ~sum;
}

/* Userspace computation on data */
static void process_data(void *data, size_t len)
{
    uint64_t *p = data;
    size_t count = len / sizeof(uint64_t);
    uint64_t checksum = 0;

    for (size_t i = 0; i < count; i++) {
        checksum ^= p[i];
        p[i] = p[i] ^ 0xDEADBEEFCAFEBABEULL;
    }

    if (count > 0)
        p[count - 1] = checksum;
}

/* Build UDP packet headers in UMEM frame.
 * When payload is already at frame + PKT_HEADER_ROOM (zero-copy NVMe path),
 * pass payload=NULL to skip the memcpy.
 * When payload is in a separate buffer, pass non-NULL to copy it. */
static size_t build_packet(struct pipeline_ctx *ctx, void *frame,
                           void *payload, size_t payload_len)
{
    struct ethhdr *eth = frame;
    struct iphdr *ip = frame + sizeof(*eth);
    struct udphdr *udp = (void *)ip + sizeof(*ip);
    void *data = (void *)udp + sizeof(*udp);
    size_t total_len;

    /* Ethernet header */
    memcpy(eth->h_dest, ctx->dst_mac, 6);
    memcpy(eth->h_source, ctx->src_mac, 6);
    eth->h_proto = htons(ETH_P_IP);

    /* IP header */
    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0;
    ip->tot_len = htons(sizeof(*ip) + sizeof(*udp) + payload_len);
    ip->id = 0;
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_UDP;
    ip->check = 0;
    ip->saddr = ctx->src_ip;
    ip->daddr = ctx->dst_ip;
    ip->check = compute_checksum(ip, sizeof(*ip));

    /* UDP header */
    udp->source = htons(ctx->src_port);
    udp->dest = htons(ctx->dst_port);
    udp->len = htons(sizeof(*udp) + payload_len);
    udp->check = 0;

    /* Copy payload only if provided (non-zero-copy fallback) */
    if (payload)
        memcpy(data, payload, payload_len);

    total_len = sizeof(*eth) + sizeof(*ip) + sizeof(*udp) + payload_len;
    return total_len;
}

/* Submit TX packet via AF_XDP */
static int xsk_tx_submit(struct xsk_ctx *xsk, uint64_t addr, uint32_t len)
{
    unsigned int prod = *xsk->tx.producer;
    unsigned int idx = prod & xsk->tx.mask;

    xsk->tx.ring[idx].addr = addr;
    xsk->tx.ring[idx].len = len;

    __atomic_store_n(xsk->tx.producer, prod + 1, __ATOMIC_RELEASE);

    return 0;
}

/* Kick TX */
static int xsk_tx_kick(struct xsk_ctx *xsk)
{
    return sendto(xsk->xsk_fd, NULL, 0, MSG_DONTWAIT, NULL, 0);
}

/* Complete TX and reclaim frames */
static void xsk_tx_complete(struct xsk_ctx *xsk)
{
    unsigned int cons = *xsk->comp.consumer;
    unsigned int prod = *xsk->comp.producer;

    while (cons != prod) {
        uint64_t addr = xsk->comp.ring[cons & xsk->comp.mask];
        xsk_free_umem_frame(xsk, addr);
        cons++;
    }

    __atomic_store_n(xsk->comp.consumer, cons, __ATOMIC_RELEASE);
}

/* Set scheduler hints for the pipeline */
static int setup_sched_hints(uint64_t read_freq_ns, uint64_t send_freq_ns, int batch_size)
{
    struct io_uring_sched_hints hints;
    int ret;

    memset(&hints, 0, sizeof(hints));
    hints.read_freq_ns = read_freq_ns;
    hints.send_freq_ns = send_freq_ns;
    hints.batch_size = batch_size;
    hints.flags = IO_URING_SCHED_HINT_NVME_XDP | IO_URING_SCHED_HINT_LATENCY;

    ret = io_uring_sched_hints_set(&hints);
    if (ret < 0) {
        fprintf(stderr, "Warning: Failed to set scheduler hints: %s\n", strerror(errno));
        return ret;
    }

    printf("Set scheduler hints: read_freq=%lu ns, send_freq=%lu ns, batch=%d\n",
           hints.read_freq_ns, hints.send_freq_ns, hints.batch_size);
    return 0;
}

/* Main pipeline loop using io_uring unified ops */
static int run_pipeline(struct pipeline_ctx *ctx, uint64_t start_lba, int num_blocks)
{
    uint64_t frame_addr;
    int ret;

    /* Set scheduler hints for expected I/O pattern */
    /* Estimate: 100us per read, 50us per send, batch of num_blocks */
    setup_sched_hints(100000, 50000, num_blocks);

    printf("Starting pipeline with io_uring unified ops (IORING_OP_URING_CMD)\n");
    printf("Reading %d blocks from LBA %lu using NVMe passthrough\n",
           num_blocks, start_lba);

    for (int i = 0; i < num_blocks; i++) {
        uint64_t lba = start_lba + i * (NVME_BLOCK_SIZE / g_lba_size);
        uint64_t user_data;
        int result;
        size_t pkt_len;

        /* Allocate UMEM frame FIRST so NVMe can DMA directly into it */
        frame_addr = xsk_alloc_umem_frame(&ctx->xsk);
        if (frame_addr == INVALID_UMEM_FRAME) {
            xsk_tx_complete(&ctx->xsk);
            frame_addr = xsk_alloc_umem_frame(&ctx->xsk);
            if (frame_addr == INVALID_UMEM_FRAME) {
                fprintf(stderr, "No free UMEM frames, skipping\n");
                continue;
            }
        }

        void *frame = ctx->xsk.umem_area + frame_addr;
        void *nvme_buf = frame + PKT_HEADER_ROOM;

        /* NVMe reads directly into UMEM frame (zero-copy) */
        ret = submit_nvme_read_cmd(ctx, nvme_buf, NVME_BLOCK_SIZE, lba, i);
        if (ret < 0) {
            perror("submit_nvme_read_cmd");
            xsk_free_umem_frame(&ctx->xsk, frame_addr);
            break;
        }

        ret = wait_nvme_completion(ctx, &user_data, &result);
        if (ret < 0) {
            perror("wait_nvme_completion");
            xsk_free_umem_frame(&ctx->xsk, frame_addr);
            break;
        }

        if (result < 0) {
            fprintf(stderr, "NVMe read error: %d (%s)\n", -result, strerror(-result));
            xsk_free_umem_frame(&ctx->xsk, frame_addr);
            continue;
        }

        printf("Block %d: read from LBA %lu (result=%d)\n", i, lba, result);
        io_uring_sched_hints_record(0);

        /* Compute in-place on UMEM data (zero-copy) */
        process_data(nvme_buf, NVME_BLOCK_SIZE);

        /* Build headers only; payload already in frame at PKT_HEADER_ROOM */
        pkt_len = build_packet(ctx, frame, NULL, NVME_BLOCK_SIZE);

        /* Submit TX */
        xsk_tx_submit(&ctx->xsk, frame_addr, pkt_len);

        /* Kick TX */
        ret = xsk_tx_kick(&ctx->xsk);
        if (ret < 0 && errno != EAGAIN && errno != EBUSY) {
            perror("xsk_tx_kick");
        }

        /* Record send operation for scheduler */
        io_uring_sched_hints_record(1);  /* 1 = send */

        printf("Block %d: transmitted %zu bytes via AF_XDP\n", i, pkt_len);

        /* Reclaim completed frames */
        xsk_tx_complete(&ctx->xsk);
    }

    return 0;
}

/* Get NVMe namespace ID */
static int get_nvme_nsid(int fd)
{
    int nsid;
    nsid = ioctl(fd, NVME_IOCTL_ID);
    if (nsid < 0) {
        perror("NVME_IOCTL_ID");
        return 1;  /* Default to nsid 1 */
    }
    return nsid;
}

/* Parse MAC address */
static int parse_mac(const char *str, uint8_t *mac)
{
    return sscanf(str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                  &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) == 6 ? 0 : -1;
}

/* Print usage */
static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [options]\n", prog);
    fprintf(stderr, "\nNVMe to AF_XDP pipeline using io_uring unified ops\n\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -d <device>     NVMe device (default: /dev/ng0n1 for char device)\n");
    fprintf(stderr, "  -i <interface>  Network interface (default: eth0)\n");
    fprintf(stderr, "  -q <queue>      XDP queue ID (default: 0)\n");
    fprintf(stderr, "  -l <lba>        Start LBA (default: 0)\n");
    fprintf(stderr, "  -n <blocks>     Number of blocks to read (default: 10)\n");
    fprintf(stderr, "  -D <mac>        Destination MAC (default: ff:ff:ff:ff:ff:ff)\n");
    fprintf(stderr, "  -S <mac>        Source MAC (default: 00:00:00:00:00:00)\n");
    fprintf(stderr, "  -a <ip>         Destination IP (default: 192.168.1.1)\n");
    fprintf(stderr, "  -s <ip>         Source IP (default: 192.168.1.2)\n");
    fprintf(stderr, "  -p <port>       Destination port (default: 12345)\n");
    fprintf(stderr, "  -P <port>       Source port (default: 54321)\n");
    fprintf(stderr, "  -b <lba_size>   LBA size in bytes (default: 512, use 4096 for 4Kn drives)\n");
  fprintf(stderr, "  -h              Show this help\n");
    fprintf(stderr, "\nNote: Use NVMe character device (e.g., /dev/ng0n1) for URING_CMD\n");
}

int main(int argc, char **argv)
{
    struct pipeline_ctx ctx;
    int opt;
    uint64_t start_lba = 0;
    int num_blocks = 10;
    int ret;

    /* Initialize defaults */
    memset(&ctx, 0, sizeof(ctx));
    ctx.nvme_device = "/dev/ng0n1";  /* NVMe generic char device */
    ctx.net_iface = "eth0";
    ctx.queue_id = 0;

    /* Default network config */
    memset(ctx.dst_mac, 0xff, 6);
    memset(ctx.src_mac, 0, 6);
    ctx.dst_ip = inet_addr("192.168.1.1");
    ctx.src_ip = inet_addr("192.168.1.2");
    ctx.dst_port = 12345;
    ctx.src_port = 54321;

    /* Parse arguments */
    while ((opt = getopt(argc, argv, "d:i:q:l:n:D:S:a:s:p:P:b:h")) != -1) {
        switch (opt) {
        case 'd':
            ctx.nvme_device = optarg;
            break;
        case 'i':
            ctx.net_iface = optarg;
            break;
        case 'q':
            ctx.queue_id = atoi(optarg);
            break;
        case 'l':
            start_lba = strtoull(optarg, NULL, 0);
            break;
        case 'n':
            num_blocks = atoi(optarg);
            break;
        case 'D':
            if (parse_mac(optarg, ctx.dst_mac) < 0) {
                fprintf(stderr, "Invalid destination MAC\n");
                return 1;
            }
            break;
        case 'S':
            if (parse_mac(optarg, ctx.src_mac) < 0) {
                fprintf(stderr, "Invalid source MAC\n");
                return 1;
            }
            break;
        case 'a':
            ctx.dst_ip = inet_addr(optarg);
            break;
        case 's':
            ctx.src_ip = inet_addr(optarg);
            break;
        case 'p':
            ctx.dst_port = atoi(optarg);
            break;
        case 'P':
            ctx.src_port = atoi(optarg);
            break;
        case 'b':
            g_lba_size = (uint32_t)strtoul(optarg, NULL, 0);
            if (g_lba_size == 0 || (g_lba_size & (g_lba_size - 1)) != 0) {
                fprintf(stderr, "Invalid LBA size: must be a power of 2\n");
                return 1;
            }
            break;
        case 'h':
        default:
            usage(argv[0]);
            return opt == 'h' ? 0 : 1;
        }
    }

    /* Get interface index */
    ctx.ifindex = if_nametoindex(ctx.net_iface);
    if (ctx.ifindex == 0) {
        fprintf(stderr, "Interface %s not found\n", ctx.net_iface);
        return 1;
    }

    /* Open NVMe character device for URING_CMD */
    ctx.nvme_fd = open(ctx.nvme_device, O_RDWR);
    if (ctx.nvme_fd < 0) {
        perror("open nvme device");
        fprintf(stderr, "Note: URING_CMD requires NVMe char device (e.g., /dev/ng0n1)\n");
        return 1;
    }

    /* Get namespace ID */
    ctx.nsid = get_nvme_nsid(ctx.nvme_fd);
    printf("Opened NVMe device: %s (nsid=%u)\n", ctx.nvme_device, ctx.nsid);

    /* Initialize io_uring with SQE128 for URING_CMD */
    ret = init_io_uring(&ctx.uring);
    if (ret < 0) {
        fprintf(stderr, "Failed to initialize io_uring with SQE128\n");
        close(ctx.nvme_fd);
        return 1;
    }

    printf("Initialized io_uring with 128-byte SQE for URING_CMD\n");

    /* Initialize AF_XDP socket */
    ret = init_xsk(&ctx.xsk, ctx.ifindex, ctx.queue_id);
    if (ret < 0) {
        fprintf(stderr, "Failed to initialize AF_XDP socket\n");
        close(ctx.nvme_fd);
        return 1;
    }

    printf("Initialized AF_XDP on %s queue %d\n", ctx.net_iface, ctx.queue_id);

    /* Run pipeline */
    ret = run_pipeline(&ctx, start_lba, num_blocks);

    /* Cleanup */
    close(ctx.xsk.xsk_fd);
    munmap(ctx.xsk.umem_area, UMEM_SIZE);
    close(ctx.uring.ring_fd);
    close(ctx.nvme_fd);

    printf("Pipeline completed\n");

    return ret;
}
