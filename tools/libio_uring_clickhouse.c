/*
 * LD_PRELOAD library for ClickHouse io_uring unified ops acceleration
 *
 * Automatically intercepts read/write/send operations and batches them
 * using io_uring for improved performance. Detects read-compute-send
 * sequences and optimizes scheduling.
 *
 * Compile:
 *   gcc -shared -fPIC -o libio_uring_clickhouse.so libio_uring_clickhouse.c -ldl -lpthread
 *
 * Usage:
 *   LD_PRELOAD=./libio_uring_clickhouse.so clickhouse-server
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <linux/io_uring.h>
#include <time.h>

/* Configuration */
#define QUEUE_DEPTH         256
#define BATCH_SIZE          32
#define MAX_PENDING_OPS     64
#define SEQUENCE_TIMEOUT_NS 1000000  /* 1ms timeout for sequence detection */

/* Syscall numbers */
#ifndef __NR_io_uring_setup
#define __NR_io_uring_setup    425
#endif
#ifndef __NR_io_uring_enter
#define __NR_io_uring_enter    426
#endif
#ifndef __NR_io_uring_sched_hints
#define __NR_io_uring_sched_hints 468
#endif

/* Scheduler hint flags */
#define IO_URING_SCHED_HINT_LATENCY     (1U << 0)
#define IO_URING_SCHED_HINT_THROUGHPUT  (1U << 1)
#define IO_URING_SCHED_HINT_NVME_XDP    (1U << 3)

/* Operation types for sequence detection */
typedef enum {
    OP_NONE = 0,
    OP_READ,
    OP_WRITE,
    OP_SEND,
    OP_RECV,
    OP_COMPUTE
} op_type_t;

/* Pending operation */
struct pending_op {
    op_type_t type;
    int fd;
    void *buf;
    size_t len;
    off_t offset;
    uint64_t timestamp;
    bool completed;
    ssize_t result;
};

/* Sequence pattern for optimization */
struct op_sequence {
    op_type_t pattern[8];
    int pattern_len;
    int match_count;
    uint64_t avg_interval_ns;
};

/* io_uring context */
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
    unsigned sq_entries;
    unsigned cq_entries;
};

/* Thread-local state */
struct thread_state {
    struct uring_ctx uring;
    bool initialized;

    /* Pending operations for batching */
    struct pending_op pending[MAX_PENDING_OPS];
    int pending_count;

    /* Sequence detection */
    op_type_t recent_ops[16];
    int recent_count;
    uint64_t last_op_time;

    /* Detected patterns */
    struct op_sequence sequences[4];
    int sequence_count;

    /* Statistics */
    uint64_t total_reads;
    uint64_t total_writes;
    uint64_t total_sends;
    uint64_t batched_ops;
    uint64_t sequence_hits;
};

/* Global state */
static __thread struct thread_state *tls_state = NULL;
static pthread_key_t tls_key;
static pthread_once_t init_once = PTHREAD_ONCE_INIT;
static bool global_enabled = false;

/* Original function pointers */
static ssize_t (*real_read)(int fd, void *buf, size_t count) = NULL;
static ssize_t (*real_write)(int fd, const void *buf, size_t count) = NULL;
static ssize_t (*real_pread)(int fd, void *buf, size_t count, off_t offset) = NULL;
static ssize_t (*real_pwrite)(int fd, const void *buf, size_t count, off_t offset) = NULL;
static ssize_t (*real_send)(int sockfd, const void *buf, size_t len, int flags) = NULL;
static ssize_t (*real_recv)(int sockfd, void *buf, size_t len, int flags) = NULL;
static ssize_t (*real_sendto)(int sockfd, const void *buf, size_t len, int flags,
                              const struct sockaddr *dest_addr, socklen_t addrlen) = NULL;
static ssize_t (*real_recvfrom)(int sockfd, void *buf, size_t len, int flags,
                                struct sockaddr *src_addr, socklen_t *addrlen) = NULL;
static ssize_t (*real_readv)(int fd, const struct iovec *iov, int iovcnt) = NULL;
static ssize_t (*real_writev)(int fd, const struct iovec *iov, int iovcnt) = NULL;

/* Get current timestamp in nanoseconds */
static inline uint64_t get_time_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

/* Initialize io_uring for thread */
static int init_uring(struct uring_ctx *ctx)
{
    struct io_uring_params params;

    memset(&params, 0, sizeof(params));
    params.flags = IORING_SETUP_SQPOLL;
    params.sq_thread_idle = 2000;

    ctx->ring_fd = syscall(__NR_io_uring_setup, QUEUE_DEPTH, &params);
    if (ctx->ring_fd < 0) {
        /* Fallback without SQPOLL */
        memset(&params, 0, sizeof(params));
        ctx->ring_fd = syscall(__NR_io_uring_setup, QUEUE_DEPTH, &params);
        if (ctx->ring_fd < 0)
            return -1;
    }

    ctx->sq_entries = params.sq_entries;
    ctx->cq_entries = params.cq_entries;

    /* Map SQ ring */
    size_t sq_ring_sz = params.sq_off.array + params.sq_entries * sizeof(unsigned);
    ctx->sq_ptr = mmap(NULL, sq_ring_sz, PROT_READ | PROT_WRITE,
                       MAP_SHARED | MAP_POPULATE, ctx->ring_fd, IORING_OFF_SQ_RING);
    if (ctx->sq_ptr == MAP_FAILED)
        goto err_close;

    /* Map CQ ring */
    size_t cq_ring_sz = params.cq_off.cqes + params.cq_entries * sizeof(struct io_uring_cqe);
    ctx->cq_ptr = mmap(NULL, cq_ring_sz, PROT_READ | PROT_WRITE,
                       MAP_SHARED | MAP_POPULATE, ctx->ring_fd, IORING_OFF_CQ_RING);
    if (ctx->cq_ptr == MAP_FAILED)
        goto err_unmap_sq;

    /* Map SQEs */
    ctx->sqes = mmap(NULL, params.sq_entries * sizeof(struct io_uring_sqe),
                     PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
                     ctx->ring_fd, IORING_OFF_SQES);
    if (ctx->sqes == MAP_FAILED)
        goto err_unmap_cq;

    /* Setup pointers */
    ctx->sq_head = ctx->sq_ptr + params.sq_off.head;
    ctx->sq_tail = ctx->sq_ptr + params.sq_off.tail;
    ctx->sq_mask = ctx->sq_ptr + params.sq_off.ring_mask;
    ctx->sq_array = ctx->sq_ptr + params.sq_off.array;

    ctx->cq_head = ctx->cq_ptr + params.cq_off.head;
    ctx->cq_tail = ctx->cq_ptr + params.cq_off.tail;
    ctx->cq_mask = ctx->cq_ptr + params.cq_off.ring_mask;
    ctx->cqes = ctx->cq_ptr + params.cq_off.cqes;

    return 0;

err_unmap_cq:
    munmap(ctx->cq_ptr, cq_ring_sz);
err_unmap_sq:
    munmap(ctx->sq_ptr, sq_ring_sz);
err_close:
    close(ctx->ring_fd);
    return -1;
}

/* Submit a single io_uring operation */
static int submit_uring_op(struct thread_state *state, int opcode, int fd,
                           void *buf, size_t len, off_t offset, uint64_t user_data)
{
    struct uring_ctx *ctx = &state->uring;
    unsigned tail = *ctx->sq_tail;
    unsigned index = tail & *ctx->sq_mask;
    struct io_uring_sqe *sqe = &ctx->sqes[index];

    memset(sqe, 0, sizeof(*sqe));
    sqe->opcode = opcode;
    sqe->fd = fd;
    sqe->addr = (unsigned long)buf;
    sqe->len = len;
    sqe->off = offset;
    sqe->user_data = user_data;

    ctx->sq_array[index] = index;
    __atomic_store_n(ctx->sq_tail, tail + 1, __ATOMIC_RELEASE);

    return 0;
}

/* Wait for io_uring completions */
static int wait_uring_completions(struct thread_state *state, int min_complete)
{
    struct uring_ctx *ctx = &state->uring;
    int ret;

    ret = syscall(__NR_io_uring_enter, ctx->ring_fd, 0, min_complete,
                  IORING_ENTER_GETEVENTS, NULL, 0);
    return ret;
}

/* Process io_uring completions */
static void process_completions(struct thread_state *state)
{
    struct uring_ctx *ctx = &state->uring;
    unsigned head = *ctx->cq_head;

    while (head != *ctx->cq_tail) {
        struct io_uring_cqe *cqe = &ctx->cqes[head & *ctx->cq_mask];
        uint64_t user_data = cqe->user_data;

        if (user_data < MAX_PENDING_OPS) {
            state->pending[user_data].completed = true;
            state->pending[user_data].result = cqe->res;
        }

        head++;
    }

    __atomic_store_n(ctx->cq_head, head, __ATOMIC_RELEASE);
}

/* Record operation for sequence detection */
static void record_operation(struct thread_state *state, op_type_t type)
{
    uint64_t now = get_time_ns();

    /* Shift recent ops */
    if (state->recent_count >= 16) {
        memmove(state->recent_ops, state->recent_ops + 1, 15 * sizeof(op_type_t));
        state->recent_count = 15;
    }
    state->recent_ops[state->recent_count++] = type;

    /* Check for read-compute-send pattern */
    if (state->recent_count >= 3) {
        int idx = state->recent_count - 3;
        if (state->recent_ops[idx] == OP_READ &&
            state->recent_ops[idx + 1] == OP_COMPUTE &&
            state->recent_ops[idx + 2] == OP_SEND) {
            state->sequence_hits++;
        }
    }

    state->last_op_time = now;

    /* Update scheduler hints */
    if (type == OP_READ) {
        state->total_reads++;
        syscall(__NR_io_uring_sched_hints, 2, NULL, 0);
    } else if (type == OP_SEND) {
        state->total_sends++;
        syscall(__NR_io_uring_sched_hints, 2, NULL, 1);
    }
}

/* Flush pending operations */
static void flush_pending(struct thread_state *state)
{
    if (state->pending_count == 0)
        return;

    /* Submit all pending operations */
    int submitted = syscall(__NR_io_uring_enter, state->uring.ring_fd,
                            state->pending_count, 0, 0, NULL, 0);
    if (submitted < 0)
        return;

    /* Wait for completions */
    wait_uring_completions(state, state->pending_count);
    process_completions(state);

    state->batched_ops += state->pending_count;
    state->pending_count = 0;
}

/* Check if fd is suitable for io_uring */
static bool should_use_uring(int fd)
{
    /* Skip stdin/stdout/stderr */
    if (fd < 3)
        return false;

    /* Check if it's a regular file or socket */
    struct stat st;
    if (fstat(fd, &st) < 0)
        return false;

    return S_ISREG(st.st_mode) || S_ISSOCK(st.st_mode) || S_ISBLK(st.st_mode);
}

/* Thread cleanup */
static void thread_cleanup(void *arg)
{
    struct thread_state *state = arg;
    if (state) {
        if (state->initialized) {
            /* Print statistics */
            fprintf(stderr, "[io_uring_clickhouse] Thread stats: "
                    "reads=%lu writes=%lu sends=%lu batched=%lu seq_hits=%lu\n",
                    state->total_reads, state->total_writes, state->total_sends,
                    state->batched_ops, state->sequence_hits);

            close(state->uring.ring_fd);
        }
        free(state);
    }
}

/* Get or create thread state */
static struct thread_state *get_thread_state(void)
{
    if (tls_state)
        return tls_state;

    tls_state = calloc(1, sizeof(struct thread_state));
    if (!tls_state)
        return NULL;

    if (init_uring(&tls_state->uring) < 0) {
        free(tls_state);
        tls_state = NULL;
        return NULL;
    }

    /* Set scheduler hints for ClickHouse workload */
    struct {
        uint64_t read_freq_ns;
        uint64_t send_freq_ns;
        uint32_t batch_size;
        uint32_t flags;
        uint64_t __resv[2];
    } hints = {
        .read_freq_ns = 10000,   /* 10us */
        .send_freq_ns = 10000,   /* 10us */
        .batch_size = BATCH_SIZE,
        .flags = IO_URING_SCHED_HINT_THROUGHPUT | IO_URING_SCHED_HINT_NVME_XDP
    };
    syscall(__NR_io_uring_sched_hints, 0, &hints, 0);

    tls_state->initialized = true;
    pthread_setspecific(tls_key, tls_state);

    return tls_state;
}

/* Global initialization */
static void global_init(void)
{
    /* Load original functions */
    real_read = dlsym(RTLD_NEXT, "read");
    real_write = dlsym(RTLD_NEXT, "write");
    real_pread = dlsym(RTLD_NEXT, "pread");
    real_pwrite = dlsym(RTLD_NEXT, "pwrite");
    real_send = dlsym(RTLD_NEXT, "send");
    real_recv = dlsym(RTLD_NEXT, "recv");
    real_sendto = dlsym(RTLD_NEXT, "sendto");
    real_recvfrom = dlsym(RTLD_NEXT, "recvfrom");
    real_readv = dlsym(RTLD_NEXT, "readv");
    real_writev = dlsym(RTLD_NEXT, "writev");

    pthread_key_create(&tls_key, thread_cleanup);

    /* Check if enabled */
    global_enabled = getenv("IO_URING_CLICKHOUSE_ENABLED") != NULL;

    if (global_enabled) {
        fprintf(stderr, "[io_uring_clickhouse] Initialized - intercepting I/O for ClickHouse\n");
    }
}

/* Intercepted read */
ssize_t read(int fd, void *buf, size_t count)
{
    pthread_once(&init_once, global_init);

    if (!global_enabled || !should_use_uring(fd))
        return real_read(fd, buf, count);

    struct thread_state *state = get_thread_state();
    if (!state)
        return real_read(fd, buf, count);

    /* For small reads, use io_uring directly */
    if (count <= 4096) {
        int idx = state->pending_count;
        if (idx >= MAX_PENDING_OPS)
            flush_pending(state);

        idx = state->pending_count++;
        state->pending[idx].type = OP_READ;
        state->pending[idx].fd = fd;
        state->pending[idx].buf = buf;
        state->pending[idx].len = count;
        state->pending[idx].completed = false;

        submit_uring_op(state, IORING_OP_READ, fd, buf, count, -1, idx);

        /* If we have a batch, submit */
        if (state->pending_count >= BATCH_SIZE) {
            flush_pending(state);
        } else {
            /* Submit and wait for this one */
            syscall(__NR_io_uring_enter, state->uring.ring_fd, 1, 1,
                    IORING_ENTER_GETEVENTS, NULL, 0);
            process_completions(state);
        }

        record_operation(state, OP_READ);

        if (state->pending[idx].completed)
            return state->pending[idx].result;
    }

    /* Fallback for large reads */
    ssize_t ret = real_read(fd, buf, count);
    record_operation(state, OP_READ);
    return ret;
}

/* Intercepted pread */
ssize_t pread(int fd, void *buf, size_t count, off_t offset)
{
    pthread_once(&init_once, global_init);

    if (!global_enabled || !should_use_uring(fd))
        return real_pread(fd, buf, count, offset);

    struct thread_state *state = get_thread_state();
    if (!state)
        return real_pread(fd, buf, count, offset);

    int idx = state->pending_count++;
    state->pending[idx].type = OP_READ;
    state->pending[idx].fd = fd;
    state->pending[idx].buf = buf;
    state->pending[idx].len = count;
    state->pending[idx].offset = offset;
    state->pending[idx].completed = false;

    submit_uring_op(state, IORING_OP_READ, fd, buf, count, offset, idx);

    /* Submit and wait */
    syscall(__NR_io_uring_enter, state->uring.ring_fd, 1, 1,
            IORING_ENTER_GETEVENTS, NULL, 0);
    process_completions(state);

    record_operation(state, OP_READ);
    state->pending_count--;

    return state->pending[idx].result;
}

/* Intercepted write */
ssize_t write(int fd, const void *buf, size_t count)
{
    pthread_once(&init_once, global_init);

    if (!global_enabled || !should_use_uring(fd))
        return real_write(fd, buf, count);

    struct thread_state *state = get_thread_state();
    if (!state)
        return real_write(fd, buf, count);

    int idx = state->pending_count++;
    state->pending[idx].type = OP_WRITE;
    state->pending[idx].fd = fd;
    state->pending[idx].buf = (void *)buf;
    state->pending[idx].len = count;
    state->pending[idx].completed = false;

    submit_uring_op(state, IORING_OP_WRITE, fd, (void *)buf, count, -1, idx);

    /* Submit and wait */
    syscall(__NR_io_uring_enter, state->uring.ring_fd, 1, 1,
            IORING_ENTER_GETEVENTS, NULL, 0);
    process_completions(state);

    state->total_writes++;
    state->pending_count--;

    return state->pending[idx].result;
}

/* Intercepted pwrite */
ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset)
{
    pthread_once(&init_once, global_init);

    if (!global_enabled || !should_use_uring(fd))
        return real_pwrite(fd, buf, count, offset);

    struct thread_state *state = get_thread_state();
    if (!state)
        return real_pwrite(fd, buf, count, offset);

    int idx = state->pending_count++;
    state->pending[idx].type = OP_WRITE;
    state->pending[idx].fd = fd;
    state->pending[idx].buf = (void *)buf;
    state->pending[idx].len = count;
    state->pending[idx].offset = offset;
    state->pending[idx].completed = false;

    submit_uring_op(state, IORING_OP_WRITE, fd, (void *)buf, count, offset, idx);

    /* Submit and wait */
    syscall(__NR_io_uring_enter, state->uring.ring_fd, 1, 1,
            IORING_ENTER_GETEVENTS, NULL, 0);
    process_completions(state);

    state->total_writes++;
    state->pending_count--;

    return state->pending[idx].result;
}

/* Intercepted send */
ssize_t send(int sockfd, const void *buf, size_t len, int flags)
{
    pthread_once(&init_once, global_init);

    if (!global_enabled)
        return real_send(sockfd, buf, len, flags);

    struct thread_state *state = get_thread_state();
    if (!state)
        return real_send(sockfd, buf, len, flags);

    int idx = state->pending_count++;
    state->pending[idx].type = OP_SEND;
    state->pending[idx].fd = sockfd;
    state->pending[idx].buf = (void *)buf;
    state->pending[idx].len = len;
    state->pending[idx].completed = false;

    submit_uring_op(state, IORING_OP_SEND, sockfd, (void *)buf, len, 0, idx);

    /* Submit and wait */
    syscall(__NR_io_uring_enter, state->uring.ring_fd, 1, 1,
            IORING_ENTER_GETEVENTS, NULL, 0);
    process_completions(state);

    record_operation(state, OP_SEND);
    state->pending_count--;

    return state->pending[idx].result;
}

/* Intercepted recv */
ssize_t recv(int sockfd, void *buf, size_t len, int flags)
{
    pthread_once(&init_once, global_init);

    if (!global_enabled)
        return real_recv(sockfd, buf, len, flags);

    struct thread_state *state = get_thread_state();
    if (!state)
        return real_recv(sockfd, buf, len, flags);

    int idx = state->pending_count++;
    state->pending[idx].type = OP_RECV;
    state->pending[idx].fd = sockfd;
    state->pending[idx].buf = buf;
    state->pending[idx].len = len;
    state->pending[idx].completed = false;

    submit_uring_op(state, IORING_OP_RECV, sockfd, buf, len, 0, idx);

    /* Submit and wait */
    syscall(__NR_io_uring_enter, state->uring.ring_fd, 1, 1,
            IORING_ENTER_GETEVENTS, NULL, 0);
    process_completions(state);

    record_operation(state, OP_RECV);
    state->pending_count--;

    return state->pending[idx].result;
}

/* Intercepted readv for vectored I/O (common in ClickHouse) */
ssize_t readv(int fd, const struct iovec *iov, int iovcnt)
{
    pthread_once(&init_once, global_init);

    if (!global_enabled || !should_use_uring(fd))
        return real_readv(fd, iov, iovcnt);

    struct thread_state *state = get_thread_state();
    if (!state)
        return real_readv(fd, iov, iovcnt);

    /* Use io_uring READV */
    struct uring_ctx *ctx = &state->uring;
    unsigned tail = *ctx->sq_tail;
    unsigned index = tail & *ctx->sq_mask;
    struct io_uring_sqe *sqe = &ctx->sqes[index];

    memset(sqe, 0, sizeof(*sqe));
    sqe->opcode = IORING_OP_READV;
    sqe->fd = fd;
    sqe->addr = (unsigned long)iov;
    sqe->len = iovcnt;
    sqe->off = -1;
    sqe->user_data = 0;

    ctx->sq_array[index] = index;
    __atomic_store_n(ctx->sq_tail, tail + 1, __ATOMIC_RELEASE);

    /* Submit and wait */
    syscall(__NR_io_uring_enter, ctx->ring_fd, 1, 1,
            IORING_ENTER_GETEVENTS, NULL, 0);

    /* Get result */
    unsigned head = *ctx->cq_head;
    ssize_t result = -EIO;
    if (head != *ctx->cq_tail) {
        struct io_uring_cqe *cqe = &ctx->cqes[head & *ctx->cq_mask];
        result = cqe->res;
        __atomic_store_n(ctx->cq_head, head + 1, __ATOMIC_RELEASE);
    }

    record_operation(state, OP_READ);
    return result;
}

/* Intercepted writev for vectored I/O */
ssize_t writev(int fd, const struct iovec *iov, int iovcnt)
{
    pthread_once(&init_once, global_init);

    if (!global_enabled || !should_use_uring(fd))
        return real_writev(fd, iov, iovcnt);

    struct thread_state *state = get_thread_state();
    if (!state)
        return real_writev(fd, iov, iovcnt);

    /* Use io_uring WRITEV */
    struct uring_ctx *ctx = &state->uring;
    unsigned tail = *ctx->sq_tail;
    unsigned index = tail & *ctx->sq_mask;
    struct io_uring_sqe *sqe = &ctx->sqes[index];

    memset(sqe, 0, sizeof(*sqe));
    sqe->opcode = IORING_OP_WRITEV;
    sqe->fd = fd;
    sqe->addr = (unsigned long)iov;
    sqe->len = iovcnt;
    sqe->off = -1;
    sqe->user_data = 0;

    ctx->sq_array[index] = index;
    __atomic_store_n(ctx->sq_tail, tail + 1, __ATOMIC_RELEASE);

    /* Submit and wait */
    syscall(__NR_io_uring_enter, ctx->ring_fd, 1, 1,
            IORING_ENTER_GETEVENTS, NULL, 0);

    /* Get result */
    unsigned head = *ctx->cq_head;
    ssize_t result = -EIO;
    if (head != *ctx->cq_tail) {
        struct io_uring_cqe *cqe = &ctx->cqes[head & *ctx->cq_mask];
        result = cqe->res;
        __atomic_store_n(ctx->cq_head, head + 1, __ATOMIC_RELEASE);
    }

    state->total_writes++;
    return result;
}

/* Mark computation phase (call from ClickHouse code or via signal) */
void io_uring_mark_compute(void)
{
    if (!global_enabled)
        return;

    struct thread_state *state = get_thread_state();
    if (state)
        record_operation(state, OP_COMPUTE);
}

/* Get statistics */
void io_uring_clickhouse_stats(uint64_t *reads, uint64_t *writes,
                                uint64_t *sends, uint64_t *batched,
                                uint64_t *seq_hits)
{
    struct thread_state *state = tls_state;
    if (!state) {
        *reads = *writes = *sends = *batched = *seq_hits = 0;
        return;
    }

    *reads = state->total_reads;
    *writes = state->total_writes;
    *sends = state->total_sends;
    *batched = state->batched_ops;
    *seq_hits = state->sequence_hits;
}

/* Print stats helper */
void print_io_uring_clickhouse_stats(void)
{
    uint64_t reads, writes, sends, batched, seq_hits;
    io_uring_clickhouse_stats(&reads, &writes, &sends, &batched, &seq_hits);

    fprintf(stderr, "[io_uring_clickhouse] Statistics:\n");
    fprintf(stderr, "  Reads:          %lu\n", reads);
    fprintf(stderr, "  Writes:         %lu\n", writes);
    fprintf(stderr, "  Sends:          %lu\n", sends);
    fprintf(stderr, "  Batched ops:    %lu\n", batched);
    fprintf(stderr, "  Sequence hits:  %lu\n", seq_hits);
}
