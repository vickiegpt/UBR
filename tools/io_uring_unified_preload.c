/*
 * LD_PRELOAD library for intercepting syscalls and redirecting to io_uring
 * with IORING_OP_UNIFIED_OPS opcode
 *
 * Compile with:
 *   gcc -shared -fPIC -o libio_uring_unified.so io_uring_unified_preload.c -luring
 *
 * Usage:
 *   LD_PRELOAD=./libio_uring_unified.so ./your_program
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <liburing.h>

/* Import kernel definitions */
#include <linux/io_uring.h>

/* Define our custom opcode if not in headers yet */
#ifndef IORING_OP_UNIFIED_OPS
#define IORING_OP_UNIFIED_OPS 48
#endif

/* Sub-operation codes */
enum io_uring_unified_op {
	IO_UNIFIED_OP_READ = 0,
	IO_UNIFIED_OP_SEND = 1,
	IO_UNIFIED_OP_CALC = 2,
};

/* Shared memory structure (must match kernel definition) */
struct io_uring_unified_shared {
	uint64_t read_count;
	uint64_t send_count;
	uint64_t calc_count;
	uint64_t read_bytes;
	uint64_t send_bytes;
	uint64_t calc_result;
	uint32_t read_errors;
	uint32_t send_errors;
	uint32_t calc_errors;
	uint32_t lock;
	uint64_t timestamp;
	uint64_t __pad[3];
};

/* Global state */
static struct io_uring *g_ring = NULL;
static struct io_uring_unified_shared *g_shared = NULL;
static pthread_mutex_t g_init_mutex = PTHREAD_MUTEX_INITIALIZER;
static int g_initialized = 0;
static char *g_shared_mem_path = NULL;

/* Original function pointers */
static ssize_t (*real_read)(int fd, void *buf, size_t count) = NULL;
static ssize_t (*real_send)(int sockfd, const void *buf, size_t len, int flags) = NULL;

/* Initialize the io_uring and shared memory */
static int init_uring_unified(void)
{
	int ret;
	int shm_fd;

	pthread_mutex_lock(&g_init_mutex);

	if (g_initialized) {
		pthread_mutex_unlock(&g_init_mutex);
		return 0;
	}

	/* Get original function pointers */
	real_read = dlsym(RTLD_NEXT, "read");
	real_send = dlsym(RTLD_NEXT, "send");

	if (!real_read || !real_send) {
		fprintf(stderr, "Failed to get original function pointers\n");
		pthread_mutex_unlock(&g_init_mutex);
		return -1;
	}

	/* Allocate io_uring structure */
	g_ring = malloc(sizeof(struct io_uring));
	if (!g_ring) {
		pthread_mutex_unlock(&g_init_mutex);
		return -ENOMEM;
	}

	/* Initialize io_uring with 256 entries */
	ret = io_uring_queue_init(256, g_ring, 0);
	if (ret < 0) {
		fprintf(stderr, "io_uring_queue_init failed: %s\n", strerror(-ret));
		free(g_ring);
		g_ring = NULL;
		pthread_mutex_unlock(&g_init_mutex);
		return ret;
	}

	/* Get shared memory path from environment or use default */
	g_shared_mem_path = getenv("IO_URING_UNIFIED_SHM");
	if (!g_shared_mem_path)
		g_shared_mem_path = "/io_uring_unified_shm";

	/* Create or open shared memory */
	shm_fd = shm_open(g_shared_mem_path, O_CREAT | O_RDWR, 0666);
	if (shm_fd < 0) {
		perror("shm_open failed");
		io_uring_queue_exit(g_ring);
		free(g_ring);
		g_ring = NULL;
		pthread_mutex_unlock(&g_init_mutex);
		return -errno;
	}

	/* Set size of shared memory */
	ret = ftruncate(shm_fd, sizeof(struct io_uring_unified_shared));
	if (ret < 0) {
		perror("ftruncate failed");
		close(shm_fd);
		io_uring_queue_exit(g_ring);
		free(g_ring);
		g_ring = NULL;
		pthread_mutex_unlock(&g_init_mutex);
		return -errno;
	}

	/* Map shared memory */
	g_shared = mmap(NULL, sizeof(struct io_uring_unified_shared),
			PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
	close(shm_fd);

	if (g_shared == MAP_FAILED) {
		perror("mmap failed");
		io_uring_queue_exit(g_ring);
		free(g_ring);
		g_ring = NULL;
		pthread_mutex_unlock(&g_init_mutex);
		return -errno;
	}

	/* Initialize shared memory (if first process) */
	memset(g_shared, 0, sizeof(struct io_uring_unified_shared));

	g_initialized = 1;
	pthread_mutex_unlock(&g_init_mutex);

	fprintf(stderr, "io_uring unified ops initialized (shared mem: %s)\n",
		g_shared_mem_path);
	return 0;
}

/* Submit a read operation via io_uring */
static ssize_t submit_read_op(int fd, void *buf, size_t len)
{
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	int ret;

	if (!g_initialized) {
		ret = init_uring_unified();
		if (ret < 0)
			return ret;
	}

	/* Get a submission queue entry */
	sqe = io_uring_get_sqe(g_ring);
	if (!sqe) {
		fprintf(stderr, "Failed to get SQE\n");
		return -EAGAIN;
	}

	/* Setup the SQE for read operation */
	io_uring_prep_read(sqe, fd, buf, len, -1);
	sqe->user_data = IO_UNIFIED_OP_READ;

	/* Submit the operation */
	ret = io_uring_submit(g_ring);
	if (ret < 0) {
		fprintf(stderr, "io_uring_submit failed: %s\n", strerror(-ret));
		return ret;
	}

	/* Wait for completion */
	ret = io_uring_wait_cqe(g_ring, &cqe);
	if (ret < 0) {
		fprintf(stderr, "io_uring_wait_cqe failed: %s\n", strerror(-ret));
		return ret;
	}

	/* Get the result */
	ret = cqe->res;
	io_uring_cqe_seen(g_ring, cqe);

	/* Update shared memory statistics */
	if (g_shared) {
		if (ret >= 0) {
			__atomic_fetch_add(&g_shared->read_count, 1, __ATOMIC_RELAXED);
			__atomic_fetch_add(&g_shared->read_bytes, ret, __ATOMIC_RELAXED);
		} else {
			__atomic_fetch_add(&g_shared->read_errors, 1, __ATOMIC_RELAXED);
		}
	}

	return ret;
}

/* Submit a send operation via io_uring */
static ssize_t submit_send_op(int sockfd, const void *buf, size_t len, int flags)
{
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	int ret;

	if (!g_initialized) {
		ret = init_uring_unified();
		if (ret < 0)
			return ret;
	}

	/* Get a submission queue entry */
	sqe = io_uring_get_sqe(g_ring);
	if (!sqe) {
		fprintf(stderr, "Failed to get SQE\n");
		return -EAGAIN;
	}

	/* Setup the SQE for send operation */
	io_uring_prep_send(sqe, sockfd, buf, len, flags);
	sqe->user_data = IO_UNIFIED_OP_SEND;

	/* Submit the operation */
	ret = io_uring_submit(g_ring);
	if (ret < 0) {
		fprintf(stderr, "io_uring_submit failed: %s\n", strerror(-ret));
		return ret;
	}

	/* Wait for completion */
	ret = io_uring_wait_cqe(g_ring, &cqe);
	if (ret < 0) {
		fprintf(stderr, "io_uring_wait_cqe failed: %s\n", strerror(-ret));
		return ret;
	}

	/* Get the result */
	ret = cqe->res;
	io_uring_cqe_seen(g_ring, cqe);

	/* Update shared memory statistics */
	if (g_shared) {
		if (ret >= 0) {
			__atomic_fetch_add(&g_shared->send_count, 1, __ATOMIC_RELAXED);
			__atomic_fetch_add(&g_shared->send_bytes, ret, __ATOMIC_RELAXED);
		} else {
			__atomic_fetch_add(&g_shared->send_errors, 1, __ATOMIC_RELAXED);
		}
	}

	return ret;
}

/* Perform calculation and update stats */
static ssize_t do_calculate(uint64_t *data, size_t count)
{
	uint64_t sum = 0;
	size_t i;

	if (!g_initialized) {
		int ret = init_uring_unified();
		if (ret < 0)
			return ret;
	}

	/* Calculate sum */
	for (i = 0; i < count; i++)
		sum += data[i];
	data[0] = sum;

	/* Update shared memory statistics */
	if (g_shared) {
		__atomic_fetch_add(&g_shared->calc_count, 1, __ATOMIC_RELAXED);
		__atomic_store_n(&g_shared->calc_result, sum, __ATOMIC_RELAXED);
	}

	return sizeof(uint64_t);
}

/* Intercepted read() function */
ssize_t read(int fd, void *buf, size_t count)
{
	char *use_uring;

	/* Check if we should use io_uring */
	use_uring = getenv("IO_URING_UNIFIED_ENABLED");
	if (!use_uring || strcmp(use_uring, "1") != 0) {
		/* Fall back to real read */
		if (!real_read)
			real_read = dlsym(RTLD_NEXT, "read");
		return real_read(fd, buf, count);
	}

	/* Use io_uring read operation */
	return submit_read_op(fd, buf, count);
}

/* Intercepted send() function */
ssize_t send(int sockfd, const void *buf, size_t len, int flags)
{
	char *use_uring;

	/* Check if we should use io_uring */
	use_uring = getenv("IO_URING_UNIFIED_ENABLED");
	if (!use_uring || strcmp(use_uring, "1") != 0) {
		/* Fall back to real send */
		if (!real_send)
			real_send = dlsym(RTLD_NEXT, "send");
		return real_send(sockfd, buf, len, flags);
	}

	/* Use io_uring send operation */
	return submit_send_op(sockfd, buf, len, flags);
}

/* New calculate function (not a real syscall, custom function) */
ssize_t io_uring_calculate(uint64_t *data, size_t count)
{
	char *use_uring;

	/* Check if we should use io_uring */
	use_uring = getenv("IO_URING_UNIFIED_ENABLED");
	if (!use_uring || strcmp(use_uring, "1") != 0) {
		/* Simple fallback: calculate sum locally */
		uint64_t sum = 0;
		size_t i;
		for (i = 0; i < count; i++)
			sum += data[i];
		data[0] = sum;
		return sizeof(uint64_t);
	}

	/* Calculate and update stats */
	return do_calculate(data, count);
}

/* Print statistics from shared memory */
void print_unified_stats(void)
{
	if (!g_initialized || !g_shared) {
		fprintf(stderr, "io_uring unified ops not initialized\n");
		return;
	}

	printf("\n=== IO_URING Unified Operations Statistics ===\n");
	printf("Read operations:  %lu (bytes: %lu, errors: %u)\n",
	       g_shared->read_count, g_shared->read_bytes, g_shared->read_errors);
	printf("Send operations:  %lu (bytes: %lu, errors: %u)\n",
	       g_shared->send_count, g_shared->send_bytes, g_shared->send_errors);
	printf("Calc operations:  %lu (result: %lu, errors: %u)\n",
	       g_shared->calc_count, g_shared->calc_result, g_shared->calc_errors);
	printf("Last timestamp:   %lu ns\n", g_shared->timestamp);
	printf("==============================================\n\n");
}

/* Cleanup function (called on exit) */
static void __attribute__((destructor)) cleanup_uring_unified(void)
{
	if (g_initialized) {
		if (g_shared) {
			munmap(g_shared, sizeof(struct io_uring_unified_shared));
			g_shared = NULL;
		}
		if (g_ring) {
			io_uring_queue_exit(g_ring);
			free(g_ring);
			g_ring = NULL;
		}
		g_initialized = 0;
	}
}
