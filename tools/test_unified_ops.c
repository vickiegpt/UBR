/*
 * Test program for io_uring unified operations
 *
 * Compile with:
 *   gcc -o test_unified_ops test_unified_ops.c
 *
 * Run with:
 *   IO_URING_UNIFIED_ENABLED=1 LD_PRELOAD=./libio_uring_unified.so ./test_unified_ops
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <time.h>
#include <linux/io_uring.h>

#ifdef UBR_ENABLE_SCHED_HINTS
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
#endif /* UBR_ENABLE_SCHED_HINTS */


/* External function from preload library (weak symbols for LD_PRELOAD) */
extern __attribute__((weak)) ssize_t io_uring_calculate(uint64_t *data, size_t count);
extern __attribute__((weak)) void print_unified_stats(void);

/* Process A: Read operation */
void process_a_read(void)
{
	int fd;
	char buffer[1024];
	ssize_t ret;

	printf("[Process A] Performing READ operation\n");

	/* Create a test file */
	fd = open("/tmp/test_unified_read.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
	if (fd < 0) {
		perror("open");
		return;
	}

	/* Write some test data */
	const char *test_data = "Hello from io_uring unified operations!";
	write(fd, test_data, strlen(test_data));
	lseek(fd, 0, SEEK_SET);

	/* Read using intercepted read() - will use io_uring */
	ret = read(fd, buffer, sizeof(buffer));
	if (ret < 0) {
		perror("read");
	} else {
		buffer[ret] = '\0';
		printf("[Process A] Read %zd bytes: '%s'\n", ret, buffer);
	}

	close(fd);
	unlink("/tmp/test_unified_read.txt");
}

/* Process B: Send operation */
void process_b_send(void)
{
	int sock;
	struct sockaddr_in addr;
	const char *message = "Test message from io_uring";
	ssize_t ret;

	printf("[Process B] Performing SEND operation\n");

	/* Create a UDP socket */
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		perror("socket");
		return;
	}

	/* Setup address */
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(12345);
	inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

	/* Connect to avoid sendto */
	if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		printf("[Process B] Connect failed (expected if no server), trying send anyway\n");
	}

	/* Send using intercepted send() - will use io_uring */
	ret = send(sock, message, strlen(message), 0);
	if (ret < 0) {
		/* This may fail if no server is listening, but that's OK for testing */
		printf("[Process B] Send returned %zd (may fail without server, but io_uring was used)\n", ret);
	} else {
		printf("[Process B] Sent %zd bytes\n", ret);
	}

	close(sock);
}

/* Process C: Calculate operation */
void process_c_calculate(void)
{
	uint64_t data[10];
	int i;
	ssize_t ret;

	printf("[Process C] Performing CALCULATE operation\n");

	/* Initialize test data */
	for (i = 0; i < 10; i++) {
		data[i] = i + 1;
	}

	printf("[Process C] Input data: ");
	for (i = 0; i < 10; i++) {
		printf("%lu ", data[i]);
	}
	printf("\n");

	/* Calculate sum using io_uring */
	if (!io_uring_calculate) {
		printf("[Process C] io_uring_calculate not available (no preload)\n");
		return;
	}
	ret = io_uring_calculate(data, 10);
	if (ret < 0) {
		perror("io_uring_calculate");
	} else {
		printf("[Process C] Calculation result (sum): %lu\n", data[0]);
		printf("[Process C] Expected: 55\n");
	}
}

/* Process D: Scheduler hints test */
#ifdef UBR_ENABLE_SCHED_HINTS
void process_d_sched_hints(void)
{
	struct io_uring_sched_hints hints;
	int ret;

	printf("[Process D] Testing scheduler hints syscall\n");

	/* Set scheduler hints for NVMe-XDP pipeline */
	memset(&hints, 0, sizeof(hints));
	hints.read_freq_ns = 100000;   /* 100us read interval */
	hints.send_freq_ns = 50000;    /* 50us send interval */
	hints.batch_size = 64;
	hints.flags = IO_URING_SCHED_HINT_NVME_XDP | IO_URING_SCHED_HINT_LATENCY;

	ret = syscall(__NR_io_uring_sched_hints, 0, &hints, 0);
	if (ret < 0) {
		printf("[Process D] Set hints failed: %s (expected on older kernels)\n",
		       strerror(errno));
		return;
	}
	printf("[Process D] Set scheduler hints: read_freq=%lu ns, send_freq=%lu ns, batch=%u\n",
	       hints.read_freq_ns, hints.send_freq_ns, hints.batch_size);

	/* Simulate some read operations */
	for (int i = 0; i < 5; i++) {
		ret = syscall(__NR_io_uring_sched_hints, 2, NULL, 0);  /* record read */
		if (ret < 0 && i == 0) {
			printf("[Process D] Record op failed: %s\n", strerror(errno));
		}
		usleep(100);  /* 100us delay */
	}

	/* Simulate some send operations */
	for (int i = 0; i < 5; i++) {
		ret = syscall(__NR_io_uring_sched_hints, 2, NULL, 1);  /* record send */
		usleep(50);   /* 50us delay */
	}

	/* Get updated hints */
	memset(&hints, 0, sizeof(hints));
	ret = syscall(__NR_io_uring_sched_hints, 1, &hints, 0);
	if (ret < 0) {
		printf("[Process D] Get hints failed: %s\n", strerror(errno));
		return;
	}

	printf("[Process D] Retrieved hints: read_freq=%lu ns, send_freq=%lu ns\n",
	       hints.read_freq_ns, hints.send_freq_ns);
	printf("[Process D] Scheduler hints test completed\n");
}
#endif /* UBR_ENABLE_SCHED_HINTS */

/* Process E: NVMe-XDP pipeline simulation */
#ifdef UBR_ENABLE_SCHED_HINTS
void process_e_nvme_xdp_pipeline(void)
{
	struct io_uring_sched_hints hints;
	int fd;
	char buffer[4096];
	struct timespec start, end;
	uint64_t total_ns = 0;
	int iterations = 10;
	int ret;

	printf("[Process E] Simulating NVMe-XDP pipeline\n");

	/* Set pipeline-optimized scheduler hints */
	memset(&hints, 0, sizeof(hints));
	hints.read_freq_ns = 10000;    /* 10us target */
	hints.send_freq_ns = 10000;    /* 10us target */
	hints.batch_size = iterations;
	hints.flags = IO_URING_SCHED_HINT_NVME_XDP |
	              IO_URING_SCHED_HINT_LATENCY |
	              IO_URING_SCHED_HINT_REALTIME;

	ret = syscall(__NR_io_uring_sched_hints, 0, &hints, 0);
	if (ret < 0) {
		printf("[Process E] Could not set scheduler hints: %s\n", strerror(errno));
		/* Continue anyway for testing */
	}

	/* Create test file simulating NVMe read */
	fd = open("/tmp/test_nvme_sim.dat", O_CREAT | O_RDWR | O_TRUNC, 0644);
	if (fd < 0) {
		perror("open");
		return;
	}

	/* Write test pattern */
	memset(buffer, 0xAB, sizeof(buffer));
	write(fd, buffer, sizeof(buffer));
	lseek(fd, 0, SEEK_SET);

	printf("[Process E] Running %d iterations of read-compute-send pipeline\n", iterations);

	clock_gettime(CLOCK_MONOTONIC, &start);

	for (int i = 0; i < iterations; i++) {
		/* Simulate NVMe read */
		lseek(fd, 0, SEEK_SET);
		ret = read(fd, buffer, sizeof(buffer));
		if (ret < 0) {
			perror("read");
			break;
		}

		/* Record read operation */
		syscall(__NR_io_uring_sched_hints, 2, NULL, 0);

		/* Simulate computation (XOR transform) */
		uint64_t *ptr = (uint64_t *)buffer;
		for (int j = 0; j < sizeof(buffer) / sizeof(uint64_t); j++) {
			ptr[j] ^= 0xDEADBEEFCAFEBABEULL;
		}

		/* Simulate network send (just record it) */
		syscall(__NR_io_uring_sched_hints, 2, NULL, 1);
	}

	clock_gettime(CLOCK_MONOTONIC, &end);

	total_ns = (end.tv_sec - start.tv_sec) * 1000000000ULL +
	           (end.tv_nsec - start.tv_nsec);

	printf("[Process E] Pipeline completed: %d iterations in %lu ns\n",
	       iterations, total_ns);
	printf("[Process E] Average latency: %lu ns per iteration\n",
	       total_ns / iterations);

	/* Get final scheduler statistics */
	memset(&hints, 0, sizeof(hints));
	ret = syscall(__NR_io_uring_sched_hints, 1, &hints, 0);
	if (ret == 0) {
		printf("[Process E] Final measured frequencies:\n");
		printf("           - Read: %lu ns\n", hints.read_freq_ns);
		printf("           - Send: %lu ns\n", hints.send_freq_ns);
	}

	close(fd);
	unlink("/tmp/test_nvme_sim.dat");
}
#endif /* UBR_ENABLE_SCHED_HINTS */

int main(int argc, char *argv[])
{
	printf("=== IO_URING Unified Operations Test ===\n\n");

	/* Check if io_uring is enabled */
	if (!getenv("IO_URING_UNIFIED_ENABLED")) {
		printf("WARNING: IO_URING_UNIFIED_ENABLED not set!\n");
		printf("Run with: IO_URING_UNIFIED_ENABLED=1 LD_PRELOAD=./libio_uring_unified.so %s\n\n",
		       argv[0]);
	}

	/* Simulate three processes doing different operations */
	printf("--- Simulating Process A (READ) ---\n");
	process_a_read();
	printf("\n");

	printf("--- Simulating Process B (SEND) ---\n");
	process_b_send();
	printf("\n");

	printf("--- Simulating Process C (CALCULATE) ---\n");
	process_c_calculate();
	printf("\n");

#ifdef UBR_ENABLE_SCHED_HINTS
	printf("--- Simulating Process D (SCHEDULER HINTS) ---\n");
	process_d_sched_hints();
#endif
	printf("\n");

#ifdef UBR_ENABLE_SCHED_HINTS
	printf("--- Simulating Process E (NVMe-XDP PIPELINE) ---\n");
	process_e_nvme_xdp_pipeline();
#endif
	printf("\n");

	/* Print statistics from shared memory */
	if (print_unified_stats) print_unified_stats();

	printf("=== All tests completed! ===\n");
	return 0;
}
