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
#include <netinet/in.h>
#include <arpa/inet.h>

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
	ret = io_uring_calculate(data, 10);
	if (ret < 0) {
		perror("io_uring_calculate");
	} else {
		printf("[Process C] Calculation result (sum): %lu\n", data[0]);
		printf("[Process C] Expected: 55\n");
	}
}

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

	/* Print statistics from shared memory */
	print_unified_stats();

	printf("Test completed!\n");
	return 0;
}
