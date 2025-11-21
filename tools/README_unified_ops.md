# IO_URING Unified Operations

This implementation provides a unified io_uring-based syscall interception mechanism that allows multiple processes to perform READ, SEND, and CALCULATE operations through a single io_uring opcode with shared memory statistics.

## Architecture

### Kernel-Side Components

1. **New io_uring opcode: `IORING_OP_UNIFIED_OPS`** (io_uring/unified_ops.c)
   - Opcode value: 48 (comes after IORING_OP_PIPE)
   - Supports three sub-operations via the `len` field:
     - `IO_UNIFIED_OP_READ (0)`: File read operation
     - `IO_UNIFIED_OP_SEND (1)`: Socket send operation
     - `IO_UNIFIED_OP_CALC (2)`: Array calculation (sum)

2. **Shared Memory Structure** (include/uapi/linux/io_uring.h)
   ```c
   struct io_uring_unified_shared {
       uint64_t read_count;    /* Number of read operations */
       uint64_t send_count;    /* Number of send operations */
       uint64_t calc_count;    /* Number of calculate operations */
       uint64_t read_bytes;    /* Total bytes read */
       uint64_t send_bytes;    /* Total bytes sent */
       uint64_t calc_result;   /* Last calculation result */
       uint32_t read_errors;   /* Read operation errors */
       uint32_t send_errors;   /* Send operation errors */
       uint32_t calc_errors;   /* Calculate operation errors */
       uint32_t lock;          /* Spinlock for synchronization */
       uint64_t timestamp;     /* Last operation timestamp */
   };
   ```

3. **SQE Field Mapping**
   - `sqe->opcode`: `IORING_OP_UNIFIED_OPS`
   - `sqe->fd`: File descriptor (for READ/SEND operations)
   - `sqe->addr`: Buffer address (userspace)
   - `sqe->addr2`: Shared memory address (userspace)
   - `sqe->len`: Sub-opcode (READ=0, SEND=1, CALC=2)
   - `sqe->rw_flags`: Buffer length
   - `sqe->off`: Offset (for READ) or flags (for SEND)

### User-Space Components

1. **LD_PRELOAD Library** (tools/io_uring_unified_preload.c)
   - Intercepts `read()` and `send()` syscalls
   - Provides custom `io_uring_calculate()` function
   - Manages io_uring ring and shared memory
   - Thread-safe initialization

2. **Test Program** (tools/test_unified_ops.c)
   - Demonstrates all three operations
   - Shows shared memory statistics
   - Simulates three processes (a, b, c)

## Building

### 1. Build the Kernel

```bash
cd /root/tdx
make -j$(nproc)
make modules_install
make install
# Reboot into the new kernel
```

### 2. Build User-Space Components

```bash
cd /root/tdx/tools
make -f Makefile.unified_ops
```

This creates:
- `libio_uring_unified.so`: LD_PRELOAD library
- `test_unified_ops`: Test program

## Usage

### Basic Usage

```bash
# Enable io_uring interception and run program
IO_URING_UNIFIED_ENABLED=1 \
LD_PRELOAD=./libio_uring_unified.so \
./test_unified_ops
```

### Environment Variables

- `IO_URING_UNIFIED_ENABLED=1`: Enable io_uring interception (default: disabled)
- `IO_URING_UNIFIED_SHM=/custom/path`: Custom shared memory path (default: /io_uring_unified_shm)

### Multi-Process Example

```bash
# Process A (read operations)
IO_URING_UNIFIED_ENABLED=1 \
LD_PRELOAD=./libio_uring_unified.so \
./process_a &

# Process B (send operations)
IO_URING_UNIFIED_ENABLED=1 \
LD_PRELOAD=./libio_uring_unified.so \
./process_b &

# Process C (calculate operations)
IO_URING_UNIFIED_ENABLED=1 \
LD_PRELOAD=./libio_uring_unified.so \
./process_c &

wait
```

All three processes will share the same statistics in shared memory.

## API

### Intercepted Functions

```c
/* Automatically intercepted when LD_PRELOAD is loaded */
ssize_t read(int fd, void *buf, size_t count);
ssize_t send(int sockfd, const void *buf, size_t len, int flags);
```

### New Functions

```c
/* Calculate sum of array using io_uring */
ssize_t io_uring_calculate(uint64_t *data, size_t count);

/* Print shared memory statistics */
void print_unified_stats(void);
```

## Example Code

### Process A: Read Operation

```c
#include <fcntl.h>
#include <unistd.h>

int main() {
    int fd = open("/tmp/data.txt", O_RDONLY);
    char buffer[1024];

    // This read() will be intercepted and use io_uring
    ssize_t n = read(fd, buffer, sizeof(buffer));

    close(fd);
    return 0;
}
```

### Process B: Send Operation

```c
#include <sys/socket.h>

int main() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    // ... connect to server ...

    const char *msg = "Hello";
    // This send() will be intercepted and use io_uring
    ssize_t n = send(sock, msg, 5, 0);

    close(sock);
    return 0;
}
```

### Process C: Calculate Operation

```c
#include <stdint.h>

extern ssize_t io_uring_calculate(uint64_t *data, size_t count);

int main() {
    uint64_t numbers[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};

    // Calculate sum using io_uring
    io_uring_calculate(numbers, 10);

    // Result is in numbers[0] (should be 55)
    printf("Sum: %lu\n", numbers[0]);
    return 0;
}
```

## Kernel Implementation Details

### Operation Flow

1. **User space** calls `read()`, `send()`, or `io_uring_calculate()`
2. **LD_PRELOAD library** intercepts the call
3. **Library** creates an io_uring SQE with opcode `IORING_OP_UNIFIED_OPS`
4. **Library** sets sub-opcode in `sqe->len` field
5. **Library** submits SQE and waits for completion
6. **Kernel** receives SQE in `io_unified_ops_prep()`
7. **Kernel** validates parameters and stores operation info
8. **Kernel** executes operation in `io_unified_ops_issue()`:
   - `IO_UNIFIED_OP_READ`: Calls file's `read_iter()`
   - `IO_UNIFIED_OP_SEND`: Calls `sock_sendmsg()`
   - `IO_UNIFIED_OP_CALC`: Sums array in kernel space
9. **Kernel** updates shared memory statistics atomically
10. **Kernel** returns result in CQE
11. **Library** receives CQE and returns result to application

### Synchronization

- Shared memory access is protected by atomic operations
- `io_unified_lock()/io_unified_unlock()` use atomic spinlock
- Multiple processes can safely update statistics concurrently

## Testing

```bash
# Run the built-in test
cd /root/tdx/tools
make -f Makefile.unified_ops test
```

Expected output:
```
=== IO_URING Unified Operations Test ===

--- Simulating Process A (READ) ---
[Process A] Performing READ operation
[Process A] Read 40 bytes: 'Hello from io_uring unified operations!'

--- Simulating Process B (SEND) ---
[Process B] Performing SEND operation
[Process B] Sent 26 bytes

--- Simulating Process C (CALCULATE) ---
[Process C] Performing CALCULATE operation
[Process C] Input data: 1 2 3 4 5 6 7 8 9 10
[Process C] Calculation result (sum): 55
[Process C] Expected: 55

=== IO_URING Unified Operations Statistics ===
Read operations:  1 (bytes: 40, errors: 0)
Send operations:  1 (bytes: 26, errors: 0)
Calc operations:  1 (result: 55, errors: 0)
Last timestamp:   1234567890 ns
==============================================

Test completed!
```

## File Structure

```
/root/tdx/
├── include/uapi/linux/io_uring.h           # Opcode and structure definitions
├── io_uring/
│   ├── unified_ops.c                       # Kernel implementation
│   ├── unified_ops.h                       # Kernel header
│   └── opdef.c                             # Opcode registration
└── tools/
    ├── io_uring_unified_preload.c          # LD_PRELOAD library
    ├── test_unified_ops.c                  # Test program
    ├── Makefile.unified_ops                # Build system
    └── README_unified_ops.md               # This file
```

## Debugging

### Enable Debug Output

Set these in the LD_PRELOAD library to see debug messages:

```bash
# Library will print initialization messages to stderr
IO_URING_UNIFIED_ENABLED=1 \
LD_PRELOAD=./libio_uring_unified.so \
./your_program 2>&1 | tee debug.log
```

### Kernel Debugging

Add `printk()` statements in `io_uring/unified_ops.c`:

```c
int io_unified_ops_issue(struct io_kiocb *req, unsigned int issue_flags)
{
    printk(KERN_INFO "io_uring: unified op=%u\n", op->opcode);
    // ...
}
```

Then check kernel logs:
```bash
dmesg | grep io_uring
```

## Performance Considerations

1. **Shared Memory Lock**: Uses atomic spinlock, minimal contention
2. **io_uring Submission**: Batching multiple operations recommended
3. **Fallback Mode**: Set `IO_URING_UNIFIED_ENABLED=0` to use regular syscalls
4. **Ring Size**: Default 256 entries, adjustable in `init_uring_unified()`

## Limitations

1. **CALCULATE operation**: Currently only supports sum, can be extended
2. **File descriptor required**: READ/SEND need valid fd
3. **Shared memory**: Limited to single machine (not distributed)
4. **Thread safety**: LD_PRELOAD library is thread-safe via mutexes

## Future Enhancements

- [ ] Support more calculation operations (multiply, min, max, etc.)
- [ ] Add WRITE and RECV operations
- [ ] Batch mode for multiple operations
- [ ] Per-process statistics in addition to global
- [ ] Configurable ring size via environment variable
- [ ] Support for registered buffers (zero-copy)

## License

This code is licensed under GPL-2.0 (kernel components) and can be used freely for the user-space components.
