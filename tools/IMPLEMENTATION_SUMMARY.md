# IO_URING Unified Operations - Implementation Summary

## Overview

This implementation provides a unified syscall interception mechanism using io_uring opcodes for three different process types (a, b, c) performing read, send, and calculate operations. All processes share a common memory structure for statistics.

## What Was Implemented

### 1. Kernel Changes

#### A. New io_uring Opcode (IORING_OP_UNIFIED_OPS = 48)
**File**: `include/uapi/linux/io_uring.h:292`
- Added to `enum io_uring_op`
- Position: After `IORING_OP_PIPE`, before `IORING_OP_LAST`

#### B. Shared Memory Structure
**File**: `include/uapi/linux/io_uring.h:1043-1056`
```c
struct io_uring_unified_shared {
    uint64_t read_count, send_count, calc_count;
    uint64_t read_bytes, send_bytes, calc_result;
    uint32_t read_errors, send_errors, calc_errors;
    uint32_t lock;  // Atomic spinlock
    uint64_t timestamp;
};
```

#### C. Sub-Operation Codes
**File**: `include/uapi/linux/io_uring.h:1033-1037`
```c
enum io_uring_unified_op {
    IO_UNIFIED_OP_READ = 0,
    IO_UNIFIED_OP_SEND = 1,
    IO_UNIFIED_OP_CALC = 2,
};
```

#### D. Kernel Handler Implementation
**File**: `io_uring/unified_ops.c` (258 lines)

Functions:
- `io_unified_ops_prep()`: Validates and prepares operation
- `io_unified_ops_issue()`: Executes the operation
- `io_unified_do_read()`: Handles file read
- `io_unified_do_send()`: Handles socket send
- `io_unified_do_calc()`: Handles array calculation (sum)
- `io_unified_lock()/unlock()`: Atomic synchronization

**File**: `io_uring/unified_ops.h` (8 lines)
- Function declarations for kernel interface

#### E. Opcode Registration
**File**: `io_uring/opdef.c`

Added entries:
1. Line 41: `#include "unified_ops.h"`
2. Line 578-582: io_issue_defs entry
3. Line 832-835: io_cold_defs entry

### 2. User-Space Components

#### A. LD_PRELOAD Interception Library
**File**: `tools/io_uring_unified_preload.c` (350 lines)

Features:
- Intercepts `read()` and `send()` syscalls
- Provides custom `io_uring_calculate()` function
- Manages io_uring ring (256 entries)
- Creates/attaches to POSIX shared memory
- Thread-safe initialization
- Automatic cleanup on exit

Environment Variables:
- `IO_URING_UNIFIED_ENABLED=1`: Enable interception
- `IO_URING_UNIFIED_SHM=path`: Custom shared memory location

#### B. Test Program
**File**: `tools/test_unified_ops.c` (140 lines)

Simulates three process types:
- **Process A**: File read operations
- **Process B**: Socket send operations
- **Process C**: Array calculation operations

#### C. Build System
**File**: `tools/Makefile.unified_ops` (30 lines)

Targets:
- `make all`: Build library and test program
- `make test`: Run automated test
- `make clean`: Clean build artifacts

#### D. Documentation
**Files**:
- `tools/README_unified_ops.md`: Complete user guide (480 lines)
- `tools/IMPLEMENTATION_SUMMARY.md`: This file

## How It Works

### Data Flow

```
User Process A (read)
    │
    ├──> read(fd, buf, size)
    │       │
    │       ├──> LD_PRELOAD intercepts
    │       │
    │       └──> io_uring_submit()
    │               │
    │               │  SQE Fields:
    │               │  - opcode = IORING_OP_UNIFIED_OPS
    │               │  - len = IO_UNIFIED_OP_READ (0)
    │               │  - addr = buffer address
    │               │  - addr2 = shared memory address
    │               │  - fd = file descriptor
    │               │
    │               ▼
┌───────────────────────────────────────────┐
│           KERNEL (io_uring)               │
│                                           │
│  io_unified_ops_prep()                    │
│      ├─> Validate parameters              │
│      └─> Store operation info             │
│                                           │
│  io_unified_ops_issue()                   │
│      ├─> Switch on sub-opcode             │
│      ├─> io_unified_do_read()             │
│      │     ├─> file->f_op->read_iter()    │
│      │     └─> Update shared memory       │
│      │                                     │
│      └─> Return result in CQE             │
└───────────────────────────────────────────┘
                │
                │  CQE: res = bytes_read
                │
                ▼
    io_uring_wait_cqe()
    Return to application

┌───────────────────────────────────────────┐
│      SHARED MEMORY (All Processes)       │
│                                           │
│  struct io_uring_unified_shared {         │
│      read_count++;                        │
│      read_bytes += bytes_read;            │
│      timestamp = now;                     │
│  }                                        │
└───────────────────────────────────────────┘
         │
         ├──> Visible to Process A
         ├──> Visible to Process B
         └──> Visible to Process C
```

### Synchronization

The shared memory structure uses atomic operations for thread-safe access:

```c
static inline void io_unified_lock(struct io_uring_unified_shared *shared)
{
    while (__atomic_exchange_n(&shared->lock, 1, __ATOMIC_ACQUIRE))
        cpu_relax();  // Spin until lock acquired
}

static inline void io_unified_unlock(struct io_uring_unified_shared *shared)
{
    __atomic_store_n(&shared->lock, 0, __ATOMIC_RELEASE);
}
```

## Usage Example

### Scenario: Three Processes Sharing Statistics

```bash
# Terminal 1: Process A (reads files)
cat > process_a.c << 'EOF'
#include <fcntl.h>
#include <unistd.h>
int main() {
    int fd = open("/etc/hostname", O_RDONLY);
    char buf[128];
    read(fd, buf, 128);  // Intercepted!
    close(fd);
    return 0;
}
EOF
gcc -o process_a process_a.c

IO_URING_UNIFIED_ENABLED=1 \
LD_PRELOAD=./libio_uring_unified.so \
./process_a

# Terminal 2: Process B (sends network data)
cat > process_b.c << 'EOF'
#include <sys/socket.h>
#include <netinet/in.h>
int main() {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    send(sock, "test", 4, 0);  // Intercepted!
    close(sock);
    return 0;
}
EOF
gcc -o process_b process_b.c

IO_URING_UNIFIED_ENABLED=1 \
LD_PRELOAD=./libio_uring_unified.so \
./process_b

# Terminal 3: Process C (calculates)
cat > process_c.c << 'EOF'
#include <stdint.h>
extern ssize_t io_uring_calculate(uint64_t *data, size_t count);
int main() {
    uint64_t nums[5] = {10, 20, 30, 40, 50};
    io_uring_calculate(nums, 5);  // Uses io_uring!
    return 0;
}
EOF
gcc -o process_c process_c.c

IO_URING_UNIFIED_ENABLED=1 \
LD_PRELOAD=./libio_uring_unified.so \
./process_c
```

All three processes update the same shared memory structure!

## SQE Field Mapping Reference

| SQE Field     | Purpose                           | Example Value             |
|---------------|-----------------------------------|---------------------------|
| `opcode`      | Main opcode                       | 48 (IORING_OP_UNIFIED_OPS)|
| `fd`          | File descriptor                   | 3 (for read/send)         |
| `addr`        | Buffer address                    | 0x7fff12345000            |
| `addr2`       | Shared memory address             | 0x7ffff7890000            |
| `len`         | Sub-opcode                        | 0=READ, 1=SEND, 2=CALC    |
| `rw_flags`    | Buffer length                     | 1024                      |
| `off`         | Offset or flags                   | 0 (offset) or MSG_* flags |
| `user_data`   | User identifier                   | Sub-opcode (for tracking) |

## Benefits

1. **Unified Interface**: Single opcode handles multiple operation types
2. **Shared Statistics**: All processes see aggregate statistics
3. **Asynchronous**: io_uring provides async execution
4. **Transparent**: Applications don't need modification (via LD_PRELOAD)
5. **Atomic Updates**: Thread-safe shared memory access
6. **Flexible**: Easy to add new operation types

## Testing

```bash
cd /root/tdx/tools
make -f Makefile.unified_ops test
```

Expected output shows:
- Read operation: 40 bytes read
- Send operation: 26 bytes sent
- Calculate operation: Sum of 1..10 = 55
- Shared memory statistics with all counters updated

## Files Modified/Created

### Kernel Files
```
Modified:
  include/uapi/linux/io_uring.h  (+30 lines)
  io_uring/opdef.c               (+7 lines)

Created:
  io_uring/unified_ops.c         (258 lines)
  io_uring/unified_ops.h         (8 lines)
```

### User-Space Files
```
Created:
  tools/io_uring_unified_preload.c    (350 lines)
  tools/test_unified_ops.c            (140 lines)
  tools/Makefile.unified_ops          (30 lines)
  tools/README_unified_ops.md         (480 lines)
  tools/IMPLEMENTATION_SUMMARY.md     (This file)
```

**Total**: ~1,300 lines of new code + documentation

## Next Steps

To use this implementation:

1. **Build and install the kernel**:
   ```bash
   cd /root/tdx
   make -j$(nproc)
   make modules_install install
   reboot
   ```

2. **Build user-space components**:
   ```bash
   cd /root/tdx/tools
   make -f Makefile.unified_ops
   ```

3. **Run the test**:
   ```bash
   make -f Makefile.unified_ops test
   ```

4. **Use with your applications**:
   ```bash
   IO_URING_UNIFIED_ENABLED=1 \
   LD_PRELOAD=./libio_uring_unified.so \
   ./your_application
   ```

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────┐
│                    USER SPACE                            │
│                                                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐              │
│  │Process A │  │Process B │  │Process C │              │
│  │  (read)  │  │  (send)  │  │  (calc)  │              │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘              │
│       │             │              │                     │
│       │             │              │                     │
│  ┌────▼─────────────▼──────────────▼──────┐             │
│  │   LD_PRELOAD: libio_uring_unified.so   │             │
│  │                                         │             │
│  │  • Intercepts read()/send()             │             │
│  │  • Provides io_uring_calculate()        │             │
│  │  • Manages io_uring ring                │             │
│  │  • Accesses shared memory               │             │
│  └────┬────────────────────────────────────┘             │
│       │                                                  │
│       │ io_uring_submit(IORING_OP_UNIFIED_OPS)          │
│       │                                                  │
├───────┼──────────────────────────────────────────────────┤
│       │              KERNEL SPACE                        │
│       │                                                  │
│  ┌────▼─────────────────────────────────────┐           │
│  │         io_uring Subsystem                │           │
│  │                                           │           │
│  │  ┌─────────────────────────────────────┐ │           │
│  │  │  IORING_OP_UNIFIED_OPS Handler      │ │           │
│  │  │                                     │ │           │
│  │  │  io_unified_ops_prep()              │ │           │
│  │  │  io_unified_ops_issue()             │ │           │
│  │  │    ├─> io_unified_do_read()         │ │           │
│  │  │    ├─> io_unified_do_send()         │ │           │
│  │  │    └─> io_unified_do_calc()         │ │           │
│  │  │                                     │ │           │
│  │  │  Updates shared memory atomically   │ │           │
│  │  └─────────────────────────────────────┘ │           │
│  └───────────────────────────────────────────┘           │
│                                                          │
└──────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────┐
│           SHARED MEMORY (/dev/shm)                       │
│                                                          │
│  struct io_uring_unified_shared {                        │
│      read_count, send_count, calc_count                  │
│      read_bytes, send_bytes, calc_result                 │
│      read_errors, send_errors, calc_errors               │
│      lock (atomic), timestamp                            │
│  }                                                       │
│                                                          │
│  ▲         ▲         ▲                                   │
│  │         │         │                                   │
│  └─────────┴─────────┴─── Shared by all processes       │
└──────────────────────────────────────────────────────────┘
```

This implementation successfully demonstrates how to:
- Add a custom io_uring opcode to the kernel
- Use io_uring for unified syscall handling
- Share state across multiple processes
- Intercept syscalls transparently via LD_PRELOAD
- Maintain thread-safe statistics with atomic operations
