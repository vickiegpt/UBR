// SPDX-License-Identifier: GPL-2.0
/*
 * io_uring scheduler hints syscall
 *
 * Provides a mechanism for userspace to communicate expected I/O patterns
 * to the kernel scheduler for better scheduling decisions.
 */

#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/sched.h>
#include <linux/io_uring_types.h>
#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "tctx.h"

/**
 * io_uring_update_sched_hints - Update scheduler hints for current task
 * @hints: User-provided scheduling hints
 *
 * Updates the io_uring_task scheduler hints that can be used by the
 * scheduler to make better decisions about task placement and priority.
 */
static int io_uring_update_sched_hints(struct io_uring_sched_hints __user *uhints)
{
	struct io_uring_task *tctx = current->io_uring;
	struct io_uring_sched_hints hints;

	if (!tctx)
		return -EINVAL;

	if (copy_from_user(&hints, uhints, sizeof(hints)))
		return -EFAULT;

	/* Validate flags */
	if (hints.flags & ~(IO_URING_SCHED_HINT_LATENCY |
			    IO_URING_SCHED_HINT_THROUGHPUT |
			    IO_URING_SCHED_HINT_REALTIME |
			    IO_URING_SCHED_HINT_NVME_XDP))
		return -EINVAL;

	/* Update the task's scheduler hints */
	tctx->sched_hints.read_freq_ns = hints.read_freq_ns;
	tctx->sched_hints.send_freq_ns = hints.send_freq_ns;
	tctx->sched_hints.batch_size = hints.batch_size;
	tctx->sched_hints.flags = hints.flags;

	return 0;
}

/**
 * io_uring_get_sched_hints - Get current scheduler hints
 * @hints: Buffer to store current hints
 *
 * Retrieves the current scheduler hints for the calling task.
 */
static int io_uring_get_sched_hints(struct io_uring_sched_hints __user *uhints)
{
	struct io_uring_task *tctx = current->io_uring;
	struct io_uring_sched_hints hints;

	if (!tctx)
		return -EINVAL;

	memset(&hints, 0, sizeof(hints));
	hints.read_freq_ns = tctx->sched_hints.read_freq_ns;
	hints.send_freq_ns = tctx->sched_hints.send_freq_ns;
	hints.batch_size = tctx->sched_hints.batch_size;
	hints.flags = tctx->sched_hints.flags;

	if (copy_to_user(uhints, &hints, sizeof(hints)))
		return -EFAULT;

	return 0;
}

/**
 * io_uring_record_op - Record an I/O operation for scheduling statistics
 * @op_type: Type of operation (0 = read, 1 = send)
 * @bytes: Number of bytes transferred
 *
 * Updates the operation counters and timestamps used by the scheduler.
 */
void io_uring_record_op(struct io_uring_task *tctx, int op_type, u64 bytes)
{
	u64 now = ktime_get_ns();

	if (!tctx)
		return;

	if (op_type == 0) {
		/* Read operation */
		if (tctx->sched_hints.last_read_ts) {
			u64 interval = now - tctx->sched_hints.last_read_ts;
			/* Exponential moving average */
			tctx->sched_hints.read_freq_ns =
				(tctx->sched_hints.read_freq_ns * 7 + interval) / 8;
		}
		tctx->sched_hints.last_read_ts = now;
		tctx->sched_hints.read_count++;
	} else {
		/* Send operation */
		if (tctx->sched_hints.last_send_ts) {
			u64 interval = now - tctx->sched_hints.last_send_ts;
			tctx->sched_hints.send_freq_ns =
				(tctx->sched_hints.send_freq_ns * 7 + interval) / 8;
		}
		tctx->sched_hints.last_send_ts = now;
		tctx->sched_hints.send_count++;
	}
}
EXPORT_SYMBOL_GPL(io_uring_record_op);

/**
 * sys_io_uring_sched_hints - Syscall to manage io_uring scheduler hints
 * @op: Operation (0 = set, 1 = get, 2 = record)
 * @hints: Pointer to hints structure (for set/get)
 * @arg: Additional argument (op_type for record, bytes for record)
 *
 * This syscall allows userspace to:
 * - Set expected I/O frequencies to help scheduler
 * - Get current statistics
 * - Record I/O operations for automatic frequency tracking
 */
SYSCALL_DEFINE3(io_uring_sched_hints, unsigned int, op,
		struct io_uring_sched_hints __user *, hints,
		unsigned long, arg)
{
	switch (op) {
	case 0: /* Set hints */
		return io_uring_update_sched_hints(hints);
	case 1: /* Get hints */
		return io_uring_get_sched_hints(hints);
	case 2: /* Record operation */
		io_uring_record_op(current->io_uring, (int)arg, 0);
		return 0;
	default:
		return -EINVAL;
	}
}
