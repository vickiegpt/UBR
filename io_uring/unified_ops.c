// SPDX-License-Identifier: GPL-2.0
/*
 * Unified operations handler for io_uring
 * Supports READ, SEND, and CALCULATE operations with shared memory
 */
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/namei.h>
#include <linux/io_uring.h>
#include <linux/uio.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/time64.h>
#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "kbuf.h"
#include "rsrc.h"
#include "unified_ops.h"
#include "sched_hints.h"

struct io_unified_ops {
	struct file			*file;
	u64				addr;		/* Buffer address */
	u64				shared_addr;	/* Shared memory address */
	u32				len;		/* Buffer length */
	u32				opcode;		/* Sub-opcode */
	u32				offset;		/* File offset or send flags */
};

/* Helper to update shared memory statistics using get_user/put_user */
static inline void io_unified_update_read_stats(struct io_uring_unified_shared __user *shared,
						ssize_t bytes, bool error)
{
	u64 val64;
	u32 val32;

	if (error) {
		if (!get_user(val32, &shared->read_errors)) {
			val32++;
			put_user(val32, &shared->read_errors);
		}
	} else {
		if (!get_user(val64, &shared->read_count)) {
			val64++;
			put_user(val64, &shared->read_count);
		}
		if (!get_user(val64, &shared->read_bytes)) {
			val64 += bytes;
			put_user(val64, &shared->read_bytes);
		}
	}
	put_user(ktime_get_ns(), &shared->timestamp);
}

static inline void io_unified_update_send_stats(struct io_uring_unified_shared __user *shared,
						ssize_t bytes, bool error)
{
	u64 val64;
	u32 val32;

	if (error) {
		if (!get_user(val32, &shared->send_errors)) {
			val32++;
			put_user(val32, &shared->send_errors);
		}
	} else {
		if (!get_user(val64, &shared->send_count)) {
			val64++;
			put_user(val64, &shared->send_count);
		}
		if (!get_user(val64, &shared->send_bytes)) {
			val64 += bytes;
			put_user(val64, &shared->send_bytes);
		}
	}
	put_user(ktime_get_ns(), &shared->timestamp);
}

static inline void io_unified_update_calc_stats(struct io_uring_unified_shared __user *shared,
						u64 result, bool error)
{
	u64 val64;
	u32 val32;

	if (error) {
		if (!get_user(val32, &shared->calc_errors)) {
			val32++;
			put_user(val32, &shared->calc_errors);
		}
	} else {
		if (!get_user(val64, &shared->calc_count)) {
			val64++;
			put_user(val64, &shared->calc_count);
		}
		put_user(result, &shared->calc_result);
	}
	put_user(ktime_get_ns(), &shared->timestamp);
}

static int io_unified_do_read(struct io_kiocb *req, struct io_unified_ops *op,
			      struct io_uring_unified_shared __user *shared)
{
	ssize_t ret;
	loff_t pos;
	void *buf;

	if (!op->file)
		return -EBADF;

	/* Allocate kernel buffer */
	buf = kmalloc(op->len, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	pos = op->offset;

	/* Perform the read using kernel_read */
	ret = kernel_read(op->file, buf, op->len, &pos);

	/* Copy to userspace if successful */
	if (ret > 0) {
		if (copy_to_user(u64_to_user_ptr(op->addr), buf, ret))
			ret = -EFAULT;
	}

	kfree(buf);

	/* Update shared memory statistics */
	io_unified_update_read_stats(shared, ret, ret < 0);

	return ret;
}

static int io_unified_do_send(struct io_kiocb *req, struct io_unified_ops *op,
			      struct io_uring_unified_shared __user *shared)
{
	struct socket *sock;
	struct msghdr msg;
	struct iovec iov;
	ssize_t ret;

	if (!op->file)
		return -EBADF;

	sock = sock_from_file(op->file);
	if (!sock)
		return -ENOTSOCK;

	/* Setup message */
	memset(&msg, 0, sizeof(msg));
	iov.iov_base = u64_to_user_ptr(op->addr);
	iov.iov_len = op->len;
	iov_iter_init(&msg.msg_iter, ITER_SOURCE, &iov, 1, op->len);
	msg.msg_flags = op->offset; /* Use offset field for flags */

	/* Perform the send */
	ret = sock_sendmsg(sock, &msg);

	/* Update shared memory statistics */
	io_unified_update_send_stats(shared, ret, ret < 0);

	return ret;
}

static int io_unified_do_calc(struct io_kiocb *req, struct io_unified_ops *op,
			      struct io_uring_unified_shared __user *shared)
{
	u64 *data;
	u64 result = 0;
	int ret = 0;
	u32 i, count;

	/* Simple calculation: sum all u64 values in the buffer */
	count = op->len / sizeof(u64);
	if (count == 0)
		return -EINVAL;

	data = kmalloc(op->len, GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	/* Copy data from userspace */
	if (copy_from_user(data, u64_to_user_ptr(op->addr), op->len)) {
		kfree(data);
		return -EFAULT;
	}

	/* Perform calculation */
	for (i = 0; i < count; i++)
		result += data[i];

	/* Write result back */
	if (copy_to_user(u64_to_user_ptr(op->addr), &result, sizeof(result))) {
		ret = -EFAULT;
	} else {
		ret = sizeof(result);
	}

	kfree(data);

	/* Update shared memory statistics */
	io_unified_update_calc_stats(shared, result, ret < 0);

	return ret;
}

int io_unified_ops_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_unified_ops *op = io_kiocb_to_cmd(req, struct io_unified_ops);

	/* sqe->len contains the sub-opcode */
	op->opcode = READ_ONCE(sqe->len);

	if (op->opcode > IO_UNIFIED_OP_CALC)
		return -EINVAL;

	/* sqe->addr contains the buffer address */
	op->addr = READ_ONCE(sqe->addr);

	/* sqe->addr2 contains the shared memory address */
	op->shared_addr = READ_ONCE(sqe->addr2);

	/* sqe->off contains buffer length or send flags */
	op->offset = READ_ONCE(sqe->off);

	/* sqe->rw_flags contains the actual buffer length */
	op->len = READ_ONCE(sqe->rw_flags);

	if (!op->addr || !op->shared_addr)
		return -EINVAL;

	/* For READ and SEND operations, we need a file descriptor */
	if (op->opcode == IO_UNIFIED_OP_READ || op->opcode == IO_UNIFIED_OP_SEND) {
		if (req->file)
			op->file = req->file;
		else
			return -EBADF;
	}

	return 0;
}

int io_unified_ops_issue(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_unified_ops *op = io_kiocb_to_cmd(req, struct io_unified_ops);
	struct io_uring_unified_shared __user *shared;
	int ret;

	/* Map shared memory */
	shared = (struct io_uring_unified_shared __user *)op->shared_addr;
	if (!access_ok(shared, sizeof(*shared)))
		return -EFAULT;

	/* Execute the appropriate operation based on opcode */
	switch (op->opcode) {
	case IO_UNIFIED_OP_READ:
		ret = io_unified_do_read(req, op, shared);
		/* Update scheduler hints for read frequency tracking */
		if (req->tctx)
			io_sched_record_op(req->tctx, 0, ret > 0 ? ret : 0);
		break;
	case IO_UNIFIED_OP_SEND:
		ret = io_unified_do_send(req, op, shared);
		/* Update scheduler hints for send frequency tracking */
		if (req->tctx)
			io_sched_record_op(req->tctx, 1, ret > 0 ? ret : 0);
		break;
	case IO_UNIFIED_OP_CALC:
		ret = io_unified_do_calc(req, op, shared);
		/* Calc ops recorded as type 2 */
		if (req->tctx)
			io_sched_record_op(req->tctx, 2, 0);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	if (ret < 0)
		req_set_fail(req);

	io_req_set_res(req, ret, 0);
	return IOU_COMPLETE;
}

void io_unified_ops_cleanup(struct io_kiocb *req)
{
	/* No cleanup needed for now */
}
