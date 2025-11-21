/* SPDX-License-Identifier: GPL-2.0 */
#ifndef IORING_UNIFIED_OPS_H
#define IORING_UNIFIED_OPS_H

int io_unified_ops_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
int io_unified_ops_issue(struct io_kiocb *req, unsigned int issue_flags);
void io_unified_ops_cleanup(struct io_kiocb *req);

#endif
