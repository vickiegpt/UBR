/* SPDX-License-Identifier: GPL-2.0 */
#ifndef IO_URING_SCHED_HINTS_H
#define IO_URING_SCHED_HINTS_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/rbtree.h>

struct io_kiocb;
struct io_ring_ctx;
struct io_uring_task;

/*
 * Priority levels for io_uring requests
 * Higher value = higher priority
 */
#define IO_PRIO_MIN		0
#define IO_PRIO_LOW		64
#define IO_PRIO_NORMAL		128
#define IO_PRIO_HIGH		192
#define IO_PRIO_REALTIME	255
#define IO_PRIO_MAX		255

/*
 * Chain node - represents a request in a dependency chain
 * Chains are simpler than DAGs: each request has at most one predecessor
 */
struct io_sched_chain_node {
	struct list_head	list;		/* Chain list linkage */
	struct hlist_node	hash_node;	/* Hash table linkage */
	struct rb_node		rb_node;	/* Priority queue rb-tree node */
	u64			id;		/* Request ID (user_data) */
	u64			pred_id;	/* Predecessor ID (0 = none) */

	/* Priority handling */
	u8			base_prio;	/* Original priority */
	u8			eff_prio;	/* Effective priority (after inheritance) */
	u8			inherited;	/* Has inherited priority */
	u8			state;		/* Node state */
#define IO_CHAIN_PENDING	0		/* Waiting for predecessor */
#define IO_CHAIN_READY		1		/* Ready to execute */
#define IO_CHAIN_RUNNING	2		/* Currently executing */
#define IO_CHAIN_DONE		3		/* Completed */

	/* Successor tracking for priority propagation */
	struct list_head	successors;	/* List of dependent nodes */
	struct list_head	succ_link;	/* Link in predecessor's successor list */

	/* Timing */
	u64			submit_ts;	/* Submission timestamp */
	u64			ready_ts;	/* When became ready */

	/* Back pointer */
	struct io_kiocb		*req;
};

/*
 * Priority queue entry for ready requests
 * Uses rb-tree for O(log n) priority-based scheduling
 */
struct io_prio_entry {
	struct rb_node		rb;		/* RB-tree node */
	struct io_sched_chain_node *chain_node;	/* Associated chain node */
	u8			priority;	/* Effective priority */
};

/*
 * Per-context scheduler state
 */
struct io_sched_ctx {
	/* Chain management */
	struct list_head	chains;		/* All active chains */
	u32			nr_chains;

	/* Priority queue (rb-tree ordered by effective priority) */
	struct rb_root		prio_queue;
	u32			nr_ready;

	/* Pending nodes (waiting for predecessors) */
	struct list_head	pending;
	u32			nr_pending;

	/* Node lookup by ID - simple hash table */
	struct hlist_head	node_hash[256];

	/* Lock for scheduler state */
	spinlock_t		lock;

	/* Statistics */
	struct {
		u64		inversions_prevented;	/* Priority inversions caught */
		u64		inherits_applied;	/* Priority inherits done */
		u64		chains_completed;	/* Full chains completed */
		u64		avg_chain_len;		/* Average chain length */
	} stats;

	/* Back pointer */
	struct io_ring_ctx	*ring_ctx;
};

/* Hash function for node lookup */
static inline u32 io_sched_hash(u64 id)
{
	return (u32)(id ^ (id >> 8)) & 0xFF;
}

/*
 * Scheduler context lifecycle
 */
int io_sched_ctx_init(struct io_sched_ctx *sched, struct io_ring_ctx *ctx);
void io_sched_ctx_destroy(struct io_sched_ctx *sched);

/*
 * Chain node operations
 */
struct io_sched_chain_node *io_sched_node_alloc(struct io_sched_ctx *sched);
void io_sched_node_free(struct io_sched_ctx *sched,
			struct io_sched_chain_node *node);
struct io_sched_chain_node *io_sched_node_lookup(struct io_sched_ctx *sched,
						  u64 id);

/*
 * Chain operations
 */
int io_sched_chain_add(struct io_sched_ctx *sched, u64 id, u64 pred_id,
		       u8 priority, struct io_kiocb *req);
void io_sched_chain_complete(struct io_sched_ctx *sched, u64 id, int result);
void io_sched_chain_cancel(struct io_sched_ctx *sched, u64 id);

/*
 * Priority inheritance - prevents priority inversion
 * When high-prio request waits on low-prio, boost the low-prio
 */
void io_sched_inherit_priority(struct io_sched_ctx *sched,
			       struct io_sched_chain_node *blocked,
			       struct io_sched_chain_node *blocker);
void io_sched_restore_priority(struct io_sched_ctx *sched,
			       struct io_sched_chain_node *node);
void io_sched_propagate_priority(struct io_sched_ctx *sched,
				 struct io_sched_chain_node *node);

/*
 * Ready queue operations
 */
struct io_sched_chain_node *io_sched_get_next(struct io_sched_ctx *sched);
int io_sched_get_batch(struct io_sched_ctx *sched,
		       struct io_sched_chain_node **nodes, u32 max);
bool io_sched_has_ready(struct io_sched_ctx *sched);

/*
 * Query operations
 */
bool io_sched_can_run(struct io_sched_ctx *sched, u64 id);
u8 io_sched_get_effective_prio(struct io_sched_ctx *sched, u64 id);

/*
 * Integration with existing scheduler hints
 */
void io_sched_record_op(struct io_uring_task *tctx, int op_type, u64 bytes);

#endif /* IO_URING_SCHED_HINTS_H */
