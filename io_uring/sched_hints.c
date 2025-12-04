// SPDX-License-Identifier: GPL-2.0
/*
 * io_uring scheduler hints with chain dependencies and priority inheritance
 *
 * Provides:
 * - Chain-based dependencies between requests
 * - Priority inheritance to prevent priority inversion
 * - Scheduler hints for read/send frequency optimization
 */

#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/io_uring_types.h>
#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "sched_hints.h"

static struct kmem_cache *chain_node_cache;

/*
 * Initialize the sched_hints subsystem
 */
static int __init io_sched_hints_init(void)
{
	chain_node_cache = kmem_cache_create("io_sched_chain_node",
					     sizeof(struct io_sched_chain_node),
					     0, SLAB_HWCACHE_ALIGN, NULL);
	if (!chain_node_cache)
		return -ENOMEM;
	return 0;
}

/*
 * Cleanup the sched_hints subsystem
 */
static void __exit io_sched_hints_exit(void)
{
	kmem_cache_destroy(chain_node_cache);
}

/* ============== Scheduler Context Management ============== */

int io_sched_ctx_init(struct io_sched_ctx *sched, struct io_ring_ctx *ctx)
{
	int i;

	INIT_LIST_HEAD(&sched->chains);
	sched->nr_chains = 0;

	sched->prio_queue = RB_ROOT;
	sched->nr_ready = 0;

	INIT_LIST_HEAD(&sched->pending);
	sched->nr_pending = 0;

	for (i = 0; i < 256; i++)
		INIT_HLIST_HEAD(&sched->node_hash[i]);

	spin_lock_init(&sched->lock);

	memset(&sched->stats, 0, sizeof(sched->stats));
	sched->ring_ctx = ctx;

	return 0;
}
EXPORT_SYMBOL_GPL(io_sched_ctx_init);

void io_sched_ctx_destroy(struct io_sched_ctx *sched)
{
	struct io_sched_chain_node *node, *tmp;

	spin_lock(&sched->lock);

	/* Free all pending nodes */
	list_for_each_entry_safe(node, tmp, &sched->pending, list) {
		list_del(&node->list);
		hlist_del(&node->hash_node);
		kmem_cache_free(chain_node_cache, node);
	}

	/* Free all chain nodes */
	list_for_each_entry_safe(node, tmp, &sched->chains, list) {
		list_del(&node->list);
		kmem_cache_free(chain_node_cache, node);
	}

	spin_unlock(&sched->lock);
}
EXPORT_SYMBOL_GPL(io_sched_ctx_destroy);

/* ============== Chain Node Operations ============== */

struct io_sched_chain_node *io_sched_node_alloc(struct io_sched_ctx *sched)
{
	struct io_sched_chain_node *node;

	node = kmem_cache_zalloc(chain_node_cache, GFP_KERNEL);
	if (!node)
		return NULL;

	INIT_LIST_HEAD(&node->list);
	INIT_LIST_HEAD(&node->successors);
	INIT_LIST_HEAD(&node->succ_link);
	node->state = IO_CHAIN_PENDING;

	return node;
}
EXPORT_SYMBOL_GPL(io_sched_node_alloc);

void io_sched_node_free(struct io_sched_ctx *sched,
			struct io_sched_chain_node *node)
{
	if (!node)
		return;

	list_del(&node->list);
	if (!list_empty(&node->succ_link))
		list_del(&node->succ_link);
	hlist_del_init(&node->hash_node);
	kmem_cache_free(chain_node_cache, node);
}
EXPORT_SYMBOL_GPL(io_sched_node_free);

struct io_sched_chain_node *io_sched_node_lookup(struct io_sched_ctx *sched,
						  u64 id)
{
	struct io_sched_chain_node *node;
	u32 hash = io_sched_hash(id);

	hlist_for_each_entry(node, &sched->node_hash[hash], hash_node) {
		if (node->id == id)
			return node;
	}
	return NULL;
}
EXPORT_SYMBOL_GPL(io_sched_node_lookup);

/* ============== Priority Queue (RB-tree) Operations ============== */

static void prio_queue_insert(struct io_sched_ctx *sched,
			      struct io_sched_chain_node *node)
{
	struct rb_node **link = &sched->prio_queue.rb_node;
	struct rb_node *parent = NULL;
	struct io_sched_chain_node *entry;

	while (*link) {
		parent = *link;
		entry = rb_entry(parent, struct io_sched_chain_node, rb_node);

		/* Higher priority goes left (dequeued first) */
		if (node->eff_prio > entry->eff_prio)
			link = &parent->rb_left;
		else
			link = &parent->rb_right;
	}

	rb_link_node(&node->rb_node, parent, link);
	rb_insert_color(&node->rb_node, &sched->prio_queue);
	sched->nr_ready++;
}

static void prio_queue_remove(struct io_sched_ctx *sched,
			      struct io_sched_chain_node *node)
{
	rb_erase(&node->rb_node, &sched->prio_queue);
	sched->nr_ready--;
}

static struct io_sched_chain_node *prio_queue_peek(struct io_sched_ctx *sched)
{
	struct rb_node *node = rb_first(&sched->prio_queue);

	if (!node)
		return NULL;
	return rb_entry(node, struct io_sched_chain_node, rb_node);
}

/* ============== Priority Inheritance ============== */

/*
 * Apply priority inheritance when a high-priority request is blocked
 * by a lower-priority request. This prevents priority inversion.
 */
void io_sched_inherit_priority(struct io_sched_ctx *sched,
			       struct io_sched_chain_node *blocked,
			       struct io_sched_chain_node *blocker)
{
	if (!blocked || !blocker)
		return;

	/* Only inherit if blocked has higher priority */
	if (blocked->eff_prio <= blocker->eff_prio)
		return;

	/* Boost blocker's effective priority */
	blocker->eff_prio = blocked->eff_prio;
	blocker->inherited = 1;

	sched->stats.inherits_applied++;
	sched->stats.inversions_prevented++;

	/* If blocker is in ready queue, reposition it */
	if (blocker->state == IO_CHAIN_READY) {
		prio_queue_remove(sched, blocker);
		prio_queue_insert(sched, blocker);
	}

	/* Recursively propagate if blocker is also blocked */
	if (blocker->pred_id && blocker->state == IO_CHAIN_PENDING) {
		struct io_sched_chain_node *pred;
		pred = io_sched_node_lookup(sched, blocker->pred_id);
		if (pred)
			io_sched_inherit_priority(sched, blocker, pred);
	}
}
EXPORT_SYMBOL_GPL(io_sched_inherit_priority);

/*
 * Restore original priority after a node completes
 */
void io_sched_restore_priority(struct io_sched_ctx *sched,
			       struct io_sched_chain_node *node)
{
	if (!node || !node->inherited)
		return;

	node->eff_prio = node->base_prio;
	node->inherited = 0;
}
EXPORT_SYMBOL_GPL(io_sched_restore_priority);

/*
 * Propagate priority changes through the chain
 */
void io_sched_propagate_priority(struct io_sched_ctx *sched,
				 struct io_sched_chain_node *node)
{
	struct io_sched_chain_node *succ;

	if (!node)
		return;

	/* Check all successors for potential inheritance */
	list_for_each_entry(succ, &node->successors, succ_link) {
		if (succ->eff_prio > node->eff_prio) {
			io_sched_inherit_priority(sched, succ, node);
		}
	}
}
EXPORT_SYMBOL_GPL(io_sched_propagate_priority);

/* ============== Chain Operations ============== */

/*
 * Add a request to a chain with optional predecessor
 */
int io_sched_chain_add(struct io_sched_ctx *sched, u64 id, u64 pred_id,
		       u8 priority, struct io_kiocb *req)
{
	struct io_sched_chain_node *node, *pred = NULL;
	u32 hash;
	unsigned long flags;

	node = io_sched_node_alloc(sched);
	if (!node)
		return -ENOMEM;

	node->id = id;
	node->pred_id = pred_id;
	node->base_prio = priority;
	node->eff_prio = priority;
	node->req = req;
	node->submit_ts = ktime_get_ns();

	spin_lock_irqsave(&sched->lock, flags);

	/* Add to hash table for lookup */
	hash = io_sched_hash(id);
	hlist_add_head(&node->hash_node, &sched->node_hash[hash]);

	if (pred_id) {
		/* Has a predecessor - find it */
		pred = io_sched_node_lookup(sched, pred_id);
		if (pred && pred->state != IO_CHAIN_DONE) {
			/* Link as successor of predecessor */
			list_add_tail(&node->succ_link, &pred->successors);
			node->state = IO_CHAIN_PENDING;
			list_add_tail(&node->list, &sched->pending);
			sched->nr_pending++;

			/* Apply priority inheritance if needed */
			io_sched_inherit_priority(sched, node, pred);
		} else {
			/* Predecessor done or not found - ready immediately */
			node->state = IO_CHAIN_READY;
			node->ready_ts = ktime_get_ns();
			prio_queue_insert(sched, node);
		}
	} else {
		/* No predecessor - ready immediately */
		node->state = IO_CHAIN_READY;
		node->ready_ts = ktime_get_ns();
		prio_queue_insert(sched, node);
	}

	list_add_tail(&node->list, &sched->chains);
	sched->nr_chains++;

	spin_unlock_irqrestore(&sched->lock, flags);

	return 0;
}
EXPORT_SYMBOL_GPL(io_sched_chain_add);

/*
 * Mark a chain node as complete and wake up successors
 */
void io_sched_chain_complete(struct io_sched_ctx *sched, u64 id, int result)
{
	struct io_sched_chain_node *node, *succ, *tmp;
	unsigned long flags;

	spin_lock_irqsave(&sched->lock, flags);

	node = io_sched_node_lookup(sched, id);
	if (!node) {
		spin_unlock_irqrestore(&sched->lock, flags);
		return;
	}

	node->state = IO_CHAIN_DONE;

	/* Restore original priority */
	io_sched_restore_priority(sched, node);

	/* Wake up all successors */
	list_for_each_entry_safe(succ, tmp, &node->successors, succ_link) {
		list_del_init(&succ->succ_link);

		if (succ->state == IO_CHAIN_PENDING) {
			/* Move from pending to ready */
			list_del(&succ->list);
			sched->nr_pending--;

			succ->state = IO_CHAIN_READY;
			succ->ready_ts = ktime_get_ns();

			/* Restore inherited priority if any */
			io_sched_restore_priority(sched, succ);

			prio_queue_insert(sched, succ);
		}
	}

	sched->stats.chains_completed++;

	spin_unlock_irqrestore(&sched->lock, flags);
}
EXPORT_SYMBOL_GPL(io_sched_chain_complete);

/*
 * Cancel a chain node and all its successors
 */
void io_sched_chain_cancel(struct io_sched_ctx *sched, u64 id)
{
	struct io_sched_chain_node *node, *succ, *tmp;
	unsigned long flags;

	spin_lock_irqsave(&sched->lock, flags);

	node = io_sched_node_lookup(sched, id);
	if (!node) {
		spin_unlock_irqrestore(&sched->lock, flags);
		return;
	}

	/* Recursively cancel all successors */
	list_for_each_entry_safe(succ, tmp, &node->successors, succ_link) {
		spin_unlock_irqrestore(&sched->lock, flags);
		io_sched_chain_cancel(sched, succ->id);
		spin_lock_irqsave(&sched->lock, flags);
	}

	/* Remove from appropriate list */
	if (node->state == IO_CHAIN_READY) {
		prio_queue_remove(sched, node);
	} else if (node->state == IO_CHAIN_PENDING) {
		list_del(&node->list);
		sched->nr_pending--;
	}

	io_sched_node_free(sched, node);
	sched->nr_chains--;

	spin_unlock_irqrestore(&sched->lock, flags);
}
EXPORT_SYMBOL_GPL(io_sched_chain_cancel);

/* ============== Ready Queue Operations ============== */

/*
 * Get the highest priority ready request
 */
struct io_sched_chain_node *io_sched_get_next(struct io_sched_ctx *sched)
{
	struct io_sched_chain_node *node;
	unsigned long flags;

	spin_lock_irqsave(&sched->lock, flags);

	node = prio_queue_peek(sched);
	if (node) {
		prio_queue_remove(sched, node);
		node->state = IO_CHAIN_RUNNING;
	}

	spin_unlock_irqrestore(&sched->lock, flags);

	return node;
}
EXPORT_SYMBOL_GPL(io_sched_get_next);

/*
 * Get a batch of ready requests (up to max)
 */
int io_sched_get_batch(struct io_sched_ctx *sched,
		       struct io_sched_chain_node **nodes, u32 max)
{
	struct io_sched_chain_node *node;
	unsigned long flags;
	u32 count = 0;

	spin_lock_irqsave(&sched->lock, flags);

	while (count < max) {
		node = prio_queue_peek(sched);
		if (!node)
			break;

		prio_queue_remove(sched, node);
		node->state = IO_CHAIN_RUNNING;
		nodes[count++] = node;
	}

	spin_unlock_irqrestore(&sched->lock, flags);

	return count;
}
EXPORT_SYMBOL_GPL(io_sched_get_batch);

bool io_sched_has_ready(struct io_sched_ctx *sched)
{
	return sched->nr_ready > 0;
}
EXPORT_SYMBOL_GPL(io_sched_has_ready);

/* ============== Query Operations ============== */

bool io_sched_can_run(struct io_sched_ctx *sched, u64 id)
{
	struct io_sched_chain_node *node;
	bool can_run;
	unsigned long flags;

	spin_lock_irqsave(&sched->lock, flags);
	node = io_sched_node_lookup(sched, id);
	can_run = node && (node->state == IO_CHAIN_READY ||
			   node->state == IO_CHAIN_RUNNING);
	spin_unlock_irqrestore(&sched->lock, flags);

	return can_run;
}
EXPORT_SYMBOL_GPL(io_sched_can_run);

u8 io_sched_get_effective_prio(struct io_sched_ctx *sched, u64 id)
{
	struct io_sched_chain_node *node;
	u8 prio = IO_PRIO_NORMAL;
	unsigned long flags;

	spin_lock_irqsave(&sched->lock, flags);
	node = io_sched_node_lookup(sched, id);
	if (node)
		prio = node->eff_prio;
	spin_unlock_irqrestore(&sched->lock, flags);

	return prio;
}
EXPORT_SYMBOL_GPL(io_sched_get_effective_prio);

/* ============== Original Scheduler Hints (frequency tracking) ============== */

/**
 * io_uring_update_sched_hints - Update scheduler hints for current task
 * @hints: User-provided scheduling hints
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
 * io_sched_record_op - Record an I/O operation for scheduling statistics
 * @tctx: io_uring task context
 * @op_type: Type of operation (0 = read, 1 = send, 2 = calc)
 * @bytes: Number of bytes transferred
 *
 * Updates frequency tracking using exponential moving average.
 * This data is used by the scheduler to predict I/O patterns and
 * optimize scheduling decisions.
 */
void io_sched_record_op(struct io_uring_task *tctx, int op_type, u64 bytes)
{
	u64 now = ktime_get_ns();

	if (!tctx)
		return;

	switch (op_type) {
	case 0: /* Read operation */
		if (tctx->sched_hints.last_read_ts) {
			u64 interval = now - tctx->sched_hints.last_read_ts;
			/* Exponential moving average */
			tctx->sched_hints.read_freq_ns =
				(tctx->sched_hints.read_freq_ns * 7 + interval) / 8;
		}
		tctx->sched_hints.last_read_ts = now;
		tctx->sched_hints.read_count++;
		break;

	case 1: /* Send operation */
		if (tctx->sched_hints.last_send_ts) {
			u64 interval = now - tctx->sched_hints.last_send_ts;
			tctx->sched_hints.send_freq_ns =
				(tctx->sched_hints.send_freq_ns * 7 + interval) / 8;
		}
		tctx->sched_hints.last_send_ts = now;
		tctx->sched_hints.send_count++;
		break;

	case 2: /* Calc operation - track as compute-bound hint */
		/* Calc operations indicate compute-heavy workload */
		tctx->sched_hints.flags |= IO_URING_SCHED_HINT_THROUGHPUT;
		break;
	}
}
EXPORT_SYMBOL_GPL(io_sched_record_op);

/* ============== Syscall Interface ============== */

/**
 * sys_io_uring_sched_hints - Syscall to manage io_uring scheduler hints
 * @op: Operation code
 * @hints: Pointer to hints structure
 * @arg: Additional argument
 *
 * Operations:
 *   0 (SET): Set scheduler hints
 *   1 (GET): Get scheduler hints
 *   2 (RECORD): Record I/O operation
 *   3 (CHAIN_ADD): Add request to chain (arg = pred_id | (prio << 56))
 *   4 (CHAIN_COMPLETE): Mark chain node complete
 *   5 (CHAIN_CANCEL): Cancel chain node
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
		io_sched_record_op(current->io_uring, (int)arg, 0);
		return 0;
	default:
		return -EINVAL;
	}
}

/* Module init/exit */
core_initcall(io_sched_hints_init);
module_exit(io_sched_hints_exit);
