/* SPDX-License-Identifier: GPL-2.0 */
/*
 * include/linux/bede.h
 *
 * TDX NUMA node memory management interface
 * Based on Bede-linux implementation
 */

#ifndef _LINUX_BEDE_H
#define _LINUX_BEDE_H

#include <asm/io.h>
#include <linux/cgroup-defs.h>
#include <linux/cgroup.h>
#include <linux/migrate.h>
#include <linux/memcontrol.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/workqueue.h>

/** Get the cgroup by this struct. */
struct bede_work_struct {
	struct delayed_work work;
	struct workqueue_struct *workqueue;
	/* cgroup struct reverse mapping */
	struct cgroup *cgrp;
	bool should_migrate;
};

/* Watermark structure for userspace control */
struct bede_watermark {
	unsigned long high_watermark;  /* High watermark to trigger demotion */
	unsigned long low_watermark;   /* Low watermark to trigger promotion */
	unsigned long migration_limit; /* Max pages to migrate per cycle */
};

/* Global watermark control */
extern struct bede_watermark bede_watermarks;

/* Page migration functions */
extern void bede_walk_page_table_and_migrate_to_node(struct task_struct *task,
						      int from_node, int to_node, int count);

/* Helper functions for NUMA node management */
extern bool bede_flush_node_rss(struct mem_cgroup *memcg);
extern int bede_get_node(struct mem_cgroup *memcg, int node);
extern bool bede_is_local_bind(struct mem_cgroup *memcg);

/* Promotion and demotion functions */
extern void bede_promotion(struct work_struct *work);
extern void bede_demotion(struct work_struct *work);
extern int bede_init_kthread(void);
extern void bede_exit_kthread(void);
extern void bede_set_watermarks(unsigned long high, unsigned long low, unsigned long limit);

#endif /* _LINUX_BEDE_H */