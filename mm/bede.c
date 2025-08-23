/* SPDX-License-Identifier: GPL-2.0 */
/*
 * mm/bede.c
 *
 * TDX NUMA node memory management
 * Simplified implementation for basic page migration support
 */

#include <linux/compiler_attributes.h>
#include <linux/list.h>
#include <linux/memcontrol.h>
#include <linux/mempolicy.h>
#include <linux/workqueue.h>
#include <linux/mm.h>
#include <linux/pagewalk.h>
#include <linux/swap.h>
#include <linux/migrate.h>
#include <linux/sched.h>
#include <linux/ksm.h>
#include <linux/huge_mm.h>
#include <linux/bede.h>
#include "internal.h"

/* Global watermark configuration */
struct bede_watermark bede_watermarks = {
	.high_watermark = 80,
	.low_watermark = 20,
	.migration_limit = 1024
};
EXPORT_SYMBOL_GPL(bede_watermarks);

/* Context structure for page table walk */
struct bede_migrate_ctx {
	int from_node;
	int to_node;
	int pages_to_migrate;
	int pages_migrated;
	struct list_head *page_list;
};

/* Handle transparent huge pages */
static int bede_pmd_entry(pmd_t *pmd, unsigned long addr,
			  unsigned long next, struct mm_walk *walk)
{
	struct bede_migrate_ctx *ctx = walk->private;
	struct page *page;
	int nid;
	
	if (!pmd_present(*pmd) || !pmd_trans_huge(*pmd))
		return 0;
		
	page = pmd_page(*pmd);
	if (!page)
		return 0;
		
	if (ctx->pages_migrated >= ctx->pages_to_migrate)
		return 1;
		
	nid = page_to_nid(page);
	if (nid != ctx->from_node)
		return 0;
		
	if (ctx->pages_migrated + HPAGE_PMD_NR > ctx->pages_to_migrate)
		return 0;
		
	if (!isolate_movable_page(page, ISOLATE_UNEVICTABLE))
		return 0;
		
	list_add_tail(&page->lru, ctx->page_list);
	ctx->pages_migrated += HPAGE_PMD_NR;
	
	return 0;
}

/* Page table entry handler for migration */
static int bede_pte_entry(pte_t *pte, unsigned long addr,
			  unsigned long next, struct mm_walk *walk)
{
	struct bede_migrate_ctx *ctx = walk->private;
	struct vm_area_struct *vma = walk->vma;
	struct page *page;
	int nid;
	
	if (!pte_present(*pte))
		return 0;
		
	page = vm_normal_page(vma, addr, *pte);
	if (!page || !page_mapped(page))
		return 0;
		
	if (ctx->pages_migrated >= ctx->pages_to_migrate)
		return 1;
		
	nid = page_to_nid(page);
	if (nid != ctx->from_node)
		return 0;
		
	if (PageHuge(page))
		return 0;
		
	if (PageCompound(page) && !PageHead(page))
		return 0;
		
	if (!isolate_movable_page(page, ISOLATE_UNEVICTABLE))
		return 0;
		
	list_add_tail(&page->lru, ctx->page_list);
	ctx->pages_migrated++;
	
	return 0;
}

static const struct mm_walk_ops bede_walk_ops = {
	.pmd_entry = bede_pmd_entry,
	.pte_entry = bede_pte_entry,
};

void bede_walk_page_table_and_migrate_to_node(struct task_struct *task,
					       int from_node, int to_node, int count)
{
	struct mm_struct *mm;
	struct bede_migrate_ctx ctx;
	struct vm_area_struct *vma;
	LIST_HEAD(page_list);
	int err;
	
	pr_debug("bede: Migrating %d pages from node %d to node %d for pid %d\n",
		 count, from_node, to_node, task->pid);
	
	mm = get_task_mm(task);
	if (!mm) {
		pr_info("bede: Failed to get mm_struct for pid %d\n", task->pid);
		return;
	}
	
	ctx.from_node = from_node;
	ctx.to_node = to_node;
	ctx.pages_to_migrate = count;
	ctx.pages_migrated = 0;
	ctx.page_list = &page_list;
	
	mmap_read_lock(mm);
	{
		VMA_ITERATOR(vmi, mm, 0);
		for_each_vma(vmi, vma) {
			if (ctx.pages_migrated >= count)
				break;
			
			if (vma->vm_flags & (VM_HUGETLB | VM_PFNMAP | VM_MIXEDMAP))
				continue;
				
			err = walk_page_range(mm, vma->vm_start, vma->vm_end,
					      &bede_walk_ops, &ctx);
			if (err)
				break;
		}
	}
	mmap_read_unlock(mm);
	
	if (!list_empty(&page_list)) {
		struct migration_target_control mtc = {
			.nid = to_node,
			.gfp_mask = GFP_HIGHUSER_MOVABLE,
		};
		
		pr_info("bede: Migrating %d pages from node %d to node %d\n",
			ctx.pages_migrated, from_node, to_node);
		
		err = migrate_pages(&page_list, alloc_migration_target, NULL,
				    (unsigned long)&mtc, MIGRATE_SYNC,
				    MR_NUMA_MISPLACED, NULL);
		
		if (err)
			pr_warn("bede: Migration failed with error %d\n", err);
		else
			pr_info("bede: Successfully migrated %d pages\n",
				ctx.pages_migrated);
		
		if (!list_empty(&page_list))
			putback_movable_pages(&page_list);
	}
	
	mmput(mm);
}
EXPORT_SYMBOL_GPL(bede_walk_page_table_and_migrate_to_node);

/* Simplified promotion/demotion stubs */
void bede_promotion(struct work_struct *work)
{
	pr_debug("bede_promotion: TDX promotion\n");
}

void bede_demotion(struct work_struct *work)
{
	pr_debug("bede_demotion: TDX demotion\n");
}

int bede_init_kthread(void)
{
	pr_info("bede: TDX NUMA management initialized\n");
	return 0;
}

void bede_exit_kthread(void)
{
	pr_info("bede: TDX NUMA management exiting\n");
}

void bede_set_watermarks(unsigned long high, unsigned long low, unsigned long limit)
{
	bede_watermarks.high_watermark = high;
	bede_watermarks.low_watermark = low;
	bede_watermarks.migration_limit = limit;
	
	pr_info("bede: Watermarks updated - high: %lu, low: %lu, limit: %lu\n",
		high, low, limit);
}