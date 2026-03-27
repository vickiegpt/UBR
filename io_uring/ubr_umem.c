// SPDX-License-Identifier: GPL-2.0
/*
 * UBR UMEM: Unified buffer memory for zero-copy io_uring unified ops.
 *
 * Registers a user memory region, pins pages, and creates a kernel
 * virtual mapping (vmap).  unified_ops can then read/compute/send
 * directly on the pinned pages without copy_to/from_user.
 */

#include "ubr_config.h"

#ifdef UBR_UMEM_ZEROCOPY

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/io_uring_types.h>
#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "ubr_umem.h"

/*
 * Global UMEM registry: allows multiple io_ring_ctx instances to share
 * the same UMEM (identified by user virtual address).  This enables
 * multi-threaded applications to use per-thread io_uring rings while
 * sharing a single pinned UMEM region.
 *
 * Protected by ubr_umem_lock.  Entries are refcounted; the UMEM is
 * freed when the last ring unreferences it.
 */
static DEFINE_MUTEX(ubr_umem_lock);
static LIST_HEAD(ubr_umem_list);

struct ubr_umem_entry {
	struct list_head	list;
	struct io_ubr_umem	*umem;
};

/* Find an existing UMEM by user address (caller holds ubr_umem_lock) */
static struct io_ubr_umem *ubr_umem_find_locked(u64 user_addr, u64 size)
{
	struct ubr_umem_entry *entry;

	list_for_each_entry(entry, &ubr_umem_list, list) {
		if (entry->umem->user_addr == user_addr &&
		    entry->umem->size == size)
			return entry->umem;
	}
	return NULL;
}

/* Add a new UMEM to the global list (caller holds ubr_umem_lock) */
static int ubr_umem_add_locked(struct io_ubr_umem *umem)
{
	struct ubr_umem_entry *entry;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;
	entry->umem = umem;
	list_add_tail(&entry->list, &ubr_umem_list);
	return 0;
}

/* Remove a UMEM from the global list (caller holds ubr_umem_lock) */
static void ubr_umem_remove_locked(struct io_ubr_umem *umem)
{
	struct ubr_umem_entry *entry, *tmp;

	list_for_each_entry_safe(entry, tmp, &ubr_umem_list, list) {
		if (entry->umem == umem) {
			list_del(&entry->list);
			kfree(entry);
			return;
		}
	}
}

static void io_ubr_umem_free(struct io_ubr_umem *umem)
{
	if (umem->vmap_addr)
		vunmap(umem->vmap_addr);
	if (umem->pages) {
		unpin_user_pages(umem->pages, umem->nr_pages);
		kvfree(umem->pages);
	}
	kfree(umem);
}

int io_ubr_umem_register(struct io_ring_ctx *ctx, void __user *arg)
{
	struct io_uring_ubr_umem_reg reg;
	struct io_ubr_umem *umem, *existing;
	unsigned long start;
	u32 nr_pages, pg_off;
	int ret;

	if (ctx->ubr_umem)
		return -EBUSY;

	if (copy_from_user(&reg, arg, sizeof(reg)))
		return -EFAULT;

	if (!reg.size || !reg.frame_size)
		return -EINVAL;
	if (reg.frame_size & (reg.frame_size - 1))
		return -EINVAL;
	if (reg.size & (reg.frame_size - 1))
		return -EINVAL;
	if (reg.flags != 0)
		return -EINVAL;
	if (reg.size > (1ULL << 30))	/* 1 GB cap */
		return -EINVAL;

	/*
	 * Check if another ring already registered a UMEM at this address.
	 * If so, share it (bump refcount).  This enables per-thread rings
	 * to share a single UMEM without re-pinning the same pages.
	 */
	mutex_lock(&ubr_umem_lock);
	existing = ubr_umem_find_locked(reg.addr, reg.size);
	if (existing) {
		atomic_inc(&existing->refcount);
		ctx->ubr_umem = existing;
		/* Update shared pointer if caller provided a new one */
		if (reg.shared_addr)
			existing->shared = (struct io_uring_unified_shared __user *)
						(uintptr_t)reg.shared_addr;
		mutex_unlock(&ubr_umem_lock);
		return 0;
	}
	mutex_unlock(&ubr_umem_lock);

	/* New UMEM: allocate, pin, vmap */
	start  = reg.addr & PAGE_MASK;
	pg_off = reg.addr & ~PAGE_MASK;
	nr_pages = (pg_off + reg.size + PAGE_SIZE - 1) >> PAGE_SHIFT;

	umem = kzalloc(sizeof(*umem), GFP_KERNEL);
	if (!umem)
		return -ENOMEM;

	umem->pages = kvmalloc_array(nr_pages, sizeof(struct page *), GFP_KERNEL);
	if (!umem->pages) {
		ret = -ENOMEM;
		goto err_umem;
	}

	ret = pin_user_pages_fast(start, nr_pages, FOLL_WRITE | FOLL_LONGTERM,
				  umem->pages);
	if (ret < 0)
		goto err_pages;
	if (ret != nr_pages) {
		unpin_user_pages(umem->pages, ret);
		ret = -EFAULT;
		goto err_pages;
	}

	umem->vmap_addr = vmap(umem->pages, nr_pages, VM_MAP, PAGE_KERNEL);
	if (!umem->vmap_addr) {
		unpin_user_pages(umem->pages, nr_pages);
		ret = -ENOMEM;
		goto err_pages;
	}

	umem->page_offset = pg_off;
	umem->user_addr   = reg.addr;
	umem->size         = reg.size;
	umem->nr_pages     = nr_pages;
	umem->frame_size   = reg.frame_size;
	umem->nr_frames    = reg.size / reg.frame_size;
	umem->shared       = (struct io_uring_unified_shared __user *)(uintptr_t)reg.shared_addr;
	atomic_set(&umem->refcount, 1);

	/* Add to global list */
	mutex_lock(&ubr_umem_lock);
	ret = ubr_umem_add_locked(umem);
	mutex_unlock(&ubr_umem_lock);
	if (ret < 0) {
		io_ubr_umem_free(umem);
		return ret;
	}

	ctx->ubr_umem = umem;
	return 0;

err_pages:
	kvfree(umem->pages);
err_umem:
	kfree(umem);
	return ret;
}

int io_ubr_umem_unregister(struct io_ring_ctx *ctx)
{
	struct io_ubr_umem *umem = ctx->ubr_umem;

	if (!umem)
		return -EINVAL;
	ctx->ubr_umem = NULL;

	/* Drop refcount; only free when last user is gone */
	if (atomic_dec_and_test(&umem->refcount)) {
		mutex_lock(&ubr_umem_lock);
		ubr_umem_remove_locked(umem);
		mutex_unlock(&ubr_umem_lock);
		io_ubr_umem_free(umem);
	}
	return 0;
}

void io_ubr_umem_destroy(struct io_ring_ctx *ctx)
{
	if (ctx->ubr_umem)
		io_ubr_umem_unregister(ctx);
}

#endif /* UBR_UMEM_ZEROCOPY */
