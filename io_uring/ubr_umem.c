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

int io_ubr_umem_register(struct io_ring_ctx *ctx, void __user *arg)
{
	struct io_uring_ubr_umem_reg reg;
	struct io_ubr_umem *umem;
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
	umem->shared        = (struct io_uring_unified_shared __user *)(uintptr_t)reg.shared_addr;

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

	if (umem->vmap_addr)
		vunmap(umem->vmap_addr);
	if (umem->pages) {
		unpin_user_pages(umem->pages, umem->nr_pages);
		kvfree(umem->pages);
	}
	kfree(umem);
	return 0;
}

void io_ubr_umem_destroy(struct io_ring_ctx *ctx)
{
	if (ctx->ubr_umem)
		io_ubr_umem_unregister(ctx);
}

#endif /* UBR_UMEM_ZEROCOPY */
