/* SPDX-License-Identifier: GPL-2.0 */
#ifndef IO_URING_UBR_UMEM_H
#define IO_URING_UBR_UMEM_H

#include "ubr_config.h"

#ifdef UBR_UMEM_ZEROCOPY

#include <linux/types.h>
#include <linux/mm_types.h>

struct io_ring_ctx;
struct io_uring_unified_shared;

struct io_ubr_umem {
	struct page	**pages;
	void		*vmap_addr;	/* raw vmap base (page-aligned) */
	u32		page_offset;	/* offset within first page */
	u64		user_addr;
	u64		size;
	u32		nr_pages;
	u32		frame_size;
	u32		nr_frames;
	struct io_uring_unified_shared __user *shared;
	atomic_t	refcount;	/* shared across multiple io_ring_ctx */
};

int io_ubr_umem_register(struct io_ring_ctx *ctx, void __user *arg);
int io_ubr_umem_unregister(struct io_ring_ctx *ctx);
void io_ubr_umem_destroy(struct io_ring_ctx *ctx);

/* Get kernel virtual address for a UMEM offset+len. Returns NULL if out of bounds. */
static inline void *io_ubr_umem_kaddr(struct io_ubr_umem *umem, u64 offset, u32 len)
{
	if (offset + len > umem->size)
		return NULL;
	return umem->vmap_addr + umem->page_offset + offset;
}

/* Get page and offset-within-page for a given UMEM offset */
static inline struct page *io_ubr_umem_offset_to_page(struct io_ubr_umem *umem,
						       u64 offset, u32 *pgoff)
{
	u64 abs_off = umem->page_offset + offset;
	u32 idx = abs_off >> PAGE_SHIFT;

	if (idx >= umem->nr_pages)
		return NULL;
	if (pgoff)
		*pgoff = abs_off & ~PAGE_MASK;
	return umem->pages[idx];
}

#endif /* UBR_UMEM_ZEROCOPY */
#endif /* IO_URING_UBR_UMEM_H */
