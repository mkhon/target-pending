/*
 * Copyright (c) 2005 Topspin Communications.  All rights reserved.
 * Copyright (c) 2005 Cisco Systems.  All rights reserved.
 * Copyright (c) 2005 Mellanox Technologies. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <linux/mm.h>
#include <linux/dma-mapping.h>
#include <linux/sched.h>
#include <linux/hugetlb.h>
#include <linux/dma-attrs.h>

//#include "uverbs.h"
#include <rdma/ib_umem.h>

#include "mfc.h"

enum ib_access_flags {
	IB_ACCESS_LOCAL_WRITE	= 1,
	IB_ACCESS_REMOTE_WRITE	= (1<<1),
	IB_ACCESS_REMOTE_READ	= (1<<2),
	IB_ACCESS_REMOTE_ATOMIC	= (1<<3),
	IB_ACCESS_MW_BIND	= (1<<4)
};

#define IB_UMEM_MAX_PAGE_CHUNK						\
	((PAGE_SIZE - offsetof(struct ib_umem_chunk, page_list)) /	\
	 ((void *) &((struct ib_umem_chunk *) 0)->page_list[1] -	\
	  (void *) &((struct ib_umem_chunk *) 0)->page_list[0]))

static void __mfc_umem_release(struct device *dev, struct ib_umem *umem, int dirty)
{
	struct ib_umem_chunk *chunk, *tmp;
	int i;

	list_for_each_entry_safe(chunk, tmp, &umem->chunk_list, list) {
		dma_unmap_sg(dev, chunk->page_list,
				chunk->nents, DMA_BIDIRECTIONAL);
		for (i = 0; i < chunk->nents; ++i) {
			struct page *page = sg_page(&chunk->page_list[i]);

			if (umem->writable && dirty)
				set_page_dirty_lock(page);
			put_page(page);
		}

		kfree(chunk);
	}
}

/**
 * mfc_umem_get - Pin and DMA map userspace memory.
 * @context: userspace context to pin memory for
 * @addr: userspace virtual address to start at
 * @size: length of region to pin
 * @access: IB_ACCESS_xxx flags for memory being pinned
 * @dmasync: flush in-flight DMA when the memory region is written
 */
struct ib_umem *mfc_umem_get(struct device *dev, unsigned long addr,
			    size_t size, int access, int dmasync)
{
	struct ib_umem *umem;
	struct page **page_list;
	struct vm_area_struct **vma_list;
	struct ib_umem_chunk *chunk;
	unsigned long locked;
	unsigned long lock_limit;
	unsigned long cur_base;
	unsigned long npages;
	int ret;
	int off;
	int i;
	DEFINE_DMA_ATTRS(attrs);

	if (dmasync)
		dma_set_attr(DMA_ATTR_WRITE_BARRIER, &attrs);

	if (!can_do_mlock())
		return ERR_PTR(-EPERM);

	umem = kmalloc(sizeof *umem, GFP_KERNEL);
	if (!umem)
		return ERR_PTR(-ENOMEM);

	umem->length    = size;
	umem->offset    = addr & ~PAGE_MASK;
	umem->page_size = PAGE_SIZE;
	/*
	 * We ask for writable memory if any access flags other than
	 * "remote read" are set.  "Local write" and "remote write"
	 * obviously require write access.  "Remote atomic" can do
	 * things like fetch and add, which will modify memory, and
	 * "MW bind" can change permissions by binding a window.
	 */
	umem->writable  = !!(access & ~IB_ACCESS_REMOTE_READ);

	/* We assume the memory is from hugetlb until proved otherwise */
	umem->hugetlb   = 1;

	INIT_LIST_HEAD(&umem->chunk_list);

	page_list = (struct page **) __get_free_page(GFP_KERNEL);
	if (!page_list) {
		kfree(umem);
		return ERR_PTR(-ENOMEM);
	}

	/*
	 * if we can't alloc the vma_list, it's not so bad;
	 * just assume the memory is not hugetlb memory
	 */
	vma_list = (struct vm_area_struct **) __get_free_page(GFP_KERNEL);
	if (!vma_list)
		umem->hugetlb = 0;

	npages = PAGE_ALIGN(size + umem->offset) >> PAGE_SHIFT;

	down_write(&current->mm->mmap_sem);

	locked     = npages + current->mm->locked_vm;
	lock_limit = current->signal->rlim[RLIMIT_MEMLOCK].rlim_cur >> PAGE_SHIFT;

	if ((locked > lock_limit) && !capable(CAP_IPC_LOCK)) {
		ret = -ENOMEM;
		goto out;
	}

	cur_base = addr & PAGE_MASK;

	ret = 0;
	while (npages) {
		ret = get_user_pages(current, current->mm, cur_base,
				     min_t(unsigned long, npages,
					   PAGE_SIZE / sizeof (struct page *)),
				     1, !umem->writable, page_list, vma_list);

		if (ret < 0)
			goto out;

		cur_base += ret * PAGE_SIZE;
		npages   -= ret;

		off = 0;

		while (ret) {
			chunk = kmalloc(sizeof *chunk + sizeof (struct scatterlist) *
					min_t(int, ret, IB_UMEM_MAX_PAGE_CHUNK),
					GFP_KERNEL);
			if (!chunk) {
				ret = -ENOMEM;
				goto out;
			}

			chunk->nents = min_t(int, ret, IB_UMEM_MAX_PAGE_CHUNK);
			sg_init_table(chunk->page_list, chunk->nents);
			for (i = 0; i < chunk->nents; ++i) {
				if (vma_list &&
				    !is_vm_hugetlb_page(vma_list[i + off]))
					umem->hugetlb = 0;
				sg_set_page(&chunk->page_list[i], page_list[i + off], PAGE_SIZE, 0);
			}

			chunk->nmap = dma_map_sg_attrs(dev,
							  &chunk->page_list[0],
							  chunk->nents,
							  DMA_BIDIRECTIONAL,
							  &attrs);
			if (chunk->nmap <= 0) {
				for (i = 0; i < chunk->nents; ++i)
					put_page(sg_page(&chunk->page_list[i]));
				kfree(chunk);

				ret = -ENOMEM;
				goto out;
			}

			ret -= chunk->nents;
			off += chunk->nents;
			list_add_tail(&chunk->list, &umem->chunk_list);
		}

		ret = 0;
	}

out:
	if (ret < 0) {
		__mfc_umem_release(dev, umem, 0);
		kfree(umem);
	} else
		current->mm->locked_vm = locked;

	up_write(&current->mm->mmap_sem);
	if (vma_list)
		free_page((unsigned long) vma_list);
	free_page((unsigned long) page_list);

	return ret < 0 ? ERR_PTR(ret) : umem;
}

/**
 * mfc_umem_release - release memory pinned with mfc_umem_get
 * @umem: umem struct to release
 */
void mfc_umem_release(struct device *dev, struct ib_umem *umem)
{
	struct mm_struct *mm;
	unsigned long diff;

	__mfc_umem_release(dev, umem, 1);

	mm = get_task_mm(current);
	if (!mm) {
		kfree(umem);
		return;
	}

	diff = PAGE_ALIGN(umem->length + umem->offset) >> PAGE_SHIFT;

	down_write(&mm->mmap_sem);

	current->mm->locked_vm -= diff;
	up_write(&mm->mmap_sem);
	mmput(mm);
	kfree(umem);
}

int mfc_umem_page_count(struct ib_umem *umem)
{
	struct ib_umem_chunk *chunk;
	int shift;
	int i;
	int n;

	shift = ilog2(umem->page_size);

	n = 0;
	list_for_each_entry(chunk, &umem->chunk_list, list)
		for (i = 0; i < chunk->nmap; ++i)
			n += sg_dma_len(&chunk->page_list[i]) >> shift;

	return n;
}

int fctgt_map_fmr(struct mfc_vhba *vhba, struct mem_buf *mem_buf,
		enum dma_data_direction dir)
{
	struct mfc_dev *mfc_dev = vhba->mfc_port->mfc_dev;
	struct ib_umem *umem;
	u64 *pages;
	struct ib_umem_chunk *chunk;
	int nr_pages = 0, j, k;
	int chunk_num = 0;
	int rc = 0;
	int access = IB_ACCESS_LOCAL_WRITE | IB_ACCESS_REMOTE_WRITE |
		IB_ACCESS_REMOTE_READ;

	umem = mfc_umem_get(mfc_dev->dma_dev, (unsigned long)mem_buf->uaddr, mem_buf->count, access, 0);
	if (IS_ERR(umem)) {
		rc = -ENOMEM;
		goto err;
	}

	pages = (u64 *) __get_free_page(GFP_KERNEL);
	if (!pages) {
		rc = -ENOMEM;
		goto err_umem_release;
	}

	list_for_each_entry(chunk, &umem->chunk_list, list) {
		chunk_num++;
		for (j = 0; j < chunk->nmap; ++j) {
			unsigned len;
			len = sg_dma_len(&chunk->page_list[j]) >> PAGE_SHIFT;

			for (k = 0; k < len; ++k) {
				pages[nr_pages++] =
					sg_dma_address(&chunk->page_list[j]) +
					umem->page_size * k;

			}
		}
	}

	rc = mlx4_fmr_alloc(mfc_dev->dev, mfc_dev->mr.pd |
				      MLX4_MPT_ENABLE_INVALIDATE,
				      MLX4_PERM_LOCAL_READ |
				      MLX4_PERM_LOCAL_WRITE |
				      MLX4_PERM_REMOTE_WRITE |
				      MLX4_PERM_REMOTE_READ,
				      nr_pages,
				      1, PAGE_SHIFT, &mem_buf->fmr);
	if (rc) {
		fctgt_err("Alloc fmr vhba=%d err=%d\n", vhba->idx, rc);
		goto err_pages_free;
	}

	rc = mlx4_fmr_enable(mfc_dev->dev, &mem_buf->fmr);
	if (rc) {
		fctgt_err("Enable FMR. err = %d\n", rc);
		goto err_free_fmr;
	}

	rc = mlx4_map_phys_fmr(mfc_dev->dev, &mem_buf->fmr, pages,
		      nr_pages, 0, &mem_buf->lkey, &mem_buf->rkey);
	if (rc) {
		fctgt_err("Map fmr vhba=%d err=%d\n", vhba->idx, rc);
		goto err_free_fmr;
	}

	free_page((unsigned long) pages);

	mem_buf->umem = umem;
	mem_buf->offset = umem->offset;

	return 0;

err_free_fmr:
	mlx4_fmr_free(mfc_dev->dev, &mem_buf->fmr);

err_pages_free:
	free_page((unsigned long) pages);

err_umem_release:
	mfc_umem_release(mfc_dev->dma_dev, umem);

err:
	return rc;
}

int fctgt_unmap_fmr(struct mfc_vhba *vhba, struct mem_buf *mem_buf)
{
	struct mfc_dev *mfc_dev = vhba->mfc_port->mfc_dev;

	mlx4_fmr_unmap(mfc_dev->dev, &mem_buf->fmr, NULL, NULL);

	mlx4_fmr_free(mfc_dev->dev, &mem_buf->fmr);

	mfc_umem_release(mfc_dev->dma_dev, mem_buf->umem);

	mem_buf->lkey = mem_buf->rkey = mem_buf->nr_pages = 0;
	mem_buf->umem = NULL;

	return 0;
}
