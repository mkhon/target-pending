/*
 * In-kernel vhost-nvme queue handling
 *
 * Copyright (c) 2015 Datera, Inc
 *
 * Functions for vhost handling
 */

#include <linux/init.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/vhost.h>
#include <uapi/linux/vhost.h>

#include <target/target_core_base.h>
#include <target/target_core_fabric.h>
#include <target/target_core_backend.h>

#include "vhost_nvme_base.h"

int vhost_nvme_create_cq(struct vhost_nvme_hba *hba)
{
	struct page *page;
	void __user *_cq_prp;
	void *cq_prp_ptr;
	int ret, offset;

	_cq_prp = vhost_map_guest_to_host(hba, 0, 0);
	if (unlikely(IS_ERR(_cq_prp))) {
		pr_err("vhost_map_guest_to_host for ca_pa failed\n");
		return -EINVAL;
	}

	ret = get_user_pages(current, hba->mm,
			    (uintptr_t)_cq_prp, 1, false, 0, &page, NULL);
	if (unlikely(ret != 1)) {
		pr_err("vhost_map_guest_to_host get_user_pages failed\n");
		return -EINVAL;
	}

	cq_prp_ptr = kmap_atomic(page);
	offset = (uintptr_t)_cq_prp & ~PAGE_MASK;

	// XXX: FIXME

	kunmap_atomic(cq_prp_ptr);
	put_page(page);

	return 0;
}

void vhost_nvme_delete_cq(struct vhost_nvme_hba *hba)
{
	return;
}

int vhost_nvme_create_sq(struct vhost_nvme_hba *hba)
{
	return 0;
}

void vhost_nvme_delete_sq(struct vhost_nvme_hba *hba)
{
	return;
}
