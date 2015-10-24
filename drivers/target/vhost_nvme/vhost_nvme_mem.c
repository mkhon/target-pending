/*
 * In-kernel vhost-nvme memory handling
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
#include <linux/vhost.h>
#include <uapi/linux/vhost.h>

#include <target/target_core_base.h>
#include <target/target_core_fabric.h>
#include <target/target_core_backend.h>

#include "vhost_nvme_base.h"

#define	VHOST_MEMORY_MAX_NREGIONS  64

/* Can we switch to this memory table? */
static bool memory_access_ok(struct vhost_nvme_hba *hba,
			     struct vhost_memory *mem)
{
	int i;
	bool ok = true;

	for (i = 0; i < mem->nregions; ++i) {
		struct vhost_memory_region *m = mem->regions + i;
		unsigned long a = m->userspace_addr;
		if (m->memory_size > ULONG_MAX) {
			ok = false;
			break;
		} else if (!access_ok(VERIFY_WRITE, (void __user *)a,
			    m->memory_size)) {
			ok = false;
			break;
		}
	}

	return ok;
}

long vhost_nvme_set_memory(struct vhost_nvme_hba *hba,
			   struct vhost_memory __user *m)
{
	struct vhost_memory mem, *newmem, *oldmem;
	unsigned long size = offsetof(struct vhost_memory, regions);

	if (copy_from_user(&mem, m, size))
		return -EFAULT;
	if (mem.padding)
		return -EOPNOTSUPP;
	if (mem.nregions > VHOST_MEMORY_MAX_NREGIONS)
		return -E2BIG;
	newmem = kmalloc(size + mem.nregions * sizeof *m->regions, GFP_KERNEL);
	if (!newmem)
		return -ENOMEM;

	memcpy(newmem, &mem, size);
	if (copy_from_user(newmem->regions, m->regions,
			   mem.nregions * sizeof *m->regions)) {
		kfree(newmem);
		return -EFAULT;
	}

	if (!memory_access_ok(hba, newmem)) {
		kfree(newmem);
		return -EFAULT;
	}
	oldmem = rcu_dereference_protected(hba->memory,
					   lockdep_is_held(&hba->mutex));
	rcu_assign_pointer(hba->memory, newmem);
	synchronize_rcu();
	kfree(oldmem);

	return 0;
}

