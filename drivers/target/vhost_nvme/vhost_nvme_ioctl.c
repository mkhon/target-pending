/*
 * In-kernel vhost-nvme ioctl handling
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
#include <linux/file.h>
#include <linux/vhost.h>
#include <uapi/linux/vhost.h>

#include <target/target_core_base.h>
#include <target/target_core_fabric.h>
#include <target/target_core_backend.h>

#include "vhost_nvme_base.h"

long
vhost_nvme_ioc_eventfd(struct vhost_nvme_hba *hba, unsigned long arg)
{
	struct vhost_nvme_eventfd __user *ue =
			(struct vhost_nvme_eventfd *)arg;
	struct vhost_nvme_eventfd *e;
	struct file *eventfd = NULL;
	int err = 0;

	if (!hba->tpg)
		return -ENXIO;

	e = kmalloc(sizeof(*e), GFP_KERNEL);
	if (!e)
		return -ENOMEM;

	if (copy_from_user(e, ue, sizeof(*e))) {
		err = -EFAULT;
		goto out;
	}

	if (e->irqfd > -1) {
		eventfd = eventfd_fget(e->irqfd);
		if (IS_ERR(eventfd)) {
			pr_err("vhost-nvme invalid irqfd descriptor\n");
			err = -EBADF;
			goto out;
		}
		printk("vhost-nvme Enabling irqfd %p\n", eventfd);
	}

	if (hba->irqfd) {
		fput(hba->irqfd);
		hba->irqfd = NULL;
	}
	if (hba->irqfd_ctx) {
		eventfd_ctx_put(hba->irqfd_ctx);
		hba->irqfd_ctx = NULL;
	}

	if (eventfd) {
		hba->irqfd = eventfd;
		hba->irqfd_ctx = eventfd_ctx_fileget(hba->irqfd);
		printk("vhost-nvme: Enabled irqfd\n");
	}
out:
	kfree(e);
	return err;
}
