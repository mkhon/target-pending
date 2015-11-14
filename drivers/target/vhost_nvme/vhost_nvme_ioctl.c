/*
 * In-kernel vhost-nvme ioctl handling
 *
 * Copyright (c) 2015 Datera, Inc
 *
 * Functions for vhost handling
 */

#include <linux/init.h>
#include <linux/slab.h>
#include <linux/module.h>
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

static int
vhost_nvme_open(struct inode *inode, struct file *f)
{
	struct vhost_nvme_hba *hba;

	printk(KERN_INFO "Adding HBA\n");
	hba = kzalloc(sizeof(*hba), GFP_KERNEL);
	if (!hba) {
		pr_err("Unable to allocate vhost_nvme_hba\n");
		return -ENOMEM;
	}
	f->private_data = hba;

	try_module_get(THIS_MODULE);
	return 0;
}

static int
vhost_nvme_release(struct inode *inode, struct file *f)
{
	struct vhost_nvme_hba *hba = f->private_data;

	if (hba->irqfd_ctx)
		eventfd_ctx_put(hba->irqfd_ctx);
	if (hba->irqfd)
		fput(hba->irqfd);
	if (hba->doorbell_ctx)
		eventfd_ctx_put(hba->doorbell_ctx);
	if (hba->doorbell_fd)
		fput(hba->doorbell_fd);
	if (hba->mm) {
		mmput(hba->mm);
		hba->mm = NULL;
	}
	kfree(hba);
	printk(KERN_INFO "Removed HBA\n");
	module_put(THIS_MODULE);

	return 0;
}

static long
vhost_nvme_ioc_endpoint(struct vhost_nvme_hba *hba, unsigned long arg)
{
	return 0;
}

static long
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
	} else {
		printk("vhost-nvme Disabling irqfd\n");
		eventfd = NULL;
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
	} else {
		printk("vhost-nvme: Disabled irqfd\n");
	}

	if (e->doorbellfd > -1) {
		eventfd = eventfd_fget(e->doorbellfd);
		if (IS_ERR(eventfd)) {
			pr_err("vhost-nvme invalid doorbellfd descriptor\n");
			err = -EBADF;
			goto out;
		}
		printk("vhost-nvme Enabling doorbellfd\n");
	} else {
		printk("vhost-nvme Disabling doorbellfd\n");
		eventfd = NULL;
	}

	if (hba->doorbell_fd) {
		fput(hba->doorbell_fd);
		hba->doorbell_fd = NULL;
	}
	if (hba->doorbell_ctx) {
		eventfd_ctx_put(hba->doorbell_ctx);
		hba->doorbell_ctx = NULL;
	}
	if (eventfd) {
		hba->doorbell_fd = eventfd;
		hba->doorbell_ctx = eventfd_ctx_fileget(hba->doorbell_fd);
		printk("vhost-nvme: Enabled doorbell_fd\n");
	} else {
		printk("vhost-nvme: Disabled doorbell_fd\n");
	}
out:
	kfree(e);
	return err;
}

static long
vhost_nvme_ioc_cc_frame(struct vhost_nvme_hba *hba, unsigned long arg)
{
	void *frame_addr;
	size_t frame_size = 0xffff; // XXX: Fixme
	u8 status;

        if (!hba->tpg) {
		pr_err("vhost_nvme_ioc_cc_frame no valid tpg\n");
		return -ENODEV;
	}
	frame_addr = vhost_map_guest_to_host(hba, 0, 0);
	status = vhost_nvme_handle_frame(hba, frame_addr, 0);
#if 0
	if (status == NVME_INVALID_STATUS)
		return -EAGAIN;
#endif
	return 0;
}

static ssize_t
vhost_nvme_write(struct file *f, const char __user *buf,
		 size_t nbytes, loff_t *ppos)
{
	struct vhost_nvme_hba *hba = f->private_data;
	int ret;

	if (!hba->tpg) {
		pr_err("vhost_nvme_write no valid tpg\n");
		return -ENODEV;
	}

	// FIXME: fill in vhost_nvme_write
	return -ENOSYS;
}

static long
vhost_nvme_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	struct vhost_nvme_hba *hba = f->private_data;
	long ret = 0;

	switch (cmd) {
	case VHOST_NVME_IOC_EVENTFD:
		ret = vhost_nvme_ioc_eventfd(hba, arg);
		break;
	case VHOST_NVME_IOC_CC_FRAME:
		ret = vhost_nvme_ioc_cc_frame(hba, arg);
		break;
	case VHOST_SET_MEM_TABLE:
		ret = vhost_nvme_set_memory(hba, (void *)arg);
		break;
	default:
		ret = -ENOTTY;
		break;
	}

	return ret;
}

static const struct file_operations vhost_nvme_fops = {
	.owner		= THIS_MODULE,
	.release	= vhost_nvme_release,
	.unlocked_ioctl	= vhost_nvme_ioctl,
	.open		= vhost_nvme_open,
	.write		= vhost_nvme_write,
	.llseek		= noop_llseek,
};

struct miscdevice vhost_nvme_misc = {
	.minor		= MISC_DYNAMIC_MINOR,
	.name		= "vhost_nvme",
	.fops		= &vhost_nvme_fops,
};
