/*
 * In-kernel vhost-nvme hardware-interface emulation
 *
 * Copyright (c) 2015 Datera, Inc
 *
 * Parts based on QEMU NVMe-HI emulation code:
 *
 * Copyright (c) 2012, Intel Corporation
 *
 * Written by Keith Busch <keith.busch@intel.com>
 *
 * This code is licensed under the GNU GPL v2 or later.
 */

#include <linux/init.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/vhost.h>
#include <uapi/linux/vhost.h>

#include "vhost_nvme_base.h"

static int
vhost_nvme_hwi_map_sgl(struct vhost_nvme_hba *hba, struct vhost_nvme_cmd *cmd)
{
	return -ENOSYS;
}

static void
vhost_nvme_hwi_work(struct work_struct *work)
{
	struct vhost_nvme_cmd *cmd = container_of(work,
				struct vhost_nvme_cmd, work);
	u8 addr = 0xff; // XXX: FIXME
	uint64_t data = 0xffffffff; // XXX: FIXME
	int rc;

	rc = vhost_nvme_hwi_map_sgl(NULL, cmd);
	if (rc) {
		// XXX: handle frame failure back to userspace
		BUG_ON();
	}

	switch (addr) {
	case 0x14: // Used for initial create config controller queue
		/*
		 * Windows first sends data, then sends enable bit
		 * for initial configuration controller MMIO WRITE
		 *
		 * XXX: Need to check existing CC state..?
		 */
		if (!NVME_CC_EN(data) && !NVME_CC_EN(n->bar.cc) &&
		    !NVME_CC_SHN(data) && !NVME_CC_SHN(n->bar.cc)) {
			n->bar.cc = data;
		}
		/*
		 * Check NVME_CC_EN state to determine if configuration
		 * controller needs initial NVMe-HI setup, or explicit
		 * cleanup for vhost PCIe MSI-X device.
		 */
		if (NVME_CC_EN(data) && !NVME_CC_EN(n->bar.cc)) {
			// vhost_nvme_start_cc();
		} else if (!NVME_CC_EN(data) && NVME_CC_EN(n->bar.cc)) {
			// vhost_nvme_clear_cc();
		}
		if (NVME_CC_SHN(data) && !(NVME_CC_SHN(n->bar.cc))) {
			// vhost_nvme_clear_cc();
		}
		break;
	default:
		break;
	}
}

static u64 vhost_nvme_get_hwi_context(u8 __user *frame_addr)
{
	u64 context;
	off_t context_offset = 0; // XXX FIXME
	int ret;

	ret = copy_from_user(&context, frame_addr + context_offset, sizeof(u64));
	if (unlikely(ret)) {
		pr_warn("Unable to get context from frame addr %p, ret %d\n",
			frame_attr, ret);
		context = (u64)-1;
	}
	return context;
}

static struct vhost_nvme_cmd *
vhost_nvme_hwi_frame(struct vhost_nvme_hba *hba, u8 __user *frame_addr,
		     u8 frame_count)
{
	return NULL;
}

static void
vhost_nvme_hwi_dequeue(struct vhost_nvme_hba *hba, struct vhost_nvme_cmd *cmd)
{
	return;
}

int
vhost_nvme_hwi_queue(struct vhost_nvme_hba *hba, u8 __user *frame_addr,
		     u8 frame_count)
{
	struct vhost_nvme_cmd *cmd;
	u8 frame_status = 0; // INVALID_STATUS
	bool wait_for_frame = false;

	cmd = vhost_nvme_hwi_frame(hba, frame_addr, frame_context, frame_count);

	INIT_WORK(&cmd->work, vhost_nvme_hwi_work);
	queue_work(hba->workqueue, &cmd->work);

	if (wait_for_frame) {
		wait_for_completion(&comp);
		frame_status = 0xdeadbeef;
		vhost_nvme_hwi_dequeue(hba, cmd);
	}

	return 0;
}
