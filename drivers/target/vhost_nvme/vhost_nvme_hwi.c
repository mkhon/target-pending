/*
 * In-kernel vhost-nvme queue handling
 *
 * Copyright (c) 2015 Datera, Inc
 *  
 * Functions for hardware-interface emulation handling
 */

#include <linux/init.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/vhost.h>
#include <uapi/linux/vhost.h>

#include "vhost_nvme_base.h"

static void
vhost_nvme_hwi_work(struct work_struct *work)
{
	return;
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
