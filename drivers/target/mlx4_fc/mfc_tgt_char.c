#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/wait.h>
#include <linux/completion.h>
#include <asm/uaccess.h>	/* for put_user */

#include "mfc.h"
#include "fcoe_tgt_api.h"

__u16 ctl_msg_len[CTL_NUM_MSGS] = {
        [CTL_HBA_CREATED] = fcoetgt_ctl_msg_len(hba_created),
        [CTL_HBA_REMOVED] = fcoetgt_ctl_msg_len(hba_removed),
};

__u16 hba_msg_len[HBA_NUM_MSGS] = {
        [HBA_REG_BUFF_REQ] = fcoetgt_hba_msg_len(reg_buf_req),
        [HBA_REG_BUFF_RSP] = fcoetgt_hba_msg_len(reg_buf_rsp),
        [HBA_RPORT_UP] = fcoetgt_hba_msg_len(rport_state),
        [HBA_RPORT_DOWN] = fcoetgt_hba_msg_len(rport_state),
        [HBA_SCSI_REQ] = fcoetgt_hba_msg_len(scsi_req),
        [HBA_RDMA_READ_START] = fcoetgt_hba_msg_len(rdma_req),
        [HBA_RDMA_WRITE_START] = fcoetgt_hba_msg_len(rdma_req),
        [HBA_RDMA_READ_DONE] = fcoetgt_hba_msg_len(rdma_done),
        [HBA_RDMA_WRITE_DONE] = fcoetgt_hba_msg_len(rdma_done),
        [HBA_SCSI_RESP] = fcoetgt_hba_msg_len(scsi_resp),
};
extern void fc_lport_enter_dns(struct fc_lport *lport);

#define CODE2STR(code) [code] = #code

char *ctl_msg_str[] = {
	CODE2STR(CTL_START),
	CODE2STR(CTL_STOP),
	CODE2STR(CTL_HBA_CREATED),
	CODE2STR(CTL_HBA_REMOVED),
};

char *hba_msg_str[] = {
	CODE2STR(HBA_REG_BUFF_REQ),
	CODE2STR(HBA_REG_BUFF_RSP),
	CODE2STR(HBA_START),
	CODE2STR(HBA_STOP),
	CODE2STR(HBA_IS_OFFLINE),
	CODE2STR(HBA_IS_ONLINE),
	CODE2STR(HBA_RPORT_UP),
	CODE2STR(HBA_RPORT_DOWN),
	CODE2STR(HBA_SCSI_REQ),
	CODE2STR(HBA_RDMA_READ_START),
	CODE2STR(HBA_RDMA_READ_DONE),
	CODE2STR(HBA_RDMA_WRITE_START),
	CODE2STR(HBA_RDMA_WRITE_DONE),
	CODE2STR(HBA_SCSI_RESP),
	CODE2STR(HBA_FLOGI_ACC),
};

enum {
	FCTGT_IOC_FABRIC_LOGIN = 1,
	FCTGT_IOC_REG_MEM = 2,
	FCTGT_IOC_DISC_START = 3,
	FCTGT_IOC_TRANS_START = 4,
};

#define FCTGT_CTL_DEV_NAME "fctgt_ctl"

#define FCTGT_MINOR_BASE 10

struct mfc_fip_ctlr *mlx4_fcoe_fip;

struct ctl_msg {
	struct list_head list;
	struct fcoetgt_ctl_msg msg;
};

struct hba_msg {
	struct list_head list;
	struct fcoetgt_hba_msg msg;
};

#define ctl_msg_list(_msg) &container_of(_msg, struct ctl_msg, msg)->list
#define hba_msg_list(_msg) &container_of(_msg, struct hba_msg, msg)->list

struct fctgt_vhba {
	struct list_head msg_queue;
	wait_queue_head_t wait;
	struct mfc_vhba *vhba;

	struct list_head mem_bufs;

	spinlock_t lock;
};

struct fctgt_ctl {
	int started;

	struct list_head msg_queue;
	wait_queue_head_t wait;

	spinlock_t lock;

	int ref_count;
	int major;

	struct fctgt_vhba vhbas[256];
} fctgt_ctl;

static inline struct fctgt_vhba *fctgt_vhba_get(int idx)
{
	if (idx < 0 || idx > ARRAY_SIZE(fctgt_ctl.vhbas))
		return NULL;

	return &fctgt_ctl.vhbas[idx];
}

static struct fcoetgt_ctl_msg *fctgt_ctl_msg_alloc(u8 hba_id, u8 type, u16 flags)
{
	struct ctl_msg *msg_list_item;
	struct fcoetgt_ctl_msg *msg;

	msg_list_item = kmalloc(sizeof(*msg_list_item), GFP_ATOMIC);
	if (!msg_list_item) {
		fctgt_err("Couldn't allocate control message\n");
		return NULL;
	}

	msg = &msg_list_item->msg;

	msg->hdr.hba_id = hba_id;
	msg->hdr.msg_type = type;
	msg->hdr.msg_len = ctl_msg_len[type];
	msg->hdr.flags = flags;
	msg->hdr.reserved = 0;

	INIT_LIST_HEAD(ctl_msg_list(msg));

	return msg;
}

static void fctgt_ctl_msg_free(struct fcoetgt_ctl_msg *msg)
{
	kfree(container_of(msg, struct ctl_msg, msg));
}

static struct fcoetgt_hba_msg *fctgt_hba_msg_alloc(u8 type, u16 flags)
{
	struct hba_msg *hba_msg;
	struct fcoetgt_hba_msg *msg;

	hba_msg = kmalloc(sizeof(*hba_msg), GFP_ATOMIC);
	if (!hba_msg) {
		fctgt_err("Couldn't allocate HBA message\n");
		return NULL;
	}

	msg = &hba_msg->msg;

	msg->hdr.msg_type = type;
	msg->hdr.msg_len = hba_msg_len[type];
	msg->hdr.flags = flags;

	INIT_LIST_HEAD(hba_msg_list(msg));

	return msg;
}

static void fctgt_hba_msg_free(struct fcoetgt_hba_msg *msg)
{
	kfree(container_of(msg, struct hba_msg, msg));
}

static int fctgt_ctl_msg_entail(struct fctgt_ctl *ctl, struct fcoetgt_ctl_msg *ctl_msg)
{
	spin_lock(&ctl->lock);
	list_add_tail(ctl_msg_list(ctl_msg), &ctl->msg_queue);
	spin_unlock(&ctl->lock);
	wake_up_interruptible(&ctl->wait);

	return 0;
}

static struct fcoetgt_ctl_msg *fctgt_ctl_msg_get(struct fctgt_ctl *ctl)
{
	struct fcoetgt_ctl_msg *msg = NULL;

	spin_lock(&ctl->lock);
	if (!list_empty(&ctl->msg_queue)) {
		msg = &list_entry(ctl->msg_queue.next, struct ctl_msg, list)->msg;
		list_del(ctl_msg_list(msg));
	}
	spin_unlock(&ctl->lock);

	if (!msg)
		fctgt_dbg("No event is waiting\n");

	return msg;
}

static int fctgt_hba_msg_entail(struct mfc_vhba *vhba, struct fcoetgt_hba_msg *msg)
{
	struct fctgt_vhba *tvhba = fctgt_vhba_get(vhba->idx);
	unsigned long flags;

	spin_lock_irqsave(&tvhba->lock, flags);
	list_add_tail(hba_msg_list(msg), &tvhba->msg_queue);
	spin_unlock_irqrestore(&tvhba->lock, flags);

	wake_up_interruptible(&tvhba->wait);

	return 0;
}

static struct fcoetgt_hba_msg *fctgt_hba_msg_get(struct mfc_vhba *vhba)
{
	struct fctgt_vhba *tvhba = fctgt_vhba_get(vhba->idx);
	struct fcoetgt_hba_msg *msg = NULL;
	unsigned long flags;

	spin_lock_irqsave(&tvhba->lock, flags);
	if (!list_empty(&tvhba->msg_queue)) {
		msg = &list_entry(tvhba->msg_queue.next, struct hba_msg, list)->msg;
		list_del(hba_msg_list(msg));
	}
	spin_unlock_irqrestore(&tvhba->lock, flags);

	if (!msg)
		fctgt_dbg("HBA message Q is empty\n");

	return msg;
}

int fctgt_vhba_entail(struct mfc_vhba *vhba)
{
	struct fctgt_vhba *tvhba;
	struct fcoetgt_ctl_msg *ctl_msg;

	tvhba = &fctgt_ctl.vhbas[vhba->idx];

	if (tvhba->vhba) {
		fctgt_dbg("vhba->idx %d already allocated\n", vhba->idx);
		return -EINVAL;
	}

	tvhba->vhba = vhba;
	INIT_LIST_HEAD(&tvhba->msg_queue);
	spin_lock_init(&tvhba->lock);
	init_waitqueue_head(&tvhba->wait);

	ctl_msg = fctgt_ctl_msg_alloc(vhba->idx, CTL_HBA_CREATED, 0);
	if (!ctl_msg)
		return -ENOMEM;

	ctl_msg->hba_created.wwpn = be64_to_cpu(vhba->lp->wwpn);
	ctl_msg->hba_created.wwnn = be64_to_cpu(vhba->lp->wwnn);

	fctgt_ctl_msg_entail(&fctgt_ctl, ctl_msg);

	return 0;
}

int fctgt_notify_flogi_acc(struct mfc_vhba *vhba, struct fc_seq *seq, struct fc_frame *fp)
{
	struct fcoetgt_hba_msg *msg;

	msg = fctgt_hba_msg_alloc(HBA_FLOGI_ACC, 0);
	if (!msg)
		return -ENOMEM;

	fctgt_dbg("FLOGI accepted\n");

	fctgt_hba_msg_entail(vhba, msg);

	fc_lport_enter_dns(vhba->lp);

	return 0;
}

static int fctgt_reg_mem(struct mfc_vhba *vhba, u64 uaddr, u32 count, u64 tgt_buf_id)
{
	struct fctgt_vhba *tvhba = fctgt_vhba_get(vhba->idx);
	struct mem_buf *mem_buf;
	struct fcoetgt_hba_msg *rsp;
	unsigned long flags;
	int rc = 0;

	mem_buf = kmalloc(sizeof(*mem_buf), GFP_KERNEL);
	if (!mem_buf) {
		fctgt_err("Out of memory\n");
		return -ENOMEM;
	}
	memset(mem_buf, 0, sizeof(*mem_buf));

	mem_buf->tgt_buf_id = tgt_buf_id;
	mem_buf->count = count;
	mem_buf->uaddr = (void __user *)uaddr;

	rc = fctgt_map_fmr(vhba, mem_buf, DMA_FROM_DEVICE);
	if (rc) {
		fctgt_err("Map FMR: %d\n", rc);
		return rc;
	}

	spin_lock_irqsave(&tvhba->lock, flags);
	list_add_tail(&mem_buf->list, &tvhba->mem_bufs);
	spin_unlock_irqrestore(&tvhba->lock, flags);

	rsp = fctgt_hba_msg_alloc(HBA_REG_BUFF_RSP, 0);
	if (!rsp) {
		rc = -ENOMEM;
		goto err;
	}

	rsp->reg_buf_rsp.tgt_buff_id = tgt_buf_id;
	rsp->reg_buf_rsp.krn_buff_id = (u64) mem_buf;

	fctgt_dbg("addr: 0x%llx len: 0x%x bytes tgt_buf_id: 0x%llx krn_id: "
			"0x%llx key: 0x%x offset: 0x%x\n",
			uaddr, count, tgt_buf_id, (u64)mem_buf, mem_buf->lkey, mem_buf->offset);

	fctgt_hba_msg_entail(vhba, rsp);
err:
	return rc;
}

static int _fctgt_dereg_mem(struct mfc_vhba *vhba, u64 krn_id)
{
	struct mem_buf *mem_buf = (struct mem_buf *)krn_id;

	list_del(&mem_buf->list);

	fctgt_unmap_fmr(vhba, mem_buf);

	kfree(mem_buf);

	return 0;
}

static int fctgt_rdma_write_done(struct mfc_vhba *vhba, struct trans_start *ts)
{
	struct fcoetgt_hba_msg *msg;

	msg = fctgt_hba_msg_alloc(HBA_RDMA_WRITE_DONE, 0);
	if (!msg)
		return -ENOMEM;

	msg->rdma_done.tgt_buf_id = ts->tgt_buf_id;

	fctgt_dbg_ts(ts, "RDMA write done. tgt_id: 0x%x\n", ts->tgt_buf_id);

	fctgt_hba_msg_entail(vhba, msg);

	return 0;
}

static int fctgt_rdma_read_done(struct mfc_vhba *vhba, struct trans_start *ts)
{
	struct fcoetgt_hba_msg *msg;

	msg = fctgt_hba_msg_alloc(HBA_RDMA_READ_DONE, 0);
	if (!msg)
		return -ENOMEM;

	msg->rdma_done.tgt_buf_id = ts->tgt_buf_id;

	fctgt_dbg_ts(ts, "RDMA read done\n");

	fctgt_hba_msg_entail(vhba, msg);

	ts->done = NULL;

	return 0;
}

static int fctgt_fcp_req_rx(struct mfc_vhba *vhba, struct fc_frame *fp)
{
	struct fcoetgt_hba_msg *msg;
	struct trans_start *ts;
	struct fc_frame_header *fh;
	void *fcp_cmd;
	struct mfc_exch *fexch;
	int rc = 0;

	msg = fctgt_hba_msg_alloc(HBA_SCSI_REQ, 0);
	if (!msg)
		return -ENOMEM;

	fcp_cmd = fc_frame_payload_get(fp, FCP_CMND_LEN);
	if (!fcp_cmd) {
		fctgt_err("Frame too small. Couldn't get fcp_cmd\n");
		return -EINVAL;
	}

	memcpy(msg->scsi_req.fcp_cmd, fcp_cmd, FCP_CMND_LEN);

	ts = kmalloc(sizeof(*ts), GFP_ATOMIC);
	if (!ts)
		return -ENOMEM;

	memset(ts, 0, sizeof(*ts));

	ts->type = MFC_TGT_RDMA_WRITE;
	fh = fc_frame_header_get(fp);
	ts->rport_id = ntoh24(fh->fh_s_id);
	ts->remote_exch_id = ntohs(fh->fh_ox_id);

	ts->local_exch_id = mfc_bitmap_slot_alloc(&vhba->fexch_bm, 0);
	fctgt_dbg("Allocated slot #0x%x\n", ts->local_exch_id);
	if (ts->local_exch_id == -1) {
		fctgt_err("No free exchange on vhba=%d port=%d\n",
			     vhba->idx, vhba->mfc_port->port);
		rc = -ENOMEM;
		goto err_out;
	}

	fexch = &vhba->fexch[ts->local_exch_id];
	fexch->context = (void *)ts;

	fctgt_dbg_ts(ts, "RX: SCSI request\n");

	msg->scsi_req.krn_cmd_id = (u64)ts;

	fctgt_hba_msg_entail(vhba, msg);

	return 0;

err_out:
	kfree(ts);
	return rc;
}

static int rdma_write_start(struct mfc_vhba *vhba, u64 krn_cmd_id,
		u64 krn_buf_id, u32 xfer_len)
{
	struct mem_buf *mem_buf = (struct mem_buf *)krn_buf_id;
	struct trans_start *ts = (struct trans_start *)krn_cmd_id;
	int rc = 0;

	if (!krn_buf_id) {
		fctgt_err("krn_buf_id = NULL\n");
		return -EINVAL;
	}

	ts->type = MFC_TGT_RDMA_WRITE;

	ts->done = fctgt_rdma_write_done;

	ts->tgt_buf_id = mem_buf->tgt_buf_id;

	ts->key = mem_buf->lkey;
	ts->offset = mem_buf->offset;
	ts->xfer_len = xfer_len;

	fctgt_dbg_ts(ts, "RDMA write. krn_cmd_id: 0x%llx rport_id: %06x len: 0x%x tgt_id: 0x%x\n",
			krn_cmd_id, ts->rport_id, ts->xfer_len, ts->tgt_buf_id);

	return rc;
}

static int rdma_read_start(struct mfc_vhba *vhba, u64 krn_cmd_id,
		u64 krn_buf_id, u32 xfer_len)
{
	struct mem_buf *mem_buf = (struct mem_buf *)krn_buf_id;
	struct trans_start *ts = (struct trans_start *)krn_cmd_id;
	int rc = 0;

	if (!krn_buf_id) {
		fctgt_err("krn_buf_id = NULL\n");
		return -EINVAL;
	}

	ts->type = MFC_TGT_RDMA_READ;

	ts->done = fctgt_rdma_read_done;

	ts->tgt_buf_id = mem_buf->tgt_buf_id;

	ts->key = mem_buf->lkey;
	ts->offset = mem_buf->offset;
	ts->xfer_len = xfer_len;

	fctgt_dbg_ts(ts, "RDMA read. krn_cmd_id: 0x%llx rport_id: %06x len: 0x%x tgt_id: 0x%x\n",
			krn_cmd_id, ts->rport_id, ts->xfer_len, ts->tgt_buf_id);

	rc = mfc_send_data(vhba, ts);
	if (rc)
		fctgt_err("Send data. rc = %d\n", rc);

	return rc;
}

static int send_scsi_resp(struct mfc_vhba *vhba, u64 krn_cmd_id,
		u32 fcp_resp_len, u8 *fcp_resp)
{
	struct trans_start *ts = (struct trans_start *)krn_cmd_id;
	int rc = 0;

	ts->fcp_rsp = kmalloc(fcp_resp_len, GFP_KERNEL);
	memcpy(ts->fcp_rsp, fcp_resp, fcp_resp_len);
	ts->fcp_rsp_len = fcp_resp_len;

	fctgt_dbg_ts(ts, "Scsi resp. krn_cmd_id: 0x%llx rport_id: %06x len: 0x%x\n",
			krn_cmd_id, ts->rport_id, ts->fcp_rsp_len);

	if (ts->type == MFC_TGT_RDMA_WRITE) {
		rc = mfc_send_data(vhba, ts);
		if (rc) {
			fctgt_err("Send data. rc = %d\n", rc);
			goto err;
		}
	}

	rc = mfc_send_resp(vhba, ts);
	if (rc) {
		fctgt_err("Send resp. rc = %d\n", rc);
		goto err;
	}

err:
	return rc;
}

static int fctgt_vhba_open(struct mfc_vhba *vhba, struct file *file)
{
	struct fctgt_vhba *tvhba = fctgt_vhba_get(vhba->idx);

	file->private_data = vhba;

	vhba->fcp_req_rx = fctgt_fcp_req_rx;
	fctgt_dbg("Starting a new vhba id:%d\n", vhba->idx);

	INIT_LIST_HEAD(&tvhba->mem_bufs);

	return 0;
}

static int fctgt_vhba_release(struct mfc_vhba *vhba, struct file *file)
{
	struct fctgt_vhba *tvhba = fctgt_vhba_get(vhba->idx);
	struct mem_buf *mem_buf, *tmp;
	unsigned long flags;
	vhba->fcp_req_rx = NULL;

	spin_lock_irqsave(&tvhba->lock, flags);
	list_for_each_entry_safe(mem_buf, tmp, &tvhba->mem_bufs, list) {
		_fctgt_dereg_mem(vhba, (u64)mem_buf);
	}
	spin_unlock_irqrestore(&tvhba->lock, flags);

	return 0;
}

static unsigned int fctgt_vhba_poll(struct file *filp, struct mfc_vhba *vhba,
		struct poll_table_struct *poll)
{
	struct fctgt_vhba *tvhba = fctgt_vhba_get(vhba->idx);
	int mask = 0;
	unsigned long flags;

	poll_wait(filp, &tvhba->wait, poll);

	spin_lock_irqsave(&tvhba->lock, flags);
	if (!list_empty(&tvhba->msg_queue))
		mask |= POLLIN;
	spin_unlock_irqrestore(&tvhba->lock, flags);

	return mask;
}

static ssize_t fctgt_hba_write(struct mfc_vhba *vhba, const char __user *buffer,
		size_t length, loff_t *offset)
{
	int rc = -EINVAL;
	struct fcoetgt_hba_msg msg;

	if (length > sizeof(msg))
		return -EINVAL;

	if (copy_from_user(&msg, buffer, length + sizeof(msg.hdr)))
		return -EINVAL;

	fctgt_info("%s\n", hba_msg_str[msg.hdr.msg_type]);
	switch (msg.hdr.msg_type) {
		case HBA_REG_BUFF_REQ:
			rc = fctgt_reg_mem(vhba,
					msg.reg_buf_req.addr,
					msg.reg_buf_req.size,
					msg.reg_buf_req.tgt_buff_id);
			break;

		case HBA_START:
			rc = fc_fabric_login(vhba->lp);
			break;

		case HBA_STOP:
			rc = 0;
			break;

		case HBA_RPORT_UP:
			break;

		case HBA_RPORT_DOWN:
			break;

		case HBA_RDMA_READ_START:
			rc = rdma_read_start(vhba,
					msg.rdma_req.krn_cmd_id,
					msg.rdma_req.krn_buf_id,
					msg.rdma_req.xfer_len);
			break;

		case HBA_RDMA_WRITE_START:
			rc = rdma_write_start(vhba,
					msg.rdma_req.krn_cmd_id,
					msg.rdma_req.krn_buf_id,
					msg.rdma_req.xfer_len);
			break;

		case HBA_SCSI_RESP:
			rc = send_scsi_resp(vhba,
					msg.scsi_resp.krn_cmd_id,
					msg.scsi_resp.fcp_resp_len,
					msg.scsi_resp.fcp_resp);
			break;

		case HBA_IS_OFFLINE:
		case HBA_IS_ONLINE:
		case HBA_SCSI_REQ:
			break;
	}

	return rc ?: length;
}

static ssize_t fctgt_ctl_write(struct file *filp, const char __user *buffer,
		size_t length, loff_t *offset)
{
	struct mfc_vhba *vhba = filp->private_data;
	struct fcoetgt_ctl_msg msg;

	if (vhba)
		return fctgt_hba_write(vhba, buffer, length, offset);

	if (length > sizeof(msg)) {
		fctgt_err("Bad message len: %ld should be %ld\n", length, sizeof(msg));
		return -EINVAL;
	}

	if (copy_from_user(&msg, buffer, length))
		return -EINVAL;

	fctgt_info("msg: %s\n", ctl_msg_str[msg.hdr.msg_type]);

	switch (msg.hdr.msg_type) {
		case CTL_START:
			fctgt_dbg("Starting fip ctlr\n");
			if (!fctgt_ctl.started) {
				mlx4_fc_register_fip_ctlr(mlx4_fcoe_fip, NET_ETH);
				fctgt_ctl.started = 1;
			}
			break;

		case CTL_STOP:
			fctgt_dbg("Stopping fip ctlr\n");
			if (fctgt_ctl.started) {
				fctgt_ctl.started = 0;
				mlx4_fc_deregister_fip_ctlr(NET_ETH);
			}
			break;

		default:
			return -EINVAL;
	}

	return length;
}

static ssize_t fctgt_hba_read(struct mfc_vhba *vhba, char __user *buffer, size_t length,
		loff_t * offset)
{
	int ret = 0;
	struct fcoetgt_hba_msg *msg;

	msg = fctgt_hba_msg_get(vhba);
	if (!msg)
		return 0;

	if (length < msg->hdr.msg_len) {
		fctgt_err("read len too small: 0x%lx msg_len: 0x%x\n", length, msg->hdr.msg_len);
		ret = -EINVAL;
		goto out;
	}

	fctgt_info("%s\n", hba_msg_str[msg->hdr.msg_type]);
	if (msg->hdr.msg_type == HBA_RDMA_WRITE_DONE) {
		fctgt_dbg("write_done tgt_id = 0x%llx\n", msg->rdma_done.tgt_buf_id);
	}

	copy_to_user(buffer, msg, sizeof(struct fcoetgt_hba_hdr) + msg->hdr.msg_len);
	ret = sizeof(struct fcoetgt_hba_hdr) + msg->hdr.msg_len;

out:
	fctgt_hba_msg_free(msg);

	return ret;
}

static ssize_t fctgt_ctl_read(struct file *filp, char __user *buffer, size_t length,
		loff_t * offset)
{
	struct mfc_vhba *vhba = filp->private_data;
	struct fcoetgt_ctl_msg *msg;
	int ret = 0;

	if (*offset) {
		fctgt_err("offset need to be 0\n");
		return -EINVAL;
	}

	if (vhba)
		return fctgt_hba_read(vhba, buffer, length, offset);

	fctgt_dbg("Read from controller\n");

	msg = fctgt_ctl_msg_get(&fctgt_ctl);
	if (!msg) {
		fctgt_dbg("Nothing in Q\n");
		return 0;
	}

	if (length < msg->hdr.msg_len) {
		fctgt_err("read len too small: 0x%lx msg_len: 0x%x\n", length, msg->hdr.msg_len);
		ret = -EINVAL;
		goto out;
	}

	fctgt_info("msg: %s\n", ctl_msg_str[msg->hdr.msg_type]);
	copy_to_user(buffer, msg, sizeof(struct fcoetgt_ctl_hdr) + msg->hdr.msg_len);
	ret = sizeof(struct fcoetgt_ctl_hdr) + msg->hdr.msg_len;

out:
	fctgt_ctl_msg_free(msg);

	return ret;
}

static unsigned int fctgt_ctl_poll(struct file *filp, struct poll_table_struct *poll)
{
	unsigned int mask = 0;
	struct mfc_vhba *vhba = filp->private_data;

	if (vhba)
		return fctgt_vhba_poll(filp, vhba, poll);

	poll_wait(filp, &fctgt_ctl.wait, poll);

	spin_lock(&fctgt_ctl.lock);
	if (!list_empty(&fctgt_ctl.msg_queue))
		mask |= POLLIN;
	spin_unlock(&fctgt_ctl.lock);

	return mask;
}

static int fctgt_ctl_open(struct inode *inode, struct file *file)
{
	int rc = 0;

	if (iminor(inode)) {
		struct fctgt_vhba *tvhba = fctgt_vhba_get(iminor(inode) - FCTGT_MINOR_BASE);

		if (!tvhba) {
			fctgt_err("Bad vhba index: %d\n", iminor(inode));
			return -EINVAL;
		}
		return fctgt_vhba_open(tvhba->vhba, file);
	}
	fctgt_dbg("New fctgt\n");

	if (fctgt_ctl.ref_count++)
		return 0;

	try_module_get(THIS_MODULE);

	fctgt_ctl.started = 0;

	spin_lock_init(&fctgt_ctl.lock);
	INIT_LIST_HEAD(&fctgt_ctl.msg_queue);
	init_waitqueue_head(&fctgt_ctl.wait);

	memset(fctgt_ctl.vhbas, 0, sizeof(fctgt_ctl.vhbas));

	return rc;
}

static int fctgt_ctl_release(struct inode *inode, struct file *file)
{
	struct fcoetgt_ctl_msg *msg;

	fctgt_dbg("Close called\n");

	if (iminor(inode)) {
		struct fctgt_vhba *tvhba = fctgt_vhba_get(iminor(inode) - FCTGT_MINOR_BASE);
		int rc;

		fctgt_dbg("Closing vhba\n");
		rc = fctgt_vhba_release(tvhba->vhba, file);

		tvhba->vhba = NULL;

		return rc;
	}

	fctgt_dbg("Closing fctgt\n");

	fctgt_ctl.ref_count--;
	if (fctgt_ctl.ref_count)
		return 0;

	if (fctgt_ctl.started) {
		fctgt_ctl.started = 0;
		mlx4_fc_deregister_fip_ctlr(NET_ETH);
	}

	while ((msg = fctgt_ctl_msg_get(&fctgt_ctl))) {
		fctgt_dbg("Purged a ctl message\n");
		fctgt_ctl_msg_free(msg);
	}

	module_put(THIS_MODULE);

	fctgt_dbg("Close finished\n");
	return 0;
}

static struct file_operations fctgt_ctl_fops = {
	.read = fctgt_ctl_read,
	.write = fctgt_ctl_write,
	.open = fctgt_ctl_open,
	.poll = fctgt_ctl_poll,
	.release = fctgt_ctl_release,
};

int fctgt_dev_register(struct mfc_fip_ctlr *fip_ctrl)
{
	int major;
	mlx4_fcoe_fip = fip_ctrl;

	major = register_chrdev(0, FCTGT_CTL_DEV_NAME, &fctgt_ctl_fops);
	fctgt_dbg("Registered major: %d\n", major);
	if (major < 0) {
		printk(KERN_ALERT "Registering char device failed with %d\n", major);
		return major;
	}

	fctgt_ctl.major = major;

	return SUCCESS;
}

int fctgt_dev_deregister(void)
{
	int rc = 0;

	mlx4_fcoe_fip = NULL;

	fctgt_dbg("Deregistering major: %d\n", fctgt_ctl.major);
	rc = unregister_chrdev(fctgt_ctl.major, FCTGT_CTL_DEV_NAME);
	if (rc < 0)
		printk(KERN_ALERT "Error in unregister_chrdev: %d\n", rc);

	fctgt_ctl.major = -1;

	return rc;
}
