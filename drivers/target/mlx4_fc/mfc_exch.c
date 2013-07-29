/*
 * Copyright (c) 2010 Mellanox Technologies. All rights reserved.
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
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/log2.h>
#include <linux/delay.h>
#include <linux/vmalloc.h>
#include <scsi/scsi.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_transport.h>
#include <scsi/scsi_transport_fc.h>
#include <scsi/scsi_tcq.h>
#include <linux/mlx4/driver.h>
#include <linux/mlx4/cmd.h>
#include <linux/mlx4/cq.h>
#include <scsi/fc_frame.h>
#include <scsi/fc/fc_fcp.h>
#include <scsi/fc/fc_els.h>
#include <scsi/fc/fc_fcoe.h>
#include <scsi/libfc.h>

#include "mfc.h"

static void mfc_exch_tx_comp(void *arg, struct mlx4_cqe *g_cqe)
{
	struct mfc_vhba *vhba = (struct mfc_vhba *)arg;
	struct mfc_exch_cqe *cqe = (struct mfc_exch_cqe *)g_cqe;
	struct mfc_exch *fexch;
	struct mfc_queue *sq;
	int wqe_idx;
	int xno;
	u32 qpn;
	unsigned long flags;
	int is_err;
	struct trans_start *ts;
	u8 op = cqe->owner_sr_opcode & MLX4_CQE_OPCODE_MASK;

	qpn = be32_to_cpu(cqe->my_qpn) & ((1 << 24) - 1);
	xno = qpn - vhba->base_fexch_qpn;
	fexch = &vhba->fexch[xno];
	sq = &fexch->fc_qp.sq;
	ts = (struct trans_start *)fexch->context;

	wqe_idx = be16_to_cpu(cqe->wqe_index) & sq->size_mask;

	is_err = (op == 0x1e) ? 1 : 0;

	if (is_err /*&& vhba->fcmd.fc_qp.is_flushing*/) {
		struct mlx4_err_cqe *cqe_err = (struct mlx4_err_cqe *)g_cqe;

		if (cqe_err->syndrome != MLX4_CQE_SYNDROME_WR_FLUSH_ERR) {
			shost_printk(KERN_ERR, vhba->lp->host, "Completion with error. "
				"exch: 0x%x qpn: 0x%x wqe_index: 0x%x vendor: 0x%x syndrome: 0x%x\n",
				xno,
				be32_to_cpu(cqe_err->my_qpn),
				be16_to_cpu(cqe_err->wqe_index),
				cqe_err->vendor_err_syndrome,
				cqe_err->syndrome);
			HEXDUMP(cqe_err, sizeof(*cqe_err));
		}

		goto out;
	}


	fctgt_dbg_ts(ts, "TX completed. qpn: 0x%x, wqe_index: 0x%x, "
			"opcode: 0x%x\n", be32_to_cpu(cqe->my_qpn),
			be16_to_cpu(cqe->wqe_index), op);

	if (op == MFC_CMD_OP_RDMA_READ || op == MFC_RFCI_OP_SEND) {
		struct trans_start *ts = (struct trans_start *)fexch->context;

		if (ts && ts->done)
			ts->done(vhba, ts);
	}

out:
	if (op == MFC_RFCI_OP_SEND) {
		struct mfcoe_cmd_send_tx_desc *tx_desc = sq->buf + wqe_idx * FEXCH_SQ_BB_SIZE;
		struct trans_start *ts = (struct trans_start *)fexch->context;

		pci_unmap_single(vhba->mfc_port->mfc_dev->dev->pdev,
				be64_to_cpu(tx_desc->data.addr),
				be32_to_cpu(tx_desc->data.count),
				PCI_DMA_TODEVICE);

		kfree(ts->fcp_rsp);
		kfree(ts);
		fexch->context = NULL;

		mfc_bitmap_slot_free(&vhba->fexch_bm, xno);
		fctgt_dbg("Freeing slot #0x%x\n", xno);
	}

	fexch->tx_completed = 1;

	spin_lock_irqsave(&sq->lock, flags);
	sq->cons++;
	spin_unlock_irqrestore(&sq->lock, flags);

	mfc_ring_db_tx(&fexch->fc_qp);
}

static void mfc_exch_err_comp(void *arg, struct mlx4_cqe *g_cqe)
{
	struct mfc_vhba *vhba = (struct mfc_vhba *)arg;
	struct mlx4_err_cqe *cqe = (struct mlx4_err_cqe *)g_cqe;
	struct mfc_exch *fexch;
	struct mfc_queue *sq;
	int wqe_idx;
	int xno;
	u32 qpn;
	unsigned long flags;
	struct trans_start *ts;

	qpn = be32_to_cpu(cqe->my_qpn) & ((1 << 24) - 1);
	xno = qpn - vhba->base_fexch_qpn;
	fexch = &vhba->fexch[xno];
	sq = &fexch->fc_qp.sq;
	ts = (struct trans_start *)fexch->context;

	wqe_idx = be16_to_cpu(cqe->wqe_index) & sq->size_mask;


	if (cqe->syndrome != MLX4_CQE_SYNDROME_WR_FLUSH_ERR) {
		shost_printk(KERN_ERR, vhba->lp->host, "Completion with error. "
				"exch: 0x%x qpn: 0x%x wqe_index: 0x%x vendor: 0x%x syndrome: 0x%x\n",
				xno,
				be32_to_cpu(cqe->my_qpn),
				be16_to_cpu(cqe->wqe_index),
				cqe->vendor_err_syndrome,
				cqe->syndrome);
	}

	if (fexch->context) {
		struct mfcoe_cmd_send_tx_desc *tx_desc = sq->buf + wqe_idx * FEXCH_SQ_BB_SIZE;
		struct trans_start *ts = (struct trans_start *)fexch->context;

		pci_unmap_single(vhba->mfc_port->mfc_dev->dev->pdev,
				be64_to_cpu(tx_desc->data.addr),
				be32_to_cpu(tx_desc->data.count),
				PCI_DMA_TODEVICE);

		kfree(ts->fcp_rsp);
		kfree(ts);
		fexch->context = NULL;

		mfc_bitmap_slot_free(&vhba->fexch_bm, xno);
	}

	fexch->tx_completed = 1;

	spin_lock_irqsave(&sq->lock, flags);
	sq->cons++;
	spin_unlock_irqrestore(&sq->lock, flags);

	mfc_ring_db_tx(&fexch->fc_qp);
}

static void mfc_qp_event(struct mlx4_qp *qp, enum mlx4_event type)
{
	printk(KERN_WARNING "qp event for qpn=0x%08x event_type=0x%x\n",
	       qp->qpn, type);
}

static int mfc_create_fexch(struct mfc_vhba *vhba, int xno)
{
	struct mfc_port *fc_port = vhba->mfc_port;
	struct mfc_dev *mfc_dev = fc_port->mfc_dev;
	struct mfc_exch *fexch = &vhba->fexch[xno];
	struct mfc_qp *qp = &fexch->fc_qp;
	struct mfc_queue *sq = &qp->sq;
	struct mfc_queue *rq = &qp->rq;
	int err = 0;

	fexch->vhba = vhba;
	mfc_q_init(sq, FEXCH_SQ_BB_SIZE, FEXCH_SQ_NUM_BBS, 0);
	mfc_q_init(rq, FEXCH_RQ_WQE_SIZE, FEXCH_RQ_NUM_WQES, 0);

	qp->buf_size = (sq->size * sq->stride) + (rq->size * rq->stride);

	err = mlx4_alloc_hwq_res(mfc_dev->dev, &qp->wqres, qp->buf_size,
				 qp->buf_size);
	if (err) {
		shost_printk(KERN_ERR, vhba->lp->host,
			     "Alloc hwq_res fexch=%x vhba=%d port=%d err=%d\n",
			     xno, vhba->idx, fc_port->port, err);
		goto err_free_rxinfo;
	}

	if (FEXCH_SQ_BB_SIZE >= FEXCH_RQ_WQE_SIZE) {
		sq->buf = qp->wqres.buf.direct.buf;
		rq->buf = sq->buf + (sq->size * sq->stride);
	} else {
		rq->buf = qp->wqres.buf.direct.buf;
		sq->buf = rq->buf + (rq->size * rq->stride);
	}

	*qp->wqres.db.db = 0;

	mfc_stamp_q(sq);
	mfc_stamp_q(rq);

	err = mlx4_qp_alloc(mfc_dev->dev, vhba->base_fexch_qpn + xno, &qp->mqp);
	if (err) {
		shost_printk(KERN_ERR, vhba->lp->host,
			     "Alloc qp=%x fexch=%x vhba=%d port=%d err=%d\n",
			     qp->mqp.qpn, xno, vhba->idx, fc_port->port, err);
		goto err_free_man;
	}

	qp->doorbell_qpn = swab32(qp->mqp.qpn << 8);
	qp->mqp.event = mfc_qp_event;

	return 0;

err_free_man:
	mlx4_free_hwq_res(mfc_dev->dev, &qp->wqres, qp->buf_size);
err_free_rxinfo:
	mfc_q_destroy(rq);
	return err;
}

static int wait_for_q_comp(struct mfc_queue *q)
{
	unsigned long end;
	unsigned long flags;
	int err;

	end = jiffies + 20 * HZ;
	spin_lock_irqsave(&q->lock, flags);
	while ((int)(q->prod - q->cons) > 1) {
		spin_unlock_irqrestore(&q->lock, flags);
		msleep(1000 / HZ);
		if (time_after(jiffies, end))
			break;
		spin_lock_irqsave(&q->lock, flags);
	}

	if ((int)(q->prod - q->cons) > 1)
		err = 1;
	else
		err = 0;

	spin_unlock_irqrestore(&q->lock, flags);

	return err;
}

int wait_for_fexch_tx_comp(struct mfc_exch *fexch, struct mfc_cq *cq)
{
	int err;
	unsigned long end;
	unsigned long flags;

	end = jiffies + 20 * HZ;
	while (!fexch->tx_completed) {
		if (spin_trylock_irqsave(&cq->lock, flags)) {
			mfc_cq_clean(cq);
			spin_unlock_irqrestore(&cq->lock, flags);
		}

		msleep(1000 / HZ);

		if (time_after(jiffies, end))
			break;
	}
	if (!fexch->tx_completed)
		err = 1;
	else
		err = 0;

	return err;
}

int flush_qp(struct mfc_dev *mfc_dev, struct mfc_qp *qp, int is_sq,
	     int is_rq, struct mfc_cq *cq, struct mfc_exch *fexch)
{
	struct mfc_queue *sq = &qp->sq;
	struct mfc_queue *rq = &qp->rq;
	unsigned long flags;
	int err = 0;

	qp->is_flushing = 1;

	err = mlx4_qp_to_error(mfc_dev->dev, &qp->mqp);
	if (err) {
		dev_err(mfc_dev->dma_dev,
			"Move qpn=0x%x to error state err=%d\n",
			qp->mqp.qpn, err);
		return err;
	}

	/* if sq in use (FCMD, RFCI), wait for sq flush */
	if (is_sq) {
		if (cq)
			if (spin_trylock_irqsave(&cq->lock, flags)) {
				mfc_cq_clean(cq);
				spin_unlock_irqrestore(&cq->lock, flags);
			}

		err = wait_for_q_comp(sq);
		if (err)
			dev_err(mfc_dev->dma_dev,
				"Flush sendq get err=%d\n", err);
	}

	/* if rq in use (FEXCH, RFCI), wait for rq flush */
	if (is_rq) {
		if (cq) {
			if (spin_trylock_irqsave(&cq->lock, flags)) {
				mfc_cq_clean(cq);
				spin_unlock_irqrestore(&cq->lock, flags);
			}
		}
		if (fexch && !fexch->tx_completed) {
			err = wait_for_fexch_tx_comp(fexch, cq);
			if (err)
				dev_err(mfc_dev->dma_dev,
					"Flush fcmd tx err=%d\n", err);
		}

		err = wait_for_q_comp(rq);
		if (err)
			dev_err(mfc_dev->dma_dev,
				"Flush recvq get err=%d\n", err);

	}

	return err;
}

static int mfc_destroy_fexch(struct mfc_vhba *vhba, int xno)
{
	struct mfc_port *fc_port = vhba->mfc_port;
	struct mfc_dev *mfc_dev = fc_port->mfc_dev;
	struct mfc_exch *fexch = &vhba->fexch[xno];
	struct mfc_qp *qp = &fexch->fc_qp;
	struct mfc_queue *rq = &qp->rq;
	struct mfc_queue *sq = &qp->sq;
	struct mfc_cq *cq = &vhba->fexch_cq[xno % num_online_cpus()];
	int err = 0;

	if (qp->is_created) {
		err = flush_qp(mfc_dev, qp, 0, 1, cq, fexch);
		if (err) {
			shost_printk(KERN_ERR, vhba->lp->host,
				     "Flush qp fexch %x error=%d\n", xno, err);
			if (vhba->fexch_bm.addr)
				mfc_bitmap_slot_free(&vhba->fexch_bm, xno);
		}
	}

	if (qp->is_created)
		mlx4_qp_to_reset(mfc_dev->dev, &qp->mqp);

	qp->is_created = 0;
	mlx4_qp_remove(mfc_dev->dev, &qp->mqp);
	mlx4_qp_free(mfc_dev->dev, &qp->mqp);
	mlx4_free_hwq_res(mfc_dev->dev, &qp->wqres, qp->buf_size);
	mfc_q_destroy(rq);
	mfc_q_destroy(sq);

	return err;
}

int mfc_init_fexch(struct mfc_vhba *vhba, int xno)
{
	struct mfc_dev *mfc_dev = vhba->mfc_port->mfc_dev;
	struct mfc_exch *fexch = &vhba->fexch[xno];
	struct mfc_qp *qp = &fexch->fc_qp;
	enum mlx4_qp_state qp_state = MLX4_QP_STATE_RST;
	int err = 0;
	u8 sched_q = 0;
	struct mlx4_qp_context context;

	if (vhba->net_type == NET_IB)
		sched_q = 0x83 |
		    (vhba->dest_ib_sl & 0xf) << 3 |
		    (vhba->mfc_port->port - 1) << 6;
	else if (vhba->net_type == NET_ETH)
		sched_q = 0x83 |
		    vhba->fc_vlan_prio << 3 | (vhba->mfc_port->port - 1) << 6;

	context = (struct mlx4_qp_context) {
		.flags = cpu_to_be32(QPC_SERVICE_TYPE_FEXCH << 16),
		.pd = cpu_to_be32(mfc_dev->priv_pdn),
		/* Raw-ETH requirement */
		.mtu_msgmax = 0x77,
		/* this means SQ_NUM_BBS=1, and SQ_BB_SIZE=1 */
		.sq_size_stride = ilog2(FEXCH_SQ_NUM_BBS) << 3 |
				  ilog2(FEXCH_SQ_BB_SIZE >> 4) |
				  SQ_NO_PREFETCH,
		.rq_size_stride = 0,
		.usr_page = cpu_to_be32(mfc_dev->priv_uar.index),
		.local_qpn = cpu_to_be32(qp->mqp.qpn),
		.pri_path.sched_queue = sched_q,
		.pri_path.counter_index = 0xff,
		.pri_path.ackto = (vhba->net_type == NET_IB) ?
			MLX4_LINK_TYPE_IB : MLX4_LINK_TYPE_ETH,
		/* Source MAC index */
		.pri_path.grh_mylmc =  (vhba->net_type == NET_IB) ?
				       0 : vhba->fc_mac_idx,
		.params2 = cpu_to_be32((qp->wqres.buf.direct.map &
					(PAGE_SIZE - 1)) & 0xfc0),
		.cqn_send =
		    cpu_to_be32(vhba->fexch_cq[xno % num_online_cpus()].mcq.cqn),
		.cqn_recv =
		    cpu_to_be32(vhba->fexch_cq[xno % num_online_cpus()].mcq.cqn),
		.db_rec_addr = cpu_to_be64(qp->wqres.db.dma),
		.srqn = 0,
#if 0
		.my_fc_id_idx = vhba->idx,
#endif
		.qkey = cpu_to_be32(MLX4_FCOIB_QKEY),
#warning FIXME: Missing exch_base + exch_size in mlx4_qp_context
#if 0
		.exch_base = cpu_to_be32(qp->mqp.qpn),
		.exch_size = ilog2(1),
#endif
	};

	fexch->tx_completed = 1;
	if (vhba->fc_vlan_id != -1) {
		context.pri_path.fl = 0x40;
		context.pri_path.vlan_index = vhba->fc_vlan_idx;
	}

	err = mlx4_qp_to_ready(mfc_dev->dev, &qp->wqres.mtt, &context, &qp->mqp,
			       &qp_state);

	if (qp_state != MLX4_QP_STATE_RST)
		qp->is_created = 1;

	if (qp_state != MLX4_QP_STATE_RTS) {
		shost_printk(KERN_ERR, vhba->lp->host,
			     "Fail to move fexch=%x qp=%x to RTS\n",
			     xno, qp->mqp.qpn);
		err = -EINVAL;
		goto out;
	}

	INIT_LIST_HEAD(&fexch->list);

	fexch->fc_qp.is_flushing = 0;
out:
	return err;
}

int mfc_fill_abort_hdr(struct fc_frame *fp, u32 did, u32 sid,
		       u16 ox_id, u8 seq_id)
{

	struct fc_frame_header *fh;
	u16 fill;

	/* Fill header */
	fh = fc_frame_header_get(fp);
	fh->fh_r_ctl = FC_RCTL_BA_ABTS;
	hton24(fh->fh_d_id, did);
	hton24(fh->fh_s_id, sid);
	fh->fh_type = FC_TYPE_BLS;
	hton24(fh->fh_f_ctl, FC_FC_END_SEQ | FC_FC_SEQ_INIT);
	fh->fh_cs_ctl = 0;
	fh->fh_df_ctl = 0;
	fh->fh_ox_id = htons(ox_id);
	fh->fh_rx_id = htons(FC_XID_UNKNOWN);
	fh->fh_seq_id = seq_id;
	fh->fh_seq_cnt = 0;
	fh->fh_parm_offset = htonl(0);

	/* Fill SOF and EOF */
	fr_sof(fp) = FC_SOF_I3;	/* resume class 3 */
	fr_eof(fp) = FC_EOF_T;

	fill = fr_len(fp) & 3;
	if (fill) {
		fill = 4 - fill;
		/* TODO, this may be a problem with fragmented skb */
		skb_put(fp_skb(fp), fill);
		hton24(fh->fh_f_ctl, ntoh24(fh->fh_f_ctl) | fill);
	}

	return 0;
}

int mfc_send_abort_tsk(struct mfc_exch *fexch, u32 rport_id)
{
	struct fc_frame *fp;
	struct fc_lport *lp;
	struct mfc_vhba *vhba = fexch->vhba;
	int ox_id, err = 0, xno;

	/* check we can use rfci */
	if (vhba->lp->state != LPORT_ST_READY || fexch->fc_qp.is_flushing)
		return -EINVAL;

	/* Send abort packet via rfci */
	xno = fexch - vhba->fexch;
	ox_id = vhba->base_fexch_qpn + xno - vhba->mfc_port->base_fexch_qpn;
	lp = vhba->lp;
	fp = fc_frame_alloc(lp, 0);
	if (fp) {
		shost_printk(KERN_INFO, vhba->lp->host,
			     "Sending ABTS for 0x%x fexch\n", xno);

		/* TODO: find out if seq_id = 0 is OK */
		mfc_fill_abort_hdr(fp, rport_id,
				   fc_host_port_id(lp->host), ox_id, 0);
		err = mfc_frame_send(lp, fp);
	} else {
		shost_printk(KERN_ERR, vhba->lp->host,
			     "Fail to send ABTS for fexch=%x ox_id=%x\n",
			     xno, ox_id);
		err = -ENOMEM;
	}

	return err;
}

/*
 * re-init and free fexch bitmap, fexch should be ready for reuse.
 */
int mfc_reset_fexch(struct mfc_vhba *vhba, struct mfc_exch *fexch)
{
	int err = 0, xno;

	xno = fexch - vhba->fexch;

	err = mfc_destroy_fexch(vhba, xno);
	if (err) {
		shost_printk(KERN_ERR, vhba->lp->host,
			     "Fail to destroy fexch=%x vhba=%d port=%d\n",
			     xno, vhba->idx, vhba->mfc_port->port);
		goto out;
	}

	err = mfc_create_fexch(vhba, xno);
	if (err) {
		shost_printk(KERN_ERR, vhba->lp->host,
			     "Fail to recreate fexch=%x vhba=%d port=%d\n",
			     xno, vhba->idx, vhba->mfc_port->port);
		goto out;
	}

	err = mfc_init_fexch(vhba, xno);
	if (err) {
		shost_printk(KERN_ERR, vhba->lp->host,
			     "Fail to init fexch=%x vhba=%d port=%d\n",
			     xno, vhba->idx, vhba->mfc_port->port);
		mfc_destroy_fexch(vhba, xno);
		goto out;
	}

	fexch->state = FEXCH_OK;
	mfc_bitmap_slot_free(&vhba->fexch_bm, xno);
out:
	return err;

}

/*
 * Attention: This function could be called from interrupt context
 */
int mfc_create_fexchs(struct mfc_vhba *vhba)
{
	struct mfc_port *fc_port = vhba->mfc_port;
	struct mfc_dev *mfc_dev = fc_port->mfc_dev;
	int err = 0;
	int i, eqidx, cpu;

	/* Create FEXCHs this vhba */
	vhba->fexch = vmalloc(vhba->num_fexch * sizeof(struct mfc_exch));
	if (!vhba->fexch) {
		shost_printk(KERN_ERR, vhba->lp->host,
			     "Fail to alloc fexchs vhba=%d port=%d err=%d\n",
			     vhba->idx, fc_port->port, err);
		goto err_out;

	}
	memset(vhba->fexch, 0, vhba->num_fexch * sizeof(struct mfc_exch));
	for (i = 0; i < vhba->num_fexch; i++) {
		vhba->fexch[i].response_buf =
		    kmalloc(MFC_CMD_RX_SKB_BUFSIZE, GFP_KERNEL);
		if (!vhba->fexch[i].response_buf) {
			shost_printk(KERN_ERR, vhba->lp->host,
				     "Fail to alloc fexch=%x for vhba=%d port=%d\n",
				     i, vhba->idx, fc_port->port);
			goto err_free_fexch_arr;
		}
	}

	err = mfc_bitmap_alloc(&vhba->fexch_bm, vhba->num_fexch);
	if (err) {
		shost_printk(KERN_ERR, vhba->lp->host,
			     "Fail to alloc fexch bitmap vhba=%d port=%d err=%d\n",
			     vhba->idx, fc_port->port, err);
		goto err_free_fexch_arr;
	}

	eqidx = 0;
	for_each_online_cpu(cpu) {
		err = mfc_create_cq(mfc_dev, &vhba->fexch_cq[eqidx],
				    vhba->num_fexch / num_online_cpus(),
				    (eqidx % num_online_cpus()) %
				     mfc_dev->dev->caps.num_comp_vectors,
				     1, NULL, mfc_exch_tx_comp, mfc_exch_err_comp, vhba, "FEXCH");
		if (err) {
			shost_printk(KERN_ERR, vhba->lp->host,
				     "Fail to create cq=%x vhba=%d port=%d err=%d\n",
				     eqidx, vhba->idx, fc_port->port, err);
			goto err_destroy_fexch_cq;
		}

		++eqidx;
	}

	for (i = 0; i < vhba->num_fexch; i++) {
		err = mfc_create_fexch(vhba, i);
		if (err) {
			shost_printk(KERN_ERR, vhba->lp->host,
				     "Fail to create fexch=%x vhba=%d port=%d err=%d\n",
				     i, vhba->idx, fc_port->port, err);
			goto err_destroy_fexch;
		}
	}

	return 0;

err_destroy_fexch:
	while (--i >= 0)
		mfc_destroy_fexch(vhba, i);
err_destroy_fexch_cq:
	while (--eqidx >= 0)
		mfc_destroy_cq(&vhba->fexch_cq[eqidx]);
	mfc_bitmap_free(&vhba->fexch_bm);
err_free_fexch_arr:
	for (i = 0; i < vhba->num_fexch; i++) {
		if (!vhba->fexch[i].response_buf)
			break;
		kfree(vhba->fexch[i].response_buf);
	}
	vfree(vhba->fexch);
err_out:
	return err;
}

void mfc_destroy_fexchs(struct mfc_vhba *vhba)
{
	int i;

	for (i = 0; i < vhba->num_fexch; ++i)
		mfc_destroy_fexch(vhba, i);

	for (i = 0; i < num_online_cpus(); ++i)
		mfc_destroy_cq(&vhba->fexch_cq[i]);

	if (!mfc_bitmap_empty(&vhba->fexch_bm))
		shost_printk(KERN_ERR, vhba->lp->host,
			     "Uncomplete exchanges while destroying vhba: %s\n",
			     mfc_bitmap_print(&vhba->fexch_bm));

	mfc_bitmap_free(&vhba->fexch_bm);

	for (i = 0; i < vhba->num_fexch; i++) {
		if (!vhba->fexch[i].response_buf)
			break;
		kfree(vhba->fexch[i].response_buf);
	}
	vfree(vhba->fexch);
}

int mfc_reset_fexchs(struct mfc_vhba *vhba)
{
	int err = 0;

	mfc_destroy_fexchs(vhba);
	err = mfc_create_fexchs(vhba);
	if (err)
		shost_printk(KERN_ERR, vhba->lp->host,
			     "Fail to create fexchs vhba=%d port=%d err=%d\n",
			     vhba->idx, vhba->mfc_port->port, err);

	return err;
}

int mfc_init_fexchs(struct mfc_vhba *vhba)
{
	int rc = 0;
	int i;

	/* bring FEXCHs to ready state */
	for (i = 0; i < vhba->num_fexch; i++) {
		rc = mfc_init_fexch(vhba, i);
		if (rc) {
			shost_printk(KERN_ERR, vhba->lp->host,
				     "Fail to init fexch=%x vhba=%d port=%d err=%d\n",
				     i, vhba->idx, vhba->mfc_port->port, rc);
			goto out;
		}
	}

out:
	return rc;
}

static inline void set_ctrl_seg(struct mfc_ctrl_seg *ctrl, int size,
				u8 seqid, u8 info, u8 ls, u32 task_retry_id, u8 sit)
{
	ctrl->size = cpu_to_be16(((size / 16) & 0x3f) | (sit << 7));
	ctrl->flags = cpu_to_be32(MFC_BIT_TX_COMP |	/* request completion */
				  (seqid << 24) | (info << 20) | (ls << 16));
	ctrl->parameter = cpu_to_be32(task_retry_id);
}

static inline int prepare_fexch(struct mfc_vhba *vhba)
{
	struct mfc_exch *fexch;
	struct mfc_dev *mfc_dev = vhba->mfc_port->mfc_dev;
	int fexch_idx;
	int rc = 0;
	int index;

	fexch_idx = mfc_bitmap_slot_alloc(&vhba->fexch_bm, 1);
	if (fexch_idx == -1) {
		shost_printk(KERN_ERR, vhba->lp->host,
			     "No free fexch on vhba=%d port=%d\n",
			     vhba->idx, vhba->mfc_port->port);
		rc = -ENOMEM;
		goto err_out;
	}

	fexch = &vhba->fexch[fexch_idx];

	fexch->state = FEXCH_OK;
	fexch->tx_completed = 0;

	index = mfc_post_rx_buf(mfc_dev, &fexch->fc_qp, fexch->response_buf,
				MFC_CMD_RX_SKB_BUFSIZE);
	if (index < 0) {
		mfc_bitmap_slot_free(&vhba->fexch_bm, fexch_idx);
		rc = -ENOMEM;
		goto err_out;
	}

	mfc_ring_db_rx(&fexch->fc_qp);

	return fexch_idx;
err_out:
	return rc;
}

static inline void set_init_seg(struct mfc_init_seg *init, u8 prio, int
		frame_size, u32 remote_fid, u8 org, int data_dir,
		int local_xid, u16 remote_xid)
{
	init->pe = 0;		/* priority enable, goes to F_CTL[17] */
	init->cs_ctl = 0;	/* CS_CTL/Priority field */
	init->seq_id_tx = 0;	/* seq. id to be used in FCP_DATA frames */
	init->mtu = cpu_to_be16(frame_size / 4);
	init->remote_fid[2] = (remote_fid) & 0xff;
	init->remote_fid[1] = (remote_fid >> 8) & 0xff;
	init->remote_fid[0] = (remote_fid >> 16) & 0xff;

	init->flags = (org << 1) | /* org */
		      (data_dir << 3) | /* op */
		      (0 << 6);  /* abort */

	init->remote_exch = cpu_to_be16(remote_xid);
	/* alloc free exchange, put index here */
	init->local_exch_idx = cpu_to_be16(local_xid);
}

static inline void set_eth_dgram_seg(struct mfc_eth_addr_seg *addr, u8 vlan_prio, u8 * dmac)
{
	addr->static_rate = 0;
	addr->vlan_prio = vlan_prio << 4;
	memcpy(&addr->dmac, dmac, ETH_ALEN);
}

static inline void set_ib_dgram_seg(struct mfc_datagram_seg *dgram,
				    int dest_lid, int dest_sl,
				    unsigned long dest_qpn)
{
	dgram->mlid_grh = 0;	/* no GRH */
	dgram->rlid = cpu_to_be16(dest_lid);	/* remote LID */
	dgram->stat_rate = 0;	/* no rate limit */
	dgram->sl_tclass_flabel = cpu_to_be32(dest_sl << 28);
	dgram->dqpn = cpu_to_be32(dest_qpn);
}

static inline void mfc_prep_init_wqe(struct mfc_vhba *vhba, int prod, u32
		rport_id, u32 rport_maxframe_size, int local_xid,
		int remote_xid, enum mfc_tgt_trans_type ttype)
{
	struct mfc_exch *fexch = &vhba->fexch[local_xid];
	struct mfc_queue *sq = &fexch->fc_qp.sq;
	int wqe_index = prod & sq->size_mask;
	struct mfcoe_cmd_tx_desc *tx_desc;
	struct mfc_ctrl_seg *ctrl = NULL;
	struct mfc_init_seg *init = NULL;
	struct trans_start *ts = (struct trans_start *)fexch->context;

	fctgt_dbg_ts(ts, "Preparing init wqe. wqe_index: %d qpn: 0x%x\n", wqe_index, fexch->fc_qp.mqp.qpn);

	tx_desc = sq->buf + wqe_index * FEXCH_SQ_BB_SIZE;
	ctrl = &tx_desc->ctrl;
	init = &tx_desc->init;

	set_ctrl_seg(ctrl,
			sizeof(struct mfcoe_cmd_tx_desc),
			wqe_index, /* seq id */
			ttype == MFC_TGT_RDMA_WRITE ? 1 : 5,
			0,
			0,
			0);

	set_eth_dgram_seg(&tx_desc->addr, vhba->fc_vlan_prio, vhba->dest_addr);

	set_init_seg(init,
			0,
			rport_maxframe_size,
			rport_id,
			0, /* Org */
			3, /* Write Enable + Read enable */
			0 /* local_xid */,
			remote_xid);

	/*
	 * Ensure new descirptor (and ownership of next descirptor) hits memory
	 * before setting ownership of this descriptor to HW
	 */
	wmb();
	ctrl->op_own = cpu_to_be32(MFC_CMD_OP_INIT) |
		(prod & sq->size ? cpu_to_be32(MFC_BIT_DESC_OWN) : 0);

//	HEXDUMP(tx_desc, sizeof(*tx_desc));
}

static inline int mfc_prep_rdma_wqe(struct mfc_vhba *vhba,
		int prod,
		u32 rport_id,
		u32 rport_maxframe_size,
		int local_xid, int remote_xid,
		u64 offset, u32 key, int buf_len, enum mfc_tgt_trans_type ttype)
{
	struct mfc_exch *fexch = &vhba->fexch[local_xid];
	struct mfc_queue *sq = &fexch->fc_qp.sq;
	int wqe_index = prod & sq->size_mask;
	struct mfcoe_cmd_rdma_desc *tx_desc = sq->buf + wqe_index * FEXCH_SQ_BB_SIZE;
	struct mfc_ctrl_seg *ctrl = &tx_desc->ctrl;
	struct mfc_data_seg *data = &tx_desc->data;
	struct trans_start *ts = (struct trans_start *)fexch->context;

	fctgt_dbg_ts(ts, "Preparing rdma wqe. wqe_index: %d\n", wqe_index);

	set_ctrl_seg(ctrl,
			sizeof(struct mfcoe_cmd_rdma_desc),
			wqe_index, /* seq id */
			ttype == MFC_TGT_RDMA_WRITE ? 1 : 5,
			0,
			0,
			ttype == MFC_TGT_RDMA_WRITE ? 0 : 1);


	data->addr = cpu_to_be64(offset);
	data->count = cpu_to_be32(buf_len);
	data->mem_type = cpu_to_be32(key);

	wmb();
	ctrl->op_own =
		cpu_to_be32(ttype == MFC_TGT_RDMA_WRITE ? MFC_CMD_OP_RDMA_WRITE : MFC_CMD_OP_RDMA_READ) |
		(prod & sq->size ? cpu_to_be32(MFC_BIT_DESC_OWN) : 0);

//	HEXDUMP(tx_desc, sizeof(*tx_desc));

	return 0;
}

static inline int mfc_prep_send_wqe(struct mfc_vhba *vhba, int local_xid, int prod,
		u8 *buf, int buf_len)
{
	struct mfc_dev *mfc_dev = vhba->mfc_port->mfc_dev;
	struct mfc_exch *fexch = &vhba->fexch[local_xid];
	struct mfc_queue *sq = &fexch->fc_qp.sq;
	int wqe_index = prod & sq->size_mask;
	struct mfcoe_cmd_send_tx_desc *tx_desc;
	struct mfc_ctrl_seg *ctrl = NULL;
	struct mfc_data_seg *data = NULL;
	dma_addr_t dma;
	struct trans_start *ts = (struct trans_start *)fexch->context;

	fctgt_dbg_ts(ts, "Preparing send wqe. wqe_index: %d\n", wqe_index);

	tx_desc = sq->buf + wqe_index * FEXCH_SQ_BB_SIZE;
	ctrl = &tx_desc->ctrl;
	data = &tx_desc->data;

	set_ctrl_seg(ctrl,
			sizeof(struct mfcoe_cmd_send_tx_desc),
			wqe_index, /* seq id */
			7,
			1,
			0,
			0);

	dma = pci_map_single(mfc_dev->dev->pdev, buf, buf_len, PCI_DMA_TODEVICE);
	if (pci_dma_mapping_error(mfc_dev->dev->pdev, dma))
		return -EINVAL;

	data->addr = cpu_to_be64(dma);
	data->count = cpu_to_be32(buf_len);
	data->mem_type = cpu_to_be32(mfc_dev->mr.key);	/* always snoop */

	/*
	 * Ensure new descirptor (and ownership of next descirptor) hits memory
	 * before setting ownership of this descriptor to HW
	 */
	wmb();
	ctrl->op_own = cpu_to_be32(MFC_RFCI_OP_SEND) |
		(prod & sq->size ? cpu_to_be32(MFC_BIT_DESC_OWN) : 0);

//	HEXDUMP(tx_desc, sizeof(*tx_desc));

	return 0;
}

int mfc_send_data(struct mfc_vhba *vhba, struct trans_start *ts)
{
	struct mfc_dev *mfc_dev = vhba->mfc_port->mfc_dev;
	struct fc_lport *lp = vhba->lp;
	struct mfc_exch *fexch;
	struct mlx4_dev *mdev;
	struct mfc_queue *sq;
	int wqes_needed;

	u32 prod;
	unsigned long flags;
	int rc;

	u32 rport_maxframe_size = 2112;

	if (vhba->going_down) {
		printk(KERN_ERR "queuecommand while going down\n");
		return -EBUSY;
	}

	if ((lp->state != LPORT_ST_READY) || lp->qfull || !lp->link_up) {
		shost_printk(KERN_ERR, lp->host,
			     "lport state=%d qfull=%d link_up=%d\n",
			lp->state, lp->qfull, lp->link_up);
		return -EBUSY;
	}

	mfc_dev = vhba->mfc_port->mfc_dev;
	mdev = mfc_dev->dev;

	/* prepare FEXCH for command */

	fexch = &vhba->fexch[ts->local_exch_id];
	ts->local_exch_id = ts->local_exch_id;

	fexch->state = FEXCH_OK;
	fexch->tx_completed = 0;

	sq = &fexch->fc_qp.sq;

	wqes_needed = ts->xfer_len > 0 ? 2 : 1;

	/* Check available SQ BBs + 1 spare SQ BB for owenership */
	spin_lock_irqsave(&sq->lock, flags);
	if (unlikely((u32) (sq->prod - sq->cons - 1) > sq->size - 1 - wqes_needed)) {
		spin_unlock_irqrestore(&sq->lock, flags);
		rc = -EBUSY;
		goto err_slot_free;
	}

	prod = sq->prod;
	sq->prod += wqes_needed;
	spin_unlock_irqrestore(&sq->lock, flags);

	/* INIT initialize FEXCH */
	mfc_prep_init_wqe(vhba, prod, ts->rport_id, rport_maxframe_size,
		       ts->local_exch_id, ts->remote_exch_id, ts->type);
	prod++;

	if (ts->xfer_len > 0) {
		/* RDMA Issue RDMA read/write */
		mfc_prep_rdma_wqe(vhba, prod, ts->rport_id,
				rport_maxframe_size, ts->local_exch_id,
				ts->remote_exch_id, ts->offset, ts->key,
				ts->xfer_len, ts->type);
		prod++;
	}

	/* Ring doorbell! */
	wmb();
	writel(fexch->fc_qp.doorbell_qpn,
	       mfc_dev->uar_map + MLX4_SEND_DOORBELL);

	return 0;

err_slot_free:
	mfc_bitmap_slot_free(&vhba->fexch_bm, ts->local_exch_id);

	return rc;
}
EXPORT_SYMBOL(mfc_send_data);

int mfc_send_resp(struct mfc_vhba *vhba, struct trans_start *ts)
{
	struct mfc_dev *mfc_dev = vhba->mfc_port->mfc_dev;
	struct mfc_exch *fexch;
	struct mfc_queue *sq;

	u32 prod;
	unsigned long flags;
	int rc = 0;

	fexch = &vhba->fexch[ts->local_exch_id];

	sq = &fexch->fc_qp.sq;

	spin_lock_irqsave(&sq->lock, flags);
	if (unlikely((u32) (sq->prod - sq->cons - 1) > sq->size - 2)) {
		spin_unlock_irqrestore(&sq->lock, flags);
		rc = -EBUSY;
		goto err;
	}

	prod = sq->prod;
	sq->prod += 1;
	spin_unlock_irqrestore(&sq->lock, flags);

	/* SEND send FCP_RSP */
	mfc_prep_send_wqe(vhba, ts->local_exch_id, prod,
		       ts->fcp_rsp, ts->fcp_rsp_len);

	/* Ring doorbell! */
	wmb();
	writel(fexch->fc_qp.doorbell_qpn,
	       mfc_dev->uar_map + MLX4_SEND_DOORBELL);

err:
	return rc;
}
EXPORT_SYMBOL(mfc_send_resp);
