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
#include <linux/etherdevice.h>

#include <linux/mlx4/driver.h>
#include <linux/mlx4/cmd.h>
#include <linux/mlx4/qp.h>
#include <linux/mlx4/cq.h>

#include <scsi/libfc.h>
#include <scsi/fc_encode.h>

#include "mfc.h"
#include "mlx4_EN_includes.h"
#include "fip_ctlr_api.h"

#define MLX4_CQE_QPN_MASK 0x00ffffff

extern struct mfc_fip_ctlr fip_ctlrs[]; /* 0=IB ctlr, 1=ETH ctlr */

u8 fc_fid_flogi[] = { 0xff, 0xff, 0xfe };

static void mfc_rx_rfci(struct work_struct *work);

struct sk_buff *mfc_alloc_fc_frame(struct mfc_vhba *vhba)
{
	struct sk_buff *skb;
	struct mfc_rfci_rx_info *fr;

	skb = dev_alloc_skb(MFC_RFCI_RX_SKB_BUFSIZE +
			    sizeof(struct mfc_rfci_rx_info));
	if (!skb) {
		shost_printk(KERN_ERR, vhba->lp->host,
			     "Fail alloc skb vhba=%d port=%d\n",
			     vhba->idx, vhba->mfc_port->port);
		return ERR_PTR(-ENOMEM);
	}

	skb_reserve(skb, sizeof(struct mfc_rfci_rx_info));

	fr = (struct mfc_rfci_rx_info *)skb->head;
	fr->vhba = vhba;
	fr->skb = skb;

	return skb;
}
EXPORT_SYMBOL(mfc_alloc_fc_frame);

static int mfc_prepare_rx_buf(struct mfc_vhba *vhba, struct mfc_rfci *rfci)
{
	struct mfc_queue *rq = &rfci->fc_qp.rq;
	struct sk_buff *skb;
	int index, rc = 0;

	skb = mfc_alloc_fc_frame(vhba);
	if (IS_ERR(skb)) {
		rc = PTR_ERR(skb);
		goto err_out;
	}

	index = mfc_post_rx_buf(vhba->mfc_port->mfc_dev, &rfci->fc_qp,
				skb->data, MFC_RFCI_RX_SKB_BUFSIZE);
	if (index < 0) {
		rc = index;
		goto err_out;
	}

	mfc_q_info_get(rq, index, struct sk_buff *) = skb;

err_out:
	return rc;
}

static void mfc_rfci_unpost_rx_bufs(struct mfc_dev *mfc_dev,
				    struct mfc_queue *rq)
{
	int i;
	unsigned long flags;

	spin_lock_irqsave(&rq->lock, flags);
	for (i = 0; i < rq->size; i++) {
		struct sk_buff *skb;

		skb = mfc_q_info_get(rq, i, struct sk_buff *);
		if (!skb)
			continue;

		mfc_q_info_get(rq, i, struct sk_buff *) = NULL;

		kfree_skb(skb);
	}
	spin_unlock_irqrestore(&rq->lock, flags);
}

static void mfc_rfci_tx_comp(void *arg, struct mlx4_cqe *cqe)
{
	struct mfc_vhba *vhba = (struct mfc_vhba *)arg;
	struct mfc_rfci *rfci = &vhba->rfci;
	struct mfc_queue *sq = &rfci->fc_qp.sq;
	struct sk_buff *skb;
	u32 index;
	unsigned long flags;
	u64 dma = 0;
	u32 count = 0;

	index = be16_to_cpu(cqe->wqe_index) & sq->size_mask;

	if (vhba->net_type == NET_IB) {
		struct mfcoib_rfci_tx_desc *tx_desc;

		tx_desc = sq->buf + index * RFCI_SQ_BB_SIZE;
		dma = be64_to_cpu(tx_desc->data.addr);
		count = be32_to_cpu(tx_desc->data.count);
	} else if (vhba->net_type == NET_ETH) {
		struct mfcoe_rfci_tx_desc *tx_desc;

		tx_desc = sq->buf + index * RFCI_SQ_BB_SIZE;
		dma = be64_to_cpu(tx_desc->data.addr);
		count = be32_to_cpu(tx_desc->data.count);
	}

	pci_unmap_single(vhba->mfc_port->mfc_dev->dev->pdev,
			 dma, count, PCI_DMA_TODEVICE);

	skb = mfc_q_info_get(sq, index, struct sk_buff *);
	mfc_q_info_get(sq, index, struct sk_buff *) = NULL;
	kfree_skb(skb);

	spin_lock_irqsave(&sq->lock, flags);
	++sq->cons;
	spin_unlock_irqrestore(&sq->lock, flags);
}

static void mfc_rfci_rx_comp(void *arg, struct mlx4_cqe *cqe)
{
	struct mfc_vhba *vhba = (struct mfc_vhba *)arg;
	struct mfc_rfci *rfci = &vhba->rfci;
	struct mfc_queue *rq = &rfci->fc_qp.rq;
	struct mfc_rx_desc *rx_desc;
	u32 index;
	int len;
	unsigned long flags;
	struct sk_buff *skb;
	struct mfc_rfci_rx_info *fr;
	int err;

	index = be16_to_cpu(cqe->wqe_index) & rq->size_mask;
	rx_desc = rq->buf + (index * rq->stride);
	pci_unmap_single(vhba->mfc_port->mfc_dev->dev->pdev,
			 be64_to_cpu(rx_desc->data[0].addr),
			 be32_to_cpu(rx_desc->data[0].count),
			 PCI_DMA_FROMDEVICE);

	spin_lock_irqsave(&rq->lock, flags);
	rfci->fc_qp.rq.cons++;
	spin_unlock_irqrestore(&rq->lock, flags);

	skb = mfc_q_info_get(rq, index, struct sk_buff *);
	if (!skb) {
		if ((cqe->owner_sr_opcode & MLX4_CQE_OPCODE_MASK) == 0x1e)
			shost_printk(KERN_ERR, vhba->lp->host,
				     "RFCI qp=%x err compl vhba=%d port=%d\n",
				     rfci->fc_qp.mqp.qpn, vhba->idx,
				     vhba->mfc_port->port);
		goto out;
	}

	mfc_q_info_get(rq, index, struct sk_buff *) = NULL;

	if (vhba->lp->state == LPORT_ST_RESET ||
	    vhba->lp->state == LPORT_ST_DISABLED || rfci->fc_qp.is_flushing) {
		goto out;
	}

	if (!vhba->rfci_rx_enabled) {
		shost_printk(KERN_ERR, vhba->lp->host,
			     "RFCI rx hasn't enabled vhba=%d port=%d\n",
			     vhba->idx, vhba->mfc_port->port);
		err = mfc_prepare_rx_buf(vhba, rfci);
		if (err) {
			shost_printk(KERN_ERR, vhba->lp->host,
				     "No mem, drop rx packet vhba=%d port=%d\n",
				     vhba->idx, vhba->mfc_port->port);
			goto free_skb;
		}

		mfc_ring_db_rx(&rfci->fc_qp);
		goto free_skb;
	}

	len = be32_to_cpu(cqe->byte_cnt);
	fr = (struct mfc_rfci_rx_info *)skb->head;

	skb_put(skb, len);
	skb_set_mac_header(skb, 0);

	if (vhba->net_type == NET_IB)
		skb_pull(skb, 0x2a);	/* 40 byte GRH, 2 byte reserved */
	else if (vhba->net_type == NET_ETH)
		skb_pull(skb, ETH_HLEN);

	INIT_WORK(&fr->work, mfc_rx_rfci);
	queue_work(vhba->mfc_port->rfci_wq, &fr->work);

	err = mfc_prepare_rx_buf(vhba, rfci);
	if (err)
		goto free_skb;

	mfc_ring_db_rx(&rfci->fc_qp);

	goto out;

free_skb:
	if (skb)
		kfree_skb(skb);
out:
	return;
}

static void mfc_rfci_err_comp(void *arg, struct mlx4_cqe *cqe)
{
	mfc_rfci_rx_comp(arg, cqe);
}

static u64 mac_to_u64(u8 *mac)
{
	int i;
	u64 ret = 0;

	for (i = 0; i < 6; i++) {
		ret <<= 8;
		ret |= mac[i];
	}
	return ret;
}

int mfc_create_rfci(struct mfc_vhba *vhba)
{
	struct mfc_rfci *rfci = &vhba->rfci;
	struct mfc_port *fc_port = vhba->mfc_port;
	struct mfc_dev *mfc_dev = fc_port->mfc_dev;
	struct mfc_qp *qp = &rfci->fc_qp;
	struct mfc_queue *sq = &qp->sq;
	struct mfc_queue *rq = &qp->rq;
	u32 qpn = 0;
	int err = 0;
	int i;

	err = mfc_q_init(sq, RFCI_SQ_BB_SIZE, mfc_num_reserved_xids,
			 sizeof(struct sk_buff *));
	if (err) {
		shost_printk(KERN_ERR, vhba->lp->host,
			     "Init rfci sq vhba=%d port=%d err=%d\n",
			     vhba->idx, fc_port->port, err);
		goto err;
	}

	err = mfc_q_init(rq, RFCI_RQ_WQE_SIZE, mfc_num_reserved_xids,
			 sizeof(struct sk_buff *));
	if (err) {
		shost_printk(KERN_ERR, vhba->lp->host,
			     "Init rfci rq vhba=%d port=%d err=%d\n",
			     vhba->idx, fc_port->port, err);
		err = -ENOMEM;
		goto err_free_txinfo;
	}

	qp->buf_size = (sq->size * sq->stride) + (rq->size * rq->stride);

	err = mlx4_alloc_hwq_res(mfc_dev->dev, &qp->wqres, qp->buf_size,
				 qp->buf_size);
	if (err)
		goto err_free_rxinfo;

	if (RFCI_SQ_BB_SIZE >= RFCI_RQ_WQE_SIZE) {
		sq->buf = qp->wqres.buf.direct.buf;
		rq->buf = sq->buf + (sq->size * sq->stride);
	} else {
		rq->buf = qp->wqres.buf.direct.buf;
		sq->buf = rq->buf + (rq->size * rq->stride);
	}

	*qp->wqres.db.db = 0;

	mfc_stamp_q(sq);
	mfc_stamp_q(rq);

	qpn = fc_port->base_rfci_qpn + vhba->idx;

	err = mlx4_qp_alloc(mfc_dev->dev, qpn, &rfci->fc_qp.mqp);
	if (err) {
		shost_printk(KERN_ERR, vhba->lp->host,
			     "Alloc rfci qp=%x vhba=%d port=%d err=%d\n",
			     qpn, vhba->idx, fc_port->port, err);
		goto err_free_man;
	}

	qp->doorbell_qpn = swab32(qp->mqp.qpn << 8);

	err = mfc_create_cq(mfc_dev, &rfci->fc_cq, 2 * mfc_num_reserved_xids,
			    0, 1, mfc_rfci_rx_comp, mfc_rfci_tx_comp, mfc_rfci_err_comp, vhba, "RFCI");
	if (err) {
		shost_printk(KERN_ERR, vhba->lp->host,
			     "Create cq rfci vhba=%d port=%d err=%d\n",
			     vhba->idx, fc_port->port, err);
		goto err_free_qp;
	}

	for (i = 0; i < rq->size - 1; i++) {
		err = mfc_prepare_rx_buf(vhba, rfci);
		if (err) {
			shost_printk(KERN_ERR, vhba->lp->host,
				     "Prepare rx_buf=%d rfci vhba=%d"
				     " port=%d err=%d\n",
				     i, vhba->idx, fc_port->port, err);
			goto err_free_cq;
		}
	}

	mfc_ring_db_rx(&rfci->fc_qp);

	rfci->created = 1;

	return 0;

err_free_cq:
	mfc_rfci_unpost_rx_bufs(mfc_dev, &rfci->fc_qp.rq);
	mfc_destroy_cq(&rfci->fc_cq);
err_free_qp:
	mlx4_qp_remove(mfc_dev->dev, &qp->mqp);
	mlx4_qp_free(mfc_dev->dev, &qp->mqp);
err_free_man:
	mlx4_free_hwq_res(mfc_dev->dev, &qp->wqres, qp->buf_size);
err_free_rxinfo:
	mfc_q_destroy(rq);
err_free_txinfo:
	mfc_q_destroy(sq);
err:
	return err;
}

int mfc_destroy_rfci(struct mfc_vhba *vhba)
{
	struct mfc_rfci *rfci = &vhba->rfci;
	struct mfc_port *fc_port = vhba->mfc_port;
	struct mfc_dev *mfc_dev = fc_port->mfc_dev;
	struct mfc_qp *qp = &rfci->fc_qp;
	struct mfc_queue *sq = &qp->sq;
	struct mfc_queue *rq = &qp->rq;
	int err;

	if (!rfci->created)
		return 0;
	if (qp->is_created) {
		err = flush_qp(mfc_dev, qp, 1, 1, &rfci->fc_cq, NULL);
		if (err) {
			shost_printk(KERN_ERR, vhba->lp->host,
				     "Flush rfci qp vhba=%d port=%d err=%d\n",
				     vhba->idx, fc_port->port, err);
			return err;
		}
	}

	mfc_destroy_cq(&rfci->fc_cq);
	if (qp->is_created)
		mlx4_qp_to_reset(mfc_dev->dev, &qp->mqp);
	qp->is_created = 0;
	mlx4_qp_remove(mfc_dev->dev, &qp->mqp);
	mlx4_qp_free(mfc_dev->dev, &qp->mqp);
	mlx4_free_hwq_res(mfc_dev->dev, &qp->wqres, qp->buf_size);

	mfc_rfci_unpost_rx_bufs(mfc_dev, &rfci->fc_qp.rq);

	mfc_q_destroy(rq);
	mfc_q_destroy(sq);

	return 0;
}

int mfc_init_rfci(struct mfc_vhba *vhba)
{
	struct mfc_rfci *rfci = &vhba->rfci;
	struct mfc_port *fc_port = vhba->mfc_port;
	struct mfc_dev *mfc_dev = fc_port->mfc_dev;
	struct mfc_qp *qp = &rfci->fc_qp;
	enum mlx4_qp_state qp_state = MLX4_QP_STATE_RST;
	int err = 0;
	u8 sched_q = 0;
	struct mlx4_qp_context context;

	if (vhba->net_type == NET_IB)
		sched_q = 0x83 |
		    (vhba->dest_ib_sl & 0xf) << 2 | (fc_port->port - 1) << 6;
	else if (vhba->net_type == NET_ETH)
		sched_q = 0x83 |
		    (vhba->fc_vlan_prio & 0xf) << 2 | (fc_port->port - 1) << 6;

	context = (struct mlx4_qp_context) {
		.flags = cpu_to_be32(QPC_SERVICE_TYPE_RFCI << 16),
		.pd = cpu_to_be32(mfc_dev->priv_pdn),
		/* Raw-ETH requirement */
		.mtu_msgmax = 0x77,
		.sq_size_stride = ilog2(mfc_num_reserved_xids) << 3 |
				  ilog2(RFCI_SQ_BB_SIZE >> 4),
		.rq_size_stride = ilog2(mfc_num_reserved_xids) << 3 |
				  ilog2(RFCI_RQ_WQE_SIZE >> 4),
		.usr_page = cpu_to_be32(mfc_dev->priv_uar.index),
		.local_qpn = cpu_to_be32(qp->mqp.qpn),
		.pri_path.sched_queue = sched_q,
		.pri_path.counter_index = 0xff,
		.pri_path.ackto = (vhba->net_type == NET_IB) ?
				  MLX4_LINK_TYPE_IB : MLX4_LINK_TYPE_ETH,
		.params2 = cpu_to_be32((qp->wqres.buf.direct.map &
					(PAGE_SIZE - 1)) & 0xfc0),
		.cqn_send = cpu_to_be32(rfci->fc_cq.mcq.cqn),
		.cqn_recv = cpu_to_be32(rfci->fc_cq.mcq.cqn),
		/* we can assume that db.dma is aligned */
		.db_rec_addr = cpu_to_be64(qp->wqres.db.dma),
		.srqn = 0,
		.qkey = cpu_to_be32(MLX4_FCOIB_QKEY),
	};

	err = mlx4_qp_to_ready(mfc_dev->dev, &qp->wqres.mtt, &context,
			       &qp->mqp, &qp_state);

	if (qp_state != MLX4_QP_STATE_RST)
		qp->is_created = 1;

	if (qp_state != MLX4_QP_STATE_RTS) {
		shost_printk(KERN_ERR, vhba->lp->host,
			     "Error move rfci qp to RTS vhba=%d port=%d\n",
			     vhba->idx, fc_port->port);
		return err;
	}

	if (vhba->net_type == NET_ETH) {
		err = mlx4_register_mac(mfc_dev->dev, fc_port->port,
				mac_to_u64(vhba->fc_mac));
		if (err) {
			shost_printk(KERN_ERR, vhba->lp->host,
					"Couldn't register mac=%llx idx=%d vhba=%d port=%d\n",
					mac_to_u64(vhba->fc_mac), vhba->fc_mac_idx, vhba->idx, fc_port->port);
			return err;
		}
		if (vhba->fc_vlan_id != -1) {
			err = mlx4_register_vlan(mfc_dev->dev, fc_port->port,
					vhba->fc_vlan_id, &vhba->fc_vlan_idx);
			if (err) {
				shost_printk(KERN_ERR, vhba->lp->host,
						"Fail to reg vlan=%d vhba=%d port=%d err=%d\n",
						vhba->fc_vlan_id, vhba->idx, fc_port->port, err);
				goto err_unreg_mac;
			}
		}

		memcpy(&vhba->steer_gid[10], vhba->fc_mac, ETH_ALEN);
		vhba->steer_gid[4] = 0; /* vep_num */
		vhba->steer_gid[5] = fc_port->port;
		vhba->steer_gid[7] = MLX4_UC_STEER << 1 |
			1 << 0 |	/* vlan present */
			1 << 2;		/* check vlan */
		*(u16 *)(&vhba->steer_gid[8]) = cpu_to_be16(vhba->fc_vlan_id & 0x0fff);
		err = mlx4_qp_attach_common(mfc_dev->dev, &rfci->fc_qp.mqp,
				vhba->steer_gid, 0, MLX4_PROT_ETH,
				MLX4_UC_STEER);
		if (err) {
			shost_printk(KERN_ERR, vhba->lp->host,
					"Couldn't register mac vhba=%d port=%d\n",
					vhba->idx, fc_port->port);
			goto err_unreg_vlan;
		}
	}
	rfci->fc_qp.is_flushing = 0;
	rfci->initialized = 1;

	return 0;

err_unreg_vlan:
	if (vhba->net_type == NET_ETH)
		if (vhba->fc_vlan_id != -1)
			mlx4_unregister_vlan(mfc_dev->dev, fc_port->port, vhba->fc_vlan_idx);
err_unreg_mac:
	if (vhba->net_type == NET_ETH)
		mlx4_unregister_mac(mfc_dev->dev, fc_port->port,
				    mac_to_u64(vhba->fc_mac));

	return err;
}

int mfc_deinit_rfci(struct mfc_vhba *vhba)
{
	struct mfc_rfci *rfci = &vhba->rfci;
	struct mfc_port *fc_port = vhba->mfc_port;
	struct mfc_dev *mfc_dev = fc_port->mfc_dev;
	int err;

	if (!rfci->initialized)
		return 0;
	if (vhba->net_type == NET_ETH) {
		if (vhba->fc_vlan_id != -1)
			mlx4_unregister_vlan(mfc_dev->dev, fc_port->port, vhba->fc_vlan_idx);
		mlx4_unregister_mac(mfc_dev->dev, fc_port->port,
				    mac_to_u64(vhba->fc_mac));
		err = mlx4_qp_detach_common(mfc_dev->dev, &rfci->fc_qp.mqp,
				vhba->steer_gid, MLX4_PROT_ETH,
				MLX4_UC_STEER);
		if (err) {
			shost_printk(KERN_ERR, vhba->lp->host,
					"Couldn't deregister mac vhba=%d port=%d\n",
					vhba->idx, fc_port->port);
			return err;
		}
	}
	rfci->initialized = 0;
	return 0;
}

int mlx4_do_rfci_xmit(struct mfc_vhba *vhba, struct sk_buff *skb, u8 fceof)
{
	struct mfc_rfci *rfci = &vhba->rfci;
	struct mfc_dev *mfc_dev = vhba->mfc_port->mfc_dev;
	struct mfc_queue *sq = &rfci->fc_qp.sq;
	struct mfc_ctrl_seg *ctrl = NULL;
	struct mfc_data_seg *data = NULL;
	struct mfc_datagram_seg *dgram;
	int desc_size;
	dma_addr_t dma;
	u32 index, prod;
	__be32 op_own;
	unsigned long flags;
	int offset = 0;
	struct mfcoib_rfci_tx_desc *tx_desc_ib;
	struct mfcoe_rfci_tx_desc *tx_desc_eth;
	u_int tlen = 0;

	spin_lock_irqsave(&sq->lock, flags);
	if (unlikely((u32) (sq->prod - sq->cons - 1) > sq->size - 1)) {
		shost_printk(KERN_ERR, vhba->lp->host,
			     "Out of sq BBs rfci tx vhba=%d port=%d\n",
			     vhba->idx, vhba->mfc_port->port);
		spin_unlock_irqrestore(&sq->lock, flags);
		return -ENOMEM;
	}

	prod = sq->prod;
	++sq->prod;
	spin_unlock_irqrestore(&sq->lock, flags);

	index = prod & sq->size_mask;
	mfc_q_info_get(sq, index, struct sk_buff *) = skb;

	if (vhba->net_type == NET_IB) {
		desc_size = sizeof(struct mfc_ctrl_seg) +
		    sizeof(struct mfc_data_seg) +
		    sizeof(struct mfc_datagram_seg);

		tx_desc_ib = sq->buf + index * RFCI_SQ_BB_SIZE;
		ctrl = &tx_desc_ib->ctrl;
		ctrl->size = cpu_to_be16((desc_size / 16) & 0x3f);
		ctrl->flags = cpu_to_be32(MFC_BIT_TX_COMP | MFC_BIT_TX_FCRC_CS);

		dgram = &tx_desc_ib->dgram;
		dgram->fl_portn_pd = cpu_to_be32((vhba->mfc_port->port << 24) |
						 mfc_dev->priv_pdn);
		dgram->mlid_grh = 0;	/* no GRH */
		dgram->rlid = cpu_to_be16(vhba->dest_ib_lid);	/* remote LID */
		dgram->mgid_idx = 0;
		dgram->stat_rate = 0;	/* no rate limit */
		dgram->sl_tclass_flabel = cpu_to_be32(0 << 28 /* SL */);
		dgram->dqpn = cpu_to_be32(vhba->dest_ib_data_qpn);
		dgram->qkey = cpu_to_be32(MLX4_FCOIB_QKEY);

		data = &tx_desc_ib->data;
		/* skip macs reserved space in skb, but not ethtype */
		offset = sizeof(struct ethhdr) - 2;
	} else if (vhba->net_type == NET_ETH) {
		desc_size = sizeof(struct mfc_ctrl_seg) +
		    sizeof(struct mfc_data_seg);

		tx_desc_eth = sq->buf + index * RFCI_SQ_BB_SIZE;
		ctrl = &tx_desc_eth->ctrl;
		ctrl->size = cpu_to_be16((desc_size / 16) & 0x3f);
		if (vhba->fc_vlan_id != -1) {
			tx_desc_eth->ctrl.size |= cpu_to_be16(MFC_BIT_INS_VLAN);
			tx_desc_eth->ctrl.vlan =
			    cpu_to_be16(vhba->fc_vlan_id |
					vhba->fc_vlan_prio << 13);
		}

		ctrl->flags = cpu_to_be32(MFC_BIT_TX_COMP |
					  MFC_BIT_NO_ICRC | MFC_BIT_TX_FCRC_CS);
		data = &tx_desc_eth->data;
		offset = 0;
	}

	op_own = cpu_to_be32(MFC_RFCI_OP_SEND) |
	    cpu_to_be32((u32) fceof << 16) |
	    ((prod & sq->size) ? cpu_to_be32(MFC_BIT_DESC_OWN) : 0);
	if (!mfc_t11_mode)
		tlen = sizeof(struct fcoe_crc_eof_old);
	else
		tlen = sizeof(struct fcoe_crc_eof);

	dma = pci_map_single(mfc_dev->dev->pdev, skb->data + offset,
			     skb->len - tlen - offset, PCI_DMA_TODEVICE);
	if (pci_dma_mapping_error(mfc_dev->dev->pdev, dma))
		return -EINVAL;

	data->addr = cpu_to_be64(dma);
	data->count = cpu_to_be32(skb->len - tlen - offset);
	data->mem_type = cpu_to_be32(mfc_dev->mr.key);	/* always snoop */

	/* Ensure new descirptor (and ownership of next descirptor) hits memory
	 * before setting ownership of this descriptor to HW */
	wmb();
	ctrl->op_own = op_own;

	/* Ring doorbell! */
	wmb();
	writel(rfci->fc_qp.doorbell_qpn, mfc_dev->uar_map + MLX4_SEND_DOORBELL);

	return 0;
}

static int mfc_recv_abort_reply(struct fc_frame *fp, struct mfc_vhba *vhba)
{
	struct fc_frame_header *fh = fc_frame_header_get(fp);
	struct mfc_exch *fexch;
	int xno, oxid;
	struct fc_ba_rjt *rjt;
	struct fc_ba_acc *acc;

	oxid = ntohs(fh->fh_ox_id);
	xno = oxid - vhba->base_fexch_qpn +
	    vhba->mfc_port->base_fexch_qpn;

	if (xno < 0 || xno > vhba->num_fexch) {
		shost_printk(KERN_ERR, vhba->lp->host,
			"BA_XXX invalid oxid=%x exch=%x vhba=%d port=%d\n",
			oxid, xno, vhba->idx, vhba->mfc_port->port);
		return -1;
	}

	fexch = &vhba->fexch[xno];

	switch (fh->fh_r_ctl) {
	case FC_RCTL_BA_RJT:
		rjt = fc_frame_payload_get(fp, sizeof(*rjt));

		if (oxid >= vhba->base_reserved_xid &&
		    oxid < vhba->base_reserved_xid + vhba->num_reserved_xid) {
			shost_printk(KERN_ERR, vhba->lp->host,
				"BA_RJT oxid=%x vhba=%d port=%d"
				" reason=%x exp=%x passing up to libfc\n",
				oxid, vhba->idx, vhba->mfc_port->port,
				rjt->br_reason, rjt->br_explan);
			return -1;
		}

		shost_printk(KERN_INFO, vhba->lp->host,
			     "BA_RJT oxid=%x fexch=%x vhba=%d port=%d reason=%x exp=%x\n",
			     oxid, xno, vhba->idx, vhba->mfc_port->port,
			     rjt->br_reason, rjt->br_explan);

		if (fexch->state == FEXCH_SEND_ABORT)
			fexch->state = FEXCH_ABORT;
		break;

	case FC_RCTL_BA_ACC:

		acc = fc_frame_payload_get(fp, sizeof(*acc));

		xno = ntohs(acc->ba_ox_id) - vhba->base_fexch_qpn +
		    vhba->mfc_port->base_fexch_qpn;

		fexch = &vhba->fexch[xno];

		if (oxid >= vhba->base_reserved_xid &&
		    oxid < vhba->base_reserved_xid + vhba->num_reserved_xid) {
			shost_printk(KERN_ERR, vhba->lp->host,
				     "BA_ACC oxid=%x vhba=%d port=%d passing up\n",
				     oxid, vhba->idx, vhba->mfc_port->port);
			return -1;
		}

		if (fexch->state == FEXCH_SEND_ABORT)
			fexch->state = FEXCH_ABORT;

		shost_printk(KERN_INFO, vhba->lp->host,
			     "BA_ACC fexch=%x vhba=%d port=%d\n",
			     xno, vhba->idx, vhba->mfc_port->port);
		break;

	default:
		return -1;
	}

	if (fexch->state == FEXCH_ABORT)
		complete(&fexch->tm_done);

	return 0;
}

static void mfc_rx_rfci(struct work_struct *work)
{
	struct mfc_rfci_rx_info *fr =
	    container_of(work, struct mfc_rfci_rx_info, work);
	u_int32_t fr_len;
	u_int hlen;
	u_int tlen;
	struct mfc_vhba *vhba = fr->vhba;
	struct fc_lport *lp = vhba->lp;
	struct fc_stats *stats = per_cpu_ptr(lp->stats, get_cpu());
	struct fc_frame_header *fh;
	struct sk_buff *skb = fr->skb;
	struct fcoe_crc_eof_old *cp;
	enum fc_sof sof;
	struct fc_frame *fp;
	struct fcoe_hdr_old *fchp;
	u_int len;
	struct fcoe_hdr *hp;
	int rc;

	/*
	 * Check the header and pull it off.
	 */
	hlen = vhba->fcoe_hlen;
	if (!mfc_t11_mode) {	/* pre-T11 */
		fchp = (struct fcoe_hdr_old *)skb->data;
		tlen = sizeof(struct fcoe_crc_eof_old);
		len = ntohs(fchp->fcoe_plen);
		fr_len = FCOE_DECAPS_LEN(len);
		fr_len = fr_len * FCOE_WORD_TO_BYTE;
		fr_len -= sizeof(cp->fcoe_crc32);
		skb_pull(skb, sizeof(*fchp));
		sof = FCOE_DECAPS_SOF(len);
		if (unlikely(fr_len + tlen > skb->len)) {
			if (stats->ErrorFrames < 5)
				shost_printk(KERN_ERR, vhba->lp->host,
					     "Len err fr_len=%x skb->len=%x (only 5 len errors will be printed)\n",
					     fr_len + tlen, skb->len);
			stats->ErrorFrames++;
			goto free_packet;
		}
	} else {		/* T11 */
		hp = (struct fcoe_hdr *)skb->data;
		skb_pull(skb, sizeof(struct fcoe_hdr));
		tlen = sizeof(struct fcoe_crc_eof);
		fr_len = skb->len - tlen;
		sof = hp->fcoe_sof;
	}

	if (unlikely(fr_len < sizeof(struct fc_frame_header))) {
		if (stats->ErrorFrames < 5)
			shost_printk(KERN_ERR, vhba->lp->host,
				     "Len err len_sof=%x (only 5 len errors will be printed)\n", fr_len);
		stats->ErrorFrames++;
		goto free_packet;
	}

	if (skb_is_nonlinear(skb))
		skb_linearize(skb);	/* not ideal */

	stats->RxFrames++;
	stats->RxWords += fr_len / FCOE_WORD_TO_BYTE;

	fp = (struct fc_frame *)skb;
	fc_frame_init(fp);
	cp = (struct fcoe_crc_eof_old *)(skb->data + fr_len);
	fr_eof(fp) = cp->fcoe_eof;
	fr_sof(fp) = sof;
	fr_dev(fp) = lp;

	fh = fc_frame_header_get(fp);

	if (fh->fh_r_ctl == FC_RCTL_BA_ACC || fh->fh_r_ctl == FC_RCTL_BA_RJT) {
		rc = mfc_recv_abort_reply(fp, vhba);
		if (!rc)
			goto free_packet;
	}

	if (vhba->fcp_req_rx &&
			fh->fh_r_ctl == FC_RCTL_DD_UNSOL_CMD &&
			fh->fh_type == FC_TYPE_FCP) {
#if 0
		shost_printk(KERN_WARNING, vhba->lp->host,
			"RFCI RX: RCTL=DD_UNSOL_CMD/DD_CMD_STATUS (%x), ox_id %hx.\n",
			fh->fh_r_ctl, ntohs(fh->fh_ox_id));
		HEXDUMP(skb->data, fr_len);

		shost_printk(KERN_WARNING, vhba->lp->host, "FIBER Channel:\n");
		HEXDUMP(skb->data, 0x18);

		shost_printk(KERN_WARNING, vhba->lp->host, "FCP_CMND:\n");
		HEXDUMP(skb->data + 0x18, 0x24);

		shost_printk(KERN_WARNING, vhba->lp->host, "SCSI_CDB:\n");
		HEXDUMP(skb->data + 0x18 + 0x24, 0x10 - 4);
#endif
		vhba->fcp_req_rx(vhba, fp);
		return;
	}

	if ((fh->fh_r_ctl == FC_RCTL_DD_SOL_DATA) ||
		(fh->fh_r_ctl == FC_RCTL_DD_CMD_STATUS)) {
		shost_printk(KERN_WARNING, vhba->lp->host,
			"RFCI RX: RCTL=DD_SOL_DATA/DD_CMD_STATUS (%x), ox_id %hx, dropping.\n",
			fh->fh_r_ctl, ntohs(fh->fh_ox_id));
		goto free_packet;
	}

	fc_exch_recv(lp, fp);

	/*
	 * no need for kfree_skb() - skb was already freed inside
	 * fc_exch_recv()
	 */
	return;

free_packet:
	kfree_skb(skb);
}

#include <scsi/fc/fc_fip.h>

struct fip_vlan_desc {
        struct fip_desc fd_desc;
        __u16           fd_vlan;
} __attribute__((packed));

struct fip_vlan_res {
        struct ethhdr eh;
        struct fip_header fh;
        struct fip_mac_desc mac;
        struct fip_vlan_desc vlan;
} __attribute__((packed));

int mfc_frame_send(struct fc_lport *lp, struct fc_frame *fp)
{
	struct mfc_vhba *vhba = lport_priv(lp);
	struct fc_frame_header *fh;
	struct sk_buff *skb;
	u8 sof, eof;
	unsigned int elen;
	unsigned int hlen;
	unsigned int tlen;
	int wlen;
	struct ethhdr *eh;
	struct fcoe_crc_eof *cp;
	struct fcoe_hdr *hp;
	struct fcoe_hdr_old *ohp;
	struct fip_vlan_res *msg;
	int rc = 0;

	printk("Entering mfc_frame_send >>>>>>>>>>>> lp: %p fp: %p\n", lp, fp);

	if (!vhba->mfc_port->link_up)
		return -EBUSY;

	//removed this... worst case we send anyway
	//if (vhba->net_type == NET_ETH && vhba->ctlr.state != FIP_ST_ENABLED)
	//	return -EBUSY;

	fh = fc_frame_header_get(fp);
        printk("mfc_frame_send: #1 fh->fh_d_id: 0x%02x %02x %02x\n",
                  fh->fh_d_id[0], fh->fh_d_id[1], fh->fh_d_id[2]);

	skb = fp_skb(fp);
#if 0
	msg = (struct fip_vlan_res *)skb->data;
	printk("mfc_frame_send using msg: %p\n", msg);

	printk("mfc_frame_send: fip_op: 0x%04x fip_subcode: 0x%04x\n",
		msg->fh.fip_op, msg->fh.fip_subcode);
#else
	printk("mfc_frame_send: fh_r_ctl: 0x%04x fc_frame_payload_op: 0x%04x\n",
			fh->fh_r_ctl, fc_frame_payload_op(fp));
#endif
	if (unlikely(fh->fh_r_ctl == FC_RCTL_ELS_REQ)) {
		printk("mfc_frame_send: fh->fh_r_ctl == FC_RCTL_ELS_REQ\n");

		if (fc_frame_payload_op(fp) == ELS_FLOGI) {
			vhba->flogi_oxid = ntohs(fh->fh_ox_id);
			vhba->rfci_rx_enabled = 1;
			if (!fip_ctlrs[vhba->net_type - 1].els_send(vhba, skb)) {
				fctgt_info("TX: FLOGI REQ\n");
				shost_printk(KERN_INFO, vhba->lp->host,
						"Send flogi over fip\n");
				goto out;
			}
		} else if (fc_frame_payload_op(fp) == ELS_LOGO &&
			   !memcmp(fc_fid_flogi, fh->fh_d_id, 3)) {
			if (!fip_ctlrs[vhba->net_type - 1].els_send(vhba, skb)) {
				shost_printk(KERN_INFO, vhba->lp->host,
						"Send logo over fip\n");
				goto out;
			}
		}
	}

	if (vhba->rfci.fc_qp.is_flushing) {
		printk("mfc_frame_send: rfci.fc_qp.is_flushing=1\n");
		rc = -1;
		goto out_skb_free;
	}

	sof = fr_sof(fp);
	eof = fr_eof(fp);

	if (!mfc_t11_mode) {
		hlen = sizeof(struct fcoe_hdr_old);
		tlen = sizeof(struct fcoe_crc_eof_old);
	} else {
		hlen = sizeof(struct fcoe_hdr);
		tlen = sizeof(struct fcoe_crc_eof);
	}

	elen = sizeof(struct ethhdr);

	cp = (struct fcoe_crc_eof *)skb_put(skb, tlen);
	memset(cp, 0, sizeof(*cp));

	wlen = (skb->len - tlen + sizeof(u32)) / FCOE_WORD_TO_BYTE;

	/* adjust skb network/transport offsets to match mac/fcoe/fc */
	skb_push(skb, elen + hlen);
	skb_reset_mac_header(skb);
	skb_reset_network_header(skb);
	skb->mac_len = elen;

	eh = eth_hdr(skb);

	if (vhba->net_type == NET_ETH) {
		struct fcoe_ctlr *ofc_ctlr = vhba->vhba_ctlr;

		skb->protocol = htons(ETH_P_FCOE);
		eh->h_proto = htons(ETH_P_FCOE);

		mfc_update_gw_addr_eth(vhba, ofc_ctlr->dest_addr, 3);

		memcpy(eh->h_dest, vhba->dest_addr, ETH_ALEN);
		memcpy(eh->h_source, vhba->fc_mac, ETH_ALEN);
		printk("mfc_send_frame: eh->h_dest: 0x%02x %02x %02x %02x %02x %02x\n",
			eh->h_dest[0], eh->h_dest[1], eh->h_dest[2], eh->h_dest[3],
			eh->h_dest[4], eh->h_dest[5]);
		 printk("mfc_send_frame: eh->h_source: 0x%02x %02x %02x %02x %02x %02x\n",
			eh->h_source[0], eh->h_source[1], eh->h_source[2], eh->h_source[3],
			eh->h_source[4], eh->h_source[5]);

		printk("mfc_send_frame: #2 fh->fh_d_id: 0x%02x %02x %02x\n",
			fh->fh_d_id[0], fh->fh_d_id[1], fh->fh_d_id[2]);
		fh->fh_d_id[0] = eh->h_dest[3];
		fh->fh_d_id[1] = eh->h_dest[4];
		fh->fh_d_id[2] = eh->h_dest[5];
		printk("mfc_send_frame: #3 fh->fh_d_id: 0x%02x %02x %02x\n",
			fh->fh_d_id[0], fh->fh_d_id[1], fh->fh_d_id[2]);

	} else if (vhba->net_type == NET_IB) {
		skb->protocol = htons(FCOIB_SIG);
		eh->h_proto = htons(FCOIB_SIG);
	}

	if (!mfc_t11_mode) {
		ohp = (struct fcoe_hdr_old *)(eh + 1);
		ohp->fcoe_plen = htons(FCOE_ENCAPS_LEN_SOF(wlen, sof));
	} else {
		hp = (struct fcoe_hdr *)(eh + 1);
		memset(hp, 0, sizeof(*hp));
		if (FC_FCOE_VER)
			FC_FCOE_ENCAPS_VER(hp, FC_FCOE_VER);
		hp->fcoe_sof = sof;
	}

	fr_dev(fp) = lp;

	rc = mlx4_do_rfci_xmit(vhba, skb, eof);
	if (!rc)
		goto out;

out_skb_free:
	kfree_skb(skb);
out:
	return rc;
}
