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
#include <linux/if_vlan.h>
#include <linux/vmalloc.h>
#include <linux/kthread.h>
#include <linux/rtnetlink.h>

#include <scsi/fc/fc_fip.h>

#include "mfc.h"
#include "mlx4_EN_includes.h"
#include "fip_ctlr_api.h"

#define DRV_NAME	"mlnx_fc"
#define PFX		DRV_NAME ": "
#define DRV_VERSION	"1.1"
#define DRV_RELDATE	"Feb 2010"

MODULE_AUTHOR("Oren Duer/Vu Pham");
MODULE_DESCRIPTION("Mellanox CX FCoE/FCoIB driver");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_VERSION(DRV_VERSION);

int fctgt_dbg_lvl = 0;
#if 0
module_param_named(fctgt_dbg_lvl, 0, int, 0666);
MODULE_PARM_DESC(fctgt_dbg_lvl, "fc target debug level");
EXPORT_SYMBOL(fctgt_dbg_lvl);
#endif

int mfc_payload_size = MLX4_DEFAULT_FC_MTU;
module_param_named(frame_size, mfc_payload_size, int, 0444);
MODULE_PARM_DESC(frame_size,
		 "Frame payload size, default is "
		 __stringify(MLX4_DEFAULT_FC_MTU));

int mfc_num_reserved_xids = MLX4_DEFAULT_NUM_RESERVED_XIDS;
module_param_named(num_reserved_xids, mfc_num_reserved_xids, int, 0444);
MODULE_PARM_DESC(num_reserved_xids,
		 "Max outstanding RFCI exchanges per virtual HBA. "
		 "Default =  " __stringify(MLX4_DEFAULT_NUM_RESERVED_XIDS));

int mfc_log_exch_per_vhba = MLX4_DEFAULT_LOG_EXCH_PER_VHBA;
module_param_named(log_exch_per_vhba, mfc_log_exch_per_vhba, int, 0444);
MODULE_PARM_DESC(log_exch_per_vhba,
		 "Max outstanding FC exchanges per virtual HBA (log). "
		 "Default =  " __stringify(MLX4_DEFAULT_LOG_EXCH_PER_VHBA));

int max_vhba_per_port = MLX4_DEFAULT_MAX_VHBA_PER_PORT;
module_param_named(max_vhba_per_port, max_vhba_per_port, int, 0444);
MODULE_PARM_DESC(max_vhba_per_port, "Max vHBAs allowed per port. "
		 "Default =  " __stringify(MLX4_DEFAULT_MAX_VHBA_PER_PORT));

int max_cmd_per_lun = MFC_MAX_CMD_PER_LUN;
module_param_named(cmd_per_lun, max_cmd_per_lun, int, 0444);
MODULE_PARM_DESC(cmd_per_lun,
		 "Max outstanding scsi commands can queue per lun. "
		 "Default =  " __stringify(MFC_MAX_CMD_PER_LUN));

static int async_events_disabled = 2;

int mfc_t11_mode = 1;
static int mfc_dev_idx;
struct mfc_fip_ctlr fip_ctlrs[2]; /* 0=IB ctlr, 1=ETH ctlr */

LIST_HEAD(mfc_dev_list);
DEFINE_MUTEX(mfc_dev_list_lock);

struct scsi_transport_template *mfc_transport_template;

static void mfc_link_work(struct work_struct *work);
static int mfc_lld_reset(struct fc_lport *lp);
static void mfc_lport_cleanup(struct fc_lport *lp);
static void mfc_lport_abort_io(struct fc_lport *lp);
static int mfc_abort(struct scsi_cmnd *cmd)
{
	printk("%s:%d - Not implemented\n", __func__, __LINE__);
	return 0;
}
static int mfc_device_reset(struct scsi_cmnd *cmd);
static int mfc_host_reset(struct scsi_cmnd *cmd)
{
	printk("%s:%d - Not implemented\n", __func__, __LINE__);
	return 0;
}

struct libfc_function_template mlx4_libfc_fcn_templ = {
//	.lport_set_port_id = mfc_set_port_id,
	.frame_send = mfc_frame_send,
	.fcp_cleanup = mfc_lport_cleanup,
	.fcp_abort_io = mfc_lport_abort_io,
};

struct scsi_host_template mfc_driver_template = {
	.name = "Mellanox CX2 FCoE/FCoIB driver",
	.proc_name = DRV_NAME,
//	.queuecommand = mfc_queuecommand,
	.slave_alloc = fc_slave_alloc,
	.change_queue_depth = fc_change_queue_depth,
	.this_id = -1,
	.cmd_per_lun = MFC_MAX_CMD_PER_LUN,
	.use_clustering = ENABLE_CLUSTERING,
	.sg_tablesize = SG_ALL,
	.max_sectors = MFC_MAX_FMR_PAGES,
	.eh_abort_handler = mfc_abort,
	.eh_device_reset_handler = mfc_device_reset,
	.eh_host_reset_handler = mfc_host_reset,
};

int mfc_q_init(struct mfc_queue *q, u16 stride, size_t size, size_t info_size)
{
	q->prod = 0;
	q->cons = 0xffffffff;
	q->stride = stride;
	q->size = size;
	q->size_mask = q->size - 1;
	q->info = NULL;

	if (info_size) {
		q->info = (u8 *) vmalloc(q->size * info_size);
		if (!q->info)
			return -ENOMEM;
	}

	spin_lock_init(&q->lock);
	memset(q->info, 0, q->size * info_size);

	return 0;
}

void mfc_q_destroy(struct mfc_queue *q)
{
	if (!q->info)
		return;

	vfree(q->info);
	q->info = NULL;
}

void mfc_stamp_q(struct mfc_queue *q)
{
	__be32 *p;
	int i;

	/* stamp first dword of every 64 byte */
	for (i = 0; i < q->size; ++i) {
		p = q->buf + i * q->stride;
		*p = cpu_to_be32(1 << 31);
	}

}

static void mfc_arm_cq(struct mfc_cq *cq)
{
	mlx4_cq_arm(&cq->mcq, MLX4_CQ_DB_REQ_NOT,
		    cq->mfc_dev->uar_map,
		    MLX4_GET_DOORBELL_LOCK(&cq->mfc_dev->uar_lock));
}

static void mfc_cq_event(struct mlx4_cq *cq, enum mlx4_event event)
{
	printk(KERN_ERR PFX "CQ event = 0x%x\n", (unsigned int)event);
}

void mfc_cq_clean(struct mfc_cq *cq)
{
	struct mlx4_cq *mcq = &cq->mcq;
	struct mlx4_cqe *cqe, cqe2;

	cqe = (struct mlx4_cqe *)cq->buf + (mcq->cons_index & cq->size_mask);

	while (XNOR(cqe->owner_sr_opcode & MLX4_CQE_OWNER_MASK,
		    mcq->cons_index & cq->size)) {
		cqe2 = *cqe;
		mcq->cons_index++;
		mlx4_cq_set_ci(mcq);

		if ((cqe->owner_sr_opcode & MLX4_CQE_OPCODE_MASK) == 0x1e) {
			struct mlx4_err_cqe *cqe_err = (struct mlx4_err_cqe *)cqe;

			if (cqe_err->syndrome != MLX4_CQE_SYNDROME_WR_FLUSH_ERR) {
				printk(KERN_ERR "Completion with error. "
				"qpn: 0x%x wqe_index: 0x%x vendor: 0x%x syndrome: 0x%x\n",
				be32_to_cpu(cqe_err->my_qpn),
				be16_to_cpu(cqe_err->wqe_index),
				cqe_err->vendor_err_syndrome,
				cqe_err->syndrome);
			}

			if (!cq->comp_err)
				printk("%s:%d - cq->comp_err = NULL\n", __func__, __LINE__);
			else
				cq->comp_err(cq->arg, &cqe2);
		} else if (cqe->owner_sr_opcode & MLX4_CQE_IS_SEND_MASK) {
			if (!cq->comp_tx)
				printk("%s:%d - cq->comp_tx = NULL\n", __func__, __LINE__);
			else
				cq->comp_tx(cq->arg, &cqe2);
		} else
			if (!cq->comp_rx)
				printk("%s:%d - cq->comp_rx = NULL cq = %p op = 0x%x\n",
					       __func__, __LINE__, cq,
					       cqe->owner_sr_opcode &
					       MLX4_CQE_OPCODE_MASK);
			else
				cq->comp_rx(cq->arg, &cqe2);

		if (!cq) {
			printk("%s:%d - cq = NULL\n", __func__, __LINE__);
			break;
		}
		if (!cq->buf) {
			printk("%s:%d - cq->buf = NULL\n", __func__, __LINE__);
			break;
		}
		if (!mcq) {
			printk("%s:%d - mcq = NULL\n", __func__, __LINE__);
			break;
		}
		cqe = (struct mlx4_cqe *)cq->buf +
		      (mcq->cons_index & cq->size_mask);
	}
}

static void mfc_cq_comp(struct mlx4_cq *mcq)
{
	struct mfc_cq *cq = container_of(mcq, struct mfc_cq, mcq);

	mfc_cq_clean(cq);
	mfc_arm_cq(cq);
}

int mfc_create_cq(struct mfc_dev *mfc_dev, struct mfc_cq *cq,
		  int entries, int eqidx, int arm, comp_fn comp_rx,
		  comp_fn comp_tx, comp_fn comp_err,
		  void *arg, char *name)
{
	int err;

	cq->mfc_dev = mfc_dev;
	cq->arg = arg;
	cq->comp_rx = comp_rx;
	cq->comp_tx = comp_tx;
	cq->comp_err = comp_err;
	strncpy(cq->name, name, sizeof(cq->name));

	cq->size = roundup_pow_of_two(entries + 1);
	cq->size_mask = cq->size - 1;
	cq->buf_size = cq->size * sizeof(struct mlx4_cqe);

	err = mlx4_alloc_hwq_res(mfc_dev->dev, &cq->wqres, cq->buf_size,
				 cq->buf_size);
	if (err)
		return err;

	cq->mcq.set_ci_db = cq->wqres.db.db;
	cq->mcq.arm_db = cq->wqres.db.db + 1;
	*cq->mcq.set_ci_db = 0;
	*cq->mcq.arm_db = 0;

	cq->buf = (struct mfc_cqe *)cq->wqres.buf.direct.buf;

	err = mlx4_cq_alloc(mfc_dev->dev, cq->size, &cq->wqres.mtt,
			    &mfc_dev->priv_uar, cq->wqres.db.dma, &cq->mcq,
			    eqidx, 0, 0);
	if (err)
		goto err_man;

	cq->mcq.comp = mfc_cq_comp;
	cq->mcq.event = mfc_cq_event;
	spin_lock_init(&cq->lock);

	if (arm)
		mfc_arm_cq(cq);

	return 0;

err_man:
	mlx4_free_hwq_res(mfc_dev->dev, &cq->wqres, cq->buf_size);
	return err;
}

void mfc_destroy_cq(struct mfc_cq *cq)
{
	struct mfc_dev *mfc_dev = cq->mfc_dev;

	mlx4_cq_free(mfc_dev->dev, &cq->mcq);
	mlx4_free_hwq_res(mfc_dev->dev, &cq->wqres, cq->buf_size);
	cq->buf_size = 0;
	cq->buf = NULL;
}

int mfc_post_rx_buf(struct mfc_dev *mfc_dev, struct mfc_qp *fc_qp,
		    void *buf, size_t buf_size)
{
	struct mfc_queue *rq = &fc_qp->rq;
	struct mfc_rx_desc *rx_desc;
	dma_addr_t dma;
	int index;
	unsigned long flags;

	spin_lock_irqsave(&rq->lock, flags);
	if ((u32) (rq->prod - rq->cons) == rq->size) {
		dev_err(mfc_dev->dma_dev,
			"RFCI rq is full: prod 0x%x, cons 0x%x, size: 0x%x\n",
			rq->prod, rq->cons, rq->size);
		spin_unlock_irqrestore(&rq->lock, flags);
		return -1;
	}
	index = rq->prod & rq->size_mask;
	++rq->prod;
	spin_unlock_irqrestore(&rq->lock, flags);

	dma = pci_map_single(mfc_dev->dev->pdev, buf, buf_size,
			     PCI_DMA_FROMDEVICE);
	if (pci_dma_mapping_error(mfc_dev->dev->pdev, dma)) {
		dev_err(mfc_dev->dma_dev, "Failed to pci_map_single\n");
		return -1;
	}

	rx_desc = rq->buf + (index * rq->stride);
	rx_desc->data[0].count = cpu_to_be32(buf_size);
	rx_desc->data[0].mem_type = cpu_to_be32(mfc_dev->mr.key);
	rx_desc->data[0].addr = cpu_to_be64(dma);

	return index;
}

static int mfc_prepare_fip_rx_buf(struct mfc_port *fc_port)
{
	struct mfc_dev *mfc_dev = fc_port->mfc_dev;
	struct mfc_queue *rq = &fc_port->fip_qp.fc_qp.rq;
	struct sk_buff *skb;
	int index;

	skb = dev_alloc_skb(MFC_FIP_RX_SKB_BUFSIZE);
	if (!skb) {
		dev_err(mfc_dev->dma_dev,
			     "Fail alloc fip skb port=%d\n",
			     fc_port->port);
		return -ENOMEM;
	}

	index = mfc_post_rx_buf(mfc_dev, &fc_port->fip_qp.fc_qp,
				skb->data, MFC_FIP_RX_SKB_BUFSIZE);
	if (index < 0) {
		kfree_skb(skb);
		return index;
	}

	mfc_q_info_get(rq, index, struct sk_buff *) = skb;

	return 0;
}

static void mfc_fip_unpost_rx_bufs(struct mfc_port *fc_port)
{
	struct mfc_queue *rq = &fc_port->fip_qp.fc_qp.rq;
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

static void mfc_fip_rx_comp(void *arg, struct mlx4_cqe *cqe)
{
	struct mfc_port *mfc_port = (struct mfc_port *)arg;
	struct mfc_dev *mfc_dev = mfc_port->mfc_dev;
	struct mfc_fip *fip = &mfc_port->fip_qp;
	struct mfc_queue *rq = &fip->fc_qp.rq;
	struct mfc_rx_desc *rx_desc;
	u32 index;
	int len;
	unsigned long flags;
	struct sk_buff *skb;
	int vlan_id;
	int err;


	index = be16_to_cpu(cqe->wqe_index) & rq->size_mask;
	rx_desc = rq->buf + (index * rq->stride);
	pci_unmap_single(mfc_port->mfc_dev->dev->pdev,
			 be64_to_cpu(rx_desc->data[0].addr),
			 be32_to_cpu(rx_desc->data[0].count),
			 PCI_DMA_FROMDEVICE);

	spin_lock_irqsave(&rq->lock, flags);
	fip->fc_qp.rq.cons++;
	spin_unlock_irqrestore(&rq->lock, flags);

	skb = mfc_q_info_get(rq, index, struct sk_buff *);
	if (!skb) {
		if ((cqe->owner_sr_opcode & MLX4_CQE_OPCODE_MASK) == 0x1e)
			dev_err(mfc_dev->dma_dev,
				     "FIP qp=%x err compl port=%d\n",
				     fip->fc_qp.mqp.qpn, mfc_port->port);
		return;
	}

	mfc_q_info_get(rq, index, struct sk_buff *) = NULL;

	if (fip->fc_qp.is_flushing)
		return;

	len = be32_to_cpu(cqe->byte_cnt);
	skb_put(skb, len);
	skb_set_mac_header(skb, 0);

	vlan_id = -1;
	if (be32_to_cpu(cqe->vlan_my_qpn) & 0x60000000)
		vlan_id = be16_to_cpu(cqe->sl_vid) & 0x0fff;

	/*
	printk("%s:%d: Port %d, vlan %d, got FIP message, size %d\n", __FUNCTION__, __LINE__,
		mfc_port->port, vlan_id, skb->len);
	HEXDUMP(skb->data, skb->len);
	*/

	err = mfc_prepare_fip_rx_buf(mfc_port);
	if (err)
		goto free_skb;

	mfc_ring_db_rx(&fip->fc_qp);

	if (fip_ctlrs[mfc_port->net_type - 1].fip_rx)
		fip_ctlrs[mfc_port->net_type - 1].fip_rx(mfc_port, vlan_id, skb);
	else
		goto free_skb;

	return;

free_skb:
	if (skb)
		kfree_skb(skb);
}

static void mfc_fip_err_comp(void *arg, struct mlx4_cqe *cqe)
{
	mfc_fip_rx_comp(arg, cqe);
}


static void mfc_fip_tx_comp(void *arg, struct mlx4_cqe *cqe)
{
	struct mfc_port *mfc_port = (struct mfc_port *)arg;
	struct mfc_fip *fip = &mfc_port->fip_qp;
	struct mfc_queue *sq = &fip->fc_qp.sq;
	struct sk_buff *skb;
	u32 index;
	unsigned long flags;
	u64 dma = 0;
	u32 count = 0;

	index = be16_to_cpu(cqe->wqe_index) & sq->size_mask;
	/*
	printk("Got FIP TX comp for port %d idx 0x%x op=0x%x\n", mfc_port->port, index, cqe->owner_sr_opcode & 0x1f);
	*/
	if (mfc_port->net_type == NET_IB) {
	} else {
		struct mfcoe_rfci_tx_desc *tx_desc;

		tx_desc = sq->buf + index * RFCI_SQ_BB_SIZE;
		dma = be64_to_cpu(tx_desc->data.addr);
		count = be32_to_cpu(tx_desc->data.count);
	}

	pci_unmap_single(mfc_port->mfc_dev->dev->pdev,
			 dma, count, PCI_DMA_TODEVICE);

	skb = mfc_q_info_get(sq, index, struct sk_buff *);
	mfc_q_info_get(sq, index, struct sk_buff *) = NULL;
	kfree_skb(skb);

	spin_lock_irqsave(&sq->lock, flags);
	++sq->cons;
	spin_unlock_irqrestore(&sq->lock, flags);
}

int mfc_fip_tx(struct mfc_port *mfc_port, struct sk_buff *skb, int vlan_id, int vlan_prio)
{
	struct mfc_fip *fip = &mfc_port->fip_qp;
	struct mfc_dev *mfc_dev = mfc_port->mfc_dev;
	struct mfc_queue *sq = &fip->fc_qp.sq;
	struct mfc_ctrl_seg *ctrl = NULL;
	struct mfc_data_seg *data = NULL;
	struct mfcoe_rfci_tx_desc *tx_desc_eth;
	int desc_size;
	dma_addr_t dma;
	u32 index, prod;
	__be32 op_own;
	unsigned long flags;

	spin_lock_irqsave(&sq->lock, flags);
	if (unlikely((u32) (sq->prod - sq->cons - 1) > sq->size - 2)) {
		dev_err(mfc_dev->dma_dev,
			     "Out of sq BBs fip tx port=%d\n",
			     mfc_port->port);
		spin_unlock_irqrestore(&sq->lock, flags);
		return -ENOMEM;
	}

	prod = sq->prod;
	++sq->prod;
	spin_unlock_irqrestore(&sq->lock, flags);

	index = prod & sq->size_mask;
	mfc_q_info_get(sq, index, struct sk_buff *) = skb;

	if (mfc_port->net_type == NET_IB) {
	} else {
		desc_size = sizeof(struct mfc_ctrl_seg) +
		    sizeof(struct mfc_data_seg);
		tx_desc_eth = sq->buf + index * FIP_SQ_BB_SIZE;
		ctrl = &tx_desc_eth->ctrl;
		ctrl->size = cpu_to_be16((desc_size / 16) & 0x3f);
		if (vlan_id != -1) {
			tx_desc_eth->ctrl.size |= cpu_to_be16(MFC_BIT_INS_VLAN);
			tx_desc_eth->ctrl.vlan =
			    cpu_to_be16(vlan_id |
					vlan_prio << 13);
		}
		ctrl->flags = cpu_to_be32(MFC_BIT_TX_COMP | MFC_BIT_NO_ICRC);
		data = &tx_desc_eth->data;
	}

	op_own = cpu_to_be32(MFC_RFCI_OP_SEND) |
	    ((prod & sq->size) ? cpu_to_be32(MFC_BIT_DESC_OWN) : 0);

	dma = pci_map_single(mfc_dev->dev->pdev, skb->data,
			     skb->len, PCI_DMA_TODEVICE);
	if (pci_dma_mapping_error(mfc_dev->dev->pdev, dma))
		return -EINVAL;

	data->addr = cpu_to_be64(dma);
	data->count = cpu_to_be32(skb->len);
	data->mem_type = cpu_to_be32(mfc_dev->mr.key);	/* always snoop */

	/* Ensure new descirptor (and ownership of next descirptor) hits memory
	 * before setting ownership of this descriptor to HW */
	wmb();
	ctrl->op_own = op_own;

/*
	printk("mfc_fip_tx: port %d, vlan_id=%d, prio=%d mailbox idx 0x%x\n", mfc_port->port, vlan_id, vlan_prio, index);
*/
	/* Ring doorbell! */
	wmb();
	writel(fip->fc_qp.doorbell_qpn, mfc_dev->uar_map + MLX4_SEND_DOORBELL);

	return 0;
}
EXPORT_SYMBOL(mfc_fip_tx);

static void mfc_qp_event(struct mlx4_qp *qp, enum mlx4_event type)
{
	printk(KERN_WARNING "qp event for qpn=0x%08x event_type=0x%x\n",
	       qp->qpn, type);
}

int mfc_create_fip(struct mfc_port *fc_port)
{
	struct mfc_dev *mfc_dev = fc_port->mfc_dev;
	struct mfc_qp *qp = &fc_port->fip_qp.fc_qp;
	struct mfc_queue *sq = &qp->sq;
	struct mfc_queue *rq = &qp->rq;
	int err = 0;
	int i;

	err = mfc_q_init(sq, FIP_SQ_BB_SIZE, FIP_SQ_NUM_BBS,
			 sizeof(struct sk_buff *));
	if (err) {
		dev_err(mfc_dev->dma_dev,
			     "Init fip sq port=%d err=%d\n",
			     fc_port->port, err);
		goto err;
	}

	err = mfc_q_init(rq, FIP_RQ_WQE_SIZE, FIP_RQ_NUM_WQES,
			 sizeof(struct sk_buff *));
	if (err) {
		dev_err(mfc_dev->dma_dev,
			     "Init fip rq port=%d err=%d\n",
			     fc_port->port, err);
		err = -ENOMEM;
		goto err_free_txinfo;
	}

	qp->buf_size = (sq->size * sq->stride) + (rq->size * rq->stride);

	err = mlx4_alloc_hwq_res(mfc_dev->dev, &qp->wqres, qp->buf_size,
				 qp->buf_size);
	if (err)
		goto err_free_rxinfo;

	if (FIP_SQ_BB_SIZE >= FIP_RQ_WQE_SIZE) {
		sq->buf = qp->wqres.buf.direct.buf;
		rq->buf = sq->buf + (sq->size * sq->stride);
	} else {
		rq->buf = qp->wqres.buf.direct.buf;
		sq->buf = rq->buf + (rq->size * rq->stride);
	}

	*qp->wqres.db.db = 0;

	mfc_stamp_q(sq);
	mfc_stamp_q(rq);

	err = mlx4_qp_reserve_range(mfc_dev->dev, 1, 1, &qp->mqp.qpn);
	if (err) {
		dev_err(mfc_dev->dma_dev,
			     "Fail to reserve qp fip for port=%d err=%d\n",
			     fc_port->port, err);
		goto err_free_man;
	}

	err = mlx4_qp_alloc(mfc_dev->dev, qp->mqp.qpn, &qp->mqp);
	if (err) {
		dev_err(mfc_dev->dma_dev,
			     "Alloc rfci qp=%x port=%d err=%d\n",
			     qp->mqp.qpn, fc_port->port, err);
		goto err_release_qp;
	}

	qp->doorbell_qpn = swab32(qp->mqp.qpn << 8);
	qp->mqp.event = mfc_qp_event;

	err = mfc_create_cq(mfc_dev, &fc_port->fip_qp.fc_cq,
			FIP_SQ_NUM_BBS + FIP_RQ_NUM_WQES,
			0, 1, mfc_fip_rx_comp, mfc_fip_tx_comp, mfc_fip_err_comp, fc_port, "FIP");
	if (err) {
		dev_err(mfc_dev->dma_dev,
			     "Create cq rfci port=%d err=%d\n",
			     fc_port->port, err);
		goto err_free_qp;
	}

	for (i = 0; i < rq->size - 1; i++) {
		err = mfc_prepare_fip_rx_buf(fc_port);
		if (err) {
			dev_err(mfc_dev->dma_dev,
				     "Prepare fip rx_buf=%d port=%d err=%d\n",
				     i, fc_port->port, err);
			goto err_free_cq;
		}
	}

	mfc_ring_db_rx(&fc_port->fip_qp.fc_qp);

	return 0;

err_free_cq:
	mfc_fip_unpost_rx_bufs(fc_port);
	mfc_destroy_cq(&fc_port->fip_qp.fc_cq);
err_free_qp:
	mlx4_qp_remove(mfc_dev->dev, &qp->mqp);
	mlx4_qp_free(mfc_dev->dev, &qp->mqp);
err_release_qp:
	mlx4_qp_release_range(mfc_dev->dev, qp->mqp.qpn, 1);
err_free_man:
	mlx4_free_hwq_res(mfc_dev->dev, &qp->wqres, qp->buf_size);
err_free_rxinfo:
	mfc_q_destroy(rq);
err_free_txinfo:
	mfc_q_destroy(sq);
err:
	return err;
}

void mfc_destroy_fip(struct mfc_port *fc_port)
{
	struct mfc_dev *mfc_dev = fc_port->mfc_dev;
	struct mfc_qp *qp = &fc_port->fip_qp.fc_qp;
	struct mfc_queue *sq = &qp->sq;
	struct mfc_queue *rq = &qp->rq;
	int err;

	if (qp->is_created) {
		err = flush_qp(mfc_dev, qp, 1, 1, NULL, NULL);
		if (err)
			dev_err(mfc_dev->dma_dev,
					"Flush fip qp port=%d err=%d\n",
					fc_port->port, err);
		mlx4_qp_to_reset(mfc_dev->dev, &qp->mqp);
	}
	mfc_destroy_cq(&fc_port->fip_qp.fc_cq);
	qp->is_created = 0;
	mlx4_qp_remove(mfc_dev->dev, &qp->mqp);
	mlx4_qp_free(mfc_dev->dev, &qp->mqp);
	mlx4_qp_release_range(mfc_dev->dev, qp->mqp.qpn, 1);
	mlx4_free_hwq_res(mfc_dev->dev, &qp->wqres, qp->buf_size);
	mfc_fip_unpost_rx_bufs(fc_port);
	mfc_q_destroy(rq);
	mfc_q_destroy(sq);
}

int mfc_init_fip(struct mfc_port *fc_port)
{
	struct mfc_dev *mfc_dev = fc_port->mfc_dev;
	struct mfc_qp *qp = &fc_port->fip_qp.fc_qp;
	enum mlx4_qp_state qp_state = MLX4_QP_STATE_RST;
	int err = 0;
	u8 sched_q = 0;
	struct mlx4_qp_context context;

	sched_q = 0x83 | (fc_port->port - 1) << 6;

	context = (struct mlx4_qp_context) {
		.flags = cpu_to_be32(QPC_SERVICE_TYPE_ETH << 16),
		.pd = cpu_to_be32(mfc_dev->priv_pdn),
		/* Raw-ETH requirement */
		.mtu_msgmax = 0xff,
		.sq_size_stride = ilog2(FIP_SQ_NUM_BBS) << 3 |
				  ilog2(FIP_SQ_BB_SIZE >> 4),
		.rq_size_stride = ilog2(FIP_RQ_NUM_WQES) << 3 |
				  ilog2(FIP_RQ_WQE_SIZE >> 4),
		.usr_page = cpu_to_be32(mfc_dev->priv_uar.index),
		.local_qpn = cpu_to_be32(qp->mqp.qpn),
		.pri_path.sched_queue = sched_q,
		.pri_path.counter_index = 0xff,
		.pri_path.ackto = (fc_port->net_type == NET_IB) ?
				  MLX4_LINK_TYPE_IB : MLX4_LINK_TYPE_ETH,
		.params2 = cpu_to_be32((qp->wqres.buf.direct.map &
					(PAGE_SIZE - 1)) & 0xfc0),
		.cqn_send = cpu_to_be32(fc_port->fip_qp.fc_cq.mcq.cqn),
		.cqn_recv = cpu_to_be32(fc_port->fip_qp.fc_cq.mcq.cqn),
		/* we can assume that db.dma is aligned */
		.db_rec_addr = cpu_to_be64(qp->wqres.db.dma),
		.srqn = 0,
		//.qkey = cpu_to_be32(MLX4_FCOIB_QKEY),
	};

	err = mlx4_qp_to_ready(mfc_dev->dev, &qp->wqres.mtt, &context,
			       &qp->mqp, &qp_state);

	if (qp_state != MLX4_QP_STATE_RST)
		qp->is_created = 1;

	if (qp_state != MLX4_QP_STATE_RTS) {
		dev_err(mfc_dev->dma_dev,
			     "Error move fip qp to RTS port=%d\n",
			     fc_port->port);
		return err;
	}

	if (fc_port->net_type == NET_ETH) {
		memcpy(&fc_port->fip_qp.steer_all_enodes_gid[10], FIP_ALL_ENODE_MACS, ETH_ALEN);
		fc_port->fip_qp.steer_all_enodes_gid[4] = 0; // vep_num
		fc_port->fip_qp.steer_all_enodes_gid[5] = fc_port->port;
		fc_port->fip_qp.steer_all_enodes_gid[7] = MLX4_MC_STEER << 1;
		err = mlx4_qp_attach_common(mfc_dev->dev, &qp->mqp,
				fc_port->fip_qp.steer_all_enodes_gid, 0,
				MLX4_PROT_ETH , MLX4_MC_STEER);
		if (err) {
			dev_err(mfc_dev->dma_dev,
					"Couldn't register fip steering rule for port=%d\n",
					fc_port->port);
			return err;
		}
		memcpy(&fc_port->fip_qp.steer_ethertype_gid[10],
				fc_port->def_mac, ETH_ALEN);
		fc_port->fip_qp.steer_ethertype_gid[4] = 0; // vep_num
		fc_port->fip_qp.steer_ethertype_gid[5] = fc_port->port;
		fc_port->fip_qp.steer_ethertype_gid[7] =
			MLX4_UC_STEER << 1 |
			1 << 3;			/* check ethertype */;
		fc_port->fip_qp.steer_ethertype_gid[2] = 0x89;
		fc_port->fip_qp.steer_ethertype_gid[3] = 0x14;
		err = mlx4_qp_attach_common(mfc_dev->dev, &qp->mqp,
				fc_port->fip_qp.steer_ethertype_gid, 0,
				MLX4_PROT_ETH , MLX4_UC_STEER);
		if (err) {
			dev_err(mfc_dev->dma_dev,
					"Couldn't register fip steering rule for port=%d\n",
					fc_port->port);
			goto err_detach_all_enodes;
		}
	}
	fc_port->fip_qp.fc_qp.is_flushing = 0;

	return 0;

err_detach_all_enodes:
	mlx4_qp_detach_common(mfc_dev->dev, &fc_port->fip_qp.fc_qp.mqp,
			fc_port->fip_qp.steer_all_enodes_gid,
			MLX4_PROT_ETH, MLX4_MC_STEER);
	return err;
}

int mfc_deinit_fip(struct mfc_port *fc_port)
{
	struct mfc_dev *mfc_dev = fc_port->mfc_dev;
	struct mfc_qp *qp = &fc_port->fip_qp.fc_qp;

	if (fc_port->net_type == NET_ETH) {
		mlx4_qp_detach_common(mfc_dev->dev, &qp->mqp,
				fc_port->fip_qp.steer_ethertype_gid,
				MLX4_PROT_ETH , MLX4_UC_STEER);
		mlx4_qp_detach_common(mfc_dev->dev, &qp->mqp,
				fc_port->fip_qp.steer_all_enodes_gid,
				MLX4_PROT_ETH, MLX4_MC_STEER);
	}
	return 0;
}

static u32 hw_index_to_key(u32 ind)
{
	return (ind >> 24) | (ind << 8);
}

static void u64_to_mac(u8 mac[6], u64 u64mac)
{
	int i;

	for (i = 5; i >= 0; i--) {
		mac[i] = u64mac & 0xff;
		u64mac >>= 8;
	}
}

static void u64_to_wwpn(u8 wwpn[8], u64 u64wwpn)
{
	int i;

	for (i = 7; i >= 0; i--) {
		wwpn[i] = u64wwpn & 0xff;
		u64wwpn >>= 8;
	}
}

void mfc_update_src_mac(struct mfc_vhba *vhba, u8 *addr)
{
	memcpy(vhba->fc_mac, addr, ETH_ALEN);
}
EXPORT_SYMBOL(mfc_update_src_mac);

void mfc_update_gw_addr_eth(struct mfc_vhba *vhba, u8 *mac, u8 prio)
{
	memcpy(vhba->dest_addr, mac, ETH_ALEN);
	vhba->fc_vlan_prio = prio;
}
EXPORT_SYMBOL(mfc_update_gw_addr_eth);

u8 *mfc_get_src_addr(struct fc_lport *lp)
{
	struct mfc_vhba *vhba = lport_priv(lp);
	return vhba->fc_mac;
}
EXPORT_SYMBOL(mfc_get_src_addr);

u32 mfc_get_src_qpn(struct mfc_vhba *vhba)
{
	return vhba->rfci.fc_qp.mqp.qpn;
}
EXPORT_SYMBOL(mfc_get_src_qpn);

void mfc_get_vhba_fcid(struct mfc_vhba *vhba, uint8_t *fcid)
{
	memcpy(fcid, vhba->my_npid.fid, 3);
}
EXPORT_SYMBOL(mfc_get_vhba_fcid);

void mfc_update_gw_addr_ib(struct mfc_vhba *vhba, u16 lid, u32 qpn, u8 sl)
{
	vhba->dest_ib_lid = lid;
	vhba->dest_ib_sl = sl;
	vhba->dest_ib_data_qpn = qpn;
}
EXPORT_SYMBOL(mfc_update_gw_addr_ib);

static int mlx4_CONFIG_FC_BASIC(struct mlx4_dev *dev, u8 port,
				struct mfc_basic_config_params *params)
{
	struct mlx4_cmd_mailbox *mailbox;
	int err;

#define CONFIG_FC_FEXCH_BASE_OFFSET	0x0
#define CONFIG_FC_NM_OFFSET		0x5
#define CONFIG_FC_NV_OFFSET		0x6
#define CONFIG_FC_NP_OOFSET		0x7
#define CONFIG_FC_BASEMPT_OFFSET	0x8
#define CONFIG_FC_NUM_RFCI_OFFSET	0xc
#define CONFIG_FC_RFCI_BASE_OFFSET	0xd
#define CONFIG_FC_PROMISC_QPN_OFFSET	0x14
#define CONFIG_FC_MCAST_QPN_OFFSET	0x18

	mailbox = mlx4_alloc_cmd_mailbox(dev);
	if (IS_ERR(mailbox))
		return PTR_ERR(mailbox);

	memset(mailbox->buf, 0, 256);

	MLX4_PUT(mailbox->buf, params->fexch_base, CONFIG_FC_FEXCH_BASE_OFFSET);
	MLX4_PUT(mailbox->buf, params->nm, CONFIG_FC_NM_OFFSET);
	MLX4_PUT(mailbox->buf, params->nv, CONFIG_FC_NV_OFFSET);
	MLX4_PUT(mailbox->buf, params->np, CONFIG_FC_NP_OOFSET);
	MLX4_PUT(mailbox->buf, (hw_index_to_key(params->fexch_base_mpt)),
		 CONFIG_FC_BASEMPT_OFFSET);
	MLX4_PUT(mailbox->buf,
		 params->rfci_base | (((u32) params->log_num_rfci) << 24),
		 CONFIG_FC_NUM_RFCI_OFFSET);
	MLX4_PUT(mailbox->buf, params->def_fcoe_promisc_qpn,
		 CONFIG_FC_PROMISC_QPN_OFFSET);
	MLX4_PUT(mailbox->buf, params->def_fcoe_mcast_qpn,
		 CONFIG_FC_MCAST_QPN_OFFSET);

	err = mlx4_cmd(dev, mailbox->dma,
		       MLX4_CMD_INMOD_BASIC_CONF | port,
		       MLX4_CMD_MOD_FC_ENABLE,
		       MLX4_CMD_CONFIG_FC, MLX4_CMD_TIME_CLASS_B,
		       MLX4_CMD_NATIVE);

	mlx4_free_cmd_mailbox(dev, mailbox);
	return err;

}

static int mlx4_CONFIG_FC_NPORT_ID(struct mlx4_dev *dev, u8 port,
				   struct nport_id *npid)
{
	struct mlx4_cmd_mailbox *mailbox;
	int err = 0;

	mailbox = mlx4_alloc_cmd_mailbox(dev);
	if (IS_ERR(mailbox))
		return PTR_ERR(mailbox);

	memcpy(mailbox->buf, npid, MFC_NUM_NPORT_IDS * sizeof(u32));

	err = mlx4_cmd(dev, mailbox->dma,
		       MLX4_CMD_INMOD_NPORT_TAB | port,
		       MLX4_CMD_MOD_FC_ENABLE,
		       MLX4_CMD_CONFIG_FC, MLX4_CMD_TIME_CLASS_B,
		       MLX4_CMD_NATIVE);

	mlx4_free_cmd_mailbox(dev, mailbox);
	return err;
}

int mfc_flogi_finished(struct mfc_vhba *vhba, u8 *my_npid)
{
	struct fc_lport *lp = vhba->lp;
	struct mfc_port *fc_port = vhba->mfc_port;
	int err = 0;

	if (!memcmp(my_npid, vhba->my_npid.fid, 3) && vhba->flogi_finished)
		return 0;

	fctgt_info("Logged in to FABRIC. fid: %02x:%02x:%02x vhba=%d port=%d\n",
		     my_npid[0], my_npid[1], my_npid[2],
		     vhba->idx, vhba->mfc_port->port);

	vhba->my_npid.reserved = 0;
	memcpy(vhba->my_npid.fid, my_npid, 3);

	/* init RFCI */
	if (!vhba->flogi_finished) {
		err = mfc_init_rfci(vhba);
		if (err) {
			shost_printk(KERN_ERR, vhba->lp->host,
				     "Init rfci vhba=%d port=%d err=%d\n",
				     vhba->idx, vhba->mfc_port->port, err);
			goto out;
		}
	}

	if ((vhba->idx < 0) || (vhba->idx >= MFC_NUM_NPORT_IDS)) {
		err = -EINVAL;
		goto err;
	}

	memcpy(&fc_port->npid_table[vhba->idx], &vhba->my_npid,
	       sizeof(vhba->my_npid));

	err = mlx4_CONFIG_FC_NPORT_ID(fc_port->mfc_dev->dev, fc_port->port,
				      fc_port->npid_table);
	if (err) {
		shost_printk(KERN_ERR, lp->host,
			     "Couldn't cfg npid %x:%x:%x to vhba=%d port=%d\n",
			     vhba->my_npid.fid[0], vhba->my_npid.fid[1],
			     vhba->my_npid.fid[2], vhba->idx, fc_port->port);

		goto err;
	}

	if (!vhba->flogi_finished) {
		err = mfc_init_fexchs(vhba);
		if (err) {
			shost_printk(KERN_ERR, lp->host,
				     "Couldn't init FCMD vhba=%d port=%d err=%d\n",
				     vhba->idx, fc_port->port, err);
			goto err;
		}
	}

	vhba->flogi_finished++;
	return 0;

err:
	mfc_deinit_rfci(vhba);
out:
	return err;
}
EXPORT_SYMBOL(mfc_flogi_finished);

static int mfc_lport_config(struct fc_lport *lp)
{
	lp->link_up = 0;
	lp->qfull = 0;
	lp->max_retry_count = 3;
	lp->max_rport_retry_count = 3;
	lp->e_d_tov = 2 * 1000;
	lp->r_a_tov = 2 * 2 * 1000;
	lp->service_params = (FCP_SPPF_TARG_FCN | FCP_SPPF_RD_XRDY_DIS |
			      FCP_SPPF_RETRY | FCP_SPPF_CONF_COMPL);
	lp->link_supported_speeds |= FC_PORTSPEED_1GBIT | FC_PORTSPEED_4GBIT |
	    FC_PORTSPEED_10GBIT | FC_PORTSPEED_8GBIT | FC_PORTSPEED_16GBIT;
	lp->link_speed = FC_PORTSPEED_10GBIT;

	if (fc_lport_init_stats(lp))
		goto err_out;

	fc_lport_config(lp);

	/* offload related configuration */
	lp->crc_offload = 0;
	lp->seq_offload = 0;
	lp->lro_enabled = 0;
	lp->lro_xid = 0;
	lp->lso_max = 0;

	return 0;

err_out:

	return -ENOMEM;
}

static void mfc_lport_cleanup(struct fc_lport *lp)
{
	struct mfc_vhba *vhba = lport_priv(lp);

	shost_printk(KERN_INFO, lp->host,
		     "Lport lld cleanup vhba=%d port=%d\n",
		     vhba->idx, vhba->mfc_port->port);

	if (!vhba->in_reset) {
		vhba->in_reset = 1;
		mfc_lld_reset(lp);
	}
}

static void mfc_lport_abort_io(struct fc_lport *lp)
{
	struct mfc_vhba *vhba = lport_priv(lp);

	shost_printk(KERN_INFO, lp->host,
		     "Lport lld abort_io vhba=%d port=%d\n",
		     vhba->idx, vhba->mfc_port->port);
}

static int mfc_libfc_init(struct fc_lport *lp, int min_xid, int max_xid,
			  u64 wwpn, u64 wwnn)
{
	struct mfc_vhba *vhba = lport_priv(lp);
//	int err;

	fc_set_wwnn(lp, wwnn);
	fc_set_wwpn(lp, wwpn);

	/* libfc expects max FC frame size, including native FC header */
	fc_set_mfs(lp, vhba->fc_payload_size + sizeof(struct fc_frame_header));

	lp->host->max_lun = MFC_MAX_LUN;
	lp->host->max_id = MFC_MAX_FCP_TARGET;
	lp->host->max_channel = 0;
	lp->host->transportt = mfc_transport_template;

//	err = scsi_add_host(lp->host, NULL);
//	if (err) {
//		shost_printk(KERN_ERR, lp->host,
//			     "Fail scsi_add_host vhba=%d port=%d err=%d\n",
//			     vhba->idx, vhba->mfc_port->port, err);
//		return err;
//	}

//	snprintf(fc_host_symbolic_name(lp->host), FC_SYMBOLIC_NAME_SIZE,
//		 "hca%d_p%d_vhba%d", vhba->mfc_port->mfc_dev->idx,
//		 vhba->mfc_port->port, vhba->idx);

	lp->tt = mlx4_libfc_fcn_templ;

	fc_exch_init(lp);
	fc_elsct_init(lp);
	fc_lport_init(lp);
	fc_rport_init(lp);
	fc_disc_init(lp);

	vhba->emp = fc_exch_mgr_alloc(lp, FC_CLASS_3, min_xid, max_xid, NULL);
	if (!vhba->emp) {
		shost_printk(KERN_ERR, lp->host,
			     "Fail alloc libfc exch manager vhba=%d port=%d\n",
			     vhba->idx, vhba->mfc_port->port);
		return -ENOMEM;
	}
	return 0;
}

static struct mfc_vhba *mfc_create_vhba(struct mfc_port *fc_port, unsigned int mtu,
		int vlan_id,
		enum mfc_net_type net_type, u64 wwpn, u64 wwnn, int priv_size,
		struct module *owner)
{
	struct mfc_dev *mfc_dev = fc_port->mfc_dev;
	struct fc_lport *lp;
	struct mfc_vhba *vhba;
	int idx, port = fc_port->port;
	int err = 0;
	unsigned long flags;
	struct Scsi_Host *shost;
	struct scsi_host_template tmp_sht;

	tmp_sht = mfc_driver_template;
	tmp_sht.can_queue = (1 << mfc_log_exch_per_vhba) -
	    mfc_num_reserved_xids;
	tmp_sht.module = owner;

	lp = libfc_host_alloc(&tmp_sht, sizeof(struct mfc_vhba) + priv_size);
	if (!lp) {
		dev_err(mfc_dev->dma_dev,
			"Could not allocate lport on port %d\n", port);
		err = -ENOMEM;
		goto err_out;
	}

	shost = lp->host;
	shost->max_cmd_len = 16;
	vhba = lport_priv(lp);
	vhba->sht = tmp_sht;
	shost->hostt = &vhba->sht;
	vhba->lp = lp;

	err = mfc_lport_config(lp);
	if (err) {
		dev_err(mfc_dev->dma_dev,
			"Error configuring lport on port %d\n", port);
		goto err_host_put;
	}

	idx = mfc_bitmap_slot_alloc(&fc_port->fexch_bulk_bm, 1);
	if (idx == -1) {
		dev_err(mfc_dev->dma_dev,
			"Failed alloc fexchs for new vhba on port %d\n", port);
		err = -ENOMEM;
		goto err_lport_destroy;
	}
	vhba->idx = idx;
	vhba->mfc_port = fc_port;
	vhba->fc_mac_idx = -1;
	/* TODO: needed? */
	vhba->rfci_rx_enabled = 0;

	if (!mfc_t11_mode) {
		vhba->fcoe_hlen = sizeof(struct fcoe_hdr_old);
		vhba->fc_payload_size = mtu -
		    sizeof(struct fcoe_hdr_old) -
		    sizeof(struct fc_frame_header) -
		    sizeof(struct fcoe_crc_eof_old);
	} else {
		vhba->fcoe_hlen = sizeof(struct fcoe_hdr);
		vhba->fc_payload_size = mtu -
		    sizeof(struct fcoe_hdr) -
		    sizeof(struct fc_frame_header) -
		    sizeof(struct fcoe_crc_eof);
	}

	if (net_type == NET_IB) {
		vhba->fc_payload_size -= 2;
		if (!mfc_t11_mode)
			/* in IB pre-T11 we have 3 padding in EOF */
			vhba->fc_payload_size -= 3;
	}

	/*
	 * Enforcing the fc_payload_size to 8B multiple to work-around
	 * Tachyon/Tachlite DIF insertion/marshalling on 8B alignment.
	 */
	vhba->fc_payload_size = min(mfc_payload_size,
				    vhba->fc_payload_size) & 0xFFFFFFFFFFFFFFF0;
	vhba->num_fexch = 1 << fc_port->log_num_fexch_per_vhba;
	vhba->base_fexch_qpn = fc_port->base_fexch_qpn + idx * vhba->num_fexch;
	vhba->base_fexch_mpt = fc_port->base_fexch_mpt + idx * vhba->num_fexch;

	shost_printk(KERN_INFO, lp->host,
		     "vhba=%d type %s on port=%d b_qpn=0x%x, b_mpt=0x%x,"
		     " n_fexch=%d, fc_payload_size=%d\n",
		     vhba->idx, (net_type == NET_IB) ? "NET_IB" : "NET_ETH",
		     port, vhba->base_fexch_qpn, vhba->base_fexch_mpt,
		     vhba->num_fexch, vhba->fc_payload_size);

	vhba->net_type = net_type;

	switch (vhba->net_type) {
	case NET_ETH:
		vhba->fc_vlan_id = vlan_id;
		break;
	case NET_IB:
		break;
	}

	err = mfc_create_rfci(vhba);
	if (err) {
		shost_printk(KERN_ERR, vhba->lp->host,
			     "Create rfci vhba=%d port=%d err=%d\n",
			     vhba->idx, vhba->mfc_port->port, err);
		goto err_free_fexch_bulk;
	}

	err = mfc_create_fexchs(vhba);
	if (err) {
		shost_printk(KERN_ERR, lp->host,
			     "Fail to create FCMD vhba=%d port=%d err=%d\n",
			     idx, port, err);
		goto err_destroy_rfci;
	}

	err = mfc_libfc_init(lp, vhba->base_reserved_xid,
			100, //FC_XID_MAX, //vhba->base_reserved_xid + vhba->num_reserved_xid - 1,
			     wwpn, wwnn);
	if (err) {
		shost_printk(KERN_ERR, lp->host,
			     "Fail to init libfc vhba=%d port=%d err=%d\n",
			     idx, port, err);
		goto err_destroy_fcmd;
	}

	spin_lock_irqsave(&fc_port->lock, flags);
	list_add(&vhba->list, &fc_port->vhba_list);
	spin_unlock_irqrestore(&fc_port->lock, flags);

	err = mfc_vhba_register_sysfs(vhba);
	if (err) {
		shost_printk(KERN_ERR, lp->host,
			     "Fail to add vhba=%d port=%d to sysfs, err=%d\n",
			     idx, port, err);
		goto err_destroy_libfc;
	}

	return vhba;

err_destroy_libfc:
	fc_remove_host(lp->host);
//	scsi_remove_host(lp->host);
	fc_lport_destroy(lp);
err_destroy_fcmd:
	mfc_destroy_fexchs(vhba);
err_destroy_rfci:
	mfc_destroy_rfci(vhba);
err_free_fexch_bulk:
	mfc_bitmap_slot_free(&fc_port->fexch_bulk_bm, idx);
err_lport_destroy:
	fc_lport_free_stats(lp);
	if (vhba->emp) {
		fc_exch_mgr_free(lp);
		vhba->emp = NULL;
	}
err_host_put:
	scsi_host_put(lp->host);
err_out:
	return ERR_PTR(err);
}

struct mfc_vhba *mfc_create_vhba_fcoe(struct mfc_port *mfc_port, int vlan_id,
		int mtu, int priv_size, struct module *owner)
{
	struct mfc_vhba *vhba;
	struct mfc_dev *mfc_dev = mfc_port->mfc_dev;
	struct mlx4_dev *dev = mfc_dev->dev;
	u64 wwn, wwpn, wwnn;

	wwn = mfc_dev->dev->caps.def_mac[mfc_port->port];
	wwnn = wwn | ((u64) 0x10 << 56);
	wwpn = wwn | ((u64) 0x20 << 56);

	vhba = mfc_create_vhba(mfc_port, mtu, vlan_id,
			NET_ETH, wwpn, wwnn, priv_size, owner);
	if (IS_ERR(vhba)) {
		dev_err(&dev->pdev->dev,
			"Could not create vhba for vlan %d\n",
			vlan_id);
	}
	return vhba;
}
EXPORT_SYMBOL(mfc_create_vhba_fcoe);

struct mfc_vhba *mfc_create_vhba_fcoib(struct mfc_port *fc_port, unsigned int mtu,
		      u64 wwpn, u64 wwnn, int priv_size,
		      struct module *owner)
{
	struct mfc_vhba *vhba;

	if (!fc_port->initialized) {
		printk(KERN_ALERT "Port is not yet initialized for FCoIB\n");
		return ERR_PTR(-EINVAL);
	}

	vhba = mfc_create_vhba(fc_port, mtu, -1,
			NET_IB, wwpn, wwnn, priv_size, owner);
	if (IS_ERR(vhba)) {
		printk(KERN_ALERT "FAIL: create vhba\n");
	}
	return vhba;
}
EXPORT_SYMBOL(mfc_create_vhba_fcoib);

void mfc_destroy_vhba(struct mfc_vhba *vhba)
{
	struct mfc_port *fc_port = vhba->mfc_port;
	int port = fc_port->port, idx = vhba->idx;
	struct fc_lport *lp = vhba->lp;
	unsigned long flags;

	shost_printk(KERN_ERR, lp->host,
		     "Remove vhba=%d on port=%d\n",
		     vhba->idx, port);

	vhba->going_down = 1;

	fc_linkdown(lp);
	if (lp->tt.rport_flush_queue)
		lp->tt.rport_flush_queue();

	spin_lock_irqsave(&fc_port->lock, flags);
	list_del(&vhba->list);
	spin_unlock_irqrestore(&fc_port->lock, flags);

	fc_lport_destroy(lp);
	mfc_destroy_fexchs(vhba);
	mfc_deinit_rfci(vhba);
	mfc_destroy_rfci(vhba);

	/* ensure that all works are done, this vhba will not queue new ones */
	flush_workqueue(vhba->mfc_port->rfci_wq);

	mfc_bitmap_slot_free(&fc_port->fexch_bulk_bm, idx);

//	fc_remove_host(lp->host);
//	scsi_remove_host(lp->host);
	if (vhba->emp) {
		fc_exch_mgr_free(lp);
		vhba->emp = NULL;
	}
	fc_lport_free_stats(lp);
	mfc_vhba_deregister_sysfs(vhba);
}
EXPORT_SYMBOL(mfc_destroy_vhba);

static struct mlx4_interface mfc_interface;

int mfc_init_port(struct mfc_dev *mfc_dev, int port)
{
	struct mfc_port *mfc_port = &mfc_dev->mfc_port[port];
	u64 wwn, wwpn;
	int err = 0;
	struct mfc_basic_config_params params = { 0 };
	int count = 0;
	char wq_name[16];

	memset(&mfc_port->npid_table, 0,
	       sizeof(struct nport_id) * MFC_NUM_NPORT_IDS);
	mfc_port->port = port;
	mfc_port->mfc_dev = mfc_dev;
	mfc_port->lock = __SPIN_LOCK_UNLOCKED(mfc_port->lock);
	INIT_LIST_HEAD(&mfc_port->vhba_list);
	INIT_DELAYED_WORK(&mfc_port->link_work, mfc_link_work);
	mfc_port->link_up = 1;
	mfc_port->num_fexch_qps =
	    (1 << mfc_log_exch_per_vhba) * max_vhba_per_port;
	mfc_port->log_num_fexch_per_vhba = mfc_log_exch_per_vhba;

	wwn = mfc_dev->dev->caps.def_mac[port];
	wwpn = wwn | ((u64) 0x20) << 56;
	u64_to_mac(mfc_port->def_mac, wwn);
	u64_to_wwpn(mfc_port->def_wwpn, wwpn);

	printk("mfc_init_port def_mac: %x:%x:%x:%x:%x:%x\n", mfc_port->def_mac[0],
		mfc_port->def_mac[1], mfc_port->def_mac[2], mfc_port->def_mac[3],
		mfc_port->def_mac[4], mfc_port->def_mac[5]);
	printk("mfc_init_port_def_wwpn %x:%x:%x:%x:%x:%x:%x:%x\n", mfc_port->def_wwpn[0],
		mfc_port->def_wwpn[1], mfc_port->def_wwpn[2], mfc_port->def_wwpn[3],
		mfc_port->def_wwpn[4], mfc_port->def_wwpn[5], mfc_port->def_wwpn[6],
		mfc_port->def_wwpn[7]);

	err = mlx4_qp_reserve_range(mfc_dev->dev, mfc_port->num_fexch_qps,
				    MFC_MAX_PORT_FEXCH,
				    &mfc_port->base_fexch_qpn);
	if (err) {
		dev_err(mfc_dev->dma_dev,
			"Could not allocate QP range for FEXCH."
			" Need 0x%x QPs aligned to 0x%x on port %d\n",
			mfc_port->num_fexch_qps, MFC_MAX_PORT_FEXCH, port);
		err = -ENOMEM;
		goto err_out;
	}

	/* TODO: for bidirectional SCSI we'll need to double the amount of
	   reserved MPTs, with proper spanning */
	err = mlx4_mr_reserve_range(mfc_dev->dev, mfc_port->num_fexch_qps,
				    2 * MFC_MAX_PORT_FEXCH,
				    &mfc_port->base_fexch_mpt);
	if (err) {
		dev_err(mfc_dev->dma_dev,
			"Could not allocate MPT range for FEXCH."
			" Need 0x%x MPTs aligned to 0x%x on port %d\n",
			mfc_port->num_fexch_qps, 2 * MFC_MAX_PORT_FEXCH, port);
		err = -ENOMEM;
		goto err_free_qp_range;
	}

	switch (mfc_dev->dev->caps.port_type[port]) {
	case MLX4_PORT_TYPE_IB:
		mfc_port->net_type = NET_IB;
		mfc_port->underdev = mlx4_get_protocol_dev(mfc_dev->dev,
						MLX4_PROT_IB_IPV4, port);
		break;
	case MLX4_PORT_TYPE_ETH:
		mfc_port->net_type = NET_ETH;
		mfc_port->underdev = mlx4_get_protocol_dev(mfc_dev->dev,
						MLX4_PROT_ETH, port);
		break;
	default:
		err = 1;
		goto err_free_qp_range;
	}

	count = max_vhba_per_port;
	err = mlx4_qp_reserve_range(mfc_dev->dev, count, count,
				    &mfc_port->base_rfci_qpn);
	if (err) {
		dev_err(mfc_dev->dma_dev,
			"Could not allocate QP range for RFCIs."
			" Need 0x%x QPs naturally aligned on port %d\n",
			max_vhba_per_port, port);
		err = -ENOMEM;
		goto err_out;
	}

	mfc_port->num_rfci_qps = count;
	params.rfci_base = mfc_port->base_rfci_qpn;
	params.fexch_base = mfc_port->base_fexch_qpn;
	params.fexch_base_mpt = mfc_port->base_fexch_mpt;
	params.log_num_rfci = ilog2(count);
	params.def_fcoe_promisc_qpn = 0x77;
	params.def_fcoe_mcast_qpn = 0x78;

	dev_info(mfc_dev->dma_dev,
		 "port %d b_fexch=0x%x, n_fexch=0x%x, b_mpt=0x%x,"
		 " b_rfci=0x%x, num_rfci=0x%x\n",
		 port, mfc_port->base_fexch_qpn, mfc_port->num_fexch_qps,
		 mfc_port->base_fexch_mpt, mfc_port->base_rfci_qpn, count);

	if (mfc_port->net_type == NET_ETH) {
		u8 pptx = 0, pprx = 0, pfctx = 0, pfcrx = 0;
		err = mlx4_SET_PORT_general(mfc_dev->dev, port,
				mfc_payload_size + sizeof(struct fcoe_hdr) +
				sizeof(struct fc_frame_header) +
				sizeof(struct fcoe_crc_eof) +
				14 + 4 + 4, /* ETH header + VLAN header + ETH_FCS */
				pptx, pfctx, pprx, pfcrx);
		if (err) {
			dev_err(mfc_dev->dma_dev,
					"could not set port %d\n", port);
			goto err_free_mr_range;
		}
	}

	err = mlx4_INIT_PORT(mfc_dev->dev, port);
	if (err) {
		dev_err(mfc_dev->dma_dev,
			"could not init port %d\n", port);
		goto err_free_mr_range;
	}

	err = mlx4_CONFIG_FC_BASIC(mfc_dev->dev, port, &params);
	if (err) {
		dev_err(mfc_dev->dma_dev,
			"Failed issue CONFIG_FC Basic on port %d\n", port);
		goto err_close_port;
	}

	err = mfc_bitmap_alloc(&mfc_port->fexch_bulk_bm,
			       mfc_port->num_fexch_qps >> mfc_port->
			       log_num_fexch_per_vhba);

	if (err) {
		dev_err(mfc_dev->dma_dev,
			"Failed alloc fexch bulks bitmap on port %d\n", port);
		goto err_free_mr_range;
	}

	snprintf(wq_name, 16, "rfci_wq_%d_%d", mfc_dev_idx, port);

	mfc_port->rfci_wq = create_singlethread_workqueue(wq_name);
	if (!mfc_port->rfci_wq)
		goto err_free_qp_range;

	snprintf(wq_name, 16, "async_wq_%d_%d", mfc_dev_idx, port);
	mfc_port->async_wq = create_singlethread_workqueue(wq_name);
	if (!mfc_port->async_wq)
		goto err_free_rfci_wq;

	err = mfc_create_fip(mfc_port);
	if (err) {
		dev_err(mfc_dev->dma_dev,
			"failed to create fip qp for port %d\n", port);
		goto err_free_async_wq;
	}

	err = mfc_init_fip(mfc_port);
	if (err) {
		dev_err(mfc_dev->dma_dev,
			"failed to init fip qp for port %d\n", port);
		goto err_destroy_fip;
	}

	mfc_port->mfc_fip_ctlr = NULL;
	mfc_port->initialized = 1;

	mfc_port_register_sysfs(mfc_port);

	if (fip_ctlrs[mfc_port->net_type - 1].add_port)
		fip_ctlrs[mfc_port->net_type - 1].add_port(mfc_port);

	return 0;

err_destroy_fip:
	mfc_destroy_fip(mfc_port);
err_free_async_wq:
	destroy_workqueue(mfc_port->async_wq);
err_free_rfci_wq:
	destroy_workqueue(mfc_port->rfci_wq);
err_free_qp_range:
	mlx4_qp_release_range(mfc_dev->dev, mfc_port->base_fexch_qpn,
			      mfc_port->num_fexch_qps);
err_close_port:
	mlx4_CLOSE_PORT(mfc_dev->dev, port);
err_free_mr_range:
	mlx4_mr_release_range(mfc_dev->dev, mfc_port->base_fexch_mpt,
			      mfc_port->num_fexch_qps);
err_out:
	return err;
}

void mfc_free_port(struct mfc_dev *mfc_dev, int port)
{
	struct mfc_port *fc_port = &mfc_dev->mfc_port[port];
	struct mfc_vhba *vhba, *tmp;

	if (fip_ctlrs[fc_port->net_type - 1].rem_port)
		fip_ctlrs[fc_port->net_type - 1].rem_port(fc_port);

	mfc_port_deregister_sysfs(fc_port);

	fc_port->initialized = 0;

	mfc_deinit_fip(fc_port);
	mfc_destroy_fip(fc_port);

	flush_workqueue(fc_port->rfci_wq);
	flush_workqueue(fc_port->async_wq);

	if (!list_empty(&fc_port->vhba_list)) {
		dev_warn(mfc_dev->dma_dev, "leakage: vHBAs exist while unloading mlx4_fc\n");
		list_for_each_entry_safe(vhba, tmp, &fc_port->vhba_list, list)
			mfc_destroy_vhba(vhba);
	}

	mlx4_qp_release_range(mfc_dev->dev, fc_port->base_rfci_qpn,
			fc_port->num_rfci_qps);
	/*
	 * make sure the bitmap is empty, meaning, no vhba's left using
	 * fexch bulk
	 */
	mfc_bitmap_free(&fc_port->fexch_bulk_bm);
	mlx4_qp_release_range(mfc_dev->dev, fc_port->base_fexch_qpn,
			      fc_port->num_fexch_qps);
	mlx4_CLOSE_PORT(mfc_dev->dev, port);
	mlx4_mr_release_range(mfc_dev->dev, fc_port->base_fexch_mpt,
			      fc_port->num_fexch_qps);

	destroy_workqueue(fc_port->rfci_wq);
	destroy_workqueue(fc_port->async_wq);
}

void mlx4_fc_rescan_ports(enum mfc_net_type net_type)
{
	struct mfc_dev *mfc_dev;
	struct mfc_port *mfc_port;
	struct mfc_fip_ctlr *mlx4_fip = &fip_ctlrs[net_type - 1];
	int port;

	mutex_lock(&mfc_dev_list_lock);
	list_for_each_entry(mfc_dev, &mfc_dev_list, list) {
		for (port = 1; port <= mfc_dev->dev->caps.num_ports; port++) {
			mfc_port = &mfc_dev->mfc_port[port];
			if (!mfc_port->initialized)
				continue;
			if (mfc_port->net_type != net_type)
				continue;
			if (mlx4_fip->add_port)
				mlx4_fip->add_port(mfc_port);
		}
	}
	mutex_unlock(&mfc_dev_list_lock);
}
EXPORT_SYMBOL(mlx4_fc_rescan_ports);

void mlx4_fc_register_fip_ctlr(struct mfc_fip_ctlr *mlx4_fip, enum mfc_net_type net_type)
{
	fip_ctlrs[net_type - 1] = *mlx4_fip;
	mlx4_fc_rescan_ports(net_type);
}
EXPORT_SYMBOL(mlx4_fc_register_fip_ctlr);

void mlx4_fc_deregister_fip_ctlr(enum mfc_net_type net_type)
{
	struct mfc_dev *mfc_dev;
	struct mfc_port *mfc_port;
	int port;

	mutex_lock(&mfc_dev_list_lock);
	list_for_each_entry(mfc_dev, &mfc_dev_list, list) {
		for (port = 1; port <= mfc_dev->dev->caps.num_ports; port++) {
			mfc_port = &mfc_dev->mfc_port[port];
			if (!mfc_port->initialized)
				continue;
			if (mfc_port->net_type != net_type)
				continue;
			if (fip_ctlrs[net_type - 1].rem_port)
				fip_ctlrs[net_type - 1].rem_port(mfc_port);
		}
	}
	mutex_unlock(&mfc_dev_list_lock);

	memset(&fip_ctlrs[net_type - 1], 0, sizeof fip_ctlrs[net_type - 1]);
}
EXPORT_SYMBOL(mlx4_fc_deregister_fip_ctlr);

static void *mfc_add_dev(struct mlx4_dev *dev)
{
	struct mfc_dev *mfc_dev;
	int port;
	int err;
	int pre_t11_enable = 0;
	int t11_supported = 0;

	async_events_disabled--;

	dev_info(&dev->pdev->dev, "Adding device[%d] %.*s at %s\n",
		 mfc_dev_idx + 1, MLX4_BOARD_ID_LEN, dev->board_id,
		 dev_driver_string(&dev->pdev->dev));

	mfc_dev = kzalloc(sizeof(struct mfc_dev), GFP_KERNEL);
	if (!mfc_dev) {
		dev_err(&dev->pdev->dev, "Alloc mfc_dev failed\n");
		goto err_out;
	}

	mfc_dev->idx = mfc_dev_idx++;

	err = mlx4_pd_alloc(dev, &mfc_dev->priv_pdn);
	if (err) {
		dev_err(&dev->pdev->dev, "PD alloc failed %d\n", err);
		goto err_free_dev;
	}

	err = mlx4_mr_alloc(dev, mfc_dev->priv_pdn, 0, ~0ull,
			    MLX4_PERM_LOCAL_WRITE | MLX4_PERM_LOCAL_READ, 0, 0,
			    &mfc_dev->mr);
	if (err) {
		dev_err(&dev->pdev->dev, "mr alloc failed %d\n", err);
		goto err_free_pd;
	}

	err = mlx4_mr_enable(dev, &mfc_dev->mr);
	if (err) {
		dev_err(&dev->pdev->dev, "mr enable failed %d\n", err);
		goto err_free_mr;
	}

	if (mlx4_uar_alloc(dev, &mfc_dev->priv_uar))
		goto err_free_mr;

	mfc_dev->uar_map = ioremap(mfc_dev->priv_uar.pfn << PAGE_SHIFT,
				   PAGE_SIZE);
	if (!mfc_dev->uar_map)
		goto err_free_uar;

	MLX4_INIT_DOORBELL_LOCK(&mfc_dev->uar_lock);

	INIT_LIST_HEAD(&mfc_dev->pgdir_list);
	mutex_init(&mfc_dev->pgdir_mutex);

	mfc_dev->dev = dev;
	mfc_dev->dma_dev = &dev->pdev->dev;
#warning mlx4_get_fc_t11_settings() missing...
#if 0
	mlx4_get_fc_t11_settings(dev, &pre_t11_enable, &t11_supported);
#else
	t11_supported = 1;
	pre_t11_enable = 0;
#endif
	if (pre_t11_enable) {
		mfc_t11_mode = 0;
		dev_info(&dev->pdev->dev, "Starting FC device PRE-T11 mode\n");
	} else if (t11_supported && !pre_t11_enable) {
		mfc_t11_mode = 1;
		dev_info(mfc_dev->dma_dev, "Starting FC device T11 mode\n");
	} else {
		dev_err(mfc_dev->dma_dev, "FAIL start fc device in T11 mode, "
			"please enable PRE-T11 in mlx4_core\n");
		goto err_free_uar;
	}

	mfc_device_register_sysfs(mfc_dev);

	for (port = 1; port <= mfc_dev->dev->caps.num_ports; port++) {
		err = mfc_init_port(mfc_dev, port);
		if (err)
			goto err_free_ports;
	}

	mutex_lock(&mfc_dev_list_lock);
	list_add(&mfc_dev->list, &mfc_dev_list);
	mutex_unlock(&mfc_dev_list_lock);

	async_events_disabled--;

	if (!async_events_disabled)
		dev_info(&dev->pdev->dev, "Event enabled\n");
	return mfc_dev;

err_free_ports:
	while (--port)
		mfc_free_port(mfc_dev, port);
	iounmap(mfc_dev->uar_map);
err_free_uar:
	mlx4_uar_free(dev, &mfc_dev->priv_uar);
err_free_mr:
	mlx4_mr_free(mfc_dev->dev, &mfc_dev->mr);
err_free_pd:
	mlx4_pd_free(dev, mfc_dev->priv_pdn);
err_free_dev:
	kfree(mfc_dev);
err_out:
	return NULL;
}

static void mfc_remove_dev(struct mlx4_dev *dev, void *fcdev_ptr)
{
	struct mfc_dev *mfc_dev = fcdev_ptr;
	int port;

	dev_info(&dev->pdev->dev, "%.*s: removing\n", MLX4_BOARD_ID_LEN,
		 dev->board_id);

	mutex_lock(&mfc_dev_list_lock);
	list_del(&mfc_dev->list);
	mutex_unlock(&mfc_dev_list_lock);

	for (port = 1; port <= mfc_dev->dev->caps.num_ports; port++)
		mfc_free_port(mfc_dev, port);

	iounmap(mfc_dev->uar_map);
	mlx4_uar_free(dev, &mfc_dev->priv_uar);
	mlx4_mr_free(dev, &mfc_dev->mr);
	mlx4_pd_free(dev, mfc_dev->priv_pdn);

	mfc_device_unregister_sysfs(mfc_dev);
}

static void mfc_link_work(struct work_struct *work)
{
	struct mfc_port *fc_port =
	    container_of(work, struct mfc_port, link_work.work);
	struct mfc_vhba *vhba, *tmp;
	struct fc_lport *lp;

	if (fip_ctlrs[fc_port->net_type - 1].link_state_changed)
		fip_ctlrs[fc_port->net_type - 1].link_state_changed(fc_port);

	list_for_each_entry_safe(vhba, tmp, &fc_port->vhba_list, list) {
		lp = vhba->lp;
		if (!fc_port->link_up) {
			if (vhba->net_type == NET_IB)
				fc_linkdown(lp);
		}
	}
}

static void mfc_async_event(struct mlx4_dev *dev, void *mfc_dev_ptr,
			    enum mlx4_dev_event event, unsigned long port)
{
	struct mfc_dev *mfc_dev = (struct mfc_dev *)mfc_dev_ptr;
	struct mfc_port *fc_port = &mfc_dev->mfc_port[port];
	int link_up;

	fctgt_dbg("Got async event: %d\n", event);
	if (async_events_disabled) {
		fctgt_dbg("Event still disabled - ignoring\n");
		return;
	}

	if (!fc_port) {
		fctgt_err("ERROR fc_port is down before disabling event!!!\n");
		return;
	}
	switch (event) {
	case MLX4_DEV_EVENT_PORT_UP:
		link_up = 1;
		break;
	case MLX4_DEV_EVENT_CATASTROPHIC_ERROR:
	case MLX4_DEV_EVENT_PORT_DOWN:
		link_up = 0;
		break;
	case MLX4_DEV_EVENT_PORT_REINIT:
	default:
		return;
	}

	fc_port->link_up = link_up;
	cancel_delayed_work(&fc_port->link_work);
	dev_info(&mfc_dev->dev->pdev->dev,
			"Link %s on port %lu\n",
			link_up ? "UP" : "DOWN", port);
	queue_delayed_work(fc_port->async_wq, &fc_port->link_work,
			MFC_ASYNC_DELAY);
}

int mfc_reset(struct Scsi_Host *shost)
{
	struct fc_lport *lp = shost_priv(shost);
	struct mfc_vhba *vhba = lport_priv(lp);

	if (vhba->in_reset)
		return FAILED;

	shost_printk(KERN_ERR, shost,
		     "Reset vhba=%d on port=%d\n", vhba->idx, vhba->mfc_port->port);

	vhba->in_reset = 1;

	return mfc_lld_reset(lp);
}

static int mfc_lld_reset(struct fc_lport *lp)
{
	struct mfc_vhba *vhba = lport_priv(lp);
	int port = vhba->mfc_port->port;
	int i;
	int err = 0;

	if (!vhba->in_reset)
		return -EINVAL;

	shost_printk(KERN_ERR, lp->host,
		     "lld reset on port%d vhba%d link_up=%d\n",
		     port, vhba->idx, vhba->mfc_port->link_up);

	for (i = 0; i < vhba->num_fexch; ++i) {
		struct mfc_exch *fexch = &vhba->fexch[i];

		if (fexch->state == FEXCH_SEND_ABORT) {
			shost_printk(KERN_ERR, lp->host,
				     "complete fexch %x state %d\n", i, fexch->state);
			fexch->state = FEXCH_ABORT_TIMEOUT;
			complete(&fexch->tm_done);
		}
	}

	vhba->rfci.fc_qp.is_flushing = 1;

	/* deinit, destroy and create rfci */
	mfc_deinit_rfci(vhba);
	err = mfc_destroy_rfci(vhba);
	if (err) {
		shost_printk(KERN_ERR, lp->host,
			     "Failed to destroy RFCI vhba%d port=%d err=%d\n",
			     vhba->idx, port, err);
		goto out;
	}

	err = mfc_create_rfci(vhba);
	if (err) {
		shost_printk(KERN_ERR, vhba->lp->host,
			     "Create rfci vhba=%d port=%d err=%d\n",
			     vhba->idx, vhba->mfc_port->port, err);
		goto out;
	}

	/* destroy and create fcmd - will be init on flogi accept */
	if (mfc_reset_fexchs(vhba))
		shost_printk(KERN_ERR, lp->host,
				"Failed to reset fexchs vhba=%d port=%d\n",
				vhba->idx, port);

	vhba->flogi_finished = 0;
	vhba->in_reset = 0;

	shost_printk(KERN_ERR, lp->host,
		     "lld reset on port%d vhba%d DONE\n",
		     port, vhba->idx);
out:
	return err;
}

static int mfc_device_reset(struct scsi_cmnd *cmd)
{
	struct mfc_vhba *vhba;
	struct fc_lport *lp;
	int rc = FAILED;

	lp = shost_priv(cmd->device->host);
	if (!lp || lp->state != LPORT_ST_READY || !lp->link_up)
		goto out;

	vhba = lport_priv(lp);
	if (!vhba || !vhba->mfc_port->link_up || vhba->going_down)
		goto out;

	shost_printk(KERN_ERR, vhba->lp->host,
		     "Device reset function called vhba=%d port=%d\n",
		     vhba->idx, vhba->mfc_port->port);
out:
	return rc;
}

struct fc_function_template mfc_transport_function = {
	.show_host_node_name = 1,
	.show_host_port_name = 1,
	.show_host_supported_classes = 1,
	.show_host_supported_fc4s = 1,
	.show_host_active_fc4s = 1,
	.show_host_maxframe_size = 1,

	.show_host_port_id = 1,
	.show_host_supported_speeds = 1,
	.get_host_speed = fc_get_host_speed,
	.show_host_speed = 1,
	.show_host_port_type = 1,
	.get_host_port_state = fc_get_host_port_state,
	.show_host_port_state = 1,
	.show_host_symbolic_name = 1,

	.dd_fcrport_size = sizeof(struct fc_rport_libfc_priv),
	.show_rport_maxframe_size = 1,
	.show_rport_supported_classes = 1,

	.show_host_fabric_name = 1,
	.show_starget_node_name = 1,
	.show_starget_port_name = 1,
	.show_starget_port_id = 1,
	.set_rport_dev_loss_tmo = fc_set_rport_loss_tmo,
	.show_rport_dev_loss_tmo = 1,
	.get_fc_host_stats = fc_get_host_stats,
	.issue_fc_host_lip = mfc_reset,
	.terminate_rport_io = fc_rport_terminate_io,
};

static struct mlx4_interface mfc_interface = {
	.add = mfc_add_dev,
	.remove = mfc_remove_dev,
	.event = mfc_async_event
};

static int __init mfc_init(void)
{
	int err = 0;

	/* verify parameters */
	if (mfc_payload_size > 2112) {
		printk(KERN_WARNING "mlx_fc: mfc_payload_size > 2112, using 2112\n");
		mfc_payload_size = 2112;
	}

//	if (scst_register_target_template(&mfct_tgt_templete) < 0) {
//		return  -ENODEV;
//	}

	mutex_init(&mfc_dev_list_lock);
	mfc_transport_template = fc_attach_transport(&mfc_transport_function);
	if (mfc_transport_template == NULL) {
		printk(KERN_ERR PFX "Fail to attach fc transport");
		return -1;
	}

	mfc_sysfs_setup();

	err = mlx4_register_interface(&mfc_interface);
	if (err) {
		fc_release_transport(mfc_transport_template);
		return err;
	}

	return 0;
}

static void __exit mfc_cleanup(void)
{
//	scst_unregister_target_template(&mfct_tgt_templete);

	mlx4_unregister_interface(&mfc_interface);

	mfc_sysfs_cleanup();

	fc_release_transport(mfc_transport_template);
}

module_init(mfc_init);
module_exit(mfc_cleanup);
