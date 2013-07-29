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
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/vmalloc.h>
#include <linux/ip.h>
#include <linux/in.h>

#include <net/dst.h>

#include "fcoib.h"
#include "mfc.h"
#include "fip_ctlr_api.h"

MODULE_DESCRIPTION("FCoIB Discovery");
MODULE_LICENSE("Dual BSD/GPL");

int fip_debug = LOG_PRIO_HIGH;
module_param_named(fip_debug_level, fip_debug, int, 0644);
MODULE_PARM_DESC(fip_debug_level, "set verbosity level of debug message");

int fip_auto_create = 0;
module_param_named(auto_create, fip_auto_create, int, 0644);
MODULE_PARM_DESC(auto_create, "Automatically create vHBAs to every discovered FCF. Default=0");

struct workqueue_struct *fip_workqueue;
struct workqueue_struct *fip_mng_workqueue;
struct ib_sa_client fip_sa_client;

static inline void fip_wr_pepare(struct fip_dev_priv *priv,
				 struct ib_send_wr *tx_wr,
				 struct ib_sge *tx_sge,
				 unsigned int wr_id, u64 mapping,
				 int size, u16 pkey_index)
{
	memset(tx_wr, 0, sizeof(struct ib_send_wr));
	tx_wr->num_sge = 1;
	tx_wr->sg_list = tx_sge;
	tx_wr->opcode = IB_WR_SEND;
	tx_wr->send_flags = IB_SEND_SIGNALED | IB_SEND_SOLICITED;
	tx_wr->wr.ud.pkey_index = pkey_index;
	tx_wr->wr_id = wr_id;

	memset(tx_sge, 0, sizeof(struct ib_sge));
	tx_sge->lkey = priv->mr->lkey;
	tx_sge->addr = mapping;
	tx_sge->length = size;
}

/*
 * send a single multicast packet.
 * return 0 on success, other on failure.
*/
int fip_mcast_send(struct fip_dev_priv *priv, struct ib_qp *qp,
		   unsigned int wr_id, u64 mapping,
		   int size, u16 pkey_index, struct mcast_entry *mcast)
{
	struct ib_send_wr *bad_wr;
	struct ib_sge tx_sge;
	struct ib_send_wr tx_wr;
	int ret;

	fip_wr_pepare(priv, &tx_wr, &tx_sge, wr_id, mapping, size, pkey_index);

	tx_wr.wr.ud.ah = mcast->ah;
	tx_wr.wr.ud.remote_qpn = 0xFFFFFFFF;
	tx_wr.wr.ud.remote_qkey = mcast->qkey;

	ret = ib_post_send(qp, &tx_wr, &bad_wr);

	return ret;
}

/*
 * send a single unicast packet.
 * return 0 on success, other on failure.
*/
int fip_ucast_send(struct fip_dev_priv *priv, struct ib_qp *qp,
		   unsigned int wr_id, u64 mapping,
		   int size, u16 pkey_index, u32 dest_qpn, u16 dlid, u32 qkey)
{
	struct ib_send_wr *bad_wr;
	struct ib_ah *new_ah;
	struct ib_sge tx_sge;
	struct ib_send_wr tx_wr;
	int ret;
	struct ib_ah_attr ah_attr = {
		.dlid = dlid,
		.port_num = priv->port,
	};

	fip_wr_pepare(priv, &tx_wr, &tx_sge, wr_id, mapping, size, pkey_index);

	new_ah = ib_create_ah(priv->pd, &ah_attr);
	if (IS_ERR(new_ah))
		return -1;

	tx_wr.wr.ud.ah = new_ah;
	tx_wr.wr.ud.remote_qpn = dest_qpn;
	tx_wr.wr.ud.remote_qkey = qkey;

	ret = ib_post_send(qp, &tx_wr, &bad_wr);

	ib_destroy_ah(new_ah);

	return ret;
}

/*
 * This is a general purpose CQ completion function that handles
 * completions on RX and TX rings. It can serve all users that are
 * using RX and TX rings.
 * RX completions are destinguished from TX comp by the MSB that is set
 * for RX and clear for TX. For RX, the memory is unmapped from the PCI,
 * The head is incremented. For TX the memory is unmapped and then freed.
 * The function returns the number of packets received.
*/
int fip_comp(struct fip_dev_priv *priv, struct ib_cq *cq,
	     struct ring *rx_ring, struct ring *tx_ring)
{
#define FIP_DISCOVER_WC_COUNT 4
	struct ib_wc ibwc[FIP_DISCOVER_WC_COUNT];
	int wrid, n, i;
	int mtu_size = FIP_UD_BUF_SIZE(priv->max_ib_mtu);
	int rx_count = 0;

	do {
		/*
		 * poll for up to FIP_DISCOVER_WC_COUNT in one request. n
		 * returns the number of WC actually polled
		 */
		n = ib_poll_cq(cq, FIP_DISCOVER_WC_COUNT, ibwc);
		for (i = 0; i < n; ++i) {
			/*
			 * use a mask on the id to decide if this is a receive
			 * or  transmit WC
			 */
			if (ibwc[i].wr_id & FIP_OP_RECV) {
				wrid = ibwc[i].wr_id & ~FIP_OP_RECV;

				ib_dma_unmap_single(priv->ca,
						    rx_ring->ring[wrid].
						    bus_addr, mtu_size,
						    DMA_FROM_DEVICE);

				/* */
				if (likely(ibwc[i].status == IB_WC_SUCCESS)) {
					rx_ring->ring[wrid].length =
					    ibwc[i].byte_len;
					rx_ring->head =
					    (wrid + 1) & (rx_ring->size - 1);
					rx_count++;
				} else {
					rx_ring->ring[wrid].length = 0;
					kfree(rx_ring->ring[wrid].mem);
				}
			} else {	/* TX completion */
				wrid = ibwc[i].wr_id;

				/* unmap and free transmitted packet */
				ib_dma_unmap_single(priv->ca,
						    tx_ring->ring[wrid].
						    bus_addr, ibwc[i].byte_len,
						    DMA_TO_DEVICE);

				kfree(tx_ring->ring[wrid].mem);
				tx_ring->ring[wrid].length = 0;
				tx_ring->tail = wrid;
			}
		}
	} while (n == FIP_DISCOVER_WC_COUNT);

	ib_req_notify_cq(cq, IB_CQ_NEXT_COMP);

	return rx_count;
}

/* configure a newly allocated QP and move it
 * from reset->init->RTR->RTS
 */
int fip_init_qp(struct fip_dev_priv *priv, struct ib_qp *qp,
		u16 pkey_index, u32 qkey)
{
	int ret;
	struct ib_qp_attr qp_attr;
	int attr_mask;

	/* TODO - fix this
	   if (!test_bit(IPOIB_PKEY_ASSIGNED, &priv->flags))
	   return -1; */

	qp_attr.qp_state = IB_QPS_RESET;
	if (ib_modify_qp(qp, &qp_attr, IB_QP_STATE))
		fip_dev_warn(priv, "Failed to modify QP to RESET state\n");

	qp_attr.qp_state = IB_QPS_INIT;
	qp_attr.qkey = qkey;
	qp_attr.port_num = priv->port;
	qp_attr.pkey_index = pkey_index;
	attr_mask = IB_QP_QKEY | IB_QP_PORT | IB_QP_PKEY_INDEX | IB_QP_STATE;
	ret = ib_modify_qp(qp, &qp_attr, attr_mask);
	if (ret) {
		fip_dev_warn(priv, "failed to modify QP to init, ret = %d\n", ret);
		fip_dev_warn(priv, "qkey=%d, port_num=%d, pkey_index=0x%x,"
			 " pkey_index=0x%x\n", (int)qp_attr.qkey,
			 (int)qp_attr.port_num, (int)priv->pkey_index,
			 (int)qp_attr.pkey_index);
		goto out_fail;
	}

	qp_attr.qp_state = IB_QPS_RTR;
	/* Can't set this in a INIT->RTR transition */
	attr_mask &= ~IB_QP_PORT;
	ret = ib_modify_qp(qp, &qp_attr, attr_mask);
	if (ret) {
		fip_dev_warn(priv, "failed to modify QP to RTR, ret = %d\n", ret);
		goto out_fail;
	}

	qp_attr.qp_state = IB_QPS_RTS;
	qp_attr.sq_psn = 0;
	attr_mask |= IB_QP_SQ_PSN;
	attr_mask &= ~IB_QP_PKEY_INDEX;
	ret = ib_modify_qp(qp, &qp_attr, attr_mask);
	if (ret) {
		fip_dev_warn(priv, "failed to modify QP to RTS, ret = %d\n", ret);
		goto out_fail;
	}

	return 0;

out_fail:
	qp_attr.qp_state = IB_QPS_RESET;
	if (ib_modify_qp(qp, &qp_attr, IB_QP_STATE))
		fip_dev_warn(priv, "Failed to modify QP to RESET state\n");

	return ret;
}

void fip_qp_to_err(struct fip_dev_priv *priv, struct ib_qp *qp)
{
	struct ib_qp_attr qp_attr;
	struct ib_qp_init_attr qp_init_attr;
	int timeout = 0;

	qp_attr.qp_state = IB_QPS_ERR;
	if (ib_modify_qp(qp, &qp_attr, IB_QP_STATE))
		fip_dev_warn(priv, "Failed to modify QP to RESET state\n");

	do {
		msleep(1 * (timeout != 0));
		ib_query_qp(qp, &qp_attr, IB_QP_CUR_STATE, &qp_init_attr);
		timeout++;
	} while (qp_attr.cur_qp_state != IB_QPS_ERR && timeout < 100);

	WARN_ON(qp_attr.cur_qp_state != IB_QPS_ERR);

	return;
}

/*
 * alloc a single buffer, map it and post it to the qp.
 * id used to identify entry in receive queue.
 */
int fip_post_receive(struct fip_dev_priv *priv,
		     struct ib_qp *qp,
		     int size, int id, char *mem, struct ring_entry *mem_entry)
{
	struct ib_recv_wr rx_wr, *bad_wr;
	struct ib_sge rx_sge;
	int ret;

	if (!mem) {
		mem_entry->mem = kmalloc(size, GFP_KERNEL);
		if (unlikely(!mem_entry->mem)) {
			mem_entry->length = 0;
			return -ENOMEM;
		}
	} else
		mem_entry->mem = mem;

	mem_entry->length = size;
	mem_entry->bus_addr = ib_dma_map_single(priv->ca, mem_entry->mem, size,
						DMA_FROM_DEVICE);

	if (unlikely(ib_dma_mapping_error(priv->ca, mem_entry->bus_addr)))
		goto error;

	rx_wr.wr_id = id | FIP_OP_RECV;
	rx_wr.next = NULL;
	rx_wr.sg_list = &rx_sge;
	rx_wr.num_sge = 1;
	rx_sge.addr = mem_entry->bus_addr;
	rx_sge.length = size;
	rx_sge.lkey = priv->mr->lkey;

	ret = ib_post_recv(qp, &rx_wr, &bad_wr);
	if (unlikely(ret)) {
		fip_dev_warn(priv, "post receive failed for buf %d (%d)\n", id,
			 ret);
		goto post_recv_failed;
	}
	return 0;

post_recv_failed:
	ib_dma_unmap_single(priv->ca, rx_sge.addr, size, DMA_FROM_DEVICE);

error:
	mem_entry->length = 0;
	kfree(mem_entry->mem);
	return -EIO;
}

void fip_flush_rings(struct fip_dev_priv *priv,
		     struct ib_cq *cq,
		     struct ib_qp *qp,
		     struct ring *rx_ring, struct ring *tx_ring)
{
	fip_dev_dbg(priv, LOG_PRIO_LOW, "fip_qp_to_err called\n");
	fip_qp_to_err(priv, qp);

	spin_lock_irq(&priv->discover.lock);
	fip_comp(priv, cq, rx_ring, tx_ring);
	spin_unlock_irq(&priv->discover.lock);
}

void fip_free_rings(struct fip_dev_priv *priv,
		    struct ring *rx_ring, struct ring *tx_ring)
{
	int i;

	for (i = rx_ring->size - 1; i >= 0; i--)
		if (rx_ring->ring[i].length != 0) {
			ib_dma_unmap_single(priv->ca,
					    rx_ring->ring[i].bus_addr,
					    rx_ring->ring[i].length,
					    DMA_FROM_DEVICE);
			kfree(rx_ring->ring[i].mem);
		}
	rx_ring->size = 0;

	for (i = tx_ring->size - 1; i >= 0; i--)
		if (tx_ring->ring[i].length != 0) {
			ib_dma_unmap_single(priv->ca,
					    tx_ring->ring[i].bus_addr,
					    tx_ring->ring[i].length,
					    DMA_TO_DEVICE);
			kfree(tx_ring->ring[i].mem);
		}
	tx_ring->size = 0;

	fip_dev_dbg(priv, LOG_PRIO_LOW, "==>Done cleaning RX and TX queues\n");

	kfree(rx_ring->ring);
	rx_ring->ring = NULL;
	kfree(tx_ring->ring);
	tx_ring->ring = NULL;
}

int fip_init_ring(struct fip_dev_priv *priv, struct ib_qp *qp, struct ring *ring)
{
	int i;
	int mtu_size = FIP_UD_BUF_SIZE(priv->max_ib_mtu);

	for (i = 0; i < ring->size; i++) {
		if (qp) {
			if (fip_post_receive(priv, qp, mtu_size, i, NULL,
					     ring->ring + i)) {
				/* we can not release memory without flushing QP */
				for (; i < ring->size; ++i) {
					ring->ring[i].mem = NULL;
					ring->ring[i].length = 0;
				}
				return -EIO;
			}
			ring->head = 0;
			ring->tail = 0;
		} else {
			ring->head = 0;
			ring->tail = ring->size - 1;
		}
	}

	return 0;
}

/*
 * TODO - we can do a nicer job here. stage 2
 *  allocates memory and post receives
 */
int fip_init_rx(struct fip_dev_priv *priv,
		int ring_size, struct ib_qp *qp, struct ring *rx_ring)
{
	rx_ring->size = ring_size;
	rx_ring->ring = kmalloc(rx_ring->size * sizeof(struct ring_entry),
				GFP_KERNEL);
	if (unlikely(!rx_ring->ring)) {
		rx_ring->size = 0;
		return -ENOMEM;
	}

	return fip_init_ring(priv, qp, rx_ring);
}

/*
 * This function allocates the tx buffers and initializes the head and
 * tail indexes.
 */
int fip_init_tx(struct fip_dev_priv *priv, int size, struct ring *tx_ring)
{
	tx_ring->size = size;
	tx_ring->ring = kzalloc(tx_ring->size * sizeof(struct ring_entry),
				GFP_KERNEL);

	if (!tx_ring->ring) {
		fip_dev_warn(priv, "fip_init_tx failed in alloc of tx. size=%d\n",
			 tx_ring->size);
		tx_ring->size = 0;
		return -ENOMEM;
	}

	return fip_init_ring(priv, NULL, tx_ring);
}

/*
 * Allocate a PD and MR that will be used by all
 * of the port's IB resources.
 * Call fip_dev_cleanup to release
 * the allocated resources.
 */
int fip_dev_init(struct fip_dev_priv *priv)
{
	struct ib_device *ca = priv->ca;

	priv->pd = ib_alloc_pd(priv->ca);
	if (IS_ERR(priv->pd)) {
		fip_dev_warn(priv, "%s: failed to allocate PD\n", ca->name);
		return -ENODEV;
	}

	priv->mr = ib_get_dma_mr(priv->pd, IB_ACCESS_LOCAL_WRITE);
	if (IS_ERR(priv->mr)) {
		fip_dev_warn(priv, "%s: ib_get_dma_mr failed\n", ca->name);
		goto out_free_pd;
	}

	return 0;

out_free_pd:
	ib_dealloc_pd(priv->pd);
	return -ENODEV;
}

/*
 * cleanup resources allocated by fip_dev_init
*/
void fip_dev_cleanup(struct fip_dev_priv *priv)
{
	/*ipoib_cm_dev_cleanup(dev); */

	if (ib_dereg_mr(priv->mr))
		fip_dev_warn(priv, "ib_dereg_mr failed\n");

	if (ib_dealloc_pd(priv->pd))
		fip_dev_warn(priv, "ib_dealloc_pd failed\n");
}

/* trigered by a core event */
void fip_event(struct ib_event_handler *handler, struct ib_event *record)
{
	struct fip_dev_priv *priv =
	    container_of(handler, struct fip_dev_priv, event_handler);

	if (record->element.port_num != priv->port)
		return;

	switch (record->event) {
	case IB_EVENT_SM_CHANGE:
	case IB_EVENT_CLIENT_REREGISTER:
	case IB_EVENT_PORT_ACTIVE:	/* link up */
		/* queue restart of discovery a bit
		 * delayed to prevent threshing */
		queue_work(fip_workqueue, &priv->discover.mcast_refresh_task);
		fip_dev_dbg(priv, LOG_PRIO_MED, "==> event=%d (CLIENT_REREGISTER,"
			" or SM_CHANGE or PORT_ACTIVE)\n", record->event);
		break;

	case IB_EVENT_PKEY_CHANGE:
	case IB_EVENT_DEVICE_FATAL:
	case IB_EVENT_LID_CHANGE:
		queue_delayed_work(fip_mng_workqueue,
				   &priv->restart_task, HZ / 10);
		fip_dev_dbg(priv, LOG_PRIO_MED,
			"event=%d (PKEY_CHANGE or LID_CHANGE\n", record->event);
		break;
	case IB_EVENT_PORT_ERR:
	case IB_EVENT_SRQ_ERR:
	case IB_EVENT_SRQ_LIMIT_REACHED:
	case IB_EVENT_QP_LAST_WQE_REACHED:
	default:
		fip_dev_dbg(priv, LOG_PRIO_MED, "event=%d unhandled\n",
			record->event);
		break;
	}
}

static inline int backoff_delay(struct mcast_entry *mcast)
{
	int delay = (mcast->backoff * HZ) + (jiffies % (HZ / 10));

	mcast->backoff *= 2;
	mcast->backoff = (mcast->backoff > FIP_MAX_BACKOFF_SECONDS) ?
	    FIP_MAX_BACKOFF_SECONDS : mcast->backoff;
	return delay;
}

static struct mcast_entry *mcast_alloc(void)
{
	struct mcast_entry *mcast;

	mcast = kzalloc(sizeof *mcast, GFP_KERNEL);
	if (!mcast)
		return NULL;

	atomic_set(&mcast->ref_cnt, 0);
	INIT_LIST_HEAD(&mcast->list);
	return mcast;
}

static void mcast_requeue_task(struct port_mcast_data *port_mcast, int delay)
{
	mutex_lock(&port_mcast->mlock);
	if (!test_bit(MCAST_TASK_STOPPED, &port_mcast->flags))
		queue_delayed_work(fip_workqueue, &port_mcast->mcast_task,
				   delay);
	mutex_unlock(&port_mcast->mlock);
}

/*
 * This function attaches a QP to a multicast group for receive.
 * If you only use the mcast for transmit you don't neet to call
 * this function. The function sets the QP's QKEY to the mcask QKEY
 * and adds the QP to the mcast group filter. If the mcast was not
 * joined for RX or the mcast joined is not done the function
 * returns an error. Caller must hold the mcast->lock.
*/
static int mcast_attach(struct mcast_entry *mcast, struct ib_qp *qp)
{
	if (test_bit(MCAST_FLAG_ATTACHED, &mcast->flags))
		return 0;

	/* attach QP to multicast group */
	if (ib_attach_mcast(qp, &mcast->mcmember.mgid,
			    be16_to_cpu(mcast->mcmember.mlid)))
		goto attach_failed;

	set_bit(MCAST_FLAG_ATTACHED, &mcast->flags);
	return 0;

attach_failed:
	printk(KERN_ALERT "mlx4_fcoib: mcast_attach failed\n");
	return -1;
}

/*
 * This function creates an address header for a multicast group needed
 * for TX (only). If the AH was previously created the previously created
 * AH will be used and the function will return success. Caller must hold
 * the mcast->lock.
*/
static int mcast_create_ah(struct mcast_entry *mcast)
{
	struct port_mcast_data *port_mcast = mcast->port_mcast;
	struct ib_ah_attr av = {
		.dlid = be16_to_cpu(mcast->mcmember.mlid),
		.port_num = port_mcast->port,
		.sl = mcast->mcmember.sl,
		.ah_flags = IB_AH_GRH,
		.static_rate = mcast->mcmember.rate,
		.grh = {
			.flow_label = be32_to_cpu(mcast->mcmember.flow_label),
			.hop_limit = mcast->mcmember.hop_limit,
			.sgid_index = 0,
			.traffic_class = mcast->mcmember.traffic_class}
	};

	if (test_bit(MCAST_FLAG_AH_SET, &mcast->flags))
		return 0;

	av.grh.dgid = mcast->mcmember.mgid;

	/* create multicast ah that will be used for all
	 * traffic of this mcast group */
	mcast->ah = ib_create_ah(port_mcast->pd, &av);

	if (IS_ERR(mcast->ah)) {
		printk(KERN_ALERT
		       "mlx4_fcoib: mcast_create_ah, failed to alloc ah\n");
		mcast->ah = NULL;
		goto create_ah_failed;
	}

	set_bit(MCAST_FLAG_AH_SET, &mcast->flags);
	return 0;

create_ah_failed:
	return -ENODEV;
}

/*
 * Called as a callback to ib_sa_join_multicast after join termination. Checks
 * that termination was successful and if so calls mcast_join_finish
 * to attach a QP to it and recalls mcast_task (maybe add more mcasts).
 * If join failed marks the mcast address as ready for retry and calls
 * mcast_task with exponential backoff.
*/
static int mcast_join_complete(int status, struct ib_sa_multicast *multicast)
{
	struct mcast_entry *mcast = multicast->context;

	/* We trap for port events ourselves. */
	if (status == -ENETRESET)
		return 0;

	/* join_complete is OK */
	if (status)
		goto retry_join_mcast;

	mcast->mcmember = multicast->rec;

	set_bit(MCAST_FLAG_JOINED, &mcast->flags);

	if (test_bit(MCAST_FLAG_RECV, &mcast->flags) &&
	    mcast_attach(mcast, mcast->qp)) {
		printk(KERN_ALERT "mlx4_fcoib: mcast_attach failed\n");
		goto retry_join_mcast;
	}

	if (test_bit(MCAST_FLAG_SEND, &mcast->flags) &&
	    mcast_create_ah(mcast)) {
		printk(KERN_ALERT "mlx4_fcoib: mcast_create_ah failed\n");
		goto unattach_mcast;
	}

	set_bit(MCAST_FLAG_DONE, &mcast->flags);

	if (mcast->callback)
		mcast->callback(mcast, mcast->context);

	/* this is to make sure no one uses the context after the
	 * callback */
	mcast->context = NULL;

	/* we will queue mcast_task again to process
	 * other mcast join requests */
	mcast_requeue_task(mcast->port_mcast, 0);
	atomic_dec(&mcast->ref_cnt);
	return 0;

unattach_mcast:
	if (test_and_clear_bit(MCAST_FLAG_ATTACHED, &mcast->flags)) {
		ib_detach_mcast(mcast->qp,
				&mcast->mcmember.mgid, mcast->mcmember.mlid);
	}

retry_join_mcast:
	printk(KERN_WARNING "mlx4_fcoib: multicast not ready, retrying\n");

	/* Clear the busy flag so we try again */
	clear_bit(MCAST_FLAG_BUSY, &mcast->flags);

	mcast_requeue_task(mcast->port_mcast, backoff_delay(mcast));
	atomic_dec(&mcast->ref_cnt);
	return -1;
}

/*
 * Join a multicast group. The mcast GID must be up to date
 * mcast->mcmember.mgid.
 * This function should not be called directly because it might fail and it
 * is assumed retries will be conducted by the mcast_task. instead add your
 * multicast to the multicast_list and activate mcast_task.
*/
static int _mcast_join(struct port_mcast_data *port_mcast,
		       struct mcast_entry *mcast, u16 pkey, u32 qkey)
{
	struct ib_sa_mcmember_rec rec = {
		.join_state = 1
	};
	ib_sa_comp_mask comp_mask;
	int ret = 0;

	rec.mgid = mcast->mcmember.mgid;
	rec.port_gid = port_mcast->local_gid;
	rec.pkey = cpu_to_be16(pkey);

	comp_mask =
	    IB_SA_MCMEMBER_REC_MGID |
	    IB_SA_MCMEMBER_REC_PORT_GID |
	    IB_SA_MCMEMBER_REC_PKEY | IB_SA_MCMEMBER_REC_JOIN_STATE;

	/*
	 * we will attempt to join a multicast group. the reply will be
	 * through the supplied callback mcast_join_complete.
	 */
	set_bit(MCAST_FLAG_BUSY, &mcast->flags);
	mcast->sa_mcast = ib_sa_join_multicast(&fip_sa_client, port_mcast->ca,
					       port_mcast->port, &rec,
					       comp_mask, GFP_KERNEL,
					       mcast_join_complete, mcast);

	if (IS_ERR(mcast->sa_mcast)) {
		clear_bit(MCAST_FLAG_BUSY, &mcast->flags);
		ret = PTR_ERR(mcast->sa_mcast);
		printk(KERN_ALERT "mlx4_fcoib: ib_sa_join_multicast failed\n");

		/*
		 * add a delayed call so it will retry
		 * to join the mcast group later.
		 */
		mcast_requeue_task(port_mcast, backoff_delay(mcast));
	}
	return ret;
}

static int mcast_start_thread(struct port_mcast_data *port_mcast)
{
	mcast_requeue_task(port_mcast, 0);
	return 0;
}

static int mcast_leave(struct mcast_entry *mcast, struct ib_qp *qp)
{
	if (test_and_set_bit(MCAST_FLAG_REMOVED, &mcast->flags))
		return 0;

	if (test_and_clear_bit(MCAST_FLAG_ATTACHED, &mcast->flags))
		if (ib_detach_mcast(qp,
				    &mcast->mcmember.mgid,
				    mcast->mcmember.mlid))
			printk(KERN_ALERT "mlx4_fcoib: "
			       "ib_detach_mcast failed\n");

	if (test_and_clear_bit(MCAST_FLAG_AH_SET, &mcast->flags))
		if (ib_destroy_ah(mcast->ah))
			printk(KERN_ALERT "mlx4_fcoib: ib_destroy_ah failed\n");

	if (test_and_clear_bit(MCAST_FLAG_BUSY, &mcast->flags))
		ib_sa_free_multicast(mcast->sa_mcast);

	return 0;
}

/* free a mcast group. This function might sleep */
void fip_mcast_free(struct mcast_entry *mcast)
{
	int max_wait = 10;

	mutex_lock(&mcast->port_mcast->mlock);
	list_del(&mcast->list);
	mutex_unlock(&mcast->port_mcast->mlock);

	while (atomic_read(&mcast->ref_cnt) && max_wait) {
		msleep(50);
		max_wait--;
	}

	if (mcast_leave(mcast, mcast->qp))
		printk(KERN_ALERT "mlx4_fcoib: fip_mcast_free failed\n");

	kfree(mcast);
}

/*
 * Stop mcast task running on thread. If the work can not be stopped at the
 * moment because it is pending or running the function would return an error
 * (it would need to be recalled)
 */
int fip_mcast_stop_thread(struct port_mcast_data *port_mcast)
{
	mutex_lock(&port_mcast->mlock);
	set_bit(MCAST_TASK_STOPPED, &port_mcast->flags);
	cancel_delayed_work(&port_mcast->mcast_task);
	mutex_unlock(&port_mcast->mlock);

	if (delayed_work_pending(&port_mcast->mcast_task))
		return -EBUSY;

	return 0;
}

/*
 * This function tries to join all the multicast groups that
 * are currently presnt in port_mcast->multicast_list. The code
 * goes over the list sequentially tries to join a single
 * group per call. mcast groups that are already being processed
 * are disregarded.
 * To join an mcast group call fip_mcast_join. Do not call this
 * function directly.
*/
void fip_mcast_join_task(struct work_struct *work)
{
	struct port_mcast_data *port_mcast =
	    container_of(work, struct port_mcast_data, mcast_task.work);
	int found = 0;

	/* if multicast task is disabled return */
	if (test_bit(MCAST_TASK_STOPPED, &port_mcast->flags))
		return;

	while (1) {
		struct mcast_entry *mcast = NULL;

		mutex_lock(&port_mcast->mlock);
		list_for_each_entry(mcast, &port_mcast->multicast_list, list) {
			if (!test_bit(MCAST_FLAG_BUSY, &mcast->flags) &&
			    !test_bit(MCAST_FLAG_JOINED, &mcast->flags) &&
			    !test_bit(MCAST_FLAG_REMOVED, &mcast->flags)) {
				/* Found the next unjoined group */
				found = 1;
				atomic_inc(&mcast->ref_cnt);
				break;
			}
		}
		mutex_unlock(&port_mcast->mlock);

		if (!found)
			break;

		if (_mcast_join(port_mcast, mcast, mcast->pkey, mcast->qkey))
			atomic_dec(&mcast->ref_cnt);

		break;
	}
}

/*
 * Join a new mcast address. The function receives a callback function to
 * call upon completion of the join operation. Be mindful that
 * a successful return of the function does not mean the mcast is joined.
 */
struct mcast_entry *fip_mcast_join(struct port_mcast_data *port_mcast,
				    void *context, const char *mgid, u32 qkey,
				    u16 pkey, struct ib_qp *qp,
				    enum mcast_join_type type,
				    void (*callback) (struct mcast_entry *,
						      void *context))
{
	struct mcast_entry *mcast;

	/* alloc a new mcast address */
	mcast = mcast_alloc();
	if (!mcast) {
		printk(KERN_ALERT "mlx4_fcoib: "
		       "fip_mcast_connect: mcast alloc failed\n");
		goto mcast_connect_exit;
	}

	mcast->port_mcast = port_mcast;
	mcast->callback = callback;
	mcast->qkey = qkey;
	mcast->pkey = pkey;
	mcast->context = context;
	mcast->qp = qp;
	mcast->backoff = 1;

	if (type != MCAST_SEND_ONLY)
		set_bit(MCAST_FLAG_RECV, &mcast->flags);
	if (type != MCAST_RECEIVE_ONLY)
		set_bit(MCAST_FLAG_SEND, &mcast->flags);

	memcpy(mcast->mcmember.mgid.raw, mgid, sizeof(union ib_gid));

	mutex_lock(&port_mcast->mlock);
	list_add_tail(&mcast->list, &port_mcast->multicast_list);
	mutex_unlock(&port_mcast->mlock);

	mcast_start_thread(port_mcast);

	return mcast;

mcast_connect_exit:
	return NULL;
}

static void fip_add_one(struct ib_device *device);
static void fip_remove_one(struct ib_device *device);

static struct ib_client fip_client = {
	.name = "fip",
	.add = fip_add_one,
	.remove = fip_remove_one
};

/*
 * query the port for a few of it's properties like:
 * LID, MTU, device capabilities, and GID. This function
 * does not allocate any resources requiring cleanup.
*/
static int fip_query_port_caps(struct fip_dev_priv *priv, u8 port)
{
	struct ib_device_attr *device_attr;
	struct ib_port_attr attr;
	int result = -ENOMEM;

	/* set max MTU */
	if (!ib_query_port(priv->ca, port, &attr)) {
		priv->local_lid = attr.lid;
		priv->max_mtu_enum = attr.max_mtu;
		priv->max_ib_mtu = ib_mtu_enum_to_int(attr.max_mtu);
	} else {
		fip_dev_warn(priv, "%s: ib_query_port %d failed\n",
			 priv->ca->name, port);
		goto device_query_failed;
	}

	if (attr.phys_state == 3)	/* port disable */
		goto device_query_failed;

	/* MTU will be reset when mcast join happens */
	priv->mtu = FIP_UD_MTU(priv->max_ib_mtu);
	priv->mcast_mtu = priv->mtu;
	/* rate in Gb/sec = speed * width * 2.5 Gb/sec (speed is 1,2,4) */
	priv->rate = ((int)attr.active_speed *
		      ib_width_enum_to_int(attr.active_width) * 25) / 10;

	result = ib_query_pkey(priv->ca, port, 0, &priv->pkey);
	if (result) {
		fip_dev_warn(priv, "%s: ib_query_pkey port %d failed"
			 " (ret = %d)\n", priv->ca->name, port, result);
		goto device_query_failed;
	}

	device_attr = kmalloc(sizeof(*device_attr), GFP_KERNEL);
	if (!device_attr) {
		fip_dev_warn(priv, "%s: allocation of %zu bytes failed\n",
			 priv->ca->name, sizeof(*device_attr));
		goto device_query_failed;
	}

	result = ib_query_device(priv->ca, device_attr);
	if (result) {
		fip_dev_warn(priv, "%s: ib_query_device failed (ret = %d)\n",
			 priv->ca->name, result);
		kfree(device_attr);
		goto device_query_failed;
	}
	priv->hca_caps = device_attr->device_cap_flags;

	kfree(device_attr);

	/*
	 * Set the full membership bit, so that we join the right
	 * broadcast group, etc.
	 */
	priv->pkey |= 0x8000;

	result = ib_query_gid(priv->ca, port, 0, &priv->local_gid);
	if (result) {
		fip_dev_warn(priv, "%s: ib_query_gid port %d failed (ret = %d)"
			 "\n", priv->ca->name, port, result);
		goto device_query_failed;
	}

	return 0;

device_query_failed:
	return result;
}

static ssize_t create_store(struct mfc_port *p, struct mfc_port_attribute *unused,
			 const char *buf, size_t count)
{
	struct fip_dev_priv *priv = p->mfc_fip_ctlr;
	int ret;
	const char *entry_type;
	u64 guid, wwpn;
	u16 port_id;
	struct fip_gw_data *gw;
	struct mfc_vhba *vhba;

	entry_type = buf;
	buf += 2;
	switch (*entry_type) {
	case 'A':
		ret = sscanf(buf, "%016llx %hx %016llx", &guid, &port_id, &wwpn);
		if (ret != 3)
			goto bad_format;
		guid = cpu_to_be64(guid);
		break;
	default:
		goto bad_format;
	}

	gw = fip_find_gw(&priv->discover, (u8 *)&guid, port_id);
	if (!gw) {
		gw = fip_discover_create_gw(priv, (u8 *)&guid, port_id);
		if (IS_ERR(gw)) {
			fip_gw_err(gw, "create: Could not create GW\n");
			return count;
		}
	}

	if (gw->fip_vhba) {
		fip_gw_err(gw, "create: GW already has vHBA\n");
		return count;
	}

	vhba = create_vhba_for_gw(gw, wwpn);
	if (IS_ERR(vhba))
		fip_gw_err(gw, "create: Could not create vHBA\n");
	return count;

bad_format:
	fip_dev_err(priv, "create: bad format\n");
	return count;
}

static ssize_t destroy_store(struct mfc_port *p, struct mfc_port_attribute *unused,
			 const char *buf, size_t count)
{
	struct fip_dev_priv *priv = p->mfc_fip_ctlr;
	struct fip_gw_data *gw;
	const char *entry_type;
	u64 guid;
	u16 port_id;
	int ret;

	entry_type = buf;
	buf += 2;
	switch (*entry_type) {
	case 'A':
		ret = sscanf(buf, "%016llx %hx", &guid, &port_id);
		if (ret != 2)
			goto bad_format;
		guid = cpu_to_be64(guid);
		break;
	default:
		goto bad_format;
	}

	gw = fip_find_gw(&priv->discover, (u8 *)&guid, port_id);
	if (!gw) {
		fip_dev_err(priv, "destroy: GW does not exist\n");
		return count;
	}
	down_write(&priv->discover.gw_list_rwsem);
	fip_close_gw(gw);
	up_write(&priv->discover.gw_list_rwsem);

	return count;

bad_format:
	fip_dev_err(priv, "destroy: bad format\n");
	return count;
}

static PORT_ATTR(create, 0200, NULL, create_store);
static PORT_ATTR(destroy, 0200, NULL, destroy_store);

/* ===================== sysfs */
#warning FIXME: fcf sysfs disabled
#if 0
static const char *gw_state_string(enum fip_gw_state state)
{
	switch (state) {
	case FIP_GW_RESET:
		return "RESET"; break;
	case FIP_GW_RCVD_UNSOL_AD:
		return "RX_UNSOL_AD"; break;
	case FIP_GW_SENT_SOL:
		return "TX_SOL"; break;
	case FIP_GW_RCVD_SOL_AD:
		return "RX_SOL_AD"; break;
	case FIP_GW_WAITING_FOR_FLOGI:
		return "WAIT_FLOGI"; break;
	case FIP_GW_SENT_FLOGI:
		return "TX_FLOGI"; break;
	case FIP_GW_RCVD_FLOGI_ACCPT:
		return "RX_FLOGI_ACC"; break;
	}
	return "";
}

static ssize_t fcf_debug_info_show(struct fip_gw_data *p, struct mfc_port_attribute *unused,
		char *buf)
{
	return 0;
}

static ssize_t guid_show(struct fip_gw_data *p, struct mfc_port_attribute *unused,
		char *buf)
{
	return sprintf(buf, "%016llx\n", be64_to_cpu(*(u64 *)p->info.gw_guid));
}

static ssize_t port_id_show(struct fip_gw_data *p, struct mfc_port_attribute *unused,
		char *buf)
{
	return sprintf(buf, "%hx\n", p->info.gw_port_id);
}

static ssize_t lid_show(struct fip_gw_data *p, struct mfc_port_attribute *unused,
		char *buf)
{
	return sprintf(buf, "%hx\n", p->info.gw_lid);
}

static ssize_t ctl_qpn_show(struct fip_gw_data *p, struct mfc_port_attribute *unused,
		char *buf)
{
	return sprintf(buf, "%x\n", p->info.gw_qpn);
}

static ssize_t data_qpn_show(struct fip_gw_data *p, struct mfc_port_attribute *unused,
		char *buf)
{
	return sprintf(buf, "%x\n", p->info.gw_data_qpn);
}

static ssize_t state_show(struct fip_gw_data *p, struct mfc_port_attribute *unused,
		char *buf)
{
	return sprintf(buf, "%s\n", gw_state_string(p->state));
}

#endif

struct mfc_fcf_attribute {
	struct attribute attr;
	ssize_t (*show)(struct fip_gw_data *, struct mfc_fcf_attribute *, char *buf);
	ssize_t (*store)(struct fip_gw_data *, struct mfc_fcf_attribute *,
			 const char *buf, size_t count);
};

#define FCF_ATTR(_name, _mode, _show, _store) \
struct mfc_fcf_attribute mfc_fcf_attr_##_name = __ATTR(_name, _mode, _show, _store)

#define FCF_ATTR_RO(_name) \
struct mfc_fcf_attribute mfc_fcf_attr_##_name = __ATTR_RO(_name)

#if 0

static FCF_ATTR_RO(fcf_debug_info);
static FCF_ATTR_RO(guid);
static FCF_ATTR_RO(port_id);
static FCF_ATTR_RO(lid);
static FCF_ATTR_RO(ctl_qpn);
static FCF_ATTR_RO(data_qpn);
static FCF_ATTR_RO(state);

static struct attribute *mfc_fcf_default_attrs[] = {
	&mfc_fcf_attr_fcf_debug_info.attr,
	&mfc_fcf_attr_guid.attr,
	&mfc_fcf_attr_port_id.attr,
	&mfc_fcf_attr_lid.attr,
	&mfc_fcf_attr_ctl_qpn.attr,
	&mfc_fcf_attr_data_qpn.attr,
	&mfc_fcf_attr_state.attr,
	NULL
};
#endif

static ssize_t mfc_fcf_attr_show(struct kobject *kobj,
			      struct attribute *attr, char *buf)
{
	struct mfc_fcf_attribute *mfc_fcf_attr =
		container_of(attr, struct mfc_fcf_attribute, attr);
	struct fip_gw_data *p = container_of(kobj, struct fip_gw_data, kobj);

	if (!mfc_fcf_attr->show)
		return -EIO;

	return mfc_fcf_attr->show(p, mfc_fcf_attr, buf);
}

static ssize_t mfc_fcf_attr_store(struct kobject *kobj,
			      struct attribute *attr, const char *buf, size_t count)
{
	struct mfc_fcf_attribute *mfc_fcf_attr =
		container_of(attr, struct mfc_fcf_attribute, attr);
	struct fip_gw_data *p = container_of(kobj, struct fip_gw_data, kobj);

	if (!mfc_fcf_attr->store)
		return -EIO;

	return mfc_fcf_attr->store(p, mfc_fcf_attr, buf, count);
}

static const struct sysfs_ops mfc_fcf_sysfs_ops = {
	.show = mfc_fcf_attr_show,
	.store = mfc_fcf_attr_store,
};

void mfc_fcf_release(struct kobject *kobj)
{
	struct fip_gw_data *p = container_of(kobj, struct fip_gw_data, kobj);
	kfree(p);
}


#if 0
static struct kobj_type mfc_fcf_sysfs_type = {
	.release       = &mfc_fcf_release,
	.sysfs_ops     = &mfc_fcf_sysfs_ops,
	.default_attrs = &mfc_fcf_default_attrs
};
#endif

int mfc_fcf_register_sysfs(struct fip_gw_data *fcf)
{
	int ret = 0;
#if 0
	ret = kobject_init_and_add(&fcf->kobj, &mfc_fcf_sysfs_type,
			kobject_get(&fcf->priv->mfc_port->kobj),
			"fcf-%016llx_%03x",
			be64_to_cpu(*(u64 *)fcf->info.gw_guid),
			fcf->info.gw_port_id);

	if (ret)
		goto err_put;
#endif
	return 0;
#if 0
err_put:
	kobject_put(&fcf->priv->mfc_port->kobj);
#endif
	return ret;
}

void mfc_fcf_deregister_sysfs(struct fip_gw_data *fcf)
{
#if 0
	kobject_put(&fcf->priv->mfc_port->kobj);
	kobject_unregister(&fcf->kobj);
#endif
}

int mfc_fcf_add_vhba_link(struct fip_gw_data *fcf)
{
	struct mfc_vhba *vhba = containing_vhba(fcf->fip_vhba);
	int rc;

	rc = sysfs_create_link(&fcf->kobj, &vhba->kobj, vhba->kobj.name);
	if (rc) {
		printk(KERN_ERR "sysfs_create_link() failed: %d\n", rc);
	}
	rc = sysfs_create_link(&vhba->kobj, &fcf->kobj, "fcf");
	if (rc) {
		printk(KERN_ERR "sysfs_create_link failed: %d\n", rc);
	}
	return 0;
}

static void fip_stop_port(struct fip_dev_priv *priv)
{
	ib_unregister_event_handler(&priv->event_handler);
	mutex_lock(&priv->mlock);
	fip_discover_cleanup(priv);
	fip_dev_cleanup(priv);
	mutex_unlock(&priv->mlock);
}

void fip_discover_restart(struct work_struct *work)
{
	struct fip_dev_priv *priv =
	    container_of(work, struct fip_dev_priv, restart_task.work);
	struct fip_discover *discover;

	discover = &priv->discover;
	mutex_lock(&priv->mlock);

	if (discover->state == FIP_DISCOVER_OFF)
		goto out;

	spin_lock_irq(&discover->lock);
	discover->state = FIP_DISCOVER_OFF;
	discover->flush = 1;
	spin_unlock_irq(&discover->lock);

	fip_discover_flush(discover, 0);

	fip_flush_rings(priv, discover->cq, discover->qp,
			&discover->rx_ring, &discover->tx_ring);
	flush_workqueue(fip_workqueue);

	/* config MTU, GID, HW offload caps etc */
	if (fip_query_port_caps(priv, priv->port)) {
		fip_dev_warn(priv, "could not fip_query_port\n");
		goto out;
	}

	discover->state = FIP_DISCOVER_INIT;
	discover->flush = 0;
	discover->pkey = priv->pkey;
	discover->backoff_time = 1;

	/* TODO - figure out whats going on with the PKEY */
	if (ib_find_pkey(priv->ca, priv->port, discover->pkey,
			 &discover->pkey_index)) {
		fip_dev_warn(priv, "P_Key 0x%04x not found\n", discover->pkey);
		goto out;
	}

	/* move QP from reset to RTS */
	if (fip_init_qp(priv, discover->qp, discover->pkey_index,
			FCOIB_FIP_QKEY)) {
		fip_dev_warn(priv, "ipoib_init_qp returned\n");
		goto out;
	}

	fip_init_ring(priv, discover->qp, &discover->rx_ring);
	fip_init_ring(priv, NULL, &discover->tx_ring);

	/* enable recieving CQ completions */
	if (ib_req_notify_cq(discover->cq, IB_CQ_NEXT_COMP))
		goto out;

	/* start discover FSM code */
	queue_delayed_work(fip_workqueue, &discover->task, 0 * HZ);

out:
	mutex_unlock(&priv->mlock);
	return;
}

static void init_port_mcast(struct fip_dev_priv *priv,
			    struct port_mcast_data *mcast)
{
	mcast->flags = 0;
	INIT_DELAYED_WORK(&mcast->mcast_task, fip_mcast_join_task);
	INIT_LIST_HEAD(&mcast->multicast_list);
	mutex_init(&mcast->mlock);
	mcast->port = priv->port;
	mcast->ca = priv->ca;
	mcast->local_gid = priv->local_gid;
	mcast->mcast_mtu = priv->max_mtu_enum;
	mcast->pd = priv->pd;
	mcast->rate = priv->rate;
}

static struct fip_dev_priv *fip_add_port(struct ib_device *hca, u8 port)
{
	struct fip_dev_priv *priv;

	priv = kzalloc(sizeof(struct fip_dev_priv), GFP_KERNEL);
	if (!priv)
		return NULL;

	/* init priv data structure vars */
	priv->ca = hca;
	priv->port = port;

	return priv;
}

static int fip_start_port(struct fip_dev_priv *priv)
{
	int result = -ENOMEM;

	/* config MTU, GID, HW offload caps etc */
	if (fip_query_port_caps(priv, priv->port)) {
		fip_dev_warn(priv, "could not fip_query_port\n");
		return result;
	}

	INIT_DELAYED_WORK(&priv->restart_task, fip_discover_restart);
	spin_lock_init(&priv->lock);
	mutex_init(&priv->mlock);

	/* create MR, PD, ... */
	result = fip_dev_init(priv);
	if (result != 0) {
		fip_dev_warn(priv, "Failed to alloc device resources ret=%d\n",
			 result);
		return result;
	}

	init_port_mcast(priv, &priv->mcast);

	/*
	 * open discover QP and move it to RTS. Alloc RX+TX rings and
	 * call the discover queue work for the discover finite state machine
	 */
	result = fip_discover_init(priv);
	if (result != 0) {
		fip_dev_warn(priv, "Failed to alloc discover resources "
			 "ret=%d\n", result);
		goto discover_init_failed;
	}

	/*
	 * TODO - fix event handler
	 * register callbacks for core events like change in LID, PKEY,...
	 */
	INIT_IB_EVENT_HANDLER(&priv->event_handler, priv->ca, fip_event);
	result = ib_register_event_handler(&priv->event_handler);
	if (result != 0) {
		fip_dev_warn(priv, "%s: ib_register_event_handler failed for "
			 "port %d (ret = %d)\n", priv->ca->name, priv->port, result);
		goto event_failed;
	}
	return 0;

event_failed:
	fip_discover_cleanup(priv);
discover_init_failed:
	fip_dev_cleanup(priv);

	return result;
}

static void fip_add_one(struct ib_device *device)
{
	struct list_head *dev_list;
	struct fip_dev_priv *priv;
	int s, e, p;

	/* check IB device is mlx4 device */
	if (rdma_node_get_transport(device->node_type) != RDMA_TRANSPORT_IB)
		return;

	dev_list = kmalloc(sizeof(*dev_list), GFP_KERNEL);
	if (!dev_list)
		return;

	INIT_LIST_HEAD(dev_list);

	if (device->node_type == RDMA_NODE_IB_SWITCH) {
		s = 0;
		e = 0;
	} else {
		s = 1;
		e = device->phys_port_cnt;
	}

	for (p = s; p <= e; ++p) {
		priv = fip_add_port(device, p);
		list_add_tail(&priv->list, dev_list);
	}

	ib_set_client_data(device, &fip_client, dev_list);
	mlx4_fc_rescan_ports(NET_IB);
}

static void fip_remove_one(struct ib_device *device)
{
	struct fip_dev_priv *priv, *tmp;
	struct list_head *dev_list;

	if (rdma_node_get_transport(device->node_type) != RDMA_TRANSPORT_IB)
		return;

	dev_list = ib_get_client_data(device, &fip_client);
	if (!dev_list) {
		printk(KERN_WARNING "dev_list is NULL on %s\n", device->name);
		return;
	}

	/* flush_workqueue(fip_workqueue); */

	list_for_each_entry_safe(priv, tmp, dev_list, list) {
		list_del(&priv->list);
		kfree(priv);
	}

	kfree(dev_list);
	ib_set_client_data(device, &fip_client, NULL);
}

static void add_port(struct mfc_port *p)
{
	struct ib_device *ibdev = (struct ib_device *)p->underdev;
	struct fip_dev_priv *priv;
	struct list_head *dev_list;

	if (!ibdev)
		return;

	if (rdma_node_get_transport(ibdev->node_type) != RDMA_TRANSPORT_IB)
		return;

	dev_list = ib_get_client_data(ibdev, &fip_client);
	if (!dev_list)
		return;

	mfc_port_attr_add(p, &mfc_port_attr_create);
	mfc_port_attr_add(p, &mfc_port_attr_destroy);

	list_for_each_entry(priv, dev_list, list) {
		if (priv->port == p->port) {
			priv->mfc_port = p;
			p->mfc_fip_ctlr = priv;
			fip_start_port(priv);
			return;
		}
	}

}

static void rem_port(struct mfc_port *p)
{
	struct ib_device *ibdev = (struct ib_device *)p->underdev;
	struct fip_dev_priv *priv, *tmp;
	struct list_head *dev_list;

	if (!ibdev)
		return;

	if (rdma_node_get_transport(ibdev->node_type) != RDMA_TRANSPORT_IB)
		return;

	dev_list = ib_get_client_data(ibdev, &fip_client);
	if (!dev_list) {
		printk(KERN_WARNING "dev_list is NULL on %s\n", ibdev->name);
		return;
	}

	mfc_port_attr_remove(p, &mfc_port_attr_create);
	mfc_port_attr_remove(p, &mfc_port_attr_destroy);

	list_for_each_entry_safe(priv, tmp, dev_list, list) {
		if (priv->port == p->port) {
			fip_stop_port(priv);
			return;
		}
	}
}

int els_send(struct mfc_vhba *vhba, struct sk_buff *skb);
static struct mfc_fip_ctlr mlx4_fcoib_fip = {
	.add_port = add_port,
	.rem_port = rem_port,
	.els_send = els_send,
};

static int __init fip_init_module(void)
{
	int ret;

	fip_workqueue = create_singlethread_workqueue("fip");
	if (!fip_workqueue) {
		ret = -ENOMEM;
		goto err_workqueue;
	}

	fip_mng_workqueue = create_singlethread_workqueue("fip_create");
	if (!fip_mng_workqueue) {
		ret = -ENOMEM;
		goto err_mng_workqueue;
	}

	ib_sa_register_client(&fip_sa_client);

	ret = ib_register_client(&fip_client);
	if (ret)
		goto err_sa;

	mlx4_fc_register_fip_ctlr(&mlx4_fcoib_fip, NET_IB);

	return 0;

err_sa:
	ib_sa_unregister_client(&fip_sa_client);
	destroy_workqueue(fip_mng_workqueue);
err_mng_workqueue:
	destroy_workqueue(fip_workqueue);
err_workqueue:
	return ret;
}

static void __exit fip_cleanup_module(void)
{
	mlx4_fc_deregister_fip_ctlr(NET_IB);
	ib_unregister_client(&fip_client);
	ib_sa_unregister_client(&fip_sa_client);
	destroy_workqueue(fip_mng_workqueue);
	destroy_workqueue(fip_workqueue);
}

module_init(fip_init_module);
module_exit(fip_cleanup_module);
