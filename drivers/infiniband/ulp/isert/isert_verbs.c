/*******************************************************************************
 * This file contains iSCSI extentions for RDMA (iSER) Verbs
 *
 * (c) Copyright 2013 RisingTide Systems LLC.
 *
 * Nicholas A. Bellinger <nab@linux-iscsi.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 ****************************************************************************/
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/in6.h>

#include <rdma/ib_verbs.h>
#include <rdma/ib_fmr_pool.h>
#include <rdma/rdma_cm.h>
#include <target/iscsi/iscsi_transport.h>

#include "isert_proto.h"
#include "isert_base.h"
#include "isert_core.h"

#define ISERT_ADDR_ROUTE_TIMEOUT 1000

#define	ISERT_MAX_CONN		8
#define ISER_MAX_RX_CQ_LEN	(ISERT_QP_MAX_RECV_DTOS * ISERT_MAX_CONN)
#define ISER_MAX_TX_CQ_LEN	(ISERT_QP_MAX_REQ_DTOS  * ISERT_MAX_CONN)

static void
isert_qp_event_callback(struct ib_event *e, void *context)
{
	pr_err("isert_qp_event_callback event: %d\n", e->event);
}

static int
isert_query_device(struct ib_device *ib_dev, struct ib_device_attr *devattr)
{
	int ret;

	ret = ib_query_device(ib_dev, devattr);
	if (ret) {
		pr_err("ib_query_device() failed: %d\n", ret);
		return ret;
	}
	pr_debug("devattr->max_mr_size: 0x%016Lx\n", devattr->max_mr_size);
	pr_debug("devattr->page_size_cap: 0x%016Lx\n", devattr->page_size_cap);
	pr_debug("devattr->max_qp: %d\n", devattr->max_qp);
	pr_debug("devattr->max_qp_wr: %d\n", devattr->max_qp_wr);
	pr_debug("devattr->device_cap_flags: 0x%08x\n", devattr->device_cap_flags);
	pr_debug("devattr->max_sge: %d\n", devattr->max_sge);
	pr_debug("devattr->max_sge_rd: %d\n", devattr->max_sge_rd);
	pr_debug("devattr->max_cq: %d\n", devattr->max_cq);
	pr_debug("devattr->max_cqe: %d\n", devattr->max_cqe);
	pr_debug("devattr->max_mr: %d\n", devattr->max_mr);
	pr_debug("devattr->max_pd: %d\n", devattr->max_pd);
	pr_debug("devattr->max_rdd: %d\n", devattr->max_rdd);
	pr_debug("devattr->max_mw: %d\n", devattr->max_mw);
	pr_debug("devattr->max_srq: %d\n", devattr->max_srq);
	pr_debug("devattr->max_srq_wr: %d\n", devattr->max_srq_wr);
	pr_debug("devattr->max_srq_sge: %d\n", devattr->max_srq_sge);

	return 0;
}

static int
isert_conn_setup_qp(struct isert_conn *isert_conn, struct rdma_cm_id *cma_id)
{
	struct ib_qp_init_attr attr;
	struct ib_device_attr devattr;
	int ret;

	memset(&devattr, 0, sizeof(struct ib_device_attr));
	ret = isert_query_device(cma_id->device, &devattr);

	memset(&attr, 0, sizeof(struct ib_qp_init_attr));
	attr.event_handler = isert_qp_event_callback;
	attr.qp_context = isert_conn;
	attr.send_cq = isert_conn->conn_tx_cq;
	attr.recv_cq = isert_conn->conn_rx_cq;
	attr.cap.max_send_wr = ISERT_QP_MAX_REQ_DTOS;
	attr.cap.max_recv_wr = ISERT_QP_MAX_RECV_DTOS;
#warning FIXME: max_sge hardcoded to 16
#if 0
	attr.cap.max_send_sge = devattr.max_sge;
	isert_conn->max_sge = devattr.max_sge;
#else
	attr.cap.max_send_sge = 16;
	isert_conn->max_sge = 16;
#endif
	attr.cap.max_recv_sge = 1;
	attr.sq_sig_type = IB_SIGNAL_REQ_WR;
	attr.qp_type = IB_QPT_RC;

	pr_debug("isert_conn_setup_qp cma_id->device: %p\n", cma_id->device);
	pr_debug("isert_conn_setup_qp conn_pd->device: %p\n", isert_conn->conn_pd->device);

	ret = rdma_create_qp(cma_id, isert_conn->conn_pd, &attr);
	if (ret) {
		pr_err("rdma_create_qp failed for cma_id %d\n", ret);
		return ret;
	}
	isert_conn->conn_qp = cma_id->qp;
	pr_debug("rdma_create_qp() returned success >>>>>>>>>>>>>>>>>>>>>>>>>.\n");

	return 0;
}

static void
isert_cq_event_callback(struct ib_event *e, void *context)
{
	pr_debug("isert_cq_event_callback event: %d\n", e->event);

	switch(e->event) {
	case IB_EVENT_QP_LAST_WQE_REACHED:
		pr_warn("Reached TX IB_EVENT_QP_LAST_WQE_REACHED:\n");
		break;
	default:
		pr_warn("Unknown e->event; %d\n", e->event);
		break;
	}
}

static int
isert_connect_request(struct rdma_cm_id *cma_id, struct rdma_cm_event *event)
{
	struct iscsi_np *np = cma_id->context;
	struct isert_np *isert_np = np->np_context;
	struct isert_conn *isert_conn;
	struct ib_device *ib_dev = cma_id->device;
	int ret;

	pr_debug("Entering isert_connect_request cma_id: %p, context: %p\n",
			cma_id, cma_id->context);

	isert_conn = kzalloc(sizeof(struct isert_conn), GFP_KERNEL);
	if (!isert_conn) {
		pr_err("Unable to allocate isert_conn\n");
		return -ENOMEM;
	}
	isert_conn->state = ISER_CONN_INIT;
	INIT_LIST_HEAD(&isert_conn->conn_accept_node);
	init_completion(&isert_conn->conn_login_comp);
	init_waitqueue_head(&isert_conn->conn_wait);
	kref_init(&isert_conn->conn_kref);
	kref_get(&isert_conn->conn_kref);

	cma_id->context = isert_conn;
	pr_debug("isert_connect_request: Setup new cma_id->context: %p\n", cma_id->context);
	isert_conn->conn_cm_id = cma_id;
	isert_conn->responder_resources = event->param.conn.responder_resources;
	isert_conn->initiator_depth = event->param.conn.initiator_depth;
	pr_debug("Using responder_resources: %u initiator_depth: %u\n",
		isert_conn->responder_resources, isert_conn->initiator_depth);

	isert_conn->login_buf = kzalloc(ISCSI_DEF_MAX_RECV_SEG_LEN +
					ISER_RX_LOGIN_SIZE, GFP_KERNEL);
	if (!isert_conn->login_buf) {
		pr_err("Unable to allocate isert_conn->login_buf\n");
		ret = -ENOMEM;
		goto out;
	}

	isert_conn->login_req_buf = isert_conn->login_buf;
	isert_conn->login_rsp_buf = isert_conn->login_buf + ISCSI_DEF_MAX_RECV_SEG_LEN;
	pr_debug("Set login_buf: %p login_req_buf: %p login_rsp_buf: %p\n",
		isert_conn->login_buf, isert_conn->login_req_buf,
		isert_conn->login_rsp_buf);

	isert_conn->login_req_dma = ib_dma_map_single(ib_dev,
					(void *)isert_conn->login_req_buf,
					ISCSI_DEF_MAX_RECV_SEG_LEN, DMA_FROM_DEVICE);

	ret = ib_dma_mapping_error(ib_dev, isert_conn->login_req_dma);
	if (ret) {
		pr_err("ib_dma_mapping_error failed for login_req_dma: %d\n", ret);
		isert_conn->login_req_dma = 0;
		goto out_login_buf;
	}

	isert_conn->login_rsp_dma = ib_dma_map_single(ib_dev,
					(void *)isert_conn->login_rsp_buf,
					ISER_RX_LOGIN_SIZE, DMA_TO_DEVICE);

	ret = ib_dma_mapping_error(ib_dev, isert_conn->login_rsp_dma);
	if (ret) {
		pr_err("ib_dma_mapping_error failed for login_rsp_dma: %d\n", ret);
		isert_conn->login_rsp_dma = 0;
		goto out_req_dma_map;
	}

	isert_conn->conn_pd = ib_alloc_pd(ib_dev);
	if (IS_ERR(isert_conn->conn_pd)) {
		ret = PTR_ERR(isert_conn->conn_pd);
		pr_err("ib_alloc_pd failed for conn_pd: %d\n", ret);
		goto out_rsp_dma_map;
	}

	isert_conn->conn_rx_cq = ib_create_cq(ib_dev, isert_cq_rx_callback,
						isert_cq_event_callback,
						(void *)isert_conn,
						ISER_MAX_RX_CQ_LEN, 0);
	if (IS_ERR(isert_conn->conn_rx_cq)) {
		ret = PTR_ERR(isert_conn->conn_rx_cq);
		pr_err("ib_create_cq failed for conn_rx_cq: %d\n", ret);
		goto out_alloc_pd;
	}

	isert_conn->conn_tx_cq = ib_create_cq(ib_dev, isert_cq_tx_callback,
						isert_cq_event_callback,
						(void *)isert_conn,
						ISER_MAX_TX_CQ_LEN, 0);
	if (IS_ERR(isert_conn->conn_tx_cq)) {
		ret = PTR_ERR(isert_conn->conn_tx_cq);
		pr_err("ib_create_cq failed for conn_tx_cq: %d\n", ret);
		goto out_rx_cq;
	}

	ret = ib_req_notify_cq(isert_conn->conn_rx_cq, IB_CQ_NEXT_COMP);
	if (ret) {
		pr_err("ib_req_notify_cq failed for conn_rx_cq: %d\n", ret);
		goto out_tx_cq;
	}
	ret = ib_req_notify_cq(isert_conn->conn_tx_cq, IB_CQ_NEXT_COMP);
	if (ret) {
		pr_err("ib_req_notify_cq failed for conn_tx_cq: %d\n", ret);
		goto out_tx_cq;
	}

	tasklet_init(&isert_conn->conn_rx_tasklet, iser_cq_rx_tasklet,
				(unsigned long)isert_conn);
	tasklet_init(&isert_conn->conn_tx_tasklet, iser_cq_tx_tasklet,
				(unsigned long)isert_conn);

	isert_conn->conn_mr = ib_get_dma_mr(isert_conn->conn_pd,
				IB_ACCESS_LOCAL_WRITE |
				IB_ACCESS_REMOTE_WRITE |
				IB_ACCESS_REMOTE_READ);
	if (IS_ERR(isert_conn->conn_mr)) {
		ret = PTR_ERR(isert_conn->conn_mr);
		pr_err("ib_get_dma_mr failed for conn->conn_mr: %d\n", ret);
		goto out_tx_cq;
	}

	ret = isert_conn_setup_qp(isert_conn, cma_id);
	if (ret)
		goto out_conn_mr;

	mutex_lock(&isert_np->np_accept_mutex);
	list_add_tail(&isert_np->np_accept_list, &isert_conn->conn_accept_node);
	mutex_unlock(&isert_np->np_accept_mutex);

	pr_debug("isert_connect_request() waking up np_accept_wq: np: %p\n", np);
	wake_up(&isert_np->np_accept_wq);
	return 0;

out_conn_mr:
	ib_dereg_mr(isert_conn->conn_mr);
	tasklet_kill(&isert_conn->conn_rx_tasklet);
	tasklet_kill(&isert_conn->conn_tx_tasklet);
out_tx_cq:
	ib_destroy_cq(isert_conn->conn_tx_cq);
out_rx_cq:
	ib_destroy_cq(isert_conn->conn_rx_cq);
out_alloc_pd:
	ib_dealloc_pd(isert_conn->conn_pd);
out_rsp_dma_map:
	ib_dma_unmap_single(ib_dev, isert_conn->login_rsp_dma,
				ISER_RX_LOGIN_SIZE, DMA_TO_DEVICE);
out_req_dma_map:
	ib_dma_unmap_single(ib_dev, isert_conn->login_req_dma,
				ISCSI_DEF_MAX_RECV_SEG_LEN, DMA_FROM_DEVICE);
out_login_buf:
	kfree(isert_conn->login_buf);
out:
	kfree(isert_conn);
	return ret;
}

static void
isert_connect_release(struct isert_conn *isert_conn)
{
	struct ib_device *ib_dev = isert_conn->conn_cm_id->device;

	pr_debug("Entering isert_connect_release(): >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");

	if (isert_conn->conn_qp)
		rdma_destroy_qp(isert_conn->conn_cm_id);

	isert_free_rx_descriptors(isert_conn);

	tasklet_kill(&isert_conn->conn_rx_tasklet);
	tasklet_kill(&isert_conn->conn_tx_tasklet);

	ib_dereg_mr(isert_conn->conn_mr);
	ib_destroy_cq(isert_conn->conn_tx_cq);
	ib_destroy_cq(isert_conn->conn_rx_cq);
	ib_dealloc_pd(isert_conn->conn_pd);

	if (isert_conn->conn_cm_id != NULL)
		rdma_destroy_id(isert_conn->conn_cm_id);

	if (isert_conn->login_buf) {
		ib_dma_unmap_single(ib_dev, isert_conn->login_rsp_dma,
				ISER_RX_LOGIN_SIZE, DMA_TO_DEVICE);
		ib_dma_unmap_single(ib_dev, isert_conn->login_req_dma,
				ISCSI_DEF_MAX_RECV_SEG_LEN, DMA_FROM_DEVICE);
		kfree(isert_conn->login_buf);
	}
	kfree(isert_conn);

	pr_debug("Leaving isert_connect_release >>>>>>>>>>>>\n");
}

static void
isert_connected_handler(struct rdma_cm_id *cma_id)
{
	return;
}

static void
isert_release_conn_kref(struct kref *kref)
{
	struct isert_conn *isert_conn = container_of(kref,
				struct isert_conn, conn_kref);

	pr_debug("Calling isert_connect_release for final kref %s/%d\n",
			current->comm, current->pid);

	isert_connect_release(isert_conn);
}

void
isert_put_conn(struct isert_conn *isert_conn)
{
	kref_put(&isert_conn->conn_kref, isert_release_conn_kref);
}

static void
isert_disconnect_work(struct work_struct *work)
{
	struct isert_conn *isert_conn = container_of(work,
				struct isert_conn, conn_logout_work);

	pr_debug("isert_disconnect_work(): >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");

	if (isert_conn->post_recv_buf_count == 0 &&
	    atomic_read(&isert_conn->post_send_buf_count) == 0) {

		pr_debug("Calling wake_up(&isert_conn->conn_wait);\n");
		isert_conn->state = ISER_CONN_DOWN;
		wake_up(&isert_conn->conn_wait);
	}

	isert_put_conn(isert_conn);
}

static void
isert_disconnected_handler(struct rdma_cm_id *cma_id)
{
	struct isert_conn *isert_conn = (struct isert_conn *)cma_id->context;

	INIT_WORK(&isert_conn->conn_logout_work, isert_disconnect_work);
	schedule_work(&isert_conn->conn_logout_work);
}

int
isert_cma_handler(struct rdma_cm_id *cma_id, struct rdma_cm_event *event)
{
	int ret = 0;

	pr_debug("isert_cma_handler: event %d status %d conn %p id %p\n",
		event->event, event->status, cma_id->context, cma_id);

	switch (event->event) {
	case RDMA_CM_EVENT_CONNECT_REQUEST:
		pr_debug("RDMA_CM_EVENT_CONNECT_REQUEST: >>>>>>>>>>>>>>>\n");
		ret = isert_connect_request(cma_id, event);
		break;
	case RDMA_CM_EVENT_ESTABLISHED:
		pr_debug("RDMA_CM_EVENT_ESTABLISHED >>>>>>>>>>>>>>\n");
		isert_connected_handler(cma_id);
		break;
	case RDMA_CM_EVENT_DISCONNECTED:
		pr_debug("RDMA_CM_EVENT_DISCONNECTED: >>>>>>>>>>>>>>\n");
		isert_disconnected_handler(cma_id);
		break;
	case RDMA_CM_EVENT_DEVICE_REMOVAL:
	case RDMA_CM_EVENT_ADDR_CHANGE:
		break;
	case RDMA_CM_EVENT_ADDR_ERROR:
	case RDMA_CM_EVENT_ROUTE_ERROR:
	case RDMA_CM_EVENT_CONNECT_ERROR:
	default:
		pr_err("Unknown RDMA CMA event: %d\n", event->event);
		break;
	}

	if (ret != 0) {
		pr_err("isert_cma_handler failed RDMA_CM_EVENT: 0x%08x,"
				" ret: %d\n", event->event, ret);
		dump_stack();
	}

	return ret;
}

int
isert_post_recv(struct isert_conn *isert_conn, u32 count)
{
	struct ib_recv_wr *rx_wr, *rx_wr_failed;
	int i, ret;
	unsigned int rx_head = isert_conn->conn_rx_desc_head;
	struct isert_rx_desc *rx_desc;
	struct iser_rx_desc *desc;

	for (rx_wr = isert_conn->conn_rx_wr, i = 0; i < count; i++, rx_wr++) {
		rx_desc		= &isert_conn->conn_rx_descs[rx_head];
		desc		= &rx_desc->desc;
		rx_wr->wr_id	= (unsigned long)desc;
		rx_wr->sg_list	= &desc->rx_sg;
		rx_wr->num_sge	= 1;
		rx_wr->next	= rx_wr + 1;
		rx_head = (rx_head + 1) & (ISERT_QP_MAX_RECV_DTOS - 1);
	}

	rx_wr--;
	rx_wr->next = NULL; /* mark end of work requests list */

	isert_conn->post_recv_buf_count += count;
	ret = ib_post_recv(isert_conn->conn_qp, isert_conn->conn_rx_wr,
				&rx_wr_failed);
	if (ret) {
		pr_err("ib_post_recv() failed with ret: %d\n", ret);
		isert_conn->post_recv_buf_count -= count;
	} else {
		pr_debug("isert_post_recv(): Posted %d RX buffers\n", count);
		isert_conn->conn_rx_desc_head = rx_head;
	}
	return ret;
}

int
isert_post_send(struct isert_conn *isert_conn, struct iser_tx_desc *tx_desc)
{
	struct ib_device *ib_dev = isert_conn->conn_cm_id->device;
	struct ib_send_wr send_wr, *send_wr_failed;
	int ret;

	ib_dma_sync_single_for_device(ib_dev, tx_desc->dma_addr,
				ISER_HEADERS_LEN, DMA_TO_DEVICE);

	send_wr.next	= NULL;
	send_wr.wr_id	= (unsigned long)tx_desc;
	send_wr.sg_list	= tx_desc->tx_sg;
	send_wr.num_sge	= tx_desc->num_sge;
	send_wr.opcode	= IB_WR_SEND;
	send_wr.send_flags = IB_SEND_SIGNALED;

	atomic_inc(&isert_conn->post_send_buf_count);

	ret = ib_post_send(isert_conn->conn_qp, &send_wr, &send_wr_failed);
	if (ret) {
		pr_err("ib_post_send() failed, ret: %d\n", ret);
		atomic_dec(&isert_conn->post_send_buf_count);
	}

	return ret;
}
