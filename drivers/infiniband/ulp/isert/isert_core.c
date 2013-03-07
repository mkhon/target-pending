/*******************************************************************************
 * This file contains iSCSI extentions for RDMA (iSER) for iscsi_target_mod
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

#include <linux/string.h>
#include <linux/module.h>
#include <linux/scatterlist.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <rdma/ib_verbs.h>
#include <rdma/ib_fmr_pool.h>
#include <rdma/rdma_cm.h>
#include <target/target_core_base.h>
#include <target/target_core_fabric.h>
#include <target/iscsi/iscsi_transport.h>

#include "isert_proto.h"
#include "isert_base.h"
#include "isert_core.h"
#include "isert_verbs.h"

static struct workqueue_struct *isert_rx_wq;
static struct workqueue_struct *isert_comp_wq;

static void
isert_create_send_desc(struct isert_conn *isert_conn,
		       struct isert_cmd *isert_cmd,
		       struct iser_tx_desc *tx_desc)
{
	struct ib_device *ib_dev = isert_conn->conn_cm_id->device;

	ib_dma_sync_single_for_cpu(ib_dev, tx_desc->dma_addr,
				ISER_HEADERS_LEN, DMA_TO_DEVICE);

	memset(&tx_desc->iser_header, 0, sizeof(struct iser_hdr));
	tx_desc->iser_header.flags = ISER_VER;

	tx_desc->num_sge = 1;
	tx_desc->isert_cmd = isert_cmd;

	if (tx_desc->tx_sg[0].lkey != isert_conn->conn_mr->lkey) {
		tx_desc->tx_sg[0].lkey = isert_conn->conn_mr->lkey;
		pr_debug("tx_desc %p lkey mismatch, fixing\n", tx_desc);
	}
}

static int
isert_init_tx_hdrs(struct isert_conn *isert_conn,
		   struct iser_tx_desc *tx_desc)
{
	struct ib_device *ib_dev = isert_conn->conn_cm_id->device;
	u64 dma_addr;

	dma_addr = ib_dma_map_single(ib_dev, (void *)tx_desc,
			ISER_HEADERS_LEN, DMA_TO_DEVICE);
	if (ib_dma_mapping_error(ib_dev, dma_addr)) {
		pr_err("ib_dma_mapping_error() failed\n");
		return -ENOMEM;
	}

	tx_desc->dma_addr = dma_addr;
	tx_desc->tx_sg[0].addr	= tx_desc->dma_addr;
	tx_desc->tx_sg[0].length = ISER_HEADERS_LEN;
	tx_desc->tx_sg[0].lkey = isert_conn->conn_mr->lkey;

	pr_debug("isert_init_tx_hdrs: Setup tx_sg[0].addr: 0x%llx length: %u,"
		" lkey: 0x%08x\n", tx_desc->tx_sg[0].addr,
		tx_desc->tx_sg[0].length, tx_desc->tx_sg[0].lkey);

	return 0;
}

static int
isert_alloc_rx_descriptors(struct isert_conn *isert_conn)
{
	struct ib_device *ib_dev = isert_conn->conn_cm_id->device;
	struct isert_rx_desc *rx_desc;
	struct iser_rx_desc *desc;
	struct ib_sge *rx_sg;
	u64 dma_addr;
	int i, j;

	isert_conn->conn_rx_descs = kzalloc(ISERT_QP_MAX_RECV_DTOS *
					sizeof(struct isert_rx_desc), GFP_KERNEL);
	if (!isert_conn->conn_rx_descs)
		goto fail;

	rx_desc = isert_conn->conn_rx_descs;

	for (i = 0; i < ISERT_QP_MAX_RECV_DTOS; i++, rx_desc++)  {
		desc = &rx_desc->desc;

		dma_addr = ib_dma_map_single(ib_dev, (void *)desc,
					ISER_RX_PAYLOAD_SIZE, DMA_FROM_DEVICE);
		if (ib_dma_mapping_error(ib_dev, dma_addr))
			goto dma_map_fail;

		desc->dma_addr = dma_addr;

		rx_sg = &desc->rx_sg;
		rx_sg->addr = desc->dma_addr;
		rx_sg->length = ISER_RX_PAYLOAD_SIZE;
		rx_sg->lkey = isert_conn->conn_mr->lkey;
	}

	isert_conn->conn_rx_desc_head = 0;
	return 0;

dma_map_fail:
	rx_desc = isert_conn->conn_rx_descs;
	for (j = 0; j < i; j++, rx_desc++) {
		desc = &rx_desc->desc;
		ib_dma_unmap_single(ib_dev, desc->dma_addr,
				ISER_RX_PAYLOAD_SIZE, DMA_FROM_DEVICE);
	}
	kfree(isert_conn->conn_rx_descs);
	isert_conn->conn_rx_descs = NULL;
fail:
	return -ENOMEM;
}

void
isert_free_rx_descriptors(struct isert_conn *isert_conn)
{
	struct ib_device *ib_dev = isert_conn->conn_cm_id->device;
	struct isert_rx_desc *rx_desc;
	struct iser_rx_desc *desc;
	int i;

	if (!isert_conn->conn_rx_descs)
		return;

	rx_desc = isert_conn->conn_rx_descs;
	for (i = 0; i < ISERT_QP_MAX_RECV_DTOS; i++, rx_desc++)  {
		desc = &rx_desc->desc;
		ib_dma_unmap_single(ib_dev, desc->dma_addr,
					ISER_RX_PAYLOAD_SIZE, DMA_FROM_DEVICE);
	}

	kfree(isert_conn->conn_rx_descs);
	isert_conn->conn_rx_descs = NULL;
}

static int isert_rdma_post_recvl(struct isert_conn *);

static int
isert_put_login_tx(struct iscsi_conn *conn, struct iscsi_login *login,
		   u32 length)
{
	struct isert_conn *isert_conn = conn->context;
	struct ib_device *ib_dev = isert_conn->conn_cm_id->device;
	struct iser_tx_desc *tx_desc = &isert_conn->conn_login_tx_desc;
	int ret;

	isert_create_send_desc(isert_conn, NULL, tx_desc);

	pr_debug("Copying login->rsp into tx_desc->iscsi_header\n");
	memcpy(&tx_desc->iscsi_header, &login->rsp[0], sizeof(struct iscsi_hdr));

	isert_init_tx_hdrs(isert_conn, tx_desc);

	if (length > 0) {
		struct ib_sge *tx_dsg = &tx_desc->tx_sg[1];

		ib_dma_sync_single_for_cpu(ib_dev, isert_conn->login_rsp_dma,
					length, DMA_TO_DEVICE);

		pr_debug("memcpy TX login->rsp_buf to isert_conn->login_rsp_buf,"
				" length: %u\n", length);
		memcpy(isert_conn->login_rsp_buf, login->rsp_buf, length);

		ib_dma_sync_single_for_device(ib_dev, isert_conn->login_rsp_dma,
				length, DMA_TO_DEVICE);

		tx_dsg->addr	= isert_conn->login_rsp_dma;
		tx_dsg->length	= length;
		tx_dsg->lkey	= isert_conn->conn_mr->lkey;
		tx_desc->num_sge = 2;
	}
	if (!login->login_failed) {
		if (login->login_complete) {
			pr_debug("isert_put_login_tx, detected login_complete=1, calling"
					" isert_alloc_rx_descriptors >>>>>>>>>>>>>>>\n");

			ret = isert_alloc_rx_descriptors(isert_conn);
			if (ret)
				return ret;

			pr_debug("isert_put_login_tx, detected login_complete=1, calling "
					"isert_post_recv to post ISERT_MIN_POSTED_RX: %d\n",
					ISERT_MIN_POSTED_RX);

			ret = isert_post_recv(isert_conn, ISERT_MIN_POSTED_RX);
			if (ret)
				return ret;

			isert_conn->state = ISER_CONN_UP;
			goto post_send;
		}

		ret = isert_rdma_post_recvl(isert_conn);
		if (ret)
			return ret;
	}
post_send:
	ret = isert_post_send(isert_conn, tx_desc);
	if (ret)
		return ret;

	return 0;
}

static void
isert_rx_login_req(struct isert_rx_desc *rx_desc, int rx_buflen,
		   struct isert_conn *isert_conn)
{
	struct iser_rx_desc *desc = &rx_desc->desc;
	struct iscsi_conn *conn = isert_conn->conn;
	struct iscsi_login *login = conn->conn_login;
	int size;

	if (!login) {
		pr_err("conn->conn_login is NULL\n");
		dump_stack();
		return;
	}

	if (login->first_request) {
		struct iscsi_login_req *login_req =
			(struct iscsi_login_req *)&desc->iscsi_header;
		/*
		 * Setup the initial iscsi_login values from the leading
		 * login request PDU.
		 */
		login->leading_connection = (!login_req->tsih) ? 1 : 0;
		login->current_stage =
			(login_req->flags & ISCSI_FLAG_LOGIN_CURRENT_STAGE_MASK) >> 2;
		login->version_min	= login_req->min_version;
		login->version_max	= login_req->max_version;
		memcpy(login->isid, login_req->isid, 6);
		login->cmd_sn		= be32_to_cpu(login_req->cmdsn);
		login->init_task_tag	= login_req->itt;
		login->initial_exp_statsn = be32_to_cpu(login_req->exp_statsn);
		login->cid		= be16_to_cpu(login_req->cid);
		login->tsih		= be16_to_cpu(login_req->tsih);
	}

	memcpy(&login->req[0], (void *)&desc->iscsi_header, ISCSI_HDR_LEN);

	size = min(rx_buflen, MAX_KEY_VALUE_PAIRS);
	pr_debug("Using login payload size: %d, rx_buflen: %d MAX_KEY_VALUE_PAIRS: %d\n",
			size, rx_buflen, MAX_KEY_VALUE_PAIRS);
	memcpy(login->req_buf, &desc->data[0], size);

	complete(&isert_conn->conn_login_comp);
}

static struct iscsi_cmd
*isert_alloc_cmd(struct iscsi_conn *conn, gfp_t gfp)
{
	struct isert_conn *isert_conn = (struct isert_conn *)conn->context;
	struct isert_cmd *isert_cmd;

	isert_cmd = kzalloc(sizeof(struct isert_cmd), gfp);
	if (!isert_cmd) {
		pr_err("Unable to allocate isert_cmd\n");
		return NULL;
	}
	isert_cmd->conn = isert_conn;

	kref_init(&isert_cmd->cmd_kref);
	kref_get(&isert_cmd->cmd_kref);

	return &isert_cmd->iscsi_cmd;
}

static int
isert_handle_scsi_cmd(struct isert_conn *isert_conn, struct isert_cmd *isert_cmd,
		      struct iser_rx_desc *rx_desc, unsigned char *buf)
{
	struct iscsi_cmd *cmd = &isert_cmd->iscsi_cmd;
	struct iscsi_conn *conn = isert_conn->conn;
	struct iscsi_scsi_req *hdr = (struct iscsi_scsi_req *)buf;
	struct scatterlist *sg;
	int imm_data, imm_data_len, unsol_data, sg_nents, rc;
	bool dump_payload = false;

	rc = iscsit_setup_scsi_cmd(conn, cmd, buf);
	if (rc < 0)
		return rc;

	imm_data = cmd->immediate_data;
	imm_data_len = cmd->first_burst_len;
	unsol_data = cmd->unsolicited_data;

	rc = iscsit_process_scsi_cmd(conn, cmd, hdr);
	if (rc < 0)
		return 0;
	else if (rc > 0) {
		dump_payload = true;
		goto sequence_cmd;
	}

	if (!imm_data)
		return 0;

	sg = &cmd->se_cmd.t_data_sg[0];
	sg_nents = max(1UL, DIV_ROUND_UP(imm_data_len, PAGE_SIZE));

	pr_debug("Copying Immediate SG: %p sg_nents: %u from %p"
		" imm_data_len: %d\n", sg, sg_nents, &rx_desc->data[0],
		imm_data_len);

	sg_copy_from_buffer(sg, sg_nents, &rx_desc->data[0], imm_data_len);

	cmd->write_data_done += imm_data_len;

	if (cmd->write_data_done == cmd->se_cmd.data_length) {
		spin_lock_bh(&cmd->istate_lock);
		cmd->cmd_flags |= ICF_GOT_LAST_DATAOUT;
		cmd->i_state = ISTATE_RECEIVED_LAST_DATAOUT;
		spin_unlock_bh(&cmd->istate_lock);
	}

sequence_cmd:
	rc = iscsit_sequence_cmd(conn, cmd, hdr->cmdsn);

	if (!rc && dump_payload == false && unsol_data)
		iscsit_set_unsoliticed_dataout(cmd);

	if (rc == CMDSN_ERROR_CANNOT_RECOVER)
		return iscsit_add_reject_from_cmd(
			   ISCSI_REASON_PROTOCOL_ERROR,
			   1, 0, (unsigned char *)hdr, cmd);

	return 0;
}

static int
isert_handle_iscsi_dataout(struct isert_conn *isert_conn,
			   struct iser_rx_desc *rx_desc, unsigned char *buf)
{
	struct scatterlist *sg_start;
	struct iscsi_conn *conn = isert_conn->conn;
	struct iscsi_cmd *cmd = NULL;
	struct iscsi_data *hdr = (struct iscsi_data *)buf;
	u32 unsol_data_len = ntoh24(hdr->dlength);
	int rc, sg_nents, sg_off, page_off;

	rc = iscsit_check_dataout_hdr(conn, buf, &cmd);
	if (rc < 0)
		return rc;
	else if (!cmd)
		return 0;

#warning FIXME: Unexpected unsolicited_data out
	if (!cmd->unsolicited_data) {
		pr_err("Received unexpected solicited data payload\n");
		dump_stack();
		return -1;
	}

	pr_debug("Unsolicited DataOut unsol_data_len: %u, write_data_done: %u,"
		" data_length: %u\n", unsol_data_len, cmd->write_data_done,
		cmd->se_cmd.data_length);

	sg_off = cmd->write_data_done / PAGE_SIZE;
	sg_start = &cmd->se_cmd.t_data_sg[sg_off];
	sg_nents = max(1UL, DIV_ROUND_UP(unsol_data_len, PAGE_SIZE));
	page_off = cmd->write_data_done % PAGE_SIZE;
#warning FIXME: Non page-aligned unsolicited_data out
	if (page_off) {
		pr_err("Received unexpected non-page aligned solicited"
			" data payload\n");
		dump_stack();
		return -1;
	}
	pr_debug("Copying DataOut: sg_start: %p, sg_off: %u sg_nents: %u from"
		" %p %u\n", sg_start, sg_off, sg_nents, &rx_desc->data[0],
		unsol_data_len);

	sg_copy_from_buffer(sg_start, sg_nents, &rx_desc->data[0],
			    unsol_data_len);

	rc = iscsit_check_dataout_payload(cmd, hdr, false);
	if (rc < 0)
		return rc;

	return 0;
}

static int
isert_rx_opcode(struct isert_conn *isert_conn, struct iser_rx_desc *rx_desc,
		uint32_t read_stag, uint64_t read_va,
		uint32_t write_stag, uint64_t write_va)
{
	struct iscsi_hdr *hdr = &rx_desc->iscsi_header;
	struct iscsi_conn *conn = isert_conn->conn;
	struct iscsi_cmd *cmd;
	struct isert_cmd *isert_cmd;
	int ret = -EINVAL;
	u8 opcode = (hdr->opcode & ISCSI_OPCODE_MASK);

	switch (opcode) {
	case ISCSI_OP_SCSI_CMD:
		cmd = iscsit_allocate_cmd(conn, GFP_KERNEL);
		if (!cmd)
			break;

		isert_cmd = container_of(cmd, struct isert_cmd, iscsi_cmd);
		isert_cmd->read_stag = read_stag;
		isert_cmd->read_va = read_va;
		isert_cmd->write_stag = write_stag;
		isert_cmd->write_va = write_va;

		ret = isert_handle_scsi_cmd(isert_conn, isert_cmd,
					rx_desc, (unsigned char *)hdr);
		break;
	case ISCSI_OP_NOOP_OUT:
		cmd = iscsit_allocate_cmd(conn, GFP_KERNEL);
		if (!cmd)
			break;

		ret = iscsit_handle_nop_out(conn, cmd, (unsigned char *)hdr);
		break;
	case ISCSI_OP_SCSI_DATA_OUT:
		ret = isert_handle_iscsi_dataout(isert_conn, rx_desc,
						(unsigned char *)hdr);
		break;
	case ISCSI_OP_SCSI_TMFUNC:
		cmd = iscsit_allocate_cmd(conn, GFP_KERNEL);
		if (!cmd)
			break;

		ret = iscsit_handle_task_mgt_cmd(conn, cmd, (unsigned char *)hdr);
		break;
	case ISCSI_OP_LOGOUT:
		cmd = iscsit_allocate_cmd(conn, GFP_KERNEL);
		if (!cmd)
			break;

		ret = iscsit_handle_logout_cmd(conn, cmd, (unsigned char *)hdr);
		if (ret > 0)
			wait_for_completion_timeout(&conn->conn_logout_comp,
					SECONDS_FOR_LOGOUT_COMP * HZ);
		break;
	default:
		pr_err("Got unknown iSCSI OpCode: 0x%02x\n", opcode);
		dump_stack();
		break;
	}

	return ret;
}

static void
isert_rx_do_work(struct work_struct *work)
{
	struct isert_rx_desc *rx_desc = container_of(work,
				struct isert_rx_desc, desc_work);
	struct isert_conn *isert_conn = rx_desc->desc_conn;
	struct iser_rx_desc *desc = &rx_desc->desc;
	struct iser_hdr *iser_hdr = &desc->iser_header;
	uint64_t read_va = 0, write_va = 0;
	uint32_t read_stag = 0, write_stag = 0;
	int rc;

	switch (iser_hdr->flags & 0xF0) {
	case ISCSI_CTRL:
		if (iser_hdr->flags & ISER_RSV) {
			read_stag = be32_to_cpu(iser_hdr->read_stag);
			read_va = be64_to_cpu(iser_hdr->read_va);
			pr_debug("ISER_RSV: read_stag: 0x%08x read_va: 0x%16llx\n",
				read_stag, (unsigned long long)read_va);
		}
		if (iser_hdr->flags & ISER_WSV) {
			write_stag = be32_to_cpu(iser_hdr->write_stag);
			write_va = be64_to_cpu(iser_hdr->write_va);
			pr_debug("ISER_WSV: write__stag: 0x%08x write_va: 0x%16llx\n",
				write_stag, (unsigned long long)write_va);
		}

		pr_debug("ISER ISCSI_CTRL PDU\n");
		break;
	case ISER_HELLO:
		pr_err("iSER Hello message\n");
		break;
	default:
		pr_warn("Unknown iSER hdr flags: 0x%02x\n", iser_hdr->flags);
		break;
	}

	rc = isert_rx_opcode(isert_conn, desc,
			     read_stag, read_va, write_stag, write_va);
}

static void
isert_rx_queue_desc(struct isert_rx_desc *rx_desc, int rx_buflen,
		    struct isert_conn *isert_conn)
{
	INIT_WORK(&rx_desc->desc_work, isert_rx_do_work);
	queue_work(isert_rx_wq, &rx_desc->desc_work);
}

static void
isert_rx_completion(struct iser_rx_desc *desc, struct isert_conn *isert_conn,
		    unsigned long xfer_len)
{
	struct ib_device *ib_dev = isert_conn->conn_cm_id->device;
	struct isert_rx_desc *rx_desc = container_of(desc,
				struct isert_rx_desc, desc);
	struct iscsi_hdr *hdr;
	u64 rx_dma;
	int rx_buflen, outstanding;

	rx_desc->desc_conn = isert_conn;

	if ((char *)desc == isert_conn->login_req_buf) {
		rx_dma = isert_conn->login_req_dma;
//		rx_buflen = ISER_RX_LOGIN_SIZE;
		rx_buflen = xfer_len;
		pr_debug("ISER login_buf: Using rx_dma: 0x%llx, rx_buflen: %d\n",
			rx_dma, rx_buflen);
	} else {
		rx_dma = desc->dma_addr;
		rx_buflen = ISER_RX_PAYLOAD_SIZE;
		pr_debug("ISER req_buf: Using rx_dma: 0x%llx, rx_buflen: %d\n",
			rx_dma, rx_buflen);
	}

	ib_dma_sync_single_for_cpu(ib_dev, rx_dma, rx_buflen, DMA_FROM_DEVICE);

	hdr = &desc->iscsi_header;
	pr_debug("iSCSI opcode: 0x%02x, ITT: 0x%08x, flags: 0x%02x dlen: %lu\n",
		hdr->opcode, hdr->itt, hdr->flags, (int)xfer_len - ISER_HEADERS_LEN);

	if ((char *)desc == isert_conn->login_req_buf) {
		isert_rx_login_req(rx_desc, rx_buflen, isert_conn);
	} else {
		isert_rx_queue_desc(rx_desc, rx_buflen, isert_conn);
	}
	ib_dma_sync_single_for_device(ib_dev, rx_dma, rx_buflen, DMA_FROM_DEVICE);

	isert_conn->post_recv_buf_count--;
	pr_debug("iSERT: Decremented post_recv_buf_count: %d\n",
			isert_conn->post_recv_buf_count);

	if ((char *)desc == isert_conn->login_req_buf)
		return;

	outstanding = isert_conn->post_recv_buf_count;
	if (outstanding + ISERT_MIN_POSTED_RX <= ISERT_QP_MAX_RECV_DTOS) {
		int err, count = min(ISERT_QP_MAX_RECV_DTOS - outstanding,
				ISERT_MIN_POSTED_RX);
		err = isert_post_recv(isert_conn, count);
		if (err) {
			pr_err("isert_post_recv() count: %d failed, %d\n",
				count, err);
		}
	}
}

static void
isert_cmd_kref_free(struct kref *kref)
{
	struct isert_cmd *isert_cmd = container_of(kref,
				struct isert_cmd, cmd_kref);

	kfree(isert_cmd);
}

static void
isert_put_cmd(struct isert_cmd *isert_cmd)
{
	kref_put(&isert_cmd->cmd_kref, isert_cmd_kref_free);
}

static void
isert_unmap_tx_desc(struct iser_tx_desc *tx_desc, struct ib_device *ib_dev)
{
	if (tx_desc->dma_addr != 0) {
		pr_debug("Calling ib_dma_unmap_single for tx_desc->dma_addr\n");
		ib_dma_unmap_single(ib_dev, tx_desc->dma_addr,
				ISER_HEADERS_LEN, DMA_TO_DEVICE);
		tx_desc->dma_addr = 0;
	}
}

static void
isert_completion_put(struct iser_tx_desc *tx_desc, struct isert_cmd *isert_cmd,
		     struct ib_device *ib_dev)
{
	if (isert_cmd->sense_buf_dma != 0) {
		pr_debug("Calling ib_dma_unmap_single for isert_cmd->sense_buf_dma\n");
		ib_dma_unmap_single(ib_dev, isert_cmd->sense_buf_dma,
				isert_cmd->sense_buf_len, DMA_TO_DEVICE);
		isert_cmd->sense_buf_dma = 0;
	}

	isert_unmap_tx_desc(tx_desc, ib_dev);
	isert_put_cmd(isert_cmd);
}

static void
isert_do_rdma_read_comp(struct work_struct *work)
{
	struct isert_cmd *isert_cmd = container_of(work,
			struct isert_cmd, comp_work);
	struct isert_rdma_wr *wr = &isert_cmd->rdma_wr;
	struct iscsi_cmd *cmd = &isert_cmd->iscsi_cmd;
	struct se_cmd *se_cmd = &cmd->se_cmd;
	struct ib_device *ib_dev = isert_cmd->conn->conn_cm_id->device;

	if (wr->sge) {
		pr_debug("isert_do_rdma_read_comp: Unmapping wr->sge from t_data_sg\n");
		ib_dma_unmap_sg(ib_dev, wr->sge, wr->num_sge, DMA_TO_DEVICE);
		wr->sge = NULL;
	}

	if (isert_cmd->ib_sge) {
		pr_debug("isert_do_rdma_read_comp: Freeing isert_cmd->ib_sge\n");
		kfree(isert_cmd->ib_sge);
		isert_cmd->ib_sge = NULL;
	}

	cmd->write_data_done = se_cmd->data_length;

	pr_debug("isert_do_rdma_read_comp, calling target_execute_cmd\n");
	spin_lock_bh(&cmd->istate_lock);
	cmd->cmd_flags |= ICF_GOT_LAST_DATAOUT;
	cmd->i_state = ISTATE_RECEIVED_LAST_DATAOUT;
	spin_unlock_bh(&cmd->istate_lock);

	target_execute_cmd(se_cmd);
}

static void
isert_completion_rdma_read(struct iser_tx_desc *tx_desc,
			   struct isert_cmd *isert_cmd)
{
	INIT_WORK(&isert_cmd->comp_work, isert_do_rdma_read_comp);
	queue_work(isert_comp_wq, &isert_cmd->comp_work);
}

static void
isert_do_control_comp(struct work_struct *work)
{
	struct isert_cmd *isert_cmd = container_of(work,
			struct isert_cmd, comp_work);
	struct isert_conn *isert_conn = isert_cmd->conn;
	struct ib_device *ib_dev = isert_conn->conn_cm_id->device;
	struct iscsi_cmd *cmd = &isert_cmd->iscsi_cmd;

	switch (cmd->i_state) {
	case ISTATE_SEND_TASKMGTRSP:
		pr_debug("Calling iscsit_tmr_post_handler >>>>>>>>>>>>>>>>>>>>>>>>>>>\n");
		iscsit_tmr_post_handler(cmd, cmd->conn);
		break;
	case ISTATE_SEND_LOGOUTRSP:
		pr_debug("Calling iscsit_logout_post_handler >>>>>>>>>>>>>>>>>>>>>>>>>>>\n");
		iscsit_logout_post_handler(cmd, cmd->conn);
		break;
	default:
		pr_err("Unknown isert_do_control_comp i_state: %d\n", cmd->i_state);
		dump_stack();
		break;
	}

	cmd->i_state = ISTATE_SENT_STATUS;
	isert_completion_put(&isert_cmd->tx_desc, isert_cmd, ib_dev);
}

static void
isert_response_completion(struct iser_tx_desc *tx_desc,
			  struct isert_cmd *isert_cmd,
			  struct isert_conn *isert_conn,
			  struct ib_device *ib_dev)
{
	struct iscsi_cmd *cmd = &isert_cmd->iscsi_cmd;

	if (cmd->i_state == ISTATE_SEND_TASKMGTRSP ||
	    cmd->i_state == ISTATE_SEND_LOGOUTRSP) {
		INIT_WORK(&isert_cmd->comp_work, isert_do_control_comp);
		queue_work(isert_comp_wq, &isert_cmd->comp_work);
		return;
	}
	cmd->i_state = ISTATE_SENT_STATUS;

	isert_completion_put(tx_desc, isert_cmd, ib_dev);
}

static void
isert_send_completion(struct iser_tx_desc *tx_desc,
		      struct isert_conn *isert_conn)
{
	struct ib_device *ib_dev = isert_conn->conn_cm_id->device;
	struct isert_cmd *isert_cmd = tx_desc->isert_cmd;
	struct isert_rdma_wr *wr;

	atomic_dec(&isert_conn->post_send_buf_count);

	if (!isert_cmd) {
		isert_unmap_tx_desc(tx_desc, ib_dev);
		return;
	}
	wr = &isert_cmd->rdma_wr;

	switch (wr->iser_ib_op) {
	case ISER_IB_RECV:
		pr_err("isert_send_completion: Got ISER_IB_RECV\n");
		dump_stack();
		break;
	case ISER_IB_SEND:
		pr_debug("isert_send_completion: Got ISER_IB_SEND\n");
		isert_response_completion(tx_desc, isert_cmd,
					  isert_conn, ib_dev);
		break;
	case ISER_IB_RDMA_WRITE:
		pr_err("isert_send_completion: Got ISER_IB_RDMA_WRITE\n");
		dump_stack();
		break;
	case ISER_IB_RDMA_READ:
		pr_debug("isert_send_completion: Got ISER_IB_RDMA_READ:\n");
		isert_completion_rdma_read(tx_desc, isert_cmd);
		break;
	default:
		pr_err("Unknown wr->iser_ib_op: 0x%02x\n", wr->iser_ib_op);
		dump_stack();
		break;
	}
}

static void
isert_cq_comp_err(struct iser_tx_desc *tx_desc, struct isert_conn *isert_conn)
{
	struct ib_device *ib_dev = isert_conn->conn_cm_id->device;

	if (tx_desc) {
		struct isert_cmd *isert_cmd = tx_desc->isert_cmd;

		if (!isert_cmd)
			isert_unmap_tx_desc(tx_desc, ib_dev);
		else
			isert_completion_put(tx_desc, isert_cmd, ib_dev);
	}

	if (isert_conn->post_recv_buf_count == 0 &&
	    atomic_read(&isert_conn->post_send_buf_count) == 0) {

		pr_debug("isert_cq_comp_err >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");
		pr_debug("Calling wake_up(&isert_conn->conn_wait); for isert_cq_comp_err\n");

		isert_conn->state = ISER_CONN_DOWN;
		wake_up(&isert_conn->conn_wait);
	}
}

void
isert_dump_ib_wc(struct ib_wc *wc)
{
	pr_debug("wc->wr_id: %llu\n", wc->wr_id);
	pr_debug("wc->status: 0x%08x\n", wc->status);
	pr_debug("wc->opcode: 0x%08x\n", wc->opcode);
	pr_debug("wc->vendor_err: 0x%08x\n", wc->vendor_err);
	pr_debug("wc->byte_len: %u\n", wc->byte_len);
	pr_debug("wc->qp: %p\n", wc->qp);
	pr_debug("wc->src_qp: %u\n", wc->src_qp);
	pr_debug("wc->wc_flags: 0x%08x\n", wc->wc_flags);
	pr_debug("wc->pkey_index: %hu\n", wc->pkey_index);
	pr_debug("wc->slid: %hu\n", wc->slid);
	pr_debug("wc->sl: 0x%02x\n", wc->sl);
	pr_debug("wc->dlid_path_bits: 0x%02x\n", wc->dlid_path_bits);
	pr_debug("wc->port_num: 0x%02x\n", wc->port_num);
}

void
iser_cq_tx_tasklet(unsigned long data)
{
	struct isert_conn *isert_conn = (struct isert_conn *)data;
	struct ib_cq *tx_cq = isert_conn->conn_tx_cq;
	struct iser_tx_desc *tx_desc;
	struct ib_wc wc;

	while (ib_poll_cq(tx_cq, 1, &wc) == 1) {
		tx_desc = (struct iser_tx_desc *)(unsigned long)wc.wr_id;

		if (wc.status == IB_WC_SUCCESS) {
			isert_send_completion(tx_desc, isert_conn);
		} else {
			pr_debug("TX wc.status != IB_WC_SUCCESS >>>>>>>>>>>>>>\n");
			isert_dump_ib_wc(&wc);
			atomic_dec(&isert_conn->post_send_buf_count);
			isert_cq_comp_err(tx_desc, isert_conn);
		}
	}

	ib_req_notify_cq(tx_cq, IB_CQ_NEXT_COMP);
}

void
isert_cq_tx_callback(struct ib_cq *cq, void *context)
{
	struct isert_conn *isert_conn = context;

	tasklet_schedule(&isert_conn->conn_tx_tasklet);
}

void
iser_cq_rx_tasklet(unsigned long data)
{
	struct isert_conn *isert_conn = (struct isert_conn *)data;
	struct ib_cq *rx_cq = isert_conn->conn_rx_cq;
	struct iser_rx_desc *rx_desc;
	struct ib_wc wc;
	unsigned long xfer_len;

	while (ib_poll_cq(rx_cq, 1, &wc) == 1) {
		rx_desc = (struct iser_rx_desc *)(unsigned long)wc.wr_id;

		if (wc.status == IB_WC_SUCCESS) {
			xfer_len = (unsigned long)wc.byte_len;
			isert_rx_completion(rx_desc, isert_conn, xfer_len);
		} else {
			pr_debug("RX wc.status != IB_WC_SUCCESS >>>>>>>>>>>>>>\n");
			if (wc.status != IB_WC_WR_FLUSH_ERR)
				isert_dump_ib_wc(&wc);

			isert_conn->post_recv_buf_count--;
			isert_cq_comp_err(NULL, isert_conn);
		}
	}

	ib_req_notify_cq(rx_cq, IB_CQ_NEXT_COMP);
}

void
isert_cq_rx_callback(struct ib_cq *cq, void *context)
{
	struct isert_conn *isert_conn = context;

	tasklet_schedule(&isert_conn->conn_rx_tasklet);
}

static int
isert_put_response(struct iscsi_cmd *cmd, struct iscsi_conn *conn)
{
	struct isert_cmd *isert_cmd = container_of(cmd,
					struct isert_cmd, iscsi_cmd);
	struct isert_conn *isert_conn = (struct isert_conn *)conn->context;
	struct ib_send_wr *send_wr = &isert_cmd->tx_desc.send_wr, *wr_failed;
	struct iscsi_scsi_rsp *hdr = (struct iscsi_scsi_rsp *)
				&isert_cmd->tx_desc.iscsi_header;
	int ret;

	isert_create_send_desc(isert_conn, isert_cmd, &isert_cmd->tx_desc);
	iscsit_build_rsp_pdu(cmd, conn, true, hdr);
	isert_init_tx_hdrs(isert_conn, &isert_cmd->tx_desc);
	/*
	 * Attach SENSE DATA payload to iSCSI Response PDU
	 */
	if (cmd->se_cmd.sense_buffer &&
	   ((cmd->se_cmd.se_cmd_flags & SCF_TRANSPORT_TASK_SENSE) ||
	    (cmd->se_cmd.se_cmd_flags & SCF_EMULATED_TASK_SENSE))) {
		struct ib_device *ib_dev = isert_conn->conn_cm_id->device;
		struct ib_sge *tx_dsg = &isert_cmd->tx_desc.tx_sg[1];
		u32 padding, sense_len;

		put_unaligned_be16(cmd->se_cmd.scsi_sense_length, cmd->sense_buffer);
		cmd->se_cmd.scsi_sense_length += sizeof (__be16);

		padding = -(cmd->se_cmd.scsi_sense_length) & 3;
		hton24(hdr->dlength, (u32)cmd->se_cmd.scsi_sense_length);
		sense_len = cmd->se_cmd.scsi_sense_length + padding;

		isert_cmd->sense_buf_dma = ib_dma_map_single(ib_dev,
				(void *)cmd->sense_buffer, sense_len,
				DMA_TO_DEVICE);

		isert_cmd->sense_buf_len = sense_len;
		ib_dma_sync_single_for_cpu(ib_dev, isert_cmd->sense_buf_dma,
					sense_len, DMA_TO_DEVICE);
		ib_dma_sync_single_for_device(ib_dev, isert_cmd->sense_buf_dma,
					sense_len, DMA_TO_DEVICE);

		tx_dsg->addr	= isert_cmd->sense_buf_dma;
		tx_dsg->length	= sense_len;
		tx_dsg->lkey	= isert_conn->conn_mr->lkey;
		isert_cmd->tx_desc.num_sge = 2;
	}

	isert_cmd->rdma_wr.iser_ib_op = ISER_IB_SEND;
	send_wr->wr_id = (unsigned long)&isert_cmd->tx_desc;
	send_wr->opcode = IB_WR_SEND;
	send_wr->send_flags = IB_SEND_SIGNALED;
	send_wr->sg_list = &isert_cmd->tx_desc.tx_sg[0];
	send_wr->num_sge = isert_cmd->tx_desc.num_sge;
	send_wr->next = NULL;

	pr_debug("Posting SCSI Response IB_WR_SEND >>>>>>>>>>>>>>>>>>>>>>\n");

	atomic_inc(&isert_conn->post_send_buf_count);

	ret = ib_post_send(isert_conn->conn_qp, &isert_cmd->tx_desc.send_wr,
			&wr_failed);
	if (ret) {
		pr_err("isert_put_response() failed to post wr,"
			" ret: %d\n", ret);
		atomic_dec(&isert_conn->post_send_buf_count);
		return ret;
	}
	return 0;
}

static int
isert_put_nopin(struct iscsi_cmd *cmd, struct iscsi_conn *conn,
		bool nopout_response)
{
	struct isert_cmd *isert_cmd = container_of(cmd,
				struct isert_cmd, iscsi_cmd);
	struct isert_conn *isert_conn = (struct isert_conn *)conn->context;
	struct ib_send_wr *send_wr = &isert_cmd->tx_desc.send_wr, *wr_failed;
	int ret;

	isert_create_send_desc(isert_conn, isert_cmd, &isert_cmd->tx_desc);
	iscsit_build_nopin_rsp(cmd, conn,
			(struct iscsi_nopin *)&isert_cmd->tx_desc.iscsi_header,
			nopout_response);
	isert_init_tx_hdrs(isert_conn, &isert_cmd->tx_desc);

	isert_cmd->rdma_wr.iser_ib_op = ISER_IB_SEND;
	send_wr->wr_id = (unsigned long)&isert_cmd->tx_desc;
	send_wr->opcode = IB_WR_SEND;
	send_wr->send_flags = IB_SEND_SIGNALED;
	send_wr->sg_list = &isert_cmd->tx_desc.tx_sg[0];
	send_wr->num_sge = isert_cmd->tx_desc.num_sge;
	send_wr->next = NULL;

	pr_debug("Posting NOPIN Reponse IB_WR_SEND >>>>>>>>>>>>>>>>>>>>>>\n");

	atomic_inc(&isert_conn->post_send_buf_count);

	ret = ib_post_send(isert_conn->conn_qp, &isert_cmd->tx_desc.send_wr,
			&wr_failed);
	if (ret) {
		pr_err("isert_put_nopin() failed to post wr,"
			" ret: %d\n", ret);
		atomic_dec(&isert_conn->post_send_buf_count);
		return ret;
	}
	return 0;
}

static int
isert_put_logout_rsp(struct iscsi_cmd *cmd, struct iscsi_conn *conn)
{
	struct isert_cmd *isert_cmd = container_of(cmd,
				struct isert_cmd, iscsi_cmd);
	struct isert_conn *isert_conn = (struct isert_conn *)conn->context;
	struct ib_send_wr *send_wr = &isert_cmd->tx_desc.send_wr, *wr_failed;
	int ret;

	isert_create_send_desc(isert_conn, isert_cmd, &isert_cmd->tx_desc);
	iscsit_build_logout_rsp(cmd, conn,
			(struct iscsi_logout_rsp *)&isert_cmd->tx_desc.iscsi_header);
	isert_init_tx_hdrs(isert_conn, &isert_cmd->tx_desc);

	isert_cmd->rdma_wr.iser_ib_op = ISER_IB_SEND;
	send_wr->wr_id = (unsigned long)&isert_cmd->tx_desc;
	send_wr->opcode = IB_WR_SEND;
	send_wr->send_flags = IB_SEND_SIGNALED;
	send_wr->sg_list = &isert_cmd->tx_desc.tx_sg[0];
	send_wr->num_sge = isert_cmd->tx_desc.num_sge;
	send_wr->next = NULL;

	pr_debug("Posting Logout Response IB_WR_SEND >>>>>>>>>>>>>>>>>>>>>>\n");

	atomic_inc(&isert_conn->post_send_buf_count);

	ret = ib_post_send(isert_conn->conn_qp, &isert_cmd->tx_desc.send_wr,
			&wr_failed);
	if (ret) {
		pr_err("isert_put_logout_rsp() failed to post wr,"
			" ret: %d\n", ret);
		atomic_dec(&isert_conn->post_send_buf_count);
		return ret;
	}
	return 0;
}

static int
isert_put_tm_rsp(struct iscsi_cmd *cmd, struct iscsi_conn *conn)
{
	struct isert_cmd *isert_cmd = container_of(cmd,
				struct isert_cmd, iscsi_cmd);
	struct isert_conn *isert_conn = (struct isert_conn *)conn->context;
	struct ib_send_wr *send_wr = &isert_cmd->tx_desc.send_wr, *wr_failed;
	int ret;

	isert_create_send_desc(isert_conn, isert_cmd, &isert_cmd->tx_desc);
	iscsit_build_task_mgt_rsp(cmd, conn,
			(struct iscsi_tm_rsp *)&isert_cmd->tx_desc.iscsi_header);
	isert_init_tx_hdrs(isert_conn, &isert_cmd->tx_desc);

	isert_cmd->rdma_wr.iser_ib_op = ISER_IB_SEND;
	send_wr->wr_id = (unsigned long)&isert_cmd->tx_desc;
	send_wr->opcode = IB_WR_SEND;
	send_wr->send_flags = IB_SEND_SIGNALED;
	send_wr->sg_list = &isert_cmd->tx_desc.tx_sg[0];
	send_wr->num_sge = isert_cmd->tx_desc.num_sge;
	send_wr->next = NULL;

	pr_debug("Posting Task Management Response IB_WR_SEND >>>>>>>>>>>>>>>>>>>>>>\n");

	atomic_inc(&isert_conn->post_send_buf_count);

	ret = ib_post_send(isert_conn->conn_qp, &isert_cmd->tx_desc.send_wr,
			&wr_failed);
	if (ret) {
		pr_err("isert_put_tm_rsp() failed to post wr,"
			" ret: %d\n", ret);
		atomic_dec(&isert_conn->post_send_buf_count);
		return ret;
	}
	return 0;
}

static int
isert_build_rdma_wr(struct isert_conn *isert_conn, struct isert_cmd *isert_cmd,
		    struct ib_sge *ib_sge, struct ib_send_wr *send_wr,
		    u32 data_left, u32 offset)
{
	struct iscsi_cmd *cmd = &isert_cmd->iscsi_cmd;
	struct scatterlist *sg_start, *tmp_sg;
	struct ib_device *ib_dev = isert_conn->conn_cm_id->device;
	u32 sg_off, page_off;
	int i = 0, sg_nents;

	sg_off = offset / PAGE_SIZE;
	sg_start = &cmd->se_cmd.t_data_sg[sg_off];
	sg_nents = min(cmd->se_cmd.t_data_nents - sg_off, isert_conn->max_sge);
	page_off = offset % PAGE_SIZE;

	send_wr->sg_list = ib_sge;
	send_wr->num_sge = sg_nents;
	send_wr->wr_id = (unsigned long)&isert_cmd->tx_desc;
	/*
	 * Perform mapping of TCM scatterlist memory ib_sge dma_addr.
	 */
	for_each_sg(sg_start, tmp_sg, sg_nents, i) {

		pr_debug("ISER RDMA from SGL dma_addr: 0x%16llx dma_len: %u,"
			"page_off: %u\n", (unsigned long long)tmp_sg->dma_address,
			tmp_sg->length, page_off);

		ib_sge->addr = ib_sg_dma_address(ib_dev, tmp_sg) + page_off;
		ib_sge->length = min_t(u32, data_left,
				ib_sg_dma_len(ib_dev, tmp_sg) - page_off);
		ib_sge->lkey = isert_conn->conn_mr->lkey;

		pr_debug("RDMA ib_sge: addr: 0x%16llx  length: %u\n",
				ib_sge->addr, ib_sge->length);
		page_off = 0;
		data_left -= ib_sge->length;
		ib_sge++;
		pr_debug("Incrementing ib_sge pointer to %p\n", ib_sge);
	}

	pr_debug("Set outgoing sg_list: %p num_sg: %u from TCM SGLs\n",
		send_wr->sg_list, send_wr->num_sge);

	return sg_nents;
}

static int
isert_put_datain(struct iscsi_cmd *cmd, struct iscsi_conn *conn)
{
	struct se_cmd *se_cmd = &cmd->se_cmd;
	struct isert_cmd *isert_cmd = container_of(cmd,
					struct isert_cmd, iscsi_cmd);
	struct isert_rdma_wr *wr = &isert_cmd->rdma_wr;
	struct isert_conn *isert_conn = (struct isert_conn *)conn->context;
	struct ib_send_wr *wr_failed, *send_wr;
	struct ib_device *ib_dev = isert_conn->conn_cm_id->device;
	struct ib_sge *ib_sge;
	struct scatterlist *sg;
	u32 offset = 0, data_len, data_left, rdma_write_max;
	int rc, ret = 0, count, sg_nents, i, ib_sge_cnt;

	pr_debug("RDMA_WRITE: data_length: %u\n", se_cmd->data_length);

	sg = &se_cmd->t_data_sg[0];
	sg_nents = se_cmd->t_data_nents;

	count = ib_dma_map_sg(ib_dev, sg, sg_nents, DMA_TO_DEVICE);
	if (unlikely(!count)) {
		pr_err("Unable to map put_datain SGs\n");
		return -EINVAL;
	}
	wr->sge = sg;
	wr->num_sge = sg_nents;
	pr_debug("Mapped IB count: %u sg: %p sg_nents: %u for"
		" RDMA_WRITE\n", count, sg, sg_nents);

	ib_sge = kzalloc(sizeof(struct ib_sge) * sg_nents, GFP_KERNEL);
	if (!ib_sge) {
		pr_warn("Unable to allocate datain ib_sge\n");
		ret = -ENOMEM;
		goto unmap_sg;
	}
	isert_cmd->ib_sge = ib_sge;

	pr_debug("Allocated ib_sge: %p from t_data_ents: %d for RDMA_WRITE\n",
			ib_sge, se_cmd->t_data_nents);

	wr->send_wr_num = DIV_ROUND_UP(sg_nents, isert_conn->max_sge);
	wr->send_wr = kzalloc(sizeof(struct ib_send_wr) * wr->send_wr_num,
				GFP_KERNEL);
	if (!wr->send_wr) {
		pr_err("Unable to allocate wr->send_wr\n");
		ret = -ENOMEM;
		goto unmap_sg;
	}
	pr_debug("Allocated wr->send_wr: %p wr->send_wr_num: %u\n",
			wr->send_wr, wr->send_wr_num);

	iscsit_increment_maxcmdsn(cmd, conn->sess);
	cmd->stat_sn = conn->stat_sn++;

	wr->isert_cmd = isert_cmd;
	rdma_write_max = isert_conn->max_sge * PAGE_SIZE;
	data_left = se_cmd->data_length;

	for (i = 0; i < wr->send_wr_num; i++) {
		send_wr = &isert_cmd->rdma_wr.send_wr[i];
		data_len = min(data_left, rdma_write_max);

		send_wr->opcode = IB_WR_RDMA_WRITE;
		send_wr->send_flags = 0;
		send_wr->wr.rdma.remote_addr = isert_cmd->read_va + offset;
		send_wr->wr.rdma.rkey = isert_cmd->read_stag;

		ib_sge_cnt = isert_build_rdma_wr(isert_conn, isert_cmd, ib_sge,
					send_wr, data_len, offset);
		ib_sge += ib_sge_cnt;

		if (i + 1 == wr->send_wr_num)
			send_wr->next = &isert_cmd->tx_desc.send_wr;
		else
			send_wr->next = &wr->send_wr[i + 1];

		offset += data_len;
		data_left -= data_len;
	}
	/*
	 * Build isert_conn->tx_desc for iSCSI response PDU and attach
	 */
	isert_create_send_desc(isert_conn, isert_cmd, &isert_cmd->tx_desc);
	iscsit_build_rsp_pdu(cmd, conn, false,
		(struct iscsi_scsi_rsp *)&isert_cmd->tx_desc.iscsi_header);
	isert_init_tx_hdrs(isert_conn, &isert_cmd->tx_desc);

	wr->iser_ib_op = ISER_IB_SEND;
	isert_cmd->tx_desc.send_wr.wr_id = (unsigned long)&isert_cmd->tx_desc;
	isert_cmd->tx_desc.send_wr.opcode = IB_WR_SEND;
	isert_cmd->tx_desc.send_wr.send_flags = IB_SEND_SIGNALED;
	isert_cmd->tx_desc.send_wr.sg_list = &isert_cmd->tx_desc.tx_sg[0];
	isert_cmd->tx_desc.send_wr.num_sge = isert_cmd->tx_desc.num_sge;

	atomic_inc(&isert_conn->post_send_buf_count);

	rc = ib_post_send(isert_conn->conn_qp, wr->send_wr, &wr_failed);
	if (rc) {
		pr_warn("ib_post_send() failed for IB_WR_RDMA_WRITE\n");
		atomic_dec(&isert_conn->post_send_buf_count);
	}
	pr_debug("Posted RDMA_WRITE + Response for iSER Data READ\n");
	return 1;

unmap_sg:
	ib_dma_unmap_sg(ib_dev, sg, sg_nents, DMA_TO_DEVICE);
	return ret;
}

static int
isert_get_dataout(struct iscsi_cmd *cmd, struct iscsi_conn *conn)
{
	struct se_cmd *se_cmd = &cmd->se_cmd;
	struct isert_cmd *isert_cmd = container_of(cmd,
					struct isert_cmd, iscsi_cmd);
	struct isert_rdma_wr *wr = &isert_cmd->rdma_wr;
	struct isert_conn *isert_conn = (struct isert_conn *)conn->context;
	struct ib_send_wr *wr_failed, *send_wr;
	struct ib_sge *ib_sge;
	struct ib_device *ib_dev = isert_conn->conn_cm_id->device;
	struct scatterlist *sg_start;
	u32 sg_off, sg_nents, page_off, va_offset = 0;
	u32 offset = 0, data_len, data_left, rdma_write_max;
	int rc, ret = 0, count, i, ib_sge_cnt;

	pr_debug("RDMA_READ: data_length: %u write_data_done: %u\n",
		se_cmd->data_length, cmd->write_data_done);

	sg_off = cmd->write_data_done / PAGE_SIZE;
	sg_start = &cmd->se_cmd.t_data_sg[sg_off];
	page_off = cmd->write_data_done % PAGE_SIZE;

	pr_debug("RDMA_READ: sg_off: %d, sg_start: %p page_off: %d\n",
			sg_off, sg_start, page_off);

	data_left = se_cmd->data_length - cmd->write_data_done;
	sg_nents = se_cmd->t_data_nents - sg_off;

	pr_debug("RDMA_READ: data_left: %d, sg_nents: %d\n",
			data_left, sg_nents);

	count = ib_dma_map_sg(ib_dev, sg_start, sg_nents, DMA_FROM_DEVICE);
	if (unlikely(!count)) {
		pr_err("Unable to map get_dataout SGs\n");
		return -EINVAL;
	}
	wr->sge = sg_start;
	wr->num_sge = sg_nents;
	pr_debug("Mapped IB count: %u sg_start: %p sg_nents: %u for"
		" RDMA_READ\n", count, sg_start, sg_nents);

	ib_sge = kzalloc(sizeof(struct ib_sge) * sg_nents, GFP_KERNEL);
	if (!ib_sge) {
		pr_warn("Unable to allocate dataout ib_sge\n");
		ret = -ENOMEM;
		goto unmap_sg;
	}
	isert_cmd->ib_sge = ib_sge;

	pr_debug("Using ib_sge: %p from sg_ents: %d for RDMA_READ\n",
			ib_sge, sg_nents);

	wr->send_wr_num = DIV_ROUND_UP(sg_nents, isert_conn->max_sge);
	wr->send_wr = kzalloc(sizeof(struct ib_send_wr) * wr->send_wr_num,
				GFP_KERNEL);
	if (!wr->send_wr) {
		pr_debug("Unable to allocate wr->send_wr\n");
		ret = -ENOMEM;
		goto unmap_sg;
	}
	pr_debug("Allocated wr->send_wr: %p wr->send_wr_num: %u\n",
			wr->send_wr, wr->send_wr_num);

	isert_cmd->tx_desc.isert_cmd = isert_cmd;

	wr->iser_ib_op = ISER_IB_RDMA_READ;
	wr->isert_cmd = isert_cmd;
	rdma_write_max = isert_conn->max_sge * PAGE_SIZE;
	offset = cmd->write_data_done;

	for (i = 0; i < wr->send_wr_num; i++) {
		send_wr = &isert_cmd->rdma_wr.send_wr[i];
		data_len = min(data_left, rdma_write_max);

		send_wr->opcode = IB_WR_RDMA_READ;
		send_wr->wr.rdma.remote_addr = isert_cmd->write_va + va_offset;
		send_wr->wr.rdma.rkey = isert_cmd->write_stag;

		ib_sge_cnt = isert_build_rdma_wr(isert_conn, isert_cmd, ib_sge,
					send_wr, data_len, offset);
		ib_sge += ib_sge_cnt;

		if (i + 1 == wr->send_wr_num)
			send_wr->send_flags = IB_SEND_SIGNALED;
		else
			send_wr->next = &wr->send_wr[i + 1];

		offset += data_len;
		va_offset += data_len;
		data_left -= data_len;
	}

	atomic_inc(&isert_conn->post_send_buf_count);

	rc = ib_post_send(isert_conn->conn_qp, wr->send_wr, &wr_failed);
	if (rc) {
		pr_warn("ib_post_send() failed for IB_WR_RDMA_READ\n");
		atomic_dec(&isert_conn->post_send_buf_count);
	}
	pr_debug("Posted RDMA_READ memory for ISER Data WRITE\n");
	return 0;

unmap_sg:
	ib_dma_unmap_sg(ib_dev, sg_start, sg_nents, DMA_FROM_DEVICE);
	return ret;
}

static int
isert_immediate_queue(struct iscsi_conn *conn, struct iscsi_cmd *cmd, int state)
{
	int ret;

	switch (state) {
	case ISTATE_SEND_R2T:
		ret = isert_get_dataout(cmd, conn);
		break;
	case ISTATE_SEND_NOPIN_WANT_RESPONSE:
		ret = isert_put_nopin(cmd, conn, false);
		break;
	case ISTATE_REMOVE:
		spin_lock_bh(&conn->cmd_lock);
		list_del(&cmd->i_conn_node);
		spin_unlock_bh(&conn->cmd_lock);

		iscsit_free_cmd(cmd);
		ret = 0;
		break;
	default:
		pr_err("Unknown immediate state: 0x%02x\n", state);
		ret = -EINVAL;
		break;
	}

	return ret;
}

static int
isert_response_queue(struct iscsi_conn *conn, struct iscsi_cmd *cmd, int state)
{
	int ret;

	switch (state) {
	case ISTATE_SEND_DATAIN:
		ret = isert_put_datain(cmd, conn);
		break;
	case ISTATE_SEND_STATUS:
		ret = isert_put_response(cmd, conn);
		break;
	case ISTATE_SEND_LOGOUTRSP:
		ret = isert_put_logout_rsp(cmd, conn);
		if (!ret) {
			pr_debug("Returning iSER Logout -EAGAIN\n");
			ret = -EAGAIN;
		}
		break;
	case ISTATE_SEND_NOPIN:
		ret = isert_put_nopin(cmd, conn, true);
		break;
	case ISTATE_SEND_TASKMGTRSP:
		ret = isert_put_tm_rsp(cmd, conn);
		break;
	default:
		pr_err("Unknown response state: 0x%02x\n", state);
		ret = -EINVAL;
		break;
	}

	return ret;
}

static int
isert_setup_np(struct iscsi_np *np,
	       struct __kernel_sockaddr_storage *ksockaddr)
{
	struct isert_np *isert_np;
	struct rdma_cm_id *isert_lid;
	struct sockaddr *sa;
	int ret;

	isert_np = kzalloc(sizeof(struct isert_np), GFP_KERNEL);
	if (!isert_np) {
		pr_err("Unable to allocate struct isert_np\n");
		return -ENOMEM;
	}
	init_waitqueue_head(&isert_np->np_accept_wq);
	mutex_init(&isert_np->np_accept_mutex);
	INIT_LIST_HEAD(&isert_np->np_accept_list);
	init_completion(&isert_np->np_login_comp);

	sa = (struct sockaddr *)ksockaddr;
	pr_debug("ksockaddr: %p, sa: %p\n", ksockaddr, sa);

	isert_lid = rdma_create_id(isert_cma_handler, np, RDMA_PS_TCP,
				IB_QPT_RC);
	if (IS_ERR(isert_lid)) {
		pr_err("rdma_create_id() for isert_listen_handler failed: %ld\n",
				PTR_ERR(isert_lid));
		return PTR_ERR(isert_lid);
	}

	ret = rdma_bind_addr(isert_lid, sa);
	if (ret) {
		pr_err("rdma_bind_addr() for isert_lid failed: %d\n", ret);
		return ret;
	}

	ret = rdma_listen(isert_lid, ISERT_RDMA_LISTEN_BACKLOG);
	if (ret) {
		pr_err("rdma_listen() for isert_lid failed: %d\n", ret);
		return ret;
	}

	isert_np->np_cm_id = isert_lid;
	np->np_context = isert_np;
	pr_debug("Setup isert_lid->context: %p\n", isert_lid->context);

	return 0;

}

static int
isert_check_accept_queue(struct isert_np *isert_np)
{
	int empty;

	mutex_lock(&isert_np->np_accept_mutex);
	empty = list_empty(&isert_np->np_accept_list);
	mutex_unlock(&isert_np->np_accept_mutex);

	return empty;
}

static int
isert_rdma_post_recvl(struct isert_conn *isert_conn)
{
	struct ib_recv_wr rx_wr, *rx_wr_fail;
	struct ib_sge sge;
	int ret;

	memset(&sge, 0, sizeof(struct ib_sge));
	sge.addr = isert_conn->login_req_dma;
	sge.length = ISER_RX_LOGIN_SIZE;
	sge.lkey = isert_conn->conn_mr->lkey;

	pr_debug("Setup sge: addr: %llx length: %d 0x%08x\n",
			sge.addr, sge.length, sge.lkey);

	memset(&rx_wr, 0, sizeof(struct ib_recv_wr));
	rx_wr.wr_id = (unsigned long)isert_conn->login_req_buf;
	rx_wr.sg_list = &sge;
	rx_wr.num_sge = 1;

	isert_conn->post_recv_buf_count++;
	ret = ib_post_recv(isert_conn->conn_qp, &rx_wr, &rx_wr_fail);
	if (ret) {
		pr_err("ib_post_recv() failed: %d\n", ret);
		isert_conn->post_recv_buf_count--;
	}

	pr_debug("ib_post_recv(): returned success >>>>>>>>>>>>>>>>>>>>>>>>\n");

	return ret;
}

static int
isert_rdma_accept(struct isert_conn *isert_conn)
{
	struct rdma_cm_id *cm_id = isert_conn->conn_cm_id;
	struct rdma_conn_param cp;
	int ret;

	memset(&cp, 0, sizeof(struct rdma_conn_param));
	cp.responder_resources = isert_conn->responder_resources;
	cp.initiator_depth = isert_conn->initiator_depth;
	cp.retry_count = 7;
	cp.rnr_retry_count = 7;

	pr_debug("Before rdma_accept >>>>>>>>>>>>>>>>>>>>.\n");

	ret = rdma_accept(cm_id, &cp);
	if (ret) {
		pr_err("rdma_accept() failed with: %d\n", ret);
		return ret;
	}

	pr_debug("After rdma_accept >>>>>>>>>>>>>>>>>>>>>.\n");

	return 0;
}

static int
isert_get_login_rx(struct iscsi_conn *conn, struct iscsi_login *login)
{
	struct isert_conn *isert_conn = (struct isert_conn *)conn->context;
	int ret;

	pr_debug("isert_get_login_rx() before conn_login_comp conn: %p login: %p"
			" login->req: %p >>>>>>>>>>>>> \n", conn, login, login->req);
	pr_debug("isert_get_login_rx() isert_conn: %p &isert_conn->conn_login_comp: %p\n",
				isert_conn, &isert_conn->conn_login_comp);

	ret = wait_for_completion_interruptible(&isert_conn->conn_login_comp);
	if (ret)
		return ret;

	pr_debug("isert_get_login_rx() processing login->req: %p\n", login->req);
	return 0;
}

static void
isert_set_conn_info(struct iscsi_np *np, struct iscsi_conn *conn,
		    struct isert_conn *isert_conn)
{
	struct rdma_cm_id *cm_id = isert_conn->conn_cm_id;
	struct rdma_route *cm_route = &cm_id->route;
	struct sockaddr_in *sock_in;
	struct sockaddr_in6 *sock_in6;

	conn->login_family = np->np_sockaddr.ss_family;

	if (np->np_sockaddr.ss_family == AF_INET6) {
		sock_in6 = (struct sockaddr_in6 *)&cm_route->addr.dst_addr;
		snprintf(conn->login_ip, sizeof(conn->login_ip), "%pI6c",
				&sock_in6->sin6_addr.in6_u);
		conn->login_port = ntohs(sock_in6->sin6_port);

		sock_in6 = (struct sockaddr_in6 *)&cm_route->addr.src_addr;
		snprintf(conn->local_ip, sizeof(conn->local_ip), "%pI6c",
				&sock_in6->sin6_addr.in6_u);
		conn->local_port = ntohs(sock_in6->sin6_port);
	} else {
		sock_in = (struct sockaddr_in *)&cm_route->addr.dst_addr;
		sprintf(conn->login_ip, "%pI4",
				&sock_in->sin_addr.s_addr);
		conn->login_port = ntohs(sock_in->sin_port);

		sock_in = (struct sockaddr_in *)&cm_route->addr.src_addr;
		sprintf(conn->local_ip, "%pI4",
				&sock_in->sin_addr.s_addr);
		conn->local_port = ntohs(sock_in->sin_port);
	}
}

static int
isert_accept_np(struct iscsi_np *np, struct iscsi_conn *conn)
{
	struct isert_np *isert_np = (struct isert_np *)np->np_context;
	struct isert_conn *isert_conn;
	int max_accept = 0, ret;

accept_wait:
	ret = wait_event_interruptible(isert_np->np_accept_wq,
			!isert_check_accept_queue(isert_np) ||
			np->np_thread_state == ISCSI_NP_THREAD_RESET);
	if (max_accept > 5)
		return -ENODEV;

	spin_lock_bh(&np->np_thread_lock);
	if (np->np_thread_state == ISCSI_NP_THREAD_RESET) {
		spin_unlock_bh(&np->np_thread_lock);
		pr_err("ISCSI_NP_THREAD_RESET for isert_accept_np\n");
		return -ENODEV;
	}
	spin_unlock_bh(&np->np_thread_lock);

	mutex_lock(&isert_np->np_accept_mutex);
	if (list_empty(&isert_np->np_accept_list)) {
		mutex_unlock(&isert_np->np_accept_mutex);
		max_accept++;
		goto accept_wait;
	}
	isert_conn = list_first_entry(&isert_np->np_accept_list,
			struct isert_conn, conn_accept_node);
	list_del_init(&isert_conn->conn_accept_node);
	mutex_unlock(&isert_np->np_accept_mutex);

	conn->context = isert_conn;
	isert_conn->conn = conn;
	max_accept = 0;

	ret = isert_rdma_post_recvl(isert_conn);
	if (ret)
		return ret;

	ret = isert_rdma_accept(isert_conn);
	if (ret)
		return ret;

	isert_set_conn_info(np, conn, isert_conn);

	pr_debug("Processing isert_accept_np: isert_conn: %p\n", isert_conn);
	return 0;
}

static void
isert_free_np(struct iscsi_np *np)
{
	struct isert_np *isert_np = (struct isert_np *)np->np_context;

	rdma_destroy_id(isert_np->np_cm_id);

	np->np_context = NULL;
	kfree(isert_np);
}

static void isert_free_conn(struct iscsi_conn *conn)
{
	struct isert_conn *isert_conn = conn->context;

	pr_debug("isert_free_conn: Before isert_put_conn\n");

	if (isert_conn->conn_cm_id)
		rdma_disconnect(isert_conn->conn_cm_id);

	pr_debug("isert_free_conn: Before wait_event :%d\n", isert_conn->state);
	wait_event(isert_conn->conn_wait, isert_conn->state == ISER_CONN_DOWN);
	pr_debug("isert_free_conn: After wait_event >>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");

	isert_put_conn(isert_conn);
}

static void
isert_unmap_cmd(struct iscsi_cmd *cmd, struct iscsi_conn *conn)
{
	struct isert_cmd *isert_cmd = container_of(cmd,
				struct isert_cmd, iscsi_cmd);
	struct isert_rdma_wr *wr = &isert_cmd->rdma_wr;
	struct isert_conn *isert_conn = conn->context;
	struct ib_device *ib_dev = isert_conn->conn_cm_id->device;

	pr_debug("isert_unmap_cmd >>>>>>>>>>>>>>>>>>>>>>>\n");

	if (wr->sge) {
		ib_dma_unmap_sg(ib_dev, wr->sge, wr->num_sge, DMA_TO_DEVICE);
		wr->sge = NULL;
	}

	if (wr->send_wr) {
		kfree(wr->send_wr);
		wr->send_wr = NULL;
	}

	if (isert_cmd->ib_sge) {
		kfree(isert_cmd->ib_sge);
		isert_cmd->ib_sge = NULL;
	}
}

static void
isert_free_cmd(struct iscsi_cmd *cmd)
{
	struct isert_cmd *isert_cmd = container_of(cmd,
				struct isert_cmd, iscsi_cmd);

	isert_put_cmd(isert_cmd);
}

static struct iscsit_transport iser_target_transport = {
	.name			= "IB/iSER",
	.transport_type		= ISCSI_INFINIBAND,
	.owner			= THIS_MODULE,
	.iscsit_setup_np	= isert_setup_np,
	.iscsit_accept_np	= isert_accept_np,
	.iscsit_free_np		= isert_free_np,
	.iscsit_free_conn	= isert_free_conn,
	.iscsit_alloc_cmd	= isert_alloc_cmd,
	.iscsit_unmap_cmd	= isert_unmap_cmd,
	.iscsit_free_cmd	= isert_free_cmd,
	.iscsit_get_login_rx	= isert_get_login_rx,
	.iscsit_put_login_tx	= isert_put_login_tx,
	.iscsit_immediate_queue	= isert_immediate_queue,
	.iscsit_response_queue	= isert_response_queue,
};

static int __init isert_init(void)
{
	int ret;

	isert_rx_wq = alloc_workqueue("isert_rx_wq", WQ_MEM_RECLAIM, 1);
	if (!isert_rx_wq) {
		pr_err("Unable to allocate isert_rx_wq\n");
		return -ENOMEM;
	}

	isert_comp_wq = alloc_workqueue("isert_comp_wq", 0, 0);
	if (!isert_comp_wq) {
		pr_err("Unable to allocate isert_comp_wq\n");
		ret = -ENOMEM;
		goto destroy_rx_wq;
	}

	iscsit_create_transport(&iser_target_transport);
	pr_debug("iSER_TARGET[0] - Loaded iser_target_transport\n");

	printk("ISER_HEADERS_LEN: %lu\n", ISER_HEADERS_LEN);
	printk("ISER_RECV_DATA_SEG_LEN: %d\n", ISER_RECV_DATA_SEG_LEN);
	printk("ISER_RX_PAYLOAD_SIZE: %lu\n", ISER_RX_PAYLOAD_SIZE);
	printk("ISER_RX_PAD_SIZE: %lu\n", ISER_RX_PAD_SIZE);

	return 0;

destroy_rx_wq:
	destroy_workqueue(isert_rx_wq);
	return ret;
}

static void __exit isert_exit(void)
{
	destroy_workqueue(isert_comp_wq);
	destroy_workqueue(isert_rx_wq);
	iscsit_destroy_transport(&iser_target_transport);
	pr_debug("iSER_TARGET[0] - Released iser_target_transport\n");
}

MODULE_DESCRIPTION("iSER-Target for mainline target infrastructure");
MODULE_VERSION("0.1");
MODULE_AUTHOR("nab@Linux-iSCSI.org");
MODULE_LICENSE("GPL");

module_init(isert_init);
module_exit(isert_exit);
