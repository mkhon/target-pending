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

#include <linux/delay.h>
#include <rdma/ib_verbs.h>

#include "fcoib.h"
#include "mfc.h"
#include "fip_ctlr_api.h"

/* string "Mellanox" */
#define FIP_VENDOR_MELLANOX {0x4d, 0x65, 0x6c, 0x6c, \
			     0x61, 0x6e, 0x6f, 0x78}

#define FIP_TEST_PKT_LENGTH(length, type)				\
	if ((length) != sizeof(type) + IB_GRH_BYTES) {			\
		fip_dev_dbg(priv, LOG_PRIO_LOW, "Dump packet: at=%d"	\
			" unexpected size. length=%d expected=%d\n",	\
			__LINE__, (int)length,				\
			(int)(sizeof(type) + IB_GRH_BYTES));		\
		return -EINVAL;						\
	}

struct fip_fcoib_ver {
	u8 version;
	u8 reserved[3];
};

struct fip_fip_type {
	u8 type;
	u8 length;
	u8 reserved[2];
};

struct fip_fip_header {
	u16 opcode;
	u8 reserved;
	u8 subcode;
	u16 list_length;
	u16 flags;
	struct fip_fip_type type;
	u8 vendor_id[8];
};

struct fcoib_solicit {
	struct fip_fcoib_ver version;
	struct fip_fip_header fip;

	u8 infiniband_address_type_f;
	u8 infiniband_address_length_f;
	u16 _reserved_1;
	u8 t10_vendor_id[8];
	u32 qpn;
	u16 sl_gwPortId;
	u16 lid;
	u8 gw_guid[8];

	u8 fip_name_id_type_f;
	u8 fip_name_id_length_f;
	u16 _reserved_2;
	u8 node_name[8];

	u8 max_receive_size_type_f;
	u8 max_receive_size_length_f;
	u16 max_fcoe_size;
};

struct fcoib_advertise {
	struct fip_fcoib_ver version;
	struct fip_fip_header fip;

	u8 fip_priority_type_f;
	u8 fip_priority_length_f;
	u8 _reserved_1;
	u8 priority;

	u8 infiniband_address_type_f;
	u8 infiniband_address_length_f;
	u16 _reserved_2;
	u8 t10_vendor_id[8];
	u32 qpn;
	u16 sl_gwportid;
	u16 lid;
	u8 gw_guid[8];

	u8 fip_name_identifier_type_f;
	u8 fip_name_identifier_length_f;
	u16 _reserved_3;
	u8 switch_name[8];

	u8 fip_fabric_name_type_f;
	u8 fip_fabric_name_length_f;
	u16 _reserved_4;
	u32 fc_map;
	u8 fabric_name[8];

	u8 fka_adv_period_type_f;
	u8 fka_adv_period_length_f;
	u16 _reserved_5;
	u32 fka_adv_period;

	u8 partition_type_f;
	u8 partition_length_f;
	u16 reserved_6;
	u8 t10_vendor_id_2[8];
	u16 reserved_7;
	u16 pkey;
};

#define FLOGI_FDISC_REQUEST_SIZE (35 * 4)
#define FLOGI_FDISC_ACCPT_SIZE (35 * 4)
#define FLOGI_FDISC_RJCT_SIZE (8 * 4)

struct fcoib_flogi_fdisc_request {
	struct fip_fcoib_ver version;
	struct fip_fip_header fip;

	u8 els_type_f;
	u8 els_length_f;
	u16 _reserved_;
	u8 els[FLOGI_FDISC_REQUEST_SIZE];

	u8 infiniband_address_type_f;
	u8 infiniband_address_length_f;
	u16 reserved;
	u8 t10_vendor_id[8];
	u32 qpn;
	u16 sl_gwportid;
	u16 lid;
	u8 port_guid[8];
};

struct fcoib_flogi_fdisc_acc {
	struct fip_fcoib_ver version;
	struct fip_fip_header fip;

	u8 els_type_f;
	u8 els_length_f;
	u16 _reserved_;
	u8 els[FLOGI_FDISC_ACCPT_SIZE];

	u8 infiniband_address_type_f;
	u8 infiniband_address_length_f;
	u16 reserved;
	u8 t10_vendor_id[8];
	u32 qpn;
	u16 sl_gwPortId;
	u16 lid;
	u8 port_guid[8];
};

struct fcoib_flogi_fdisc_rjt {
	struct fip_fcoib_ver version;
	struct fip_fip_header fip;

	u8 els_type_f;
	u8 els_length_f;
	u16 _reserved_;
	u8 els[FLOGI_FDISC_RJCT_SIZE];
};

#define LOGO_REQUEST_SIZE (10 * 4)
#define LOGO_ACCPT_SIZE (9 * 4)
#define LOGO_RJCT_SIZE (8 * 4)

struct fcoib_logo_request {
	struct fip_fcoib_ver version;
	struct fip_fip_header fip;

	u8 els_type_f;
	u8 els_length_f;
	u16 _reserved_;
	u8 els[LOGO_REQUEST_SIZE];

	u8 infiniband_address_type_f;
	u8 infiniband_address_length_f;
	u16 reserved;
	u8 t10_vendor_id[8];
	u32 qpn;
	u16 sl_gwportid;
	u16 lid;
	u8 port_guid[8];
};

struct fcoib_ioa_alive {
	struct fip_fcoib_ver version;
	struct fip_fip_header fip;

	uint8_t infiniband_address_type_f;
	uint8_t infiniband_address_length_f;
	u16 reserved;
	u8 t10_vendor_id[8];
	u32 qpn;
	u16 sl_gwportid;
	u16 lid;
	u8 port_guid[8];
};

struct fcoib_vhba_alive {
	struct fip_fcoib_ver version;
	struct fip_fip_header fip;

	u8 infiniband_address_type_f;
	u8 infiniband_address_length_f;
	u16 reserved;
	u8 t10_vendor_id[8];
	u32 qpn;
	u16 sl_gwportid;
	u16 lid;
	u8 port_guid[8];

	u8 infiniband_vx_port_id_type_f;
	u8 infiniband_vx_port_id_length_f;
	u16 reserved_2;
	u8 t10_vendor_id_2[8];
	u32 vn_port_qpn;
	u8 vn_port_guid[8];
	u32 vn_port_addres_id;
	u8 vn_port_name[8];
};

struct fcoib_clear_virtual_link_ioa {
	struct fip_fcoib_ver version;
	struct fip_fip_header fip;

	u8 infiniband_address_type_f;
	u8 infiniband_address_length_f;
	u16 reserved;
	u8 t10_vendor_id[8];
	u32 qpn;
	u16 sl_gwPortId;
	u16 lid;
	u8 gw_guid[8];

	u8 fip_name_identifier_type_f;
	u8 fip_name_identifier_length_f;
	u16 reserved_3;
	u8 switch_name[8];
};

struct fcoib_clear_virtual_link_vhba {
	struct fip_fcoib_ver version;
	struct fip_fip_header fip;

	u8 infiniband_address_type_f;
	u8 infiniband_address_length_f;
	u16 reserved;
	u8 t10_vendor_id[8];
	u32 qpn;
	u16 sl_gwPortId;
	u16 lid;
	u8 gw_guid[8];

	u8 fip_name_identifier_type_f;
	u8 fip_name_identifier_length_f;
	u16 reserved_3;
	u8 switch_name[8];

	/* TODO: array of items */
	u8 infiniband_vx_port_id_type_f;
	u8 infiniband_vx_port_id_length_f;
	u16 reserved_2;
	u8 t10_vendor_id_2[8];
	u32 vn_port_qpn;
	u8 vn_port_guid[8];
	u32 vn_port_addres_id;
	u8 vn_port_name[8];
};

enum fip_packet_fields {
	FCOIB_FIP_OPCODE = 0xFFF8,
	EOIB_FIP_OPCODE = 0xFFF9,
	FIP_FIP_HDR_LENGTH = 3,
	FIP_FIP_HDR_TYPE = 13,

	FIP_HOST_SOL_SUB_OPCODE = 0x1,
	FIP_GW_ADV_SUB_OPCODE = 0x2,
	FIP_HOST_LOGIN_SUB_OPCODE = 0x3,
	FIP_GW_LOGIN_SUB_OPCODE = 0x4,
	FIP_HOST_LOGOUT_SUB_OPCODE = 0x5,
	FIP_GW_UPDATE_SUB_OPCODE = 0x6,
	FIP_GW_TABLE_SUB_OPCODE = 0x7,
	FIP_HOST_ALIVE_SUB_OPCODE = 0x8,

	FCOIB_HOST_SOL_SUB_OPCODE = 0x1,
	FCOIB_GW_ADV_SUB_OPCODE = 0x2,
	FCOIB_LS_REQUEST_SUB_OPCODE = 0x3,
	FCOIB_LS_REPLY_SUB_OPCODE = 0x4,
	FCOIB_HOST_ALIVE_SUB_OPCODE = 0x8,
	FCOIB_CLVL_SUB_OPCODE = 0x9,

	FIP_FIP_FCF_FLAG = 0x1,
	FIP_FIP_SOLICITED_FLAG = 0x2,
	FIP_FIP_ADVRTS_FLAG = 0x4,
	FIP_FIP_FP_FLAG = 0x80,
	FIP_FIP_SP_FLAG = 0x40,

	FIP_BASIC_LENGTH = 7,
	FIP_BASIC_TYPE = 240,

	FIP_ADVERTISE_LENGTH_1 = 4,
	FIP_ADVERTISE_TYPE_1 = 241,
	FIP_ADVERTISE_HOST_VLANS = 0x80,

	FIP_LOGIN_LENGTH_1 = 13,
	FIP_LOGIN_TYPE_1 = 242,
	FIP_LOGIN_LENGTH_2 = 4,
	FIP_LOGIN_TYPE_2 = 246,

	FIP_LOGIN_V_FLAG = 0x8000,
	FIP_LOGIN_M_FLAG = 0x4000,
	FIP_LOGIN_VP_FLAG = 0x2000,
	FIP_LOGIN_DMAC_MGID_MASK = 0x3F,
	FIP_LOGIN_RSS_MGID_MASK = 0x0F,
	FIP_LOGIN_RSS_SHIFT = 4,

	FIP_LOGOUT_LENGTH_1 = 13,
	FIP_LOGOUT_TYPE_1 = 245,

	FIP_HOST_UPDATE_LENGTH = 13,
	FIP_HOST_UPDATE_TYPE = 245,
	FIP_HOST_VP_FLAG = 0x01,
	FIP_HOST_U_FLAG = 0x80,
	FIP_HOST_R_FLAG = 0x40,

	FIP_CONTEXT_UP_LENGTH = 9,
	FIP_CONTEXT_UP_TYPE = 243,
	FIP_CONTEXT_V_FLAG = 0x80,
	FIP_CONTEXT_RSS_FLAG = 0x40,
	FIP_CONTEXT_TYPE_MASK = 0x0F,

	FIP_CONTEXT_TBL_TYPE = 244,
	FIP_CONTEXT_TBL_SEQ_MASK = 0xC0,
	FIP_CONTEXT_TBL_SEQ_FIRST = 0x40,
	FIP_CONTEXT_TBL_SEQ_LAST = 0x80,

	FKA_ADV_PERIOD = 8,
	FKA_VHBA_PERIOD = 60,

	FIP_PRIORITY_TYPE = 1,
	FIP_PRIORITY_LENGTH = 1,
	FIP_MAC_TYPE = 2,
	FIP_MAC_LENGTH = 2,
	FIP_FC_MAP_TYPE = 3,
	FIP_FC_MAP_LENGTH = 2,
	FIP_NAME_IDENTIFIER_TYPE = 4,
	FIP_NAME_IDENTIFIER_LENGTH = 3,
	FIP_FABRIC_NAME_TYPE = 5,
	FIP_FABRIC_NAME_LENGTH = 4,
	MAX_RECEIVE_SIZE_TYPE = 6,
	MAX_RECEIVE_SIZE_LENGTH = 1,
	FLOGI_TYPE = 7,
	FLOGI_REQUEST_LENGTH = 36,
	FLOGI_ACCEPT_LENGTH = 36,
	FLOGI_REJECT_LENGTH = 9,

	FDISC_TYPE = 8,
	FDISC_REQUEST_LENGTH = 36,
	FDISC_ACCEPT_LENGTH = 36,
	FDISC_REJECT_LENGTH = 9,
	LOGO_TYPE = 9,
	LOGO_REQUEST_LENGTH = 11,
	LOGO_ACCEPT_LENGTH = 10,
	LOGO_REJECT_LENGTH = 9,
	VX_PORT_ID_TYPE = 11,
	VX_PORT_ID_LENGTH = 5,
	FKA_ADV_PERIOD_TYPE = 12,
	FKA_ADV_PERIOD_LENGTH = 2,
	INFINIBAND_ADDRESS_TYPE = 240,
	INFINIBAND_ADDRESS_LENGTH = 7,
	EOIB_GW_INFORMATION_TYPE = 241,
	EOIB_GW_INFORMATION_LENGTH = 4,
	VNIC_LOGIN_OR_ACK_INFORMATION_TYPE = 242,
	VNIC_LOGIN_OR_ACK_INFORMATION_LENGTH = 13,
	VHUB_UPDATE_TYPE = 243,
	VHUB_UPDATE_LENGTH = 9,
	VHUB_TABLE_TYPE = 244,
	VNIC_IDENTITY_TYPE = 245,
	VNIC_IDENTITY_LENGTH = 13,
	PARTITION_TYPE = 246,
	PARTITION_LENGTH = 4,
	INFINIBAND_VX_PORT_ID_TYPE = 247,
	INFINIBAND_VX_PORT_ID_LENGTH = 10,
	BXM_TUNNELED_PACKET_TYPE = 250,
	BXM_COMMAND_TYPE = 251,
	FIP_VENDOR_ID_TYPE = 13,
	FIP_VENDOR_ID_LENGTH = 3,
};

const char FIP_DISCOVER_MGID[16] = {
	0xFF, 0x12, 0xFC, 0x1B,
	0x00, 0x06, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00
};

const char FIP_SOLICIT_MGID[16] = {
	0xFF, 0x12, 0xFC, 0x1B,
	0x00, 0x07, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00
};

static void fip_gw_fsm(struct work_struct *work);
static void fip_purge_gws(struct work_struct *work);

static inline int _map_generic_pkt(struct fip_dev_priv *priv,
				   struct ring_entry *tx_ring_entry,
				   char *mem, int pkt_size)
{
	/* alloc packet to be sent */
	tx_ring_entry->mem = mem;

	/* map packet to bus */
	tx_ring_entry->length = pkt_size;
	tx_ring_entry->bus_addr = ib_dma_map_single(priv->ca,
						    tx_ring_entry->mem,
						    pkt_size, DMA_TO_DEVICE);

	if (unlikely(ib_dma_mapping_error(priv->ca, tx_ring_entry->bus_addr))) {
		fip_dev_warn(priv, "send_generic_pkt failed to map to pci\n");
		return -ENODEV;
	}

	return 0;
}

static inline int send_generic_mcast_pkt(struct fip_dev_priv *priv,
					 struct ring *tx_ring,
					 char *mem, int pkt_size,
					 struct ib_qp *qp,
					 int pkey_index,
					 struct mcast_entry *mcast)
{
	int index, ret;

	/*
	 * we are only allowed to update the head at task level so no need to
	 * perform any locks here
	 */
	index = tx_ring->head;
	fip_dev_dbg(priv, LOG_PRIO_VERY_LOW, "send mcast packet\n");

	/* it is possible for the AH to be missing in transient
	 * states (after events) */
	if (!mcast || !test_bit(MCAST_FLAG_AH_SET, &mcast->flags))
		return -EBUSY;

	/* ring full try again */
	if (index == tx_ring->tail) {
		fip_dev_warn(priv, "send_generic_pkt ring full\n");
		return -EAGAIN;
	}

	ret = _map_generic_pkt(priv, &tx_ring->ring[index], mem, pkt_size);
	if (ret)
		return ret;

	ret = fip_mcast_send(priv, qp, tx_ring->head,
			     tx_ring->ring[index].bus_addr,
			     pkt_size, pkey_index, mcast);

	if (ret) {
		fip_dev_warn(priv,
			 "send_generic_mcast_pkt: fip_mcast_send ret=%d\n",
			 ret);
		ret = -EINVAL;
		goto error_unmap_dma;
	}

	tx_ring->head = (index + 1) & (tx_ring->size - 1);

	return 0;

error_unmap_dma:
	ib_dma_unmap_single(priv->ca,
			    tx_ring->ring[index].bus_addr,
			    pkt_size, DMA_TO_DEVICE);
	return -ENODEV;
}

static inline int send_generic_ucast_pkt(struct fip_dev_priv *priv,
					 struct ring *tx_ring,
					 char *mem, int pkt_size,
					 struct ib_qp *qp,
					 int pkey_index,
					 u32 dst_qpn, u16 dst_lid, u32 qkey)
{
	int index, ret;

	/*
	 * we are only allowed to update the head at task level so no need to
	 * perform any locks here
	 */
	index = tx_ring->head;

	fip_dev_dbg(priv, LOG_PRIO_VERY_LOW, "send ucast packet\n");

	/* ring full try again */
	if (index == tx_ring->tail) {
		fip_dev_warn(priv, "send_generic_pkt ring full\n");
		return -EAGAIN;
	}

	ret = _map_generic_pkt(priv, &tx_ring->ring[index], mem, pkt_size);
	if (ret)
		return ret;

	ret = fip_ucast_send(priv, qp,
			     tx_ring->head, tx_ring->ring[index].bus_addr,
			     pkt_size, priv->pkey_index,
			     dst_qpn, dst_lid, qkey);

	if (ret) {
		fip_dev_warn(priv,
			 "send_generic_ucast_pkt: fip_ucast_send ret=%d\n",
			 ret);
		ret = -EINVAL;
		goto error_unmap_dma;
	}

	tx_ring->head = (index + 1) & (tx_ring->size - 1);

	return 0;

error_unmap_dma:
	ib_dma_unmap_single(priv->ca,
			    tx_ring->ring[index].bus_addr,
			    pkt_size, DMA_TO_DEVICE);
	return -ENODEV;
}

const struct fcoib_solicit base_fcoib_solicit_pkt = {
	.fip.subcode = FCOIB_HOST_SOL_SUB_OPCODE,
	.fip.type.type = FIP_FIP_HDR_TYPE,
	.fip.type.length = FIP_FIP_HDR_LENGTH,
	.fip.vendor_id = FIP_VENDOR_MELLANOX,

	.infiniband_address_type_f = INFINIBAND_ADDRESS_TYPE,
	.infiniband_address_length_f = INFINIBAND_ADDRESS_LENGTH,
	.t10_vendor_id = "mellanox",

	.fip_name_id_type_f = FIP_NAME_IDENTIFIER_TYPE,
	.fip_name_id_length_f = FIP_NAME_IDENTIFIER_LENGTH,

	.max_receive_size_type_f = MAX_RECEIVE_SIZE_TYPE,
	.max_receive_size_length_f = MAX_RECEIVE_SIZE_LENGTH,
};

struct fcoib_flogi_fdisc_request base_flogi_request_pkt = {
	.fip.subcode = FCOIB_LS_REQUEST_SUB_OPCODE,
	.fip.type.type = FIP_FIP_HDR_TYPE,
	.fip.type.length = FIP_FIP_HDR_LENGTH,
	.fip.vendor_id = FIP_VENDOR_MELLANOX,

	.els_type_f = FLOGI_TYPE,
	.els_length_f = FLOGI_REQUEST_LENGTH,
	.infiniband_address_type_f = INFINIBAND_ADDRESS_TYPE,
	.infiniband_address_length_f = INFINIBAND_ADDRESS_LENGTH,
	.t10_vendor_id = "mellanox",
};

struct fcoib_logo_request base_logo_request_pkt = {
	.fip.subcode = FCOIB_LS_REQUEST_SUB_OPCODE,
	.fip.type.type = FIP_FIP_HDR_TYPE,
	.fip.type.length = FIP_FIP_HDR_LENGTH,
	.fip.vendor_id = FIP_VENDOR_MELLANOX,

	.els_type_f = LOGO_TYPE,
	.els_length_f = LOGO_REQUEST_LENGTH,
	.infiniband_address_type_f = INFINIBAND_ADDRESS_TYPE,
	.infiniband_address_length_f = INFINIBAND_ADDRESS_LENGTH,
	.t10_vendor_id = "mellanox",
};

struct fcoib_ioa_alive base_ioa_alive_pkt = {
	.fip.subcode = FCOIB_HOST_ALIVE_SUB_OPCODE,
	.fip.type.type = FIP_FIP_HDR_TYPE,
	.fip.type.length = FIP_FIP_HDR_LENGTH,
	.fip.vendor_id = FIP_VENDOR_MELLANOX,

	.infiniband_address_type_f = INFINIBAND_ADDRESS_TYPE,
	.infiniband_address_length_f = INFINIBAND_ADDRESS_LENGTH,
	.t10_vendor_id = "mellanox",
};

struct fcoib_vhba_alive base_vhba_alive_pkt = {
	.fip.subcode = FCOIB_HOST_ALIVE_SUB_OPCODE,
	.fip.type.type = FIP_FIP_HDR_TYPE,
	.fip.type.length = FIP_FIP_HDR_LENGTH,
	.fip.vendor_id = FIP_VENDOR_MELLANOX,

	.infiniband_address_type_f = INFINIBAND_ADDRESS_TYPE,
	.infiniband_address_length_f = INFINIBAND_ADDRESS_LENGTH,
	.t10_vendor_id = "mellanox",

	.infiniband_vx_port_id_type_f = INFINIBAND_VX_PORT_ID_TYPE,
	.infiniband_vx_port_id_length_f = INFINIBAND_VX_PORT_ID_LENGTH,
	.t10_vendor_id_2 = "mellanox",
};

int fcoib_advertise_parse(struct fip_dev_priv *priv,
			  char *buffer, int length, struct fip_gw_data *data)
{
	int desc_length;
	struct fcoib_advertise *pkt;

	FIP_TEST_PKT_LENGTH(length, struct fcoib_advertise);

	pkt = (struct fcoib_advertise *)(buffer + IB_GRH_BYTES);
	desc_length = be16_to_cpu(pkt->fip.list_length);

	data->info.flags = (be16_to_cpu(pkt->fip.flags) & FIP_FIP_ADVRTS_FLAG) ?
	    FIP_GW_AVAILABLE : 0;

	data->info.flags |=
	    (be16_to_cpu(pkt->fip.flags) & FIP_FIP_SOLICITED_FLAG) ?
	    0 : FIP_RCV_MULTICAST;

	if (be16_to_cpu(pkt->fip.opcode) == FCOIB_FIP_OPCODE) {
		if (pkt->fip_priority_type_f != FIP_PRIORITY_TYPE ||
		    pkt->fip_priority_length_f != FIP_PRIORITY_LENGTH ||
		    pkt->infiniband_address_type_f != INFINIBAND_ADDRESS_TYPE ||
		    pkt->infiniband_address_length_f !=
		    INFINIBAND_ADDRESS_LENGTH ||
		    pkt->fip_name_identifier_type_f !=
		    FIP_NAME_IDENTIFIER_TYPE ||
		    pkt->fip_name_identifier_length_f !=
		    FIP_NAME_IDENTIFIER_LENGTH ||
		    pkt->fip_fabric_name_type_f != FIP_FABRIC_NAME_TYPE ||
		    pkt->fip_fabric_name_length_f != FIP_FABRIC_NAME_LENGTH ||
		    pkt->fka_adv_period_type_f != FKA_ADV_PERIOD_TYPE ||
		    pkt->fka_adv_period_length_f != FKA_ADV_PERIOD_LENGTH ||
		    pkt->partition_type_f != PARTITION_TYPE ||
		    pkt->partition_length_f != PARTITION_LENGTH) {
			fip_dev_dbg(priv, LOG_PRIO_LOW,
				"fcoib_advertise_parse dump packet\n");
			return -EINVAL;
		}

		data->info.flags |= FIP_IS_FIP;

		data->info.priority = pkt->priority;
		data->info.gw_qpn = be32_to_cpu(pkt->qpn);
		data->info.gw_data_qpn = 0;
		data->info.gw_port_id = be16_to_cpu(pkt->sl_gwportid) & 0xfff;
		data->info.sl = be16_to_cpu(pkt->sl_gwportid) >> 12;
		data->info.gw_lid = be16_to_cpu(pkt->lid);
		memcpy(data->info.gw_guid, pkt->gw_guid,
		       sizeof(data->info.gw_guid));
		memcpy(data->info.switch_name, pkt->switch_name,
		       sizeof(data->info.switch_name));

		memcpy(data->info.fabric_name, pkt->fabric_name,
		       sizeof(data->info.fabric_name));
		data->info.keep_alive_frq = be32_to_cpu(pkt->fka_adv_period);
		data->info.pkey = be16_to_cpu(pkt->pkey);

	} else {
		fip_dev_dbg(priv, LOG_PRIO_LOW,
			"fcoib_advertise_parse packet opcode is not "
			"supported=0x%x\n", (int)be16_to_cpu(pkt->fip.opcode));
		return -EINVAL;
	}

	return 0;
}

int fcoib_solicit_send(struct fip_dev_priv *priv,
		       enum fip_packet_type multicast, u32 dqpn, u16 dlid)
{
	int pkt_size = sizeof(struct fcoib_solicit);
	struct fip_discover *discover = &priv->discover;
	int ret;
	char *mem;
	struct fcoib_solicit *pkt;
	int i;

	/* alloc packet to be sent */
	mem = kzalloc(pkt_size, GFP_KERNEL);
	if (!mem) {
		fip_dev_warn(priv, "fcoib_solicit_send malloc failed\n");
		return -EAGAIN;
	}

	pkt = (struct fcoib_solicit *)mem;
	memcpy(pkt, &base_fcoib_solicit_pkt, sizeof(struct fcoib_solicit));
	pkt->fip.opcode = cpu_to_be16(FCOIB_FIP_OPCODE);
	pkt->fip.list_length =
	    cpu_to_be16((sizeof(struct fcoib_solicit) >> 2) - 2),
	    pkt->qpn = cpu_to_be32(discover->qp->qp_num);
	pkt->lid = cpu_to_be16(priv->local_lid);
	memcpy(pkt->gw_guid, &priv->local_gid.global.interface_id,
	       sizeof(pkt->gw_guid));

	for (i = 0; i < 8; i++)
		pkt->node_name[i] = i;

	pkt->max_fcoe_size = cpu_to_be32(priv->max_ib_mtu);

	fip_dev_dbg(priv, LOG_PRIO_MED, "fcoib_solicit_send creating "
		"multicast=%d solicit packet\n", multicast);

	if (multicast)
		ret = send_generic_mcast_pkt(priv, &discover->tx_ring,
					     mem, pkt_size, discover->qp,
					     discover->pkey_index,
					     discover->mcast[1]);
	else
		ret = send_generic_ucast_pkt(priv, &discover->tx_ring,
					     mem, pkt_size, discover->qp,
					     discover->pkey_index,
					     dqpn, dlid, FCOIB_FIP_QKEY);
	if (ret) {
		fip_dev_warn(priv, "discover_send error ret=%d\n", ret);
		goto error_free_mem;
	}

	return 0;

error_free_mem:
	kfree(mem);
	return -ENOMEM;
}

/* flogi is assumed to be 35 * 4 bytes */
static int fcoib_flogi_request_send(struct fip_gw_data *gw,
				    u8 *flogi, u32 host_data_qpn)
{
	struct fip_dev_priv *priv = gw->priv;
	int pkt_size = sizeof(struct fcoib_flogi_fdisc_request);
	struct fcoib_flogi_fdisc_request *pkt;
	int ret;
	char *mem;

	fip_gw_dbg(gw, LOG_PRIO_LOW, "Sending FIP FLOGI request\n");

	/* alloc packet to be sent */
	mem = kzalloc(pkt_size, GFP_ATOMIC);
	if (!mem) {
		fip_gw_warn(gw, "flogi request send malloc failed\n");
		return -EAGAIN;
	}

	pkt = (struct fcoib_flogi_fdisc_request *)mem;
	memcpy(pkt, &base_flogi_request_pkt,
	       sizeof(struct fcoib_flogi_fdisc_request));

	memcpy(pkt->els, flogi, sizeof(pkt->els));
	pkt->fip.opcode = cpu_to_be16(FCOIB_FIP_OPCODE);
	pkt->fip.list_length = cpu_to_be16((sizeof(struct
						   fcoib_flogi_fdisc_request) >>
					    2) - 2);
	pkt->qpn = cpu_to_be32(host_data_qpn);
	pkt->sl_gwportid = cpu_to_be16(gw->info.gw_port_id);
	pkt->lid = cpu_to_be16(priv->local_lid);
	memcpy(pkt->port_guid, &priv->local_gid.global.interface_id,
	       sizeof(pkt->port_guid));

	ret = send_generic_ucast_pkt(priv,
				     &priv->discover.tx_ring,
				     mem, pkt_size, priv->discover.qp,
				     priv->pkey_index, gw->info.gw_qpn,
				     gw->info.gw_lid, FCOIB_FIP_QKEY);
	if (ret) {
		fip_gw_warn(gw,
			 "flogi request send:  fip_ucast_send ret=%d\n", ret);
		kfree(mem);
		return -ENOMEM;
	}

	return 0;
}

static int fcoib_logo_request_send(struct fip_gw_data *gw,
				   u8 *logo, u32 host_data_qpn)
{
	struct fip_dev_priv *priv = gw->priv;
	int pkt_size = sizeof(struct fcoib_logo_request);
	struct fcoib_logo_request *pkt;
	int ret;
	char *mem;

	/* alloc packet to be sent */
	mem = kzalloc(pkt_size, GFP_ATOMIC);
	if (!mem) {
		fip_gw_warn(gw, "logo request send malloc failed\n");
		return -EAGAIN;
	}

	pkt = (struct fcoib_logo_request *)mem;
	memcpy(pkt, &base_logo_request_pkt, sizeof(struct fcoib_logo_request));

	memcpy(pkt->els, logo, sizeof(pkt->els));
	pkt->fip.opcode = cpu_to_be16(FCOIB_FIP_OPCODE);
	pkt->fip.list_length = cpu_to_be16((sizeof(struct
						   fcoib_logo_request) >> 2) -
					   2);
	pkt->qpn = cpu_to_be32(host_data_qpn);
	pkt->sl_gwportid = cpu_to_be16(gw->info.gw_port_id);
	pkt->lid = cpu_to_be16(priv->local_lid);
	memcpy(pkt->port_guid, &priv->local_gid.global.interface_id,
	       sizeof(pkt->port_guid));

	ret = send_generic_ucast_pkt(priv,
				     &priv->discover.tx_ring,
				     mem, pkt_size, priv->discover.qp,
				     priv->pkey_index, gw->info.gw_qpn,
				     gw->info.gw_lid, FCOIB_FIP_QKEY);
	if (ret) {
		fip_gw_warn(gw,
			 "logo request send:  fip_ucast_send ret=%d\n", ret);
		kfree(mem);
		return -ENOMEM;
	}

	return 0;
}

int fcoib_ioa_alive_send(struct fip_dev_priv *priv, struct fip_gw_data *gw)
{
	int pkt_size = sizeof(struct fcoib_ioa_alive);
	struct fcoib_ioa_alive *pkt;
	int ret;
	char *mem;

	/* alloc packet to be sent */
	mem = kzalloc(pkt_size, GFP_KERNEL);
	if (!mem) {
		fip_gw_warn(gw, "IOA alive send malloc failed\n");
		return -EAGAIN;
	}

	pkt = (struct fcoib_ioa_alive *)mem;
	memcpy(pkt, &base_ioa_alive_pkt, sizeof(struct fcoib_ioa_alive));

	pkt->fip.opcode = cpu_to_be16(FCOIB_FIP_OPCODE);
	pkt->fip.list_length = cpu_to_be16(FIP_VENDOR_ID_LENGTH +
					   INFINIBAND_ADDRESS_LENGTH);
	pkt->qpn = cpu_to_be32(gw->info.gw_qpn);
	pkt->sl_gwportid = cpu_to_be16(gw->info.gw_port_id);
	pkt->lid = cpu_to_be16(priv->local_lid);
	memcpy(pkt->port_guid, &priv->local_gid.global.interface_id,
	       sizeof(pkt->port_guid));

	ret = send_generic_ucast_pkt(priv,
				     &priv->discover.tx_ring,
				     mem, pkt_size, priv->discover.qp,
				     priv->pkey_index, gw->info.gw_qpn,
				     gw->info.gw_lid, FCOIB_FIP_QKEY);
	if (ret) {
		fip_gw_warn(gw, "IOA alive send:  fip_ucast_send ret=%d\n", ret);
		goto error_free_mem;
	}

	return 0;

error_free_mem:
	kfree(mem);
	return -ENOMEM;
}

int fcoib_vhba_alive_send(struct fip_dev_priv *priv, struct fip_gw_data *gw)
{
	struct mfc_vhba *vhba = containing_vhba(gw->fip_vhba);
	int pkt_size = sizeof(struct fcoib_vhba_alive);
	struct fcoib_vhba_alive *pkt;
	int ret;
	char *mem;

	/* alloc packet to be sent */
	mem = kzalloc(pkt_size, GFP_KERNEL);
	if (!mem) {
		fip_gw_warn(gw, "vHBA alive send malloc failed\n");
		return -EAGAIN;
	}

	pkt = (struct fcoib_vhba_alive *)mem;
	memcpy(pkt, &base_vhba_alive_pkt, sizeof(struct fcoib_vhba_alive));

	pkt->fip.opcode = cpu_to_be16(FCOIB_FIP_OPCODE);
	pkt->fip.list_length = cpu_to_be16(FIP_VENDOR_ID_LENGTH +
					   INFINIBAND_ADDRESS_LENGTH +
					   INFINIBAND_VX_PORT_ID_LENGTH);
	pkt->qpn = cpu_to_be32(gw->info.gw_qpn);
	pkt->sl_gwportid = cpu_to_be16(gw->info.gw_port_id);
	pkt->lid = cpu_to_be16(priv->local_lid);
	memcpy(pkt->port_guid, &priv->local_gid.global.interface_id,
	       sizeof(pkt->port_guid));

	mfc_get_vhba_fcid(vhba, (u8 *) (&pkt->vn_port_addres_id) + 1);

	ret = send_generic_ucast_pkt(priv,
				     &priv->discover.tx_ring,
				     mem, pkt_size, priv->discover.qp,
				     priv->pkey_index, gw->info.gw_qpn,
				     gw->info.gw_lid, FCOIB_FIP_QKEY);
	if (ret) {
		fip_gw_warn(gw,
			 "vHBA alive send:  fip_ucast_send ret=%d\n", ret);
		goto error_free_mem;
	}

	return 0;

error_free_mem:
	kfree(mem);
	return -ENOMEM;
}

int fcoib_pkt_parse(struct fip_dev_priv *priv,
		    char *buffer, int length, int *fip_type)
{
	struct fip_fip_header *fip_header;
	u16 fip_opcode;

	fip_header = (struct fip_fip_header *)(buffer +
					       IB_GRH_BYTES +
					       sizeof(struct fip_fcoib_ver));

	fip_opcode = be16_to_cpu(fip_header->opcode);

	if (fip_opcode != FCOIB_FIP_OPCODE) {
		fip_dev_dbg(priv, LOG_PRIO_LOW, "packet: packet is "
			"not FCoIB FIP packet\n");
		*fip_type = 0;
		return -EINVAL;
	}

	*fip_type = fip_opcode;

	return fip_header->subcode;
}

/*
 * Configure the discover QP. This includes configuring rx+tx
 * moving the discover QP to RTS and creating the tx  and rx rings
 */
int fip_discover_start_rings(struct fip_dev_priv *priv)
{
	int ret;
	struct fip_discover *discover = &priv->discover;

	spin_lock_init(&discover->lock);

	ret = fip_init_tx(priv, discover->tx_ring.size, &discover->tx_ring);
	if (ret) {
		fip_dev_warn(priv, "fip_init_tx failed ret=%d\n", ret);
		return ret;
	}

	ret = fip_init_rx(priv, discover->rx_ring.size, discover->qp,
			  &discover->rx_ring);
	if (ret) {
		fip_dev_warn(priv, "fip_init_rx returned %d\n", ret);
		goto release_queues;
	}

	return 0;

release_queues:
	fip_flush_rings(priv, discover->cq, discover->qp,
			&discover->rx_ring, &discover->tx_ring);
	fip_free_rings(priv, &discover->rx_ring, &discover->tx_ring);
	return ret;
}

/*
 * This function is the RX packet handler entry point at the thread level
 * (unlike the completion handler that runs from interrupt context).
 * the function calls a handler function and then reallocats the ring
 * entry for the next receive.
*/
void fip_discover_process_rx(struct work_struct *work)
{
	struct fip_discover *discover =
	    container_of(work, struct fip_discover, pkt_rcv_task);
	struct fip_dev_priv *priv =
	    container_of(discover, struct fip_dev_priv, discover);
	int mtu_size = FIP_UD_BUF_SIZE(priv->max_ib_mtu);
	int ret;

	if (priv->discover.flush == 1)
		return;

	while (discover->rx_ring.head != discover->rx_ring.tail) {
		if (discover->rx_ring.ring[discover->rx_ring.tail].length == 0)
			continue;

		if (discover->state == FIP_DISCOVER_LOGIN) {
			/* login is the first state we RX packets in */
			ret = fip_discover_rx_packet(priv,
						     discover->rx_ring.tail);
			if (ret)
				fip_dev_warn(priv, "discover_rx_packet ret=%d\n",
					 ret);
		}

		ret = fip_post_receive(priv, discover->qp, mtu_size,
				       discover->rx_ring.tail,
				       discover->rx_ring.ring[discover->rx_ring.
							      tail].mem,
				       discover->rx_ring.ring +
				       discover->rx_ring.tail);
		if (ret)
			fip_dev_warn(priv, "fip_post_receive ret=%d\n", ret);

		discover->rx_ring.tail++;
		discover->rx_ring.tail &= (discover->rx_ring.size - 1);
	}
	return;
}

/*
 * Alloc the discover CQ, QP. Configure the QP to RTS.
 * alloc the RX + TX rings and queue work for discover
 * finite state machine code.
 */
int fip_discover_init(struct fip_dev_priv *priv)
{
	struct ib_device *ca = priv->ca;
	struct ib_qp_init_attr qp_init_attr;
	struct fip_discover *discover;
	int i;

	discover = &priv->discover;

	discover->state = FIP_DISCOVER_INIT;
	discover->flush = 0;
	discover->rx_ring.size = FIP_PROTOCOL_RX_SIZE;
	discover->tx_ring.size = FIP_PROTOCOL_TX_SIZE;
	discover->pkey = priv->pkey;
	discover->backoff_time = 1;
	for (i = 0; i < FIP_DISCOVER_NUM_MCAST; i++)
		discover->mcast[i] = NULL;

	sema_init(&discover->flush_done, 0);

	INIT_DELAYED_WORK(&discover->task, fip_discover_fsm);
	INIT_DELAYED_WORK(&discover->cleanup_task, fip_purge_gws);
	INIT_WORK(&discover->pkt_rcv_task, fip_discover_process_rx);
	INIT_WORK(&discover->mcast_refresh_task, fip_refresh_mcasts);
	INIT_LIST_HEAD(&discover->gw_list);
	INIT_LIST_HEAD(&discover->gw_rm_list);
	init_rwsem(&discover->gw_list_rwsem);

	discover->cq = ib_create_cq(priv->ca, fip_discover_comp, NULL, priv,
				    discover->rx_ring.size +
				    discover->tx_ring.size, 0);
	if (IS_ERR(discover->cq)) {
		fip_dev_warn(priv, "%s: failed to create receive CQ\n", ca->name);
		return -EIO;
	}

	memset(&qp_init_attr, 0, sizeof(qp_init_attr));
	qp_init_attr.cap.max_send_wr = discover->tx_ring.size;
	qp_init_attr.cap.max_recv_wr = discover->rx_ring.size;
	qp_init_attr.cap.max_send_sge = 1;
	qp_init_attr.cap.max_recv_sge = 1;
	qp_init_attr.sq_sig_type = IB_SIGNAL_ALL_WR;
	qp_init_attr.qp_type = IB_QPT_UD;
	qp_init_attr.send_cq = discover->cq;
	qp_init_attr.recv_cq = discover->cq;

	discover->qp = ib_create_qp(priv->pd, &qp_init_attr);
	if (IS_ERR(discover->qp)) {
		fip_dev_warn(priv, "%s: failed to create QP\n", ca->name);
		goto error_free_cq;
	}

	fip_dev_dbg(priv, LOG_PRIO_HIGH, "Local QPN=%d, LID=%d\n",
		(int)discover->qp->qp_num, (int)priv->local_lid);

	/* TODO - figure out whats going on with the PKEY */
	if (ib_find_pkey(priv->ca, priv->port, discover->pkey,
			 &discover->pkey_index)) {
		fip_dev_warn(priv, "P_Key 0x%04x not found\n", discover->pkey);
		goto error_free_qp;
	}

	/* move QP from reset to RTS */
	if (fip_init_qp(priv, discover->qp, discover->pkey_index,
			FCOIB_FIP_QKEY)) {
		fip_dev_warn(priv, "ipoib_init_qp returned\n");
		goto error_free_qp;
	}

	/* init RX+TX rings */
	if (fip_discover_start_rings(priv)) {
		fip_dev_warn(priv, "%s: failed to move QP to RTS or "
			 "allocate queues\n", ca->name);
		goto error_free_qp;
	}

	/* enable recieving CQ completions */
	if (ib_req_notify_cq(discover->cq, IB_CQ_NEXT_COMP))
		goto error_release_rings;

	/* start discover FSM code */
	queue_delayed_work(fip_workqueue, &discover->task, 0 * HZ);

	return 0;

error_release_rings:
	fip_flush_rings(priv, discover->cq, discover->qp,
			&discover->rx_ring, &discover->tx_ring);
	fip_free_rings(priv, &discover->rx_ring, &discover->tx_ring);
error_free_qp:
	ib_destroy_qp(discover->qp);
error_free_cq:
	ib_destroy_cq(discover->cq);
	return -ENODEV;
}

/*
 * free the discover TX and RX rings, QP and CQ.
*/
void fip_discover_cleanup(struct fip_dev_priv *priv)
{
	if (priv->discover.state == FIP_DISCOVER_OFF)
		goto cleanup_done;

	/*
	 * move FSM to flush state and wait for the FSM
	 * to finish whatever it is doing before we continue
	 */
	fip_dev_dbg(priv, LOG_PRIO_LOW, "==>priv->discover.flush = 1\n");

	spin_lock_irq(&priv->discover.lock);
	priv->discover.flush = 1;
	spin_unlock_irq(&priv->discover.lock);

	cancel_delayed_work(&priv->discover.task);
	queue_delayed_work(fip_workqueue, &priv->discover.task, 0);
	down(&priv->discover.flush_done);

	fip_flush_rings(priv, priv->discover.cq, priv->discover.qp,
			&priv->discover.rx_ring, &priv->discover.tx_ring);
	flush_workqueue(fip_workqueue);

	fip_free_rings(priv, &priv->discover.rx_ring, &priv->discover.tx_ring);
	if (priv->discover.qp)
		ib_destroy_qp(priv->discover.qp);
	priv->discover.qp = NULL;

	if (priv->discover.cq)
		ib_destroy_cq(priv->discover.cq);
	priv->discover.cq = NULL;

cleanup_done:
	return;
}

/*
 * This function handles completions of both TX and RX
 * packets. RX packets are unmapped and passed to a thread
 * for processing. TX packets are unmapped and freed.
 * Note: this function is called from interrupt context
 */
void fip_discover_comp(struct ib_cq *cq, void *dev_ptr)
{
	struct fip_dev_priv *priv = dev_ptr;

	spin_lock(&priv->discover.lock);
	/* handle completions. On RX packets this will call discover_process_rx
	 * from thread context to continue processing */
	if (fip_comp(priv, priv->discover.cq, &priv->discover.rx_ring,
		     &priv->discover.tx_ring)) {
		if (!priv->discover.flush)
			queue_work(fip_workqueue, &priv->discover.pkt_rcv_task);
	}
	spin_unlock(&priv->discover.lock);
}

/*
 * Queue the GW for deletion. And trigger a delayed call to the cleanup
 * function.
 * Note: This deletion method insures that all pending GW work requests
 * are cleared without dependency of the calling context.
 * Must be called with discover->gw_list_rwsem taken
*/
void fip_close_gw(struct fip_gw_data *gw)
{
	if (gw->fip_vhba)
		mfc_destroy_vhba(containing_vhba(gw->fip_vhba));
	gw->fip_vhba = NULL;

	gw->vhba_ka_tmr_valid = 0;
	gw->host_ka_tmr_valid = 0;
	gw->gw_ka_tmr_valid = 0;
	gw->flush = 1;
	list_del(&gw->list);
	list_add(&gw->list, &gw->priv->discover.gw_rm_list);
	gw->state = FIP_GW_RESET;
	cancel_delayed_work(&gw->gw_task);

	queue_delayed_work(fip_workqueue, &gw->priv->discover.cleanup_task,
			   DELAYED_WORK_CLEANUP_JIFFS);
}

/*
 * Free GW resources. This includes destroying the vnics. If the GW can be
 * totaly destroyed (no pending work for the GW and all the vnics have been
 * destroyed) the GW will be removed from the GWs list and it's memory
 * freed. If the GW can not be closed at this time it will not be freed
 * and the function will return an error.
 * In this case the caller needs to recall the function to complete the
 * operation.
 * Do not call this function directly use: fip_close_gw
 * Must be called with discover->gw_list_rwsem taken
*/
static int fip_free_gw(struct fip_dev_priv *priv, struct fip_gw_data *gw)
{
	gw->flush = 1;

	cancel_delayed_work(&gw->gw_task);
	if (delayed_work_pending(&gw->gw_task))
		return -EBUSY;

	fip_gw_dbg(gw, LOG_PRIO_LOW, "fip_free_gw. freeing GW\n");
	list_del(&gw->list);
	mfc_fcf_deregister_sysfs(gw);

	return 0;
}

/*
 * permanently delete all GWs pending delete. The function goes over
 * the list of GWs awaiting deletion and tries to delete them. If the
 * GW destructor returns an error value (currently busy) the function
 * will requeue it self for another try.
 */
static void fip_purge_gws(struct work_struct *work)
{
	struct fip_discover *discover = container_of(work,
						     struct fip_discover,
						     cleanup_task.work);
	struct fip_dev_priv *priv = container_of(discover,
						 struct fip_dev_priv, discover);
	struct fip_gw_data *gw, *tmp_gw;
	int respawn = 0;

	down_write(&discover->gw_list_rwsem);
	list_for_each_entry_safe(gw, tmp_gw, &discover->gw_rm_list, list) {
		if (fip_free_gw(priv, gw) == -EBUSY)
			respawn = 1;
	}
	up_write(&discover->gw_list_rwsem);

	if (respawn) {
		fip_dev_dbg(priv, LOG_PRIO_LOW,
			"fip_free_gw is busy. respawn purge_gws\n");
		queue_delayed_work(fip_workqueue, &discover->cleanup_task,
				   DELAYED_WORK_CLEANUP_JIFFS);
	}
}

#define NO_GWS_OPEN(discover) \
	(list_empty(&(discover)->gw_rm_list) && \
	list_empty(&(discover)->gw_list))

/*
 * Go over the GW list and try to close the GWs. It is possible that some
 * of the GWs have pending work and therefore can not be closed. We can not
 * sleep on this because we might be running on the same context as the one
 * we are waiting for. To solve this recall the function if needed.
 * Returns 0 if all GWs were removed and -EBUSY if one or more are still
 * open.
*/
int fip_free_gw_list(struct fip_dev_priv *priv)
{
	struct fip_discover *discover = &priv->discover;
	struct fip_gw_data *curr_gw, *tmp_gw;

	down_write(&discover->gw_list_rwsem);
	list_for_each_entry_safe(curr_gw, tmp_gw, &discover->gw_list, list)
		fip_close_gw(curr_gw);

	if (!NO_GWS_OPEN(discover)) {
		fip_dev_dbg(priv, LOG_PRIO_LOW, "fip_free_gw_list discover->"
			"gw_rm_list %s gw_list %s\n",
			list_empty(&discover->
				   gw_rm_list) ? "empty" : "not empty",
			list_empty(&discover->gw_list) ? "empty" : "not empty");
		up_write(&discover->gw_list_rwsem);
		return -EBUSY;
	}
	up_write(&discover->gw_list_rwsem);

	cancel_delayed_work(&discover->cleanup_task);
	if (delayed_work_pending(&discover->cleanup_task)) {
		fip_dev_dbg(priv, LOG_PRIO_LOW, "fip_free_gw_list waiting for "
			"pending work on cleanup_task\n");
		return -EBUSY;
	}

	fip_dev_dbg(priv, LOG_PRIO_LOW, "fip_free_gw_list"
		" Done freeing all GW we can go on\n");

	return 0;
}

/*
 * Look for a GW in the GW list. The search keys used are the GW lid (unique)
 * and the GW port_id assuming that a single GW phisical port can advertise
 * itself more then once.
*/
struct fip_gw_data *fip_find_gw(struct fip_discover *discover,
		u8 *gw_guid, u16 gw_port_id)
{
	struct fip_gw_data *curr_gw;

	down_read(&discover->gw_list_rwsem);
	list_for_each_entry(curr_gw, &discover->gw_list, list) {
		if ((!memcmp(curr_gw->info.gw_guid, gw_guid,
						sizeof curr_gw->info.gw_guid)) &&
		    (curr_gw->info.gw_port_id == gw_port_id)) {
			up_read(&discover->gw_list_rwsem);
			return curr_gw;
		}
	}
	up_read(&discover->gw_list_rwsem);
	return NULL;
}

struct fip_gw_data *fip_discover_create_gw(struct fip_dev_priv *priv,
		u8 *gw_guid, u16 gw_port_id)
{
	struct fip_gw_data *gw_data;

	gw_data = kzalloc(sizeof(struct fip_gw_data), GFP_KERNEL);
	if (!gw_data)
		return ERR_PTR(-ENOMEM);

	gw_data->priv = priv;
	down_write(&priv->discover.gw_list_rwsem);
	list_add_tail(&gw_data->list, &priv->discover.gw_list);
	up_write(&priv->discover.gw_list_rwsem);
	INIT_DELAYED_WORK(&gw_data->gw_task, fip_gw_fsm);
	memcpy(gw_data->info.gw_guid, gw_guid, 8);
	gw_data->info.gw_port_id = gw_port_id;

	mfc_fcf_register_sysfs(gw_data);

	return gw_data;
}


static int gw_info_differ(struct fip_gw_data_info *orig_info,
		struct fip_gw_data_info *new_info)
{
	if (orig_info->gw_lid != new_info->gw_lid)
		return 1;
	if (orig_info->gw_qpn != new_info->gw_qpn)
		return 1;
	return 0;
}

static int fip_discover_rx_advertise(struct fip_dev_priv *priv,
				     struct fip_gw_data *advertise_data)
{
	struct fip_discover *discover = &priv->discover;
	struct fip_gw_data *gw_data;
	struct mfc_vhba *vhba;
	int update_entry = 0;

	/* see if we received advertise packets from this GW before */
	gw_data = fip_find_gw(discover, advertise_data->info.gw_guid,
			advertise_data->info.gw_port_id);

	/*
	 * GW not found in GW list, create a new GW structure and add it to GW
	 * list. If GW was found in list but it is in multicast state (based on
	 * received mcast packet) we will replace it with the newer up-to-date
	 * packet.
	 */
	if (!gw_data) {
		gw_data = fip_discover_create_gw(priv,
				advertise_data->info.gw_guid,
				advertise_data->info.gw_port_id);
		if (IS_ERR(gw_data))
			return -ENOMEM;
		update_entry = 1;
	} else {
		if (gw_data->flush)
			return 0;

		if (gw_data->state <= FIP_GW_RCVD_UNSOL_AD) {
			update_entry = 1;
		}
	}

	if (update_entry) {
		memcpy(&gw_data->info, &advertise_data->info,
		       sizeof(struct fip_gw_data_info));
		gw_data->state = FIP_GW_RCVD_UNSOL_AD;
	}

	if (gw_info_differ(&gw_data->info, &advertise_data->info)) {
		fip_gw_warn(gw_data,
				"GW info change detected, link down vHBA GW\n");
		gw_data->vhba_ka_tmr_valid = 0;
		gw_data->host_ka_tmr_valid = 0;
		gw_data->gw_ka_tmr_valid = 0;
		gw_data->state = FIP_GW_RESET;
		cancel_delayed_work(&gw_data->gw_task);
		if (gw_data->fip_vhba) {
			vhba = containing_vhba(gw_data->fip_vhba);
			fc_linkdown(vhba->lp);
		}
		return 0;
	}

	/* if multicast advertisement received */
	if (advertise_data->info.flags & FIP_RCV_MULTICAST) {
		gw_data->gw_ka_tmr = jiffies + 3 * FKA_ADV_PERIOD * HZ;

		/* we are beyond accepting mcast advertisement */
		if (gw_data->state != FIP_GW_RCVD_UNSOL_AD)
			return 0;

		fip_gw_dbg(gw_data, LOG_PRIO_LOW,
			"Received mcast advertise from"
			" GW qpn=%d lid=%d flags=0x%x\n",
			gw_data->info.gw_qpn, gw_data->info.gw_lid,
			gw_data->info.flags);
	} else {		/* unicast advertisement received */
		int ack_received =
		    advertise_data->info.flags & FIP_GW_AVAILABLE;

		fip_gw_dbg(gw_data, LOG_PRIO_LOW,
			"received ucast advertise from GW qpn=%d lid=%d"
			" flags=0x%x\n",
			gw_data->info.gw_qpn, gw_data->info.gw_lid,
			gw_data->info.flags);

		/* if this is first ACK received move to FIP_GW_ACK_RCVD */
		if (ack_received && gw_data->state == FIP_GW_SENT_SOL)
			gw_data->state = FIP_GW_RCVD_SOL_AD;
	}

	/* we will call the GW FSM to handle */
	cancel_delayed_work(&gw_data->gw_task);
	fip_gw_fsm(&gw_data->gw_task.work);
	return 0;
}

static int recvd_flogi_reply(struct fip_gw_data *gw, u8 *flogi_reply,
			    int size, u32 gw_data_qpn)
{
	struct fip_vhba *fip_vhba = gw->fip_vhba;
	struct mfc_vhba *vhba = containing_vhba(fip_vhba);
	struct fc_lport *lp = vhba->lp;
	struct fc_frame *fp;
	struct sk_buff *skb;

	skb = mfc_alloc_fc_frame(vhba);
	if (IS_ERR(skb))
		return PTR_ERR(skb);

	memcpy(skb_put(skb, size), flogi_reply, size);
	fp = (struct fc_frame *)skb;
	fc_frame_init(fp);
	fr_eof(fp) = FC_EOF_T;
	fr_sof(fp) = FC_SOF_I3;
	fr_dev(fp) = lp;

	ASSERT(vhba->net_type == NET_IB);

	mfc_update_gw_addr_ib(vhba, gw->info.gw_lid, gw_data_qpn, gw->info.sl);
	mfc_flogi_finished(vhba, &flogi_reply[1]);

	fc_exch_recv(lp, fp);

	return 0;
}

/*
 * This function handles a single received packet that are expected to be
 * GW advertisements or login ACK packets. The function first parses the
 * packet and decides what is the packet type and then handles the packets
 * specifically according to its type. This functions runs in task context.
*/
int fip_discover_rx_packet(struct fip_dev_priv *priv, int index)
{
	struct fip_discover *discover = &priv->discover;
	union {
		struct fip_gw_data advertise_data;
	} pkt_data;
	char *packet = discover->rx_ring.ring[index].mem;
	int length = discover->rx_ring.ring[index].length;
	int ret, pkt_type, fip_type;

	pkt_type = fcoib_pkt_parse(priv, packet, length, &fip_type);
	if (pkt_type < 0)
		return 0;

	switch (pkt_type) {
	case FCOIB_GW_ADV_SUB_OPCODE:
		ret = fcoib_advertise_parse(priv, packet, length,
					    &pkt_data.advertise_data);
		if (!ret) {
			return fip_discover_rx_advertise(priv, &pkt_data.
							 advertise_data);
		}
		break;
	case FCOIB_LS_REPLY_SUB_OPCODE:
		{
			struct fcoib_flogi_fdisc_acc *rep =
			    (struct fcoib_flogi_fdisc_acc *)(packet +
							     IB_GRH_BYTES);
			struct fip_gw_data *gw;

			/* find the GW that this login belongs to */
			gw = fip_find_gw(discover, rep->port_guid,
					be16_to_cpu(rep->sl_gwPortId));
			if (!gw)
				break;

			if (!gw->fip_vhba) {
				fip_gw_warn(gw, "Got LS REPLY but no vHBA for this GW\n");
				break;
			}

			gw->info.gw_data_qpn = be32_to_cpu(rep->qpn);
			if (!recvd_flogi_reply(gw, rep->els,
						(rep->els_length_f - 1) * 4,
						gw->info.gw_data_qpn)) {
				if (gw->state == FIP_GW_SENT_FLOGI) {
					fip_gw_dbg(gw, LOG_PRIO_LOW,
						"Connected\n");
					gw->state = FIP_GW_RCVD_FLOGI_ACCPT;
				}
				cancel_delayed_work(&gw->gw_task);
				fip_gw_fsm(&gw->gw_task.work);

			} else {
				printk(KERN_WARNING
					"mlx4_fcoib: rejected gw\n");
				gw->state = FIP_GW_RESET;
			}
		}
		break;
	case FCOIB_CLVL_SUB_OPCODE:
		{
			struct fcoib_clear_virtual_link_ioa *clvl =
			    (struct fcoib_clear_virtual_link_ioa *)
			    (packet + IB_GRH_BYTES);
			struct fip_gw_data *gw;
#define IOA_CLVL_LIST_LENGTH  (FIP_VENDOR_ID_LENGTH + \
						  INFINIBAND_ADDRESS_LENGTH + \
						 FIP_NAME_IDENTIFIER_LENGTH)
#define VHBA_CLVL_LIST_LENGTH (IOA_CLVL_LIST_LENGTH + \
					       INFINIBAND_VX_PORT_ID_LENGTH)

			/* we should not look for gw by its' lid - because the
			   gw may send CLVL because of changing this lid */

			gw = fip_find_gw(discover, clvl->gw_guid,
					be16_to_cpu(clvl->sl_gwPortId));
			if (!gw) {
				printk(KERN_ERR
					"CLVL for non-existing gw\n");
				break;
			}

			/* TODO: We should differ between IOA_CLVL to VHBA_CLVL
			 * after vhba virtualization implementation, for now
			 * we close the gw on VHBA_CLVL because each gw has one
			 * vhba*/

			if (be16_to_cpu(clvl->fip.list_length) >=
			    IOA_CLVL_LIST_LENGTH) {
				struct mfc_vhba *vhba;
				fip_gw_dbg(gw, LOG_PRIO_MED,
					"received CLVL - reset GW\n");
				if (gw->fip_vhba) {
					vhba = containing_vhba(gw->fip_vhba);
					fc_linkdown(vhba->lp);
				}
				gw->state = FIP_GW_RESET;
				queue_work(fip_workqueue,
					   &gw->priv->discover.mcast_refresh_task);
			} else
				printk(KERN_WARNING
				       "received CLVL with unexpected size\n");
		}
		break;
	default:
		printk(KERN_WARNING "received unknown packet\n");
		break;
	}
	return 0;
}

/*
 * This function is a callback called upon successful join to a
 * multicast group. The function checks if we have joined + attached
 * to all required mcast groups and if so moves the discovery FSM to solicit.
*/
void fip_discover_mcast_connect_cb(struct mcast_entry *mcast,
				   void *discover_context)
{
	struct fip_discover *discover = discover_context;
	struct fip_dev_priv *priv =
	    container_of(discover, struct fip_dev_priv, discover);
	int i;

	for (i = 0; i < FIP_DISCOVER_NUM_MCAST; i++)
		if (mcast == discover->mcast[i])
			break;

	/*
	 * if we have not started joining the mcast or the join is still in
	 * progress return. We will continue only when all is done
	 */
	for (i = 0; i < FIP_DISCOVER_NUM_MCAST; i++) {
		if (discover->mcast[i] == NULL ||
		    !test_bit(MCAST_FLAG_DONE, &discover->mcast[i]->flags))
			return;
	}

	/* in the case of a reconnect don't change state or send a solicit
	 * packet */
	if (discover->state < FIP_DISCOVER_SOLICIT) {
		fip_dev_dbg(priv, LOG_PRIO_LOW,
			"fip_multicast_connected "
			"moved state to solicit\n");
		spin_lock_irq(&discover->lock);
		if (!discover->flush) {
			/* delay sending solicit packet by 0-100 mSec */
			int rand_delay = jiffies % 100;	/*get_random_int() */
			discover->state = FIP_DISCOVER_SOLICIT;
			cancel_delayed_work(&discover->task);
			/* This is really (rand_delay / 1000) * HZ */
			queue_delayed_work(fip_workqueue, &discover->task,
					   (rand_delay * HZ) / 1000);
		}
		spin_unlock_irq(&discover->lock);
	}
	fip_dev_dbg(priv, LOG_PRIO_LOW, "discover_mcast_connect_cb done\n");
}

/*
 * Try to connect to the relevant mcast groups. If one of the mcast failed
 * The function should be recalled to try and complete the join process
 * (for the mcast groups that the join process was not performed).
 * Note: A successful return of fip_mcast_join means that the mcast join
 * started, not that the join completed. completion of the connection process
 * is asyncronous and uses a supplyed callback.
*/
int fip_discover_mcast_connect(struct fip_dev_priv *priv)
{
	struct fip_discover *discover = &priv->discover;

	fip_dev_dbg(priv, LOG_PRIO_LOW, "discover_mcast_connect\n");

	priv->mcast.flags = 0;

	/* connect to a well known multi cast group */
	discover->mcast[0] = fip_mcast_join(&priv->mcast, discover,
					     FIP_DISCOVER_MGID, FCOIB_FIP_QKEY,
					     priv->discover.pkey,
					     priv->discover.qp,
					     MCAST_RECEIVE_ONLY,
					     fip_discover_mcast_connect_cb);
	if (!discover->mcast[0]) {
		fip_dev_warn(priv, "failed to join advertise MCAST groups\n");
		return -1;
	}

	discover->mcast[1] = fip_mcast_join(&priv->mcast, discover,
					     FIP_SOLICIT_MGID, FCOIB_FIP_QKEY,
					     priv->discover.pkey,
					     priv->discover.qp, MCAST_SEND_ONLY,
					     fip_discover_mcast_connect_cb);
	if (!discover->mcast[1]) {
		fip_dev_warn(priv, "failed to join solicit MCAST groups\n");
		return -1;
	}

	return 0;
}

void fip_discover_mcast_disconnect(struct fip_dev_priv *priv)
{
	struct fip_discover *discover = &priv->discover;
	int i;

	for (i = 0; i < FIP_DISCOVER_NUM_MCAST; i++) {
		if (discover->mcast[i])
			fip_mcast_free(discover->mcast[i]);
		discover->mcast[i] = NULL;
	}
}

static int fip_discover_mcast_recnct(struct fip_dev_priv *priv)
{
	fip_discover_mcast_disconnect(priv);
	return fip_discover_mcast_connect(priv);
}

/*
 * This function unjoins and rejoins all the mcasts used for a specific port.
 * This includes 2 mcasts used by the discovery and the mcasts used for the
 * vnics attached to the various GW using the port.
*/
void fip_refresh_mcasts(struct work_struct *work)
{
	struct fip_discover *discover =
	    container_of(work, struct fip_discover, mcast_refresh_task);
	struct fip_dev_priv *priv =
	    container_of(discover, struct fip_dev_priv, discover);

	if (discover->flush)
		return;

	fip_dev_dbg(priv, LOG_PRIO_LOW, "discover_refresh_mcast: "
		"calling discover_mcast_recnct\n");
	if (fip_discover_mcast_recnct(priv))
		fip_dev_warn(priv, "discover_refresh_mcast: "
			 "discover_mcast_recnct failed\n");
}

int els_send(struct mfc_vhba *vhba, struct sk_buff *skb)
{
	struct fip_vhba *fip_vhba = vhba_priv(vhba);
	struct fip_gw_data *curr_gw = fip_vhba->gw;
	struct fc_frame_header *fh = (struct fc_frame_header *)skb->data;
	u8 op;
	int ret = -EINVAL;
	u32 host_data_qpn = mfc_get_src_qpn(containing_vhba(fip_vhba));

	op = *(u8 *)(fh + 1);

	if (!curr_gw) return ret;
	switch (op) {
	case ELS_FLOGI:
		curr_gw->vhba_ka_tmr_valid = 0;
		curr_gw->state = FIP_GW_SENT_FLOGI;
		ret = fcoib_flogi_request_send(curr_gw, skb->data,
				host_data_qpn);
		break;

	case ELS_LOGO:
		ret = fcoib_logo_request_send(curr_gw, skb->data,
				host_data_qpn);
		break;
	}
	kfree_skb(skb);
	return ret;
}

static void fip_handle_gw_timers(struct fip_gw_data *curr_gw)
{
	if (curr_gw->host_ka_tmr_valid &&
	    time_after_eq(jiffies, curr_gw->host_ka_tmr)) {
		curr_gw->host_ka_tmr = jiffies + FKA_ADV_PERIOD * HZ;
		fcoib_ioa_alive_send(curr_gw->priv, curr_gw);
	}

	if (curr_gw->vhba_ka_tmr_valid &&
	    time_after_eq(jiffies, curr_gw->vhba_ka_tmr)) {
		curr_gw->vhba_ka_tmr = jiffies + FKA_VHBA_PERIOD * HZ; // Spec says 90, but allow delay
		fcoib_vhba_alive_send(curr_gw->priv, curr_gw);
	}

	if (curr_gw->gw_ka_tmr_valid &&
	    time_after_eq(jiffies, curr_gw->gw_ka_tmr)) {
		curr_gw->gw_ka_tmr = jiffies + 3 * FKA_ADV_PERIOD * HZ;
		fip_gw_dbg(curr_gw, LOG_PRIO_MED,
			"no keep alives from GW - reset GW\n");
		curr_gw->state = FIP_GW_RESET;
		if (curr_gw->fip_vhba)
			fc_linkdown(containing_vhba(curr_gw->fip_vhba)->lp);
		queue_work(fip_workqueue,
			   &curr_gw->priv->discover.mcast_refresh_task);
	}
}

static inline u64 guid_to_mac(u64 guid)
{
	return (guid & 0xffffff) | ((guid & 0xffffff0000000000) >> 16);
}

struct mfc_vhba *create_vhba_for_gw(struct fip_gw_data *gw, u64 wwpn)
{
	struct fip_vhba *fip_vhba;
	struct mfc_vhba *vhba;
	u64 wwn, wwnn;

	wwn = guid_to_mac(be64_to_cpu
				(gw->priv->local_gid.global.interface_id));
	wwnn = wwn | ((u64) 0x10 << 56);
	if (!wwpn)
		wwpn = wwn | ((u64) 0x20 << 56) |
			((u64) (gw->info.gw_port_id & 0xfff) << 48);

	vhba = mfc_create_vhba_fcoib(gw->priv->mfc_port,
			gw->priv->max_ib_mtu,
			wwpn, wwnn, sizeof(struct fip_vhba),
			THIS_MODULE);
	if (IS_ERR(vhba)) {
		return vhba;
	}
	fip_vhba = vhba_priv(vhba);
	fip_vhba->gw = gw;
	gw->fip_vhba = fip_vhba;
	mfc_fcf_add_vhba_link(gw);

	return vhba;
}

static void fip_gw_fsm(struct work_struct *work)
{
	struct fip_gw_data *curr_gw = container_of(work,
						   struct fip_gw_data,
						   gw_task.work);
	int ret;
	unsigned long next_wakeup = (3 * FKA_ADV_PERIOD * HZ);	/* timeout */
	unsigned long rand = jiffies % 100;
	struct mfc_vhba *vhba;

	if (curr_gw->flush)
		return;

	switch (curr_gw->state) {
	case FIP_GW_RCVD_UNSOL_AD:
		ret = 0;
		if (!fip_auto_create && !curr_gw->fip_vhba)
			break;

		fip_gw_dbg(curr_gw, LOG_PRIO_LOW,
			"Sending ucast solicit"
			" to GW qpn=%d lid=%d flags=0x%x\n",
			curr_gw->info.gw_qpn, curr_gw->info.gw_lid,
			curr_gw->info.flags);

		curr_gw->state = FIP_GW_SENT_SOL;
		ret = fcoib_solicit_send(curr_gw->priv,
					 FIP_DISCOVER_UCAST,
					 curr_gw->info.gw_qpn,
					 curr_gw->info.gw_lid);
		if (ret)
			next_wakeup = (rand * HZ) / 250;
		else
			next_wakeup = (rand * HZ) / 25;
		break;
	case FIP_GW_RCVD_SOL_AD:
		/* if GW was ACKed */
		fip_gw_dbg(curr_gw, LOG_PRIO_LOW,
			"Discover login, gw_ack_rcv\n");
		curr_gw->state = FIP_GW_WAITING_FOR_FLOGI;

		if (!curr_gw->fip_vhba) {
			vhba = create_vhba_for_gw(curr_gw, 0);
			if (IS_ERR(vhba)) {
				curr_gw->state = FIP_GW_RCVD_SOL_AD;
				fip_gw_err(curr_gw, "Could not create vHBA\n");
				break;
			}
		} else {
			fip_gw_dbg(curr_gw, LOG_PRIO_LOW,
				"Discover login, reset vhba/lport\n");
			vhba = containing_vhba(curr_gw->fip_vhba);
			fc_linkdown(vhba->lp);
		}

		curr_gw->host_ka_tmr = jiffies;
		curr_gw->host_ka_tmr_valid = 1;
		curr_gw->gw_ka_tmr = jiffies + FKA_ADV_PERIOD * 3 * HZ;
		curr_gw->gw_ka_tmr_valid = 1;
		fc_fabric_login(vhba->lp);
		fc_linkup(vhba->lp);
		break;
	case FIP_GW_RCVD_FLOGI_ACCPT:
		next_wakeup = FKA_ADV_PERIOD * HZ;
		if (!curr_gw->vhba_ka_tmr_valid) {
			curr_gw->vhba_ka_tmr = jiffies + FKA_VHBA_PERIOD * HZ;
			curr_gw->vhba_ka_tmr_valid = 1;
		}
		break;
	default:
		break;
	}

	fip_handle_gw_timers(curr_gw);

	/* go to sleep until time out. We expect that we will be awaken by
	 * RX packets and never get to wake up due to timeout
	 */
	if (next_wakeup > FKA_ADV_PERIOD * HZ)
		next_wakeup = FKA_ADV_PERIOD * HZ;

	cancel_delayed_work(&curr_gw->gw_task);
	queue_delayed_work(fip_workqueue, &curr_gw->gw_task, next_wakeup);
}

int fip_discover_flush(struct fip_discover *discover, int unload)
{
	struct fip_dev_priv *priv =
	    container_of(discover, struct fip_dev_priv, discover);
	int ret = 0;

	fip_dev_dbg(priv, LOG_PRIO_LOW,
		    "==>FLUSHING discover\n");

	/* if we failed to remove all GWs we
	 * will retry to remove them */
	if (unload) {
		if (fip_free_gw_list(priv)) {
			fip_dev_dbg(priv, LOG_PRIO_LOW,
				    "fip_free_gw_list not done, recalling\n");
			ret = -EAGAIN;
			goto out;
		}
		fip_dev_dbg(priv, LOG_PRIO_LOW, "fip_free_gw_list done\n");
	} else {
		struct fip_gw_data *curr_gw, *tmp_gw;

		list_for_each_entry_safe(curr_gw, tmp_gw, &discover->gw_list, list) {
			fip_gw_warn(curr_gw,
				    "async_event detected, link down vHBA GW\n");
			curr_gw->vhba_ka_tmr_valid = 0;
			curr_gw->host_ka_tmr_valid = 0;
			curr_gw->gw_ka_tmr_valid = 0;
			curr_gw->state = FIP_GW_RESET;
			cancel_delayed_work(&curr_gw->gw_task);
			if (curr_gw->fip_vhba)
				fc_linkdown(containing_vhba(curr_gw->fip_vhba)->lp);
		}
	}

	fip_discover_mcast_disconnect(priv);

	if (fip_mcast_stop_thread(&priv->mcast)) {
		fip_dev_dbg(priv, LOG_PRIO_LOW,
			    "fip_mcast_stop_thread not done, recalling\n");
		ret = -EAGAIN;
		goto out;
	}

	discover->state = FIP_DISCOVER_OFF;

	/* signal the unload to continue */
	if (unload)
		up(&priv->discover.flush_done);

out:
	return ret;
}

/*
 * This is the discover finite state machine that runs the
 * advertise and solicit packet exchange of the discovery
 * process.
 * It is assumed that this function is only called from work queue
 * task context (for locking)
 */
void fip_discover_fsm(struct work_struct *work)
{
	struct fip_discover *discover =
	    container_of(work, struct fip_discover, task.work);
	struct fip_dev_priv *priv =
	    container_of(discover, struct fip_dev_priv, discover);
	int recall_time = -1;

	/* we got a flush request and we have not performed it yet */
	if (discover->flush && discover->state != FIP_DISCOVER_OFF) {
		if (fip_discover_flush(discover, 1)) {
			recall_time = DELAYED_WORK_CLEANUP_JIFFS * 2;
			goto recall_fsm;
		}

		return;
	}

	if (!priv->local_lid) {
		recall_time = 1 * HZ;
		goto recall_fsm;
	}

	switch (discover->state) {
	case FIP_DISCOVER_OFF:
		return;
	case FIP_DISCOVER_INIT:
		fip_dev_dbg(priv, LOG_PRIO_LOW, "DISCOVER_INIT\n");
		/* in init try and join the discover multicast group
		 * This is a preliminary request for all other progress */
		if (fip_discover_mcast_connect(priv)) {
			fip_dev_warn(priv, "failed to join MCAST groups "
				 "allocate queues\n");
			/* try again later */
			recall_time = 1 * HZ;
		}
		break;

	case FIP_DISCOVER_SOLICIT:
		/* future mcast solicitation requests may be inserted here */
		discover->state = FIP_DISCOVER_LOGIN;
		discover->backoff_time = -1;
		break;

	case FIP_DISCOVER_LOGIN:
		/* do nothing */
		break;

	default:
		fip_dev_warn(priv, "discover->state in illegal state %d\n",
			discover->state);
		break;

	}

recall_fsm:
	if (recall_time >= 0)
		queue_delayed_work(fip_workqueue, &discover->task, recall_time);

	return;
}
