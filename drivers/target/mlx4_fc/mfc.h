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

#ifndef MFC_H
#define MFC_H

#include <linux/compiler.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <linux/interrupt.h>
#include <linux/kobject.h>

#include <linux/mlx4/driver.h>
#include <linux/mlx4/device.h>
#include <linux/mlx4/qp.h>
#include <linux/mlx4/doorbell.h>
#include <linux/mlx4/qp.h>
#include <linux/mlx4/srq.h>
#include <linux/mlx4/cq.h>
#include <linux/mlx4/cmd.h>
#include <linux/netdevice.h>

#include <scsi/scsi_cmnd.h>
#include <scsi/libfc.h>
#include <scsi/libfcoe.h>
#include <scsi/fc_frame.h>
#include <scsi/fc/fc_fcp.h>
#include <scsi/fc/fc_fcoe.h>

#include <target/target_core_base.h>
#include "mlx4_fc_base.h"

#define MFC_CMD_TIMEOUT			(5 * HZ)
#define MFC_MAX_LUN			255
#define MFC_MAX_FCP_TARGET		256
#define MFC_MAX_CMD_PER_LUN		16
#define MFC_BIT_DESC_OWN		0x80000000
#define MFC_RFCI_OP_SEND		0xa
#define MFC_CMD_OP_RDMA_WRITE		0x8
#define MFC_CMD_OP_RDMA_READ 		0x10
#define MFC_CMD_OP_INIT			0xc
#define MFC_BIT_INS_VLAN		0x4000
#define MFC_BIT_NO_ICRC			0x2
#define MFC_BIT_TX_COMP			0xc
#define MFC_BIT_TX_IP_CS		0x10
#define MFC_BIT_TX_TCP_CS		0x20
#define MFC_BIT_TX_FCRC_CS		0x40
#define MFC_CQ_ARM_CMD			0x2
#define MFC_CMD_CQ_ENTRIES		128
#define MFC_RFCI_CQ_ENTRIES		128
#define MFC_NUM_NPORT_IDS		128
#define MFC_MAX_PORT_FEXCH		(64 * 1024)
#define MFC_MAX_FMR_PAGES		512
#define MFC_FMR_PAGE_SHIFT		9
#define MFC_RFCI_RX_SKB_BUFSIZE		(PAGE_SIZE - 1024)
#define MFC_FIP_RX_SKB_BUFSIZE		(PAGE_SIZE - 1024)
#define MFC_CMD_RX_SKB_BUFSIZE		(PAGE_SIZE - 1024)
#define MFC_ALLOC_ORDER			2
#define MFC_ALLOC_SIZE			(PAGE_SIZE << MFC_ALLOC_ORDER)
#define MFC_GW_ADDR_MODE		0x00
#define MFC_FCOUI_ADDR_MODE		0x01
#define MFC_ASYNC_DELAY			(HZ / 4)

#define MLX4_CMD_CONFIG_FC		0x4a
#define MLX4_CMD_SET_VLAN_FLTR		0x47
#define MLX4_CMD_MOD_FC_ENABLE		0
#define MLX4_CMD_MOD_FC_DISABLE		1
#define MLX4_CMD_INMOD_BASIC_CONF	0x0000
#define MLX4_CMD_INMOD_NPORT_TAB	0x0100
#define MLX4_LINK_TYPE_IB		0
#define MLX4_LINK_TYPE_ETH		1
#define MLX4_MPT_ENABLE_INVALIDATE	(0x3 << 24)
#define MLX4_FCOIB_QKEY			0x80020005
#define MLX4_DEFAULT_FC_MTU		2112
#define MLX4_DEFAULT_NUM_RESERVED_XIDS	256
#define MLX4_DEFAULT_LOG_EXCH_PER_VHBA	10
#define MLX4_DEFAULT_MAX_VHBA_PER_PORT			\
	(1 << (16 - MLX4_DEFAULT_LOG_EXCH_PER_VHBA))

/* aligned to cacheline (wqe bug), enough for 1 ctl + 1 dgram + 1 ds */
#define RFCI_SQ_BB_SIZE			128
#define RFCI_RQ_WQE_SIZE		sizeof(struct mfc_data_seg)
#define FIP_SQ_BB_SIZE			128
#define FIP_RQ_WQE_SIZE			sizeof(struct mfc_data_seg)
#define FIP_SQ_NUM_BBS			128
#define FIP_RQ_NUM_WQES			128

/* 1 ctl + 1 IB addr + 1 fcp init + 1 ds = 96*/
#define FCMD_SQ_BB_SIZE			128
#define FCMD_RQ_NUM_WQES		1	/* minimum allowed 2^0 */
#define FCMD_RQ_WQE_SIZE		16	/* minimum allowed 2^0 * 16 */
#define FEXCH_SQ_NUM_BBS		8	/* minimum allowed 2^0 */
#define FEXCH_SQ_BB_SIZE		64	/* minimum allowed 2^0 * 16 */
#define FEXCH_RQ_WQE_SIZE		16	/* 1 ds */
#define FEXCH_RQ_NUM_WQES		1
#define VLAN_FLTR_SIZE			128
#define VHBA_SYSFS_LEN			32
#define FC_MAX_ERROR_CNT		5
#define QPC_SERVICE_TYPE_RFCI		9
#define QPC_SERVICE_TYPE_ETH		7
#define QPC_SERVICE_TYPE_FCMD		4
#define QPC_SERVICE_TYPE_FEXCH		5
#define ETH_P_FIP			0x8914
#define FCOIB_SIG			0x4000
#define QUERY_PORT_LINK_MASK		0x80
#define SQ_NO_PREFETCH			(1 << 7)
#define DATA_QPN			0
#define CTRL_QPN			0

#define FCOE_WORD_TO_BYTE		4
#define	FCOE_ENCAPS_LEN_SOF(len, sof)	((FC_FCOE_VER << 14) |	\
					 (((len) & 0x3ff) << 4) | ((sof) & 0xf))
#define	FCOE_DECAPS_LEN(n)		(((n) >> 4) & 0x3ff)
#define	FCOE_DECAPS_SOF(n)		(((n) & 0x8) ? (((n) &	\
					 0xf) + 0x20) : (((n) & 0xf) + 0x30))

#define XNOR(x, y)			(!(x) == !(y))

#define MLX4_PUT(dest, source, offset)				\
do {								\
	void *__d = ((char *) (dest) + (offset));		\
	switch (sizeof(source)) {				\
	case 1:							\
		*(u8 *) __d = (source);				\
		break;						\
	case 2:							\
		*(__be16 *) __d = cpu_to_be16(source);		\
		break;						\
	case 4:							\
		*(__be32 *) __d = cpu_to_be32(source);		\
		break;						\
	case 8:							\
		*(__be64 *) __d = cpu_to_be64(source);		\
		break;						\
	default:						\
		BUG();						\
	}							\
} while (0)

#define OFFSET_IN_PAGE(v)	((u64)(v) & (PAGE_SIZE - 1))
#define SHIFT_TO_SIZE(x)	(1 << (x))
#define SHIFT_TO_MASK(x)	(~((u64) SHIFT_TO_SIZE(x) - 1))

#define MAC_PRINTF_FMT "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_PRINTF_VAR(m) m[0], m[1], m[2], m[3], m[4], m[5]

#define fctgt_err(fmt, arg...) printk(KERN_DEBUG "### Error %s:%d - " fmt, __func__, __LINE__, ## arg)

#if 0
extern int fctgt_dbg_lvl;

#define fctgt_info(fmt, arg...) do { \
	if (fctgt_dbg_lvl & 1) \
		printk(KERN_ERR "### %30s:%-4d - " fmt, __func__, __LINE__, ## arg); \
} while (0)

#define fctgt_dbg_ts(ts, fmt, arg...) do { \
	if (fctgt_dbg_lvl & 2) \
		printk(KERN_ERR "### %30s:%-4d - [%4x:%-4x] " \
			fmt, __func__, __LINE__, ts ? ts->local_exch_id : -1, \
				ts ? ts->remote_exch_id : -1, ## arg); \
} while (0)

#define fctgt_dbg(fmt, arg...) do { \
	if (fctgt_dbg_lvl & 4) \
		printk(KERN_ERR "### %30s:%-4d - " fmt, __func__, __LINE__, ## arg); \
} while (0)

#else
#define fctgt_info(fmt, arg...)
#define fctgt_dbg(fmt, arg...)
#define fctgt_dbg_ts(ts, fmt, arg...)
#endif

#define mfc_q_info_get(q, index, type)				\
	(*((type *)((q)->info + ((index) * sizeof(type)))))

#define mlx4_from_ctlr(fc) container_of(fc, struct mfc_vhba, ctlr)

#define ASSERT(x) do { if (!(x)) { printk("%s:%d ASSERT(" # x ")\n", __FUNCTION__, __LINE__); BUG(); } } while (0)

#define HEXDUMP(ptr, count) do { \
	int i; \
	char buf[1024]; \
	int len = 0; \
	for (i = 0; i < count; ++i) { \
		if (i % 4 == 0) \
			len += snprintf(buf + len, sizeof(buf) - len, "\n%04hx: ", i);\
		len += snprintf(buf + len, sizeof(buf) - len, "%02hx ", *((unsigned char *)(ptr) + i));\
	}\
	printk("%s: %s\n", #ptr, buf);\
} while (0)

struct mfc_vhba;

struct fcoe_hdr_old {
	__be16 fcoe_plen;	/* fc frame len and SOF */
};

struct fcoe_crc_eof_old {
	__be32 fcoe_crc32;	/* CRC for FC packet */
	u8 fcoe_eof;		/* EOF */
} __attribute__ ((packed));

enum mfc_cmd_io_dir {
	FCMD_IO_DIR_TARGET = 0,
	FCMD_IO_DIR_READ,
	FCMD_IO_DIR_WRITE,
	FCMD_IO_DIR_BIDI,
};

struct mfc_basic_config_params {
	__be32 fexch_base;
	u8 nm, nv, np;
	__be32 fexch_base_mpt;
	u8 log_num_rfci;
	__be32 rfci_base;
	__be32 def_fcoe_promisc_qpn;
	__be32 def_fcoe_mcast_qpn;
};

struct mfc_query_port_context {
	u8 supported_port_type;
	u8 actual_port_type;
	__be16 mtu;
	u32 reserved2[3];
	__be64 mac;
};

struct mfc_set_vlan_fltr_mbox {
	__be32 entry[VLAN_FLTR_SIZE];
};

struct mfc_exch_cqe {
	__be32 my_qpn;
	__be32 invalidate_key;
	__be32 seq_id_rqpn_srq;
	__be32 xmit_byte_count;
	__be32 rcv_byte_count;
	__be32 byte_cnt;
	__be16 wqe_index;
	__be16 seq_count;
	u8 reserved[3];
	u8 owner_sr_opcode;
};

enum mfc_link_state {
	LINK_DOWN,
	LINK_UP
};

enum mfc_net_type {
	NET_IB = 1,
	NET_ETH = 2,
};

struct mfc_bitmap {
	unsigned long *addr;
	unsigned size;
	unsigned long last_bit;
};

typedef void (*comp_fn) (void *, struct mlx4_cqe *);

struct mfc_cq {
	struct mlx4_cq mcq;
	struct mlx4_hwq_resources wqres;
	int size;
	int buf_size;
	struct mfc_cqe *buf;
	int size_mask;
	char name[10];
	struct mfc_dev *mfc_dev;
	comp_fn comp_rx;
	comp_fn comp_tx;
	comp_fn comp_err;
	spinlock_t lock;
	void *arg;
};

struct mfc_queue {
	u32 size;
	u32 size_mask;
	u16 stride;
	u32 prod;
	u32 cons;
	void *buf;
	spinlock_t lock;
	void *info;
};

struct mfc_qp {
	struct mlx4_qp mqp;
	u32 buf_size;
	struct mlx4_hwq_resources wqres;
	struct mfc_queue sq;
	struct mfc_queue rq;
	u32 doorbell_qpn;
	int is_created;
	int is_flushing;
};

struct mfc_rfci {
	struct mfc_qp fc_qp;
	struct mfc_cq fc_cq;
	int created;
	int initialized;
};

struct mfc_cmd {
	struct mfc_qp fc_qp;
	struct mfc_cq fc_cq;
};

enum mfc_exch_state {
	FEXCH_OK = 1,
	FEXCH_CMD_DONE,
	FEXCH_SEND_ABORT,
	FEXCH_ABORT_TIMEOUT,
	FEXCH_ABORT
};

struct mfc_exch {
	struct mfc_vhba *vhba;
	struct mfc_qp fc_qp;
	int tx_completed;
	int mtu;
	int fcmd_wqe_idx;
	u8 *response_buf;
	struct completion tm_done;
	enum mfc_exch_state state;
	void *context;
	struct list_head list;
};

struct mfc_fip {
	struct mfc_qp fc_qp;
	struct mfc_cq fc_cq;
	u8 steer_all_enodes_gid[16];
	u8 steer_ethertype_gid[16];
	u8 steer_all_vn2vn_gid[16];
	u8 steer_all_p2p_gid[16];
};

struct mfc_sysfs_attr {
	void *ctx;
	struct kobject *kobj;
	unsigned long data;
	char name[VHBA_SYSFS_LEN];
//	struct module_attribute mattr;
	struct device *dev;
};

struct nport_id {
	u8 reserved;
	u8 fid[3];
};

struct mfctgt {
	struct list_head pending_list;
	void *ctx;
	struct completion comp;
};

/* represents a virtual HBA on a port */
struct mfc_vhba {
	struct list_head list;
	struct mfctgt tgt;
	struct fc_lport *lp;
	struct mfc_port *mfc_port;
	struct fcoe_ctlr *vhba_ctlr;
	struct se_session *vhba_sess;
	int idx;
	int fc_mac_idx;
	u8 fc_mac[ETH_ALEN];
	u8 steer_gid[16];
	int fc_vlan_idx;
	int fc_vlan_id;
	int fc_vlan_prio;
	struct mfc_rfci rfci;
	struct mfc_exch *fexch;
	struct mfc_bitmap fexch_bm;
	int num_fexch;

	struct mfc_cq fexch_cq[NR_CPUS];

	int base_fexch_qpn;
	int base_fexch_mpt;
	int base_reserved_xid;
	int num_reserved_xid;
	enum mfc_net_type net_type;
	u8 dest_addr[ETH_ALEN];
	int dest_ib_lid;
	unsigned long dest_ib_data_qpn;
	int dest_ib_sl;
	int flogi_finished;
	struct nport_id my_npid;
	int fc_payload_size;
	u16 flogi_oxid;
	u8 fcoe_hlen;
	u8 rfci_rx_enabled;
	u8 in_reset;
	u8 going_down;

	/* sysfs stuff */
	struct kobject kobj;
#if 0
	struct fc_exch_mgr *emp;
#endif
	struct scsi_host_template sht;

	int (*fcp_req_rx)(struct mfc_vhba *, struct fc_frame *);

};

/* represents a physical port on HCA */
struct mfc_port {
	struct mfc_dev *mfc_dev;
	u8 port;
	enum mfc_net_type net_type;
	int base_rfci_qpn;
	int num_rfci_qps;
	int base_fexch_qpn;
	int base_fexch_mpt;
	int num_fexch_qps;
	int log_num_fexch_per_vhba;
	int initialized;
	int fc_payload_size;
	u8 fcoe_hlen;
	struct mfc_bitmap fexch_bulk_bm;
	struct list_head vhba_list;
	spinlock_t lock;
	//struct mfc_sysfs_attr dentry;
	struct nport_id npid_table[MFC_NUM_NPORT_IDS];
	struct workqueue_struct *rfci_wq;
	struct workqueue_struct *async_wq;
	void *mfc_fip_ctlr;
	void *underdev;
	u8 def_mac[ETH_ALEN];
	u8 wwpn[32];
	struct mfc_fip fip_qp;
	int link_up;
       int fip_mac_idx;
	enum fip_state fip_mode;
	struct fc_lport *lport;
	struct delayed_work link_work;

	/* sysfs */
	struct kobject kobj;
	struct mlx4_fc_port mlx4_fc_port;
};

/* represents a single HCA */
struct mfc_dev {
	struct list_head list;
	struct mlx4_dev *dev;
	struct mfc_port mfc_port[MLX4_MAX_PORTS + 1];
	struct list_head pgdir_list;
	struct mutex pgdir_mutex;
	void __iomem *uar_map;
	struct mlx4_uar priv_uar;
	u32 priv_pdn;
	struct mlx4_mr mr;
	struct device *dma_dev;
	int idx;
	MLX4_DECLARE_DOORBELL_LOCK(uar_lock);

	/* sysfs */
#if 1
	struct device class_dev;
#endif
};

struct mfc_rfci_rx_info {
	struct mfc_vhba *vhba;
	struct sk_buff *skb;
	struct work_struct work;
};

struct mfc_flogi_finished_info {
	struct work_struct work;
	struct sk_buff *skb;
	u8 eof;
	struct fc_lport *lp;
};

struct mfc_ctrl_seg {
	__be32 op_own;
	__be16 vlan;
	__be16 size;
	__be32 flags;
	__be32 parameter;
};

struct mfc_datagram_seg {
	__be32 fl_portn_pd;
	u8 reserved1;
	u8 mlid_grh;
	__be16 rlid;
	u8 reserved2;
	u8 mgid_idx;
	u8 stat_rate;
	u8 hop_limit;
	__be32 sl_tclass_flabel;
	__be32 rgid[4];
	__be32 dqpn;
	__be32 qkey;
	__be32 reserved3[2];
};				/* size 12 dwords */

struct mfc_radr_seg {
	__be64 addr;
	__be32 rkey;
	__be32 reserved;
};

struct mfc_data_seg {
	__be32 count;
	__be32 mem_type;
	__be64 addr;
};

struct mfcoe_rfci_tx_desc {
	struct mfc_ctrl_seg ctrl;
	struct mfc_data_seg data;	/* at least one data segment */
};				/* size 8 dwords */

struct mfcoib_rfci_tx_desc {
	struct mfc_ctrl_seg ctrl;
	struct mfc_datagram_seg dgram;
	struct mfc_data_seg data;	/* at least one data segment */
};				/* size 20 dwords */

struct mfc_rx_desc {
	struct mfc_data_seg data[0];
};

struct mfc_eth_addr_seg {
	u8 static_rate;
	u8 reserved1[3];
	__be32 reserved2;
	u8 vlan_prio;
	u8 reserved3[1];
	u8 dmac[6];
};

struct mfc_init_seg {
	u8 reserved1;
	u8 pe;
	u16 reserved;
	u8 cs_ctl;
	u8 seq_id_tx;
	__be16 mtu;
	u8 remote_fid[3];
	u8 flags;
	__be16 remote_exch;
	__be16 local_exch_idx;
};

struct mfcoe_cmd_tx_desc {
	struct mfc_ctrl_seg ctrl;
	struct mfc_eth_addr_seg addr;
	struct mfc_init_seg init;
};

struct mfcoe_cmd_rdma_desc {
	struct mfc_ctrl_seg ctrl;
	struct mfc_eth_addr_seg addr; /* This segment is needed by HW but
				       * ignored */
	struct mfc_data_seg data;
};

struct mfcoe_cmd_send_tx_desc {
	struct mfc_ctrl_seg ctrl;
	struct mfc_data_seg data;
};

struct mfcoib_cmd_tx_desc {
	struct mfc_ctrl_seg ctrl;
	struct mfc_datagram_seg addr;
	struct mfc_init_seg init;
	struct mfc_data_seg data;
};

struct mfc_rx_thread {
	int cpu;
	struct task_struct *thread;
	struct sk_buff_head rx_list;
};

enum mfc_tgt_trans_type {
	MFC_TGT_RDMA_READ = 0,
	MFC_TGT_RDMA_WRITE = 1,
};

struct trans_start {
	enum mfc_tgt_trans_type type;
	u32 rport_id;
	u32 remote_exch_id;
	u32 local_exch_id;

	void *fcp_rsp;
	u32 fcp_rsp_len;

	u64 offset;
	u32 key;
	u32 xfer_len;

	u32 tgt_buf_id;

	int (*done)(struct mfc_vhba *, struct trans_start *);
};

static inline void *vhba_priv(const struct mfc_vhba *vhba)
{
	return (void *)(vhba + 1);
}

static inline struct mfc_vhba *containing_vhba(void *priv)
{
	return ((struct mfc_vhba *)priv) - 1;
}

static inline int mlx4_qp_to_reset(struct mlx4_dev *dev, struct mlx4_qp *qp)
{
	return mlx4_cmd(dev, 0, qp->qpn, 2,
			MLX4_CMD_2RST_QP, MLX4_CMD_TIME_CLASS_A,
			MLX4_CMD_NATIVE);
}

static inline int mlx4_qp_to_error(struct mlx4_dev *dev, struct mlx4_qp *qp)
{
	return mlx4_cmd(dev, 0, qp->qpn, 0,
			MLX4_CMD_2ERR_QP, MLX4_CMD_TIME_CLASS_A,
			MLX4_CMD_NATIVE);
}

#define mfc_bitmap_empty(bm)					\
	(find_first_bit((bm)->addr, (bm)->size) >= (bm)->size)

static inline int mfc_bitmap_alloc(struct mfc_bitmap *bitmap, unsigned size)
{
	bitmap->addr = kzalloc(sizeof(unsigned long) * BITS_TO_LONGS(size),
			       GFP_KERNEL);
	if (!bitmap->addr)
		return -ENOMEM;

	bitmap->size = size;
	bitmap->last_bit = size - 1;

	return 0;
}

static inline void mfc_bitmap_free(struct mfc_bitmap *bitmap)
{
	kfree(bitmap->addr);
	bitmap->addr = NULL;
}

static inline int mfc_bitmap_slot_alloc(struct mfc_bitmap *bm, int from_zero)
{
	int slot_num, last_bit = bm->last_bit + 1;

	if (from_zero)
		last_bit = 0;
	do {
		slot_num = find_next_zero_bit(bm->addr, bm->size,
					      last_bit % bm->size);
		if (slot_num >= bm->size) {
			slot_num = find_first_zero_bit(bm->addr, bm->size);
			if (slot_num >= bm->size)
				return -1;
		}
	} while (test_and_set_bit(slot_num, bm->addr));

	bm->last_bit = slot_num;
	return slot_num;
}

static inline void mfc_bitmap_slot_free(struct mfc_bitmap *bm, int slot_num)
{
	if (slot_num >= bm->size)
		printk(KERN_WARNING
		       "Error: Trying to free out of bound slot number\n");
	clear_bit(slot_num, bm->addr);
}

static inline char *mfc_bitmap_print(struct mfc_bitmap *bm)
{
#define BM_STR_BUF_LEN 1024
	static char buf[BM_STR_BUF_LEN];
	int i;
	int len = 0;

	len +=
	    snprintf(buf + len, BM_STR_BUF_LEN - len, "size: %d, ", bm->size);

	for (i = 0; i < BITS_TO_LONGS(bm->size); i++) {
		len += snprintf(buf + len, BM_STR_BUF_LEN - len, "%08llx ",
				cpu_to_be64(bm->addr[i]));
	}

	buf[len] = '\0';
	return buf;
}

static inline void mfc_ring_db_tx(struct mfc_qp *fc_qp)
{
	struct mfc_queue *sq = &fc_qp->sq;

	wmb();
	*fc_qp->wqres.db.db = cpu_to_be32(sq->prod & 0xffff);
	wmb();
}

static inline void mfc_ring_db_rx(struct mfc_qp *fc_qp)
{
	struct mfc_queue *rq = &fc_qp->rq;

	wmb();
	*fc_qp->wqres.db.db = cpu_to_be32(rq->prod & 0xffff);
	wmb();
}

extern int mfc_num_reserved_xids;
extern int mfc_t11_mode;
extern int mfc_debug_mode;

extern int mfc_create_rfci(struct mfc_vhba *);
extern int mfc_destroy_rfci(struct mfc_vhba *);
extern int mfc_init_rfci(struct mfc_vhba *);
extern int mfc_deinit_rfci(struct mfc_vhba *vhba);

extern int mfc_init_port(struct mfc_dev *, int);
extern void mfc_free_port(struct mfc_dev *, int);

extern int mfc_init_fexchs(struct mfc_vhba *);
extern int mfc_reset_fexchs(struct mfc_vhba *);
extern int mfc_create_fexchs(struct mfc_vhba *);
extern void mfc_destroy_fexchs(struct mfc_vhba *);
extern int mfc_post_rx_buf(struct mfc_dev *, struct mfc_qp *, void *, size_t);
extern int mfc_q_init(struct mfc_queue *, u16, size_t, size_t);
extern void mfc_q_destroy(struct mfc_queue *);
extern void mfc_stamp_q(struct mfc_queue *);
extern int flush_qp(struct mfc_dev *, struct mfc_qp *, int, int,
		    struct mfc_cq *, struct mfc_exch *);
extern int mfc_create_cq(struct mfc_dev *, struct mfc_cq *, int, int, int,
			 comp_fn, comp_fn, comp_fn, void *arg, char *);
extern void mfc_destroy_cq(struct mfc_cq *);
extern void mfc_cq_clean(struct mfc_cq *);
extern void mfc_recv_flogi(struct fc_lport *, struct fc_frame *, u8 mc[6]);
extern int mfc_reset_fexch(struct mfc_vhba *, struct mfc_exch *);
extern int mfc_frame_send(struct fc_lport *, struct fc_frame *);
extern int mfc_send_abort_tsk(struct mfc_exch *, u32);
struct mfc_fip_ctlr;
extern void mlx4_fc_register_fip_ctlr(struct mfc_fip_ctlr *mlx4_fip,
	       enum mfc_net_type net_type);
extern void mlx4_fc_deregister_fip_ctlr(enum mfc_net_type net_type);

struct sk_buff *mfc_alloc_fc_frame(struct mfc_vhba *vhba);
int mfc_send_data(struct mfc_vhba *vhba, struct trans_start *ts);
int mfc_send_resp(struct mfc_vhba *vhba, struct trans_start *ts);

/* sysfs */
int mfc_sysfs_setup(void);
void mfc_sysfs_cleanup(void);
int mfc_device_register_sysfs(struct mfc_dev *device);
void mfc_device_unregister_sysfs(struct mfc_dev *device);
int mfc_port_register_sysfs(struct mfc_port *mfc_port);
void mfc_port_deregister_sysfs(struct mfc_port *mfc_port);
int mfc_vhba_register_sysfs(struct mfc_vhba *mfc_vhba);
void mfc_vhba_deregister_sysfs(struct mfc_vhba *mfc_vhba);

int mlx4_fc_register_configfs(void);
void mlx4_fc_deregister_configfs(void);

struct ib_umem;

/* mfct */
struct mem_buf {
	struct list_head list;

	u64 tgt_buf_id;
	void __user *uaddr;
	u32 count;

	u32 offset;
	u32 lkey;
	u32 rkey;
	struct mlx4_fmr fmr;
	unsigned int nr_pages;

	struct ib_umem *umem;
};

int fctgt_dev_register(struct mfc_fip_ctlr *fip_ctrl);
int fctgt_dev_deregister(void);
int fctgt_vhba_entail(struct mfc_vhba *vhba);
int fctgt_notify_flogi_acc(struct mfc_vhba *vhba, struct fc_seq *seq, struct fc_frame *fp);

/* umem */
int fctgt_map_fmr(struct mfc_vhba *vhba, struct mem_buf *mem_buf,
		enum dma_data_direction dir);
int fctgt_unmap_fmr(struct mfc_vhba *vhba, struct mem_buf *mem_buf);

u64 mac_to_u64(u8 *mac);
#endif /* MFC_H */
