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

#ifndef MLX4_FCOIB_H
#define MLX4_FCOIB_H

#include <linux/netdevice.h>
#include <linux/in.h>
#include <net/dst.h>
#include <rdma/ib_verbs.h>
#include <rdma/ib_pack.h>
#include <rdma/ib_sa.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/workqueue.h>
#include <linux/version.h>

struct fip_dev_priv;

/* Extern Variables */
extern int fip_debug;
extern struct workqueue_struct *fip_workqueue;

/* definitions */
#define DRV_NAME  "mlx4_fcoib"

#define	FIP_OP_RECV	(1ul << 31)
#define FIP_UD_MTU(ib_mtu)	(ib_mtu - FIP_ENCAP_LEN - FIP_ETH_HEADER_LEN)
#define FIP_UD_BUF_SIZE(ib_mtu)	(ib_mtu + IB_GRH_BYTES)
#define	FIP_MAX_BACKOFF_SECONDS	16
#define	FIP_MAX_VHBAS_PER_GW	256
#define FIP_DISCOVER_NUM_MCAST		2

#define VHBAS_BITMASK	(FIP_MAX_VHBAS_PER_GW / 8 / sizeof(unsigned long))
#define DELAYED_WORK_CLEANUP_JIFFS	2

enum debug_print_level {
	LOG_PRIO_HIGH = 1,
	LOG_PRIO_MED = 2,
	LOG_PRIO_LOW = 3,
	LOG_PRIO_VERY_LOW = 4
};

#define fip_dev_printk(level, priv, format, arg...)			\
	printk(level "mlx4_fcoib: %s:%d: " format,		\
		((struct fip_dev_priv *) priv)->ca->name,	\
		((struct fip_dev_priv *) priv)->port, ## arg)

#define fip_dev_err(priv, format, arg...)				\
	fip_dev_printk(KERN_ERR, priv, format , ## arg)

#define fip_dev_warn(priv, format, arg...)				\
	fip_dev_printk(KERN_WARNING, priv, format , ## arg)

#define fip_dev_dbg(priv, level, format, arg...)			\
	if (fip_debug >= level)					\
		fip_dev_printk(KERN_WARNING, priv, format , ## arg)

#define fip_gw_printk(level, gw, format, arg...)			\
	printk(level "mlx4_fcoib: %s:%d gw_%x:%x: " format,		\
		((struct fip_gw_data *) gw)->priv->ca->name,	\
		((struct fip_gw_data *) gw)->priv->port, \
		((struct fip_gw_data *) gw)->info.gw_lid, \
		((struct fip_gw_data *) gw)->info.gw_port_id, \
		## arg)

#define fip_gw_err(gw, format, arg...)				\
	fip_gw_printk(KERN_ERR, gw, format , ## arg)

#define fip_gw_warn(gw, format, arg...)				\
	fip_gw_printk(KERN_WARNING, gw, format , ## arg)

#define fip_gw_dbg(gw, level, format, arg...)			\
	if (fip_debug >= level)					\
		fip_gw_printk(KERN_WARNING, gw, format , ## arg)

#define FCOIB_FIP_QKEY	0x80020004

struct fip_mcast {
	struct login_ctx *login;
	char name[ETH_ALEN * 2 + IFNAMSIZ];
	u8 mac[ETH_ALEN];
	int vid;
	union ib_gid gid;
	u8 rss;
	struct rb_node rb_node;
	struct mcast_entry *mcast_data;
};

struct port_mcast_data {
	struct list_head multicast_list;
	struct delayed_work mcast_task;
	struct mutex mlock;
	unsigned long flags;

	u8 port;
	struct ib_pd *pd;
	union ib_gid local_gid;
	unsigned int mcast_mtu;
	int rate;
	struct ib_device *ca;
};

enum mcast_join_state {
	MCAST_FLAG_USED = 0,
	MCAST_FLAG_SEND = 1,
	MCAST_FLAG_RECV = 2,
	MCAST_FLAG_BUSY = 3,
	MCAST_FLAG_JOINED = 4,
	MCAST_FLAG_DONE = 5,
	MCAST_FLAG_ATTACHED = 6,
	MCAST_FLAG_AH_SET = 7,
	MCAST_FLAG_REMOVED = 8
};

enum mcast_join_type {
	MCAST_SEND_RECEIVE = 0,
	MCAST_RECEIVE_ONLY = 1,
	MCAST_SEND_ONLY = 2,
};

enum {
	MCAST_TASK_RUN = 1,
	MCAST_TASK_STOPPED = 2,
};

struct mcast_entry {
	struct ib_sa_multicast *sa_mcast;
	struct ib_sa_mcmember_rec mcmember;
	struct list_head list;
	unsigned long flags;
	struct ib_ah *ah;
	struct port_mcast_data *port_mcast;
	atomic_t ref_cnt;
	int backoff;
	void (*callback) (struct mcast_entry *, void *context);
	void *context;
	struct ib_qp *qp;
	u32 qkey;
	u32 pkey;
};

enum {
	FIP_ETH_HEADER_LEN = 14,
	FIP_ENCAP_LEN = 4,
	FIP_PROTOCOL_RX_SIZE = 64,	/* must be power of 2 */
	FIP_PROTOCOL_TX_SIZE = 64,	/* must be power of 2 */
};

enum fip_packet_type {
	FIP_DISCOVER_UCAST = 0,
	FIP_DISCOVER_MCAST = 1
};

struct ring_entry {
	char *mem;
	u64 bus_addr;
	int length;
};

struct ring {
	int size;
	struct ring_entry *ring;
	int head;
	int tail;
};

enum fip_discover_state {
	FIP_DISCOVER_OFF,
	FIP_DISCOVER_INIT,
	FIP_DISCOVER_SOLICIT,
	FIP_DISCOVER_LOGIN
};

struct fip_discover {
	spinlock_t lock;
	struct list_head gw_list;
	struct list_head gw_rm_list;
	struct rw_semaphore gw_list_rwsem; /* protect both gw_list and gw_rm_list */
	enum fip_discover_state state;
	int flush;
	struct semaphore flush_done;
	struct ib_cq *cq;
	struct ib_qp *qp;
	struct ring rx_ring;
	struct ring tx_ring;

	u16 pkey;
	u16 pkey_index;
	struct delayed_work task;
	struct delayed_work cleanup_task;
	struct work_struct pkt_rcv_task;
	struct work_struct mcast_refresh_task;

	int mcast_dest_mask;
	struct mcast_entry *mcast[FIP_DISCOVER_NUM_MCAST];

	int backoff_time;
};

enum fip_gw_state {
	FIP_GW_RESET,
	FIP_GW_RCVD_UNSOL_AD,
	FIP_GW_SENT_SOL,
	FIP_GW_RCVD_SOL_AD,
	FIP_GW_WAITING_FOR_FLOGI,
	FIP_GW_SENT_FLOGI,
	FIP_GW_RCVD_FLOGI_ACCPT,
};

struct fip_gw_data_info {
	int flags;
	u32 gw_qpn;
	u32 gw_data_qpn;
	u16 gw_lid;
	u16 gw_port_id;
	u8 gw_guid[8];
	u8 switch_name[8];
	u8 fabric_name[8];
	u32 keep_alive_frq;
	u8 gw_vendor_id[9];
	u8 priority;
	u16 pkey;
	u8 sl;
};

struct fip_vhba {
	struct fip_gw_data *gw;
};

struct fip_gw_data {
	int flush;
	struct fip_dev_priv *priv;
	struct list_head list;
	enum fip_gw_state state;
	struct list_head fip_destroy;
	struct delayed_work gw_task;
	struct delayed_work fip_cleanup_task;
	struct fip_gw_data_info info;
	unsigned long bitmask[VHBAS_BITMASK];

	/* vHBA info - currently support single vHBA per gw */
	struct fip_vhba *fip_vhba;

	/* unified timers */
	unsigned long vhba_ka_tmr;
	int vhba_ka_tmr_valid;
	unsigned long gw_ka_tmr;
	int gw_ka_tmr_valid;
	unsigned long host_ka_tmr;
	int host_ka_tmr_valid;

	/* sysfs */
	struct kobject kobj;
};

enum fip_gw_data_flags {
	FIP_IS_FIP = 1,		/* protocol type */
	FIP_RCV_MULTICAST = 1 << 1,	/* received mcast packet */
	FIP_GW_AVAILABLE = 1 << 2,	/* GW available bit set in pkt */
	FIP_HOST_ASSIGNED_VLAN = 1 << 3	/* H bit set in advertise pkt */
};

struct fip_dev_priv {
	spinlock_t lock;
	struct mutex mlock;
	struct fip_discover discover;
	struct port_mcast_data mcast;

	struct mfc_port *mfc_port;

	struct delayed_work restart_task;
	struct ib_device *ca;
	u8 port;
	u16 pkey;
	u16 pkey_index;
	struct ib_pd *pd;
	struct ib_mr *mr;
	union ib_gid local_gid;
	u16 local_lid;

	int max_mtu_enum;
	unsigned int mtu;
	unsigned int mcast_mtu;
	int rate;
	unsigned int max_ib_mtu;
	struct ib_event_handler event_handler;
	struct list_head list;

	int hca_caps;

};

extern int fip_auto_create;

/*
 * send a single multicast packet.
 */
int fip_mcast_send(struct fip_dev_priv *priv, struct ib_qp *qp,
		   unsigned int wr_id, u64 mapping, int size,
		   u16 pkey_index, struct mcast_entry *mcast);
/*
 * send a single unicast packet.
 */
int fip_ucast_send(struct fip_dev_priv *priv, struct ib_qp *qp,
		   unsigned int wr_id, u64 mapping, int size,
		   u16 pkey_index, u32 dest_qpn, u16 dlid, u32 qkey);

int fip_init_qp(struct fip_dev_priv *priv, struct ib_qp *qp,
		u16 pkey_index, u32 qkey);
int fip_post_receive(struct fip_dev_priv *priv, struct ib_qp *qp, int size,
		     int id, char *mem, struct ring_entry *mem_entry);

void fip_flush_rings(struct fip_dev_priv *priv, struct ib_cq *cq,
		     struct ib_qp *qp, struct ring *rx, struct ring *tx);
void fip_free_rings(struct fip_dev_priv *p, struct ring *rx, struct ring *tx);

int fip_init_tx(struct fip_dev_priv *priv, int size, struct ring *tx_ring);
int fip_init_rx(struct fip_dev_priv *priv, int size,
		struct ib_qp *qp, struct ring *rx_ring);
int fip_comp(struct fip_dev_priv *priv, struct ib_cq *cq,
	     struct ring *rx_ring, struct ring *tx_ring);
void fip_discover_comp(struct ib_cq *cq, void *dev_ptr);
void fip_discover_fsm(struct work_struct *work);
int fip_discover_rx_packet(struct fip_dev_priv *priv, int index);
void fip_discover_process_rx(struct work_struct *work);

void fip_discover_mcast_connect_cb(struct mcast_entry *mcast,
				   void *discover_context);
struct mcast_entry *fip_mcast_join(struct port_mcast_data *port_mcast,
				    void *context, const char *mgid, u32 qkey,
				    u16 pkey, struct ib_qp *qp,
				    enum mcast_join_type type,
				    void (*callback) (struct mcast_entry *,
						      void *context));
void fip_mcast_free(struct mcast_entry *mcast);
int fip_mcast_stop_thread(struct port_mcast_data *port_mcast);
void fip_mcast_join_task(struct work_struct *work);

int fip_free_gw_list(struct fip_dev_priv *priv);
void fip_refresh_mcasts(struct work_struct *work);

int fip_dev_init(struct fip_dev_priv *priv);
void fip_dev_cleanup(struct fip_dev_priv *priv);
int fip_discover_init(struct fip_dev_priv *priv);
void fip_discover_cleanup(struct fip_dev_priv *priv);
int fip_discover_flush(struct fip_discover *discover, int unload);

struct mfc_vhba *create_vhba_for_gw(struct fip_gw_data *gw, u64 wwpn);
struct fip_gw_data *fip_discover_create_gw(struct fip_dev_priv *priv,
		u8 *gw_guid, u16 gw_port_id);
void fip_close_gw(struct fip_gw_data *gw);
struct fip_gw_data *fip_find_gw(struct fip_discover *discover,
		u8 *gw_guid, u16 gw_port_id);

int mfc_fcf_register_sysfs(struct fip_gw_data *fcf);
void mfc_fcf_deregister_sysfs(struct fip_gw_data *fcf);
int mfc_fcf_add_vhba_link(struct fip_gw_data *fcf);

#endif /* MLX4_FCOIB_H */
