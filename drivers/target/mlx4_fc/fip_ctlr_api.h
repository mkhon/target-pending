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

#ifndef FIP_CTLR_API_H
#define FIP_CTLR_API_H

/* This .h file is used to integrate the mlx4_fc module with
 * the FCoIB/FCoE discovery modules.
 *
 * mlx4_fc will implement these functions.
 */

struct mfc_fip_ctlr {
	void (*add_port)(struct mfc_port *);
	void (*rem_port)(struct mfc_port *);
	void (*link_state_changed)(struct mfc_port *);
	int (*els_send)(struct mfc_vhba *, struct sk_buff *skb);
	void (*fip_rx)(struct mfc_port *, int vlan_id, struct sk_buff *);
	struct fcoe_ctlr *(*create_fcoe_ctlr)(struct mfc_port *);
	void (*start_fcoe_ctlr)(struct mfc_port *, struct fcoe_ctlr *);
	struct fc_seq *(*elsct_send)(struct fc_lport *, u32, struct fc_frame *,
				     unsigned int, void (*resp)(struct fc_seq *,
				     struct fc_frame *, void *), void *, u32);
};

void mlx4_fc_register_fip_ctlr(struct mfc_fip_ctlr *mlx4_fip, enum mfc_net_type net_type);
void mlx4_fc_deregister_fip_ctlr(enum mfc_net_type net_type);
void mlx4_fc_rescan_ports(enum mfc_net_type net_type);
struct mfc_port *mlx4_fc_get_port_by_wwpn(const char *wwpn);

struct fc_lport *mfc_create_lport(struct mfc_port *, u64, u64, struct module *);

struct mfc_vhba *mfc_create_vhba_fcoe(struct mfc_port *mfc_port, int vlan_id,
		int mtu, int priv_size, struct module *owner);
struct mfc_vhba *mfc_create_vhba_fcoib(struct mfc_port *fc_port, unsigned int mtu,
		u64 wwpn, u64 wwnn, int priv_size, struct module *owner);
void mfc_destroy_vhba(struct mfc_vhba *vhba);
void mfc_update_src_mac(struct mfc_vhba *vhba, u8 *addr);
void mfc_update_gw_addr_eth(struct mfc_vhba *vhba, u8 *mac, u8 prio);
void mfc_update_gw_addr_ib(struct mfc_vhba *vhba, u16 lid, u32 qpn, u8 sl);
int mfc_flogi_finished(struct mfc_vhba *vhba, u8 *my_npid);
u8 *mfc_get_src_addr(struct fc_lport *lp);
u32 mfc_get_src_qpn(struct mfc_vhba *vhba);
void mfc_get_vhba_fcid(struct mfc_vhba *, u8 *fcid);
int mfc_fip_tx(struct mfc_port *mfc_port, struct sk_buff *skb, int vlan_id, int vlan_prio);

struct mfc_port_attribute {
	struct attribute attr;
	ssize_t (*show)(struct mfc_port *, struct mfc_port_attribute *, char *buf);
	ssize_t (*store)(struct mfc_port *, struct mfc_port_attribute *,
			 const char *buf, size_t count);
};

#define PORT_ATTR(_name, _mode, _show, _store) \
struct mfc_port_attribute mfc_port_attr_##_name = __ATTR(_name, _mode, _show, _store)

#define PORT_ATTR_RO(_name) \
struct mfc_port_attribute mfc_port_attr_##_name = __ATTR_RO(_name)

int mfc_port_attr_add(struct mfc_port *mfc_port, struct mfc_port_attribute *attr);
void mfc_port_attr_remove(struct mfc_port *mfc_port, struct mfc_port_attribute *attr);

#endif /* FIP_CTLR_API_H */
