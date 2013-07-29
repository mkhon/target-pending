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
#include <linux/kernel.h>
#include <linux/vmalloc.h>
#include <linux/if_vlan.h>
#include <scsi/fc/fc_fip.h>

//#include "fcoib.h"
//#include "fcoib_api.h"
#include "mfc.h"
#include "fip_ctlr_api.h"

MODULE_DESCRIPTION("FCoE Discovery");
MODULE_LICENSE("Dual BSD/GPL");

struct fcf {
	struct mfc_vhba *vhba;
	struct fcoe_ctlr ofc_ctlr;
	struct mlx4_fcoe_fip *fcoe_fip;
};

struct mlx4_fcoe_fip {
	struct mfc_port *mfc_port;
	struct work_struct create_vhba_work;
	struct delayed_work vlan_req_work;
	struct {
		u8 mac[6];
		u16 vlan_id;
		struct fcf *fcf;
	} selected_fcf;
};

struct fip_vlan_req {
	struct ethhdr eh;
	struct fip_header fh;
	struct fip_mac_desc mac;
} __attribute__((packed));

struct fip_vlan_desc {
	struct fip_desc fd_desc;
	__u16		fd_vlan;
} __attribute__((packed));

struct fip_vlan_res {
	struct ethhdr eh;
	struct fip_header fh;
	struct fip_mac_desc mac;
	struct fip_vlan_desc vlan;
} __attribute__((packed));

static void u64_to_mac(u8 mac[6], u64 u64mac)
{
	int i;

	for (i = 5; i >= 0; i--) {
		mac[i] = u64mac & 0xff;
		u64mac >>= 8;
	}
}

static void fip_send(struct fcoe_ctlr *ofc_ctlr, struct sk_buff *skb)
{
	struct fcf *fcf = container_of(ofc_ctlr, struct fcf, ofc_ctlr);
	struct mlx4_fcoe_fip *fip = fcf->fcoe_fip;

	mfc_fip_tx(fip->mfc_port, skb, fip->selected_fcf.vlan_id, 3);
}

static void create_vhba(struct work_struct *work);

static void fip_rx_vlan_resp(struct mfc_port *mfc_port, struct sk_buff *skb)
{
	struct mlx4_fcoe_fip *fip = (struct mlx4_fcoe_fip *)mfc_port->mfc_fip_ctlr;
	struct fip_vlan_res *msg;

	msg = (struct fip_vlan_res *)skb->data;

	if ((msg->fh.fip_dl_len < htons((sizeof(msg->mac) +
						sizeof(msg->vlan)) / FIP_BPW)) ||
			(msg->mac.fd_desc.fip_dtype != FIP_DT_MAC) ||
			(msg->mac.fd_desc.fip_dlen != sizeof(msg->mac) / FIP_BPW) ||
			(msg->vlan.fd_desc.fip_dtype != FIP_DT_VLAN) ||
			(msg->vlan.fd_desc.fip_dlen != sizeof(msg->vlan) / FIP_BPW))
		goto out_free_skb;

	cancel_delayed_work(&fip->vlan_req_work);

	/*
	dev_info(&mfc_port->mfc_dev->dev->pdev->dev,"port %d: "
			"FCF %02x:%02x:%02x:%02x:%02x:%02x "
			"servicing on VLAN %d\n",
		mfc_port->port,
		msg->mac.fd_mac[0], msg->mac.fd_mac[1],
		msg->mac.fd_mac[2], msg->mac.fd_mac[3],
		msg->mac.fd_mac[4], msg->mac.fd_mac[5],
		ntohs(msg->vlan.fd_vlan) & 0x0fff);
	*/

	if (fip->selected_fcf.fcf) {
		/*
		dev_info(&mfc_port->mfc_dev->dev->pdev->dev,"port %d: "
				"Already have FCF servicing this port, ignoring\n",
				mfc_port->port);
		*/
		goto out_free_skb;
	}

	memcpy(fip->selected_fcf.mac, msg->mac.fd_mac, ETH_ALEN);
	fip->selected_fcf.vlan_id = ntohs(msg->vlan.fd_vlan) & 0x0fff;

	schedule_work(&fip->create_vhba_work);

out_free_skb:
	kfree_skb(skb);
}

static void fip_rx(struct mfc_port *mfc_port, int vlan_id, struct sk_buff *skb)
{
	struct mlx4_fcoe_fip *fip = (struct mlx4_fcoe_fip *)mfc_port->mfc_fip_ctlr;
	struct fip_vlan_res *msg;

	msg = (struct fip_vlan_res *)skb->data;

	if (msg->fh.fip_ver != FIP_VER_ENCAPS(FIP_VER)) {
		printk(KERN_WARNING "mlx4_fcoe: warning: got FIP message with "
				"wrong FIP version: 0x%x\n", msg->fh.fip_ver);
		goto out_free_skb;
	}

	if ((msg->fh.fip_op == htons(FIP_OP_VLAN)) &&
			(msg->fh.fip_subcode == FIP_SC_VL_REP)) {
		fip_rx_vlan_resp(mfc_port, skb);
		return;
	}

	/* other FIP messages forwarded to internal OFC FIP controller */
	if (fip->selected_fcf.fcf &&
		(fip->selected_fcf.vlan_id == vlan_id)) {
		skb_reset_mac_header(skb);
		skb->data = skb_pull(skb, sizeof(struct ethhdr));
		fcoe_ctlr_recv(&fip->selected_fcf.fcf->ofc_ctlr, skb);
	}

	return;

out_free_skb:
	kfree_skb(skb);
}

static void flogi_resp(struct fc_seq *seq, struct fc_frame *fp, void *arg)
{
	struct fcf *fcf = arg;
	struct mfc_vhba *vhba = fcf->vhba;
//	struct fc_lport *lport = vhba->lp;
	u8 *mac;

	fctgt_dbg("RX: FLOGI RES\n");
//	printk("Got flogi response: err: %ld\n", IS_ERR(fp));
	if (IS_ERR(fp))
		goto done;

	mac = fr_cb(fp)->granted_mac;
	/* pre-FIP
	if (is_zero_ether_addr(mac) && vhba->net_type == NET_ETH) {
		if (fcoe_ctlr_recv_flogi(fip, lport, fp)) {
			fc_frame_free(fp);
			return;
		}
	}
	*/

	ASSERT(vhba->net_type == NET_ETH);

	/* TODO: take prio from DCBX, or let mlx4_fc do that */
	mfc_update_gw_addr_eth(vhba, fcf->ofc_ctlr.dest_addr, 3);
	mfc_update_src_mac(vhba, mac);
	mfc_flogi_finished(vhba, fc_frame_header_get(fp)->fh_d_id);
done:
	fc_lport_flogi_resp(seq, fp, vhba->lp);
	fctgt_notify_flogi_acc(vhba, seq, fp);

}

static void logo_resp(struct fc_seq *seq, struct fc_frame *fp, void *arg)
{
	struct fcf *fcf = arg;
	struct mfc_vhba *vhba = fcf->vhba;
	struct fc_lport *lport = vhba->lp;
	static u8 zero_mac[ETH_ALEN] = { 0 };

	if (!IS_ERR(fp))
		mfc_update_src_mac(vhba, zero_mac);
	fc_lport_logo_resp(seq, fp, lport);
}

static struct fc_seq *elsct_send(struct fc_lport *lport, u32 did,
				     struct fc_frame *fp, unsigned int op,
				     void (*resp) (struct fc_seq *,
						   struct fc_frame *,
						   void *), void *arg,
						   u32 timeout)
{
	struct mfc_vhba *vhba = lport_priv(lport);
	struct fcf *fcf = vhba_priv(vhba);
	struct fc_frame_header *fh = fc_frame_header_get(fp);

	switch (op) {
	case ELS_FLOGI:
	case ELS_FDISC:
		return fc_elsct_send(lport, did, fp, op, flogi_resp,
				     fcf, timeout);
	case ELS_LOGO:
		/* only hook onto fabric logouts, not port logouts */
		if (ntoh24(fh->fh_d_id) != FC_FID_FLOGI)
			break;
		return fc_elsct_send(lport, did, fp, op, logo_resp,
				     fcf, timeout);
	}
	return fc_elsct_send(lport, did, fp, op, resp, arg, timeout);
}

static void ofc_update_src_mac(struct fc_lport *lport, u8 *mac)
{
	shost_printk(KERN_INFO, lport->host, "ofc ctlr called update_mac(). Should not happen.\n");
}

static void create_vhba(struct work_struct *work)
{
	struct mlx4_fcoe_fip *fip =
		container_of(work, struct mlx4_fcoe_fip, create_vhba_work);
	struct fcf *fcf;
	struct mfc_vhba *vhba;

	vhba = mfc_create_vhba_fcoe(fip->mfc_port, fip->selected_fcf.vlan_id,
			2200, sizeof(struct fcf), THIS_MODULE);
	if (IS_ERR(vhba)) {
		printk("ERROR: could not create vhba, err=%ld\n", PTR_ERR(vhba));
		return;
	}

	fcf = vhba_priv(vhba);
	fcf->vhba = vhba;
	fcf->fcoe_fip = fip;
	fip->selected_fcf.fcf = fcf;

	fcoe_ctlr_init(&fcf->ofc_ctlr, FIP_MODE_AUTO);
	fcf->ofc_ctlr.send = fip_send;
	fcf->ofc_ctlr.update_mac = ofc_update_src_mac;
	fcf->ofc_ctlr.get_src_addr = mfc_get_src_addr;
	fcf->ofc_ctlr.lp = vhba->lp;
	vhba->lp->tt.elsct_send = elsct_send;

	/* setup Source Mac Address */
	if (!fcf->ofc_ctlr.spma)
		memcpy(fcf->ofc_ctlr.ctl_src_addr, fip->mfc_port->def_mac,
		       ETH_ALEN);

	fcoe_ctlr_link_up(&fcf->ofc_ctlr);
#warning FIXME: fctgt_vhba_entail in create_hba
#if 0
	fctgt_vhba_entail(vhba);
#endif

}

static int els_send(struct mfc_vhba *vhba, struct sk_buff *skb)
{
	struct fcf *fcf = vhba_priv(vhba);

	if (!vhba->mfc_port->link_up)
		return 0;

	return !fcoe_ctlr_els_send(&fcf->ofc_ctlr, vhba->lp, skb);
}

static void send_vlan_request(struct mlx4_fcoe_fip *fip)
{
	struct mfc_port *mfc_port = fip->mfc_port;
	struct sk_buff *skb;
	struct fip_vlan_req *msg;
	int err;

	struct mlx4_caps *caps = &mfc_port->mfc_dev->dev->caps;
	u8 smac[ETH_ALEN];

	u64_to_mac(smac, caps->def_mac[fip->mfc_port->port]);

	skb = dev_alloc_skb(sizeof *msg);
	if (!skb)
		return;

	msg = (struct fip_vlan_req *)skb->data;
	memset(msg, 0, sizeof *msg);
	memcpy(msg->eh.h_dest, FIP_ALL_FCF_MACS, ETH_ALEN);
	memcpy(msg->eh.h_source, smac, ETH_ALEN);
	msg->eh.h_proto = htons(ETH_P_FIP);
	msg->fh.fip_ver = FIP_VER_ENCAPS(FIP_VER);
	msg->fh.fip_op = htons(FIP_OP_VLAN);
	msg->fh.fip_subcode = FIP_SC_VL_REQ;
	msg->fh.fip_dl_len = htons(sizeof(msg->mac) / FIP_BPW);
	msg->fh.fip_flags = htons(FIP_FL_FPMA);
	msg->mac.fd_desc.fip_dtype = FIP_DT_MAC;
	msg->mac.fd_desc.fip_dlen = sizeof(msg->mac) / FIP_BPW;
	memcpy(msg->mac.fd_mac, smac, ETH_ALEN);

	skb_put(skb, sizeof(*msg));
	skb->protocol = htons(ETH_P_FIP);
	skb_reset_mac_header(skb);
	skb_reset_network_header(skb);
	err = mfc_fip_tx(mfc_port, skb, -1, -1);
	//dev_info(&mfc_port->mfc_dev->dev->pdev->dev, "port %d: sent VLAN req, ret=%d\n", mfc_port->port, err);
	schedule_delayed_work(&fip->vlan_req_work, 8 * HZ);
}

void vlan_req_work(struct work_struct *work)
{
	struct mlx4_fcoe_fip *fip = container_of(work, struct mlx4_fcoe_fip, vlan_req_work.work);
	send_vlan_request(fip);
}

static void link_state_changed(struct mfc_port *mfc_port)
{
	struct mlx4_fcoe_fip *fip = (struct mlx4_fcoe_fip *)mfc_port->mfc_fip_ctlr;
	struct fcf *fcf = fip->selected_fcf.fcf;

	if (!fcf) {
		if (mfc_port->link_up)
			schedule_delayed_work(&fip->vlan_req_work,
					2 * HZ);
		return;
	}

	if (mfc_port->link_up)
		fcoe_ctlr_link_up(&fcf->ofc_ctlr);
	else
		fcoe_ctlr_link_down(&fcf->ofc_ctlr);
}

/*
static ssize_t create_show(struct mfc_port *p, struct mfc_port_attribute *unused,
		char *buf)
{
	return sprintf(buf, "mfc%d port%d this is the create entry\n", p->mfc_dev->idx, p->port);
}

static ssize_t create_store(struct mfc_port *p, struct mfc_port_attribute *unused,
			 const char *buf, size_t count)
{
	printk("mfc%d port%d create string: %*s\n", p->mfc_dev->idx, p->port, (int)count, buf);
	return count;
}

static ssize_t destroy_show(struct mfc_port *p, struct mfc_port_attribute *unused,
		char *buf)
{
	return sprintf(buf, "mfc%d port%d this is the destroy entry\n", p->mfc_dev->idx, p->port);
}

static ssize_t destroy_store(struct mfc_port *p, struct mfc_port_attribute *unused,
			 const char *buf, size_t count)
{
	printk("mfc%d port%d destroy string: %*s\n", p->mfc_dev->idx, p->port, (int)count, buf);
	return count;
}

static PORT_ATTR(create, 0600, create_show, create_store);
static PORT_ATTR(destroy, 0600, destroy_show, destroy_store);
*/

static void add_port(struct mfc_port *mfc_port)
{
	struct mlx4_fcoe_fip *fip;

	fip = kzalloc(sizeof *fip, GFP_ATOMIC);
	if (!fip) {
		printk(KERN_ERR "mfc%d port%d Cound not allocate FCoE FIP controller\n",
			mfc_port->mfc_dev->idx, mfc_port->port);
		return;
	}

	/*
	mfc_port_attr_add(mfc_port, &mfc_port_attr_create);
	mfc_port_attr_add(mfc_port, &mfc_port_attr_destroy);
	*/

	fip->mfc_port = mfc_port;
	mfc_port->mfc_fip_ctlr = fip;
	INIT_WORK(&fip->create_vhba_work, create_vhba);
	INIT_DELAYED_WORK(&fip->vlan_req_work, vlan_req_work);

	if (mfc_port->link_up)
		schedule_delayed_work(&fip->vlan_req_work, 1 * HZ);

	return;
}

static void rem_port(struct mfc_port *mfc_port)
{
	struct mlx4_fcoe_fip *fip = (struct mlx4_fcoe_fip *)mfc_port->mfc_fip_ctlr;

	struct fcf *fcf = fip->selected_fcf.fcf;

	cancel_delayed_work_sync(&fip->vlan_req_work);

	/*
	mfc_port_attr_remove(mfc_port, &mfc_port_attr_create);
	mfc_port_attr_remove(mfc_port, &mfc_port_attr_destroy);
	*/

	if (fcf) {
		if (fcf->vhba)
			mfc_destroy_vhba(fcf->vhba);

		fcoe_ctlr_link_down(&fcf->ofc_ctlr);
		fcoe_ctlr_destroy(&fcf->ofc_ctlr);
	}

	kfree(fip);
	return;
}

static struct mfc_fip_ctlr mlx4_fcoe_fip = {
	.add_port = add_port,
	.rem_port = rem_port,
	.link_state_changed = link_state_changed,
	.els_send = els_send,
	.fip_rx = fip_rx,
};

#warning FIXME: fip_init_module fctgt_dev_register disabled
static int __init fip_init_module(void)
{
	int rc = 0;
#if 0
	rc = fctgt_dev_register(&mlx4_fcoe_fip);
#endif
	return rc;
}

static void __exit fip_cleanup_module(void)
{
#if 0
	fctgt_dev_deregister();
#endif
}

module_init(fip_init_module);
module_exit(fip_cleanup_module);
