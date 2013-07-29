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

#include <scsi/libfc.h>
#include "mfc.h"
#include "fip_ctlr_api.h"


/* ============== mfc_vhba sysfs ================ */
struct mfc_vhba_attribute {
	struct attribute attr;
	ssize_t (*show)(struct mfc_vhba *, struct mfc_vhba_attribute *, char *buf);
	ssize_t (*store)(struct mfc_vhba *, struct mfc_vhba_attribute *,
			 const char *buf, size_t count);
};

#define VHBA_ATTR(_name, _mode, _show, _store) \
struct mfc_vhba_attribute mfc_vhba_attr_##_name = __ATTR(_name, _mode, _show, _store)

#define VHBA_ATTR_RO(_name) \
struct mfc_vhba_attribute mfc_vhba_attr_##_name = __ATTR_RO(_name)

static inline const char *fc_lport_state_name(enum fc_lport_state lp_state)
{
	static const char *fc_lport_state_names[] = {
		[LPORT_ST_DISABLED] = "Disabled",
		[LPORT_ST_FLOGI] = "FLOGI",
		[LPORT_ST_DNS] = "DNS",
		[LPORT_ST_RNN_ID] = "RNN_ID",
		[LPORT_ST_RSNN_NN] = "RSNN_NN",
		[LPORT_ST_RSPN_ID] = "RSPN_ID",
		[LPORT_ST_RFT_ID] = "RFT_ID",
		[LPORT_ST_RFF_ID] = "RFF_ID",
		[LPORT_ST_SCR] = "SCR",
		[LPORT_ST_READY] = "Ready",
		[LPORT_ST_LOGO] = "LOGO",
		[LPORT_ST_RESET] = "reset",
	};

	if (lp_state > LPORT_ST_RESET)
		return NULL;

	return fc_lport_state_names[lp_state];
};

static ssize_t vhba_debug_info_show(struct mfc_vhba *vhba, struct mfc_vhba_attribute *unused,
		char *buf)
{
	struct net_device *netdev;
	ssize_t len = 0;
	int cpu, eqidx;

	switch (vhba->net_type) {
	case NET_ETH:
		/* FCOE VHBA */
		netdev = (struct net_device *)vhba->mfc_port->underdev;

		len += sprintf(buf + len, "ETH_IF                   %s\n",
			      netdev->name);
		len += sprintf(buf + len, "MAC_HW_TABLE_IDX         %d\n",
			      vhba->fc_mac_idx);
		len += sprintf(buf + len, "VLAN_HW_TABLE_IDX        %d\n",
			      vhba->fc_vlan_idx);
		break;
	case NET_IB:
		/* FCOIB VHBA */
		break;
	}

	/* RFCI */
	len += sprintf(buf + len, "RFCI_QPN                 0x%x\n",
			vhba->rfci.fc_qp.mqp.qpn);
	len += sprintf(buf + len, "RFCI_CQN                 0x%x\n",
			vhba->rfci.fc_cq.mcq.cqn);

	/* Exchanges */
	len += sprintf(buf + len, "BASE_FEXCH_QPN           0x%x\n",
			vhba->base_fexch_qpn);
	len += sprintf(buf + len, "NUM_FEXCH                %d\n",
			vhba->num_fexch);
	len += sprintf(buf + len, "BASE_FEXCH_MPT           0x%x\n",
			vhba->base_fexch_mpt);
	len += sprintf(buf + len, "BASE_LIBFC_XID           0x%x\n",
			vhba->base_reserved_xid);
	len += sprintf(buf + len, "NUM_LIBFC_XID            %d\n",
			vhba->num_reserved_xid);
	eqidx = 0;
	for_each_online_cpu(cpu) {
		len += sprintf(buf + len, "FEXCH_CQN[%d]             0x%x\n",
				eqidx, vhba->fexch_cq[eqidx].mcq.cqn);
		++eqidx;
	}

	len += sprintf(buf + len, "VHBA_NAME                %s\n",
			fc_host_symbolic_name(vhba->lp->host));

	return len;
}

static ssize_t protocol_show(struct mfc_vhba *vhba, struct mfc_vhba_attribute *unused,
		char *buf)
{
	if (vhba->net_type == NET_ETH)
		return sprintf(buf, "FCoE\n");
	else
		return sprintf(buf, "FCoIB\n");
}

static ssize_t lport_state_show(struct mfc_vhba *vhba, struct mfc_vhba_attribute *unused,
		char *buf)
{
	return sprintf(buf, "%s\n", fc_lport_state_name(vhba->lp->state));
}

static ssize_t fc_payload_size_show(struct mfc_vhba *vhba, struct mfc_vhba_attribute *unused,
		char *buf)
{
	return sprintf(buf, "%d\n", vhba->fc_payload_size);
}

static ssize_t gw_mac_show(struct mfc_vhba *vhba, struct mfc_vhba_attribute *unused,
		char *buf)
{
	return sprintf(buf, MAC_PRINTF_FMT "\n", MAC_PRINTF_VAR(vhba->dest_addr));
}

static ssize_t vlan_id_show(struct mfc_vhba *vhba, struct mfc_vhba_attribute *unused,
		char *buf)
{
	return sprintf(buf, "%d\n", vhba->fc_vlan_id);
}

static ssize_t priority_show(struct mfc_vhba *vhba, struct mfc_vhba_attribute *unused,
		char *buf)
{
	return sprintf(buf, "%d\n", vhba->fc_vlan_prio);
}

static ssize_t my_mac_show(struct mfc_vhba *vhba, struct mfc_vhba_attribute *unused,
		char *buf)
{
	return sprintf(buf, MAC_PRINTF_FMT "\n",
			MAC_PRINTF_VAR(vhba->fc_mac));
}

static ssize_t gw_data_qpn_show(struct mfc_vhba *vhba, struct mfc_vhba_attribute *unused,
		char *buf)
{
	return sprintf(buf, "0x%lx\n", vhba->dest_ib_data_qpn);
}

static ssize_t gw_lid_show(struct mfc_vhba *vhba, struct mfc_vhba_attribute *unused,
		char *buf)
{
	return sprintf(buf, "0x%x\n", vhba->dest_ib_lid);
}

/* common to FCoE & FCoIB */
VHBA_ATTR_RO(vhba_debug_info);
VHBA_ATTR_RO(protocol);
VHBA_ATTR_RO(lport_state);
VHBA_ATTR_RO(fc_payload_size);

/* only FCoE */
VHBA_ATTR_RO(gw_mac);
VHBA_ATTR_RO(vlan_id);
VHBA_ATTR_RO(priority);
VHBA_ATTR_RO(my_mac);

/* only FCoIB */
VHBA_ATTR_RO(gw_lid);
VHBA_ATTR_RO(gw_data_qpn);

#warning FIXME: mfc_vhba_fcoe_default_attrs + mfc_vhba_fcoib_default_attrs disabled
#if 0
static struct attribute *mfc_vhba_fcoe_default_attrs[] = {
	&mfc_vhba_attr_vhba_debug_info.attr,
	&mfc_vhba_attr_protocol.attr,
	&mfc_vhba_attr_lport_state.attr,
	&mfc_vhba_attr_fc_payload_size.attr,
	&mfc_vhba_attr_gw_mac.attr,
	&mfc_vhba_attr_vlan_id.attr,
	&mfc_vhba_attr_priority.attr,
	&mfc_vhba_attr_my_mac.attr,
	NULL
};

static struct attribute *mfc_vhba_fcoib_default_attrs[] = {
	&mfc_vhba_attr_vhba_debug_info.attr,
	&mfc_vhba_attr_protocol.attr,
	&mfc_vhba_attr_lport_state.attr,
	&mfc_vhba_attr_fc_payload_size.attr,
	&mfc_vhba_attr_gw_lid.attr,
	&mfc_vhba_attr_gw_data_qpn.attr,
	NULL
};
#endif

static ssize_t mfc_vhba_attr_show(struct kobject *kobj,
			      struct attribute *attr, char *buf)
{
	struct mfc_vhba_attribute *mfc_vhba_attr =
		container_of(attr, struct mfc_vhba_attribute, attr);
	struct mfc_vhba *p = container_of(kobj, struct mfc_vhba, kobj);

	if (!mfc_vhba_attr->show)
		return -EIO;

	return mfc_vhba_attr->show(p, mfc_vhba_attr, buf);
}

static ssize_t mfc_vhba_attr_store(struct kobject *kobj,
			      struct attribute *attr, const char *buf, size_t count)
{
	struct mfc_vhba_attribute *mfc_vhba_attr =
		container_of(attr, struct mfc_vhba_attribute, attr);
	struct mfc_vhba *p = container_of(kobj, struct mfc_vhba, kobj);

	if (!mfc_vhba_attr->store)
		return -EIO;

	return mfc_vhba_attr->store(p, mfc_vhba_attr, buf, count);
}

static const struct sysfs_ops mfc_vhba_sysfs_ops = {
	.show = mfc_vhba_attr_show,
	.store = mfc_vhba_attr_store,
};

void mfc_vhba_release(struct kobject *kobj)
{
	struct mfc_vhba *p = container_of(kobj, struct mfc_vhba, kobj);
	/* FIXME: free of vHBA should be done here */
	scsi_host_put(p->lp->host);
}

#warning FIXME: mfc_vhba_fcoe_type + mfc_vhba_fcoib_type disabled
#if 0
static struct kobj_type mfc_vhba_fcoe_type = {
	.release       = &mfc_vhba_release,
	.sysfs_ops     = &mfc_vhba_sysfs_ops,
	.default_attrs = mfc_vhba_fcoe_default_attrs
};

static struct kobj_type mfc_vhba_fcoib_type = {
	.release       = &mfc_vhba_release,
	.sysfs_ops     = &mfc_vhba_sysfs_ops,
	.default_attrs = mfc_vhba_fcoib_default_attrs
};
#endif

int mfc_vhba_register_sysfs(struct mfc_vhba *vhba)
{
	int ret = 0;
#if 0
	struct kobj_type *type = (vhba->net_type == NET_ETH)?
		&mfc_vhba_fcoe_type : &mfc_vhba_fcoib_type;

	ret = kobject_init_and_add(&vhba->kobj, type,
				   kobject_get(&vhba->mfc_port->kobj),
				   "vhba%d", vhba->idx);
	if (ret)
		goto err_put;

	sysfs_create_link(&vhba->kobj, &vhba->lp->host->shost_gendev.kobj, "device");
#endif
	return 0;
#if 0
err_put:
	kobject_put(&vhba->mfc_port->kobj);
#endif
	return ret;
}

void mfc_vhba_deregister_sysfs(struct mfc_vhba *vhba)
{
#if 0
	sysfs_remove_link(&vhba->kobj, "device");
	kobject_put(&vhba->mfc_port->kobj);
	kobject_unregister(&vhba->kobj);
#endif
}


/* ===================== mfc_port sysfs ============== */

#if 0
static ssize_t port_debug_info_show(struct mfc_port *p, struct mfc_port_attribute *unused,
		char *buf)
{
	ssize_t len = 0;

	len += sprintf(buf + len, "default_mac          " MAC_PRINTF_FMT "\n",
			MAC_PRINTF_VAR(p->def_mac));
	len += sprintf(buf + len, "base_rfci_qpn        0x%x\n", p->base_rfci_qpn);
	len += sprintf(buf + len, "num_rfci_qps         0x%x\n", p->num_rfci_qps);
	len += sprintf(buf + len, "base_fexch_qpn       0x%x\n", p->base_fexch_qpn);
	len += sprintf(buf + len, "num_fexch_qps        0x%x\n", p->num_fexch_qps);
	len += sprintf(buf + len, "base_fexch_mpt       0x%x\n", p->base_fexch_mpt);
	len += sprintf(buf + len, "log_num_fexch_per_vhba 0x%x\n", p->log_num_fexch_per_vhba);
	len += sprintf(buf + len, "fip_qpn              0x%x\n", p->fip_qp.fc_qp.mqp.qpn);
	len += sprintf(buf + len, "fip_cqn              0x%x\n", p->fip_qp.fc_cq.mcq.cqn);
	len += sprintf(buf + len, "initialized          %s\n", p->initialized? "yes":"no");

	return len;
}

static ssize_t link_type_show(struct mfc_port *p, struct mfc_port_attribute *unused,
		char *buf)
{
	return sprintf(buf, "%s\n", (p->net_type == NET_ETH)? "Ethernet":"Infiniband");
}

static ssize_t link_state_show(struct mfc_port *p, struct mfc_port_attribute *unused,
		char *buf)
{
	return sprintf(buf, "%s\n", (p->link_up)? "UP":"DOWN");
}

static PORT_ATTR_RO(port_debug_info);
static PORT_ATTR_RO(link_type);
static PORT_ATTR_RO(link_state);
#endif

#warning FIXME: mfc_port_default_attrs disabled
#if 0
static struct attribute *mfc_port_default_attrs[] = {
	&mfc_port_attr_port_debug_info.attr,
	&mfc_port_attr_link_type.attr,
	&mfc_port_attr_link_state.attr,
	NULL
};
#endif

static ssize_t mfc_port_attr_show(struct kobject *kobj,
			      struct attribute *attr, char *buf)
{
	struct mfc_port_attribute *mfc_port_attr =
		container_of(attr, struct mfc_port_attribute, attr);
	struct mfc_port *p = container_of(kobj, struct mfc_port, kobj);

	if (!mfc_port_attr->show)
		return -EIO;

	return mfc_port_attr->show(p, mfc_port_attr, buf);
}

static ssize_t mfc_port_attr_store(struct kobject *kobj,
			      struct attribute *attr, const char *buf, size_t count)
{
	struct mfc_port_attribute *mfc_port_attr =
		container_of(attr, struct mfc_port_attribute, attr);
	struct mfc_port *p = container_of(kobj, struct mfc_port, kobj);

	if (!mfc_port_attr->store)
		return -EIO;

	return mfc_port_attr->store(p, mfc_port_attr, buf, count);
}

static const struct sysfs_ops mfc_port_sysfs_ops = {
	.show = mfc_port_attr_show,
	.store = mfc_port_attr_store,
};

#if 0
static void mfc_port_release(struct kobject *kobj)
{
	/* No kfree since mfc_port is embedded in mfc_dev */
}
#endif

#warning FIXME: mfc_port_type disabled
#if 0
static struct kobj_type mfc_port_type = {
	.release       = &mfc_port_release,
	.sysfs_ops     = &mfc_port_sysfs_ops,
	.default_attrs = mfc_port_default_attrs
};
#endif

int mfc_port_attr_add(struct mfc_port *mfc_port, struct mfc_port_attribute *attr)
{
	return sysfs_create_file(&mfc_port->kobj, &attr->attr);
}
EXPORT_SYMBOL(mfc_port_attr_add);

void mfc_port_attr_remove(struct mfc_port *mfc_port, struct mfc_port_attribute *attr)
{
	sysfs_remove_file(&mfc_port->kobj, &attr->attr);
}
EXPORT_SYMBOL(mfc_port_attr_remove);

#warning FIXME: mfc_port_register_sysfs disabled
int mfc_port_register_sysfs(struct mfc_port *mfc_port)
{
	int ret = 0;
#if 0
	ret = kobject_init_and_add(&mfc_port->kobj, &mfc_port_type,
				   kobject_get(&mfc_port->mfc_dev->class_dev.kobj),
				   "port%d", mfc_port->port);
	if (ret)
		goto err_put;
#endif
	return 0;
#if 0
err_put:
	kobject_put(&mfc_port->mfc_dev->class_dev.kobj);
#endif
	return ret;
}

#warning FIXME: mfc_port_deregister_sysfs disabled
void mfc_port_deregister_sysfs(struct mfc_port *mfc_port)
{
#if 0
	kobject_put(&mfc_port->mfc_dev->class_dev.kobj);
	kobject_unregister(&mfc_port->kobj);
#endif
}

/* ===================== mfc_dev sysfs ============== */

#warning FIXME: mfc_dev sysfs disabled
#if 0
static ssize_t show_mfc_dev_debug_info(struct class_device *cdev, char *buf)
{
#if 0
	struct mfc_dev *mfc_dev = container_of(cdev, struct mfc_dev, class_dev);
	int len = 0;

	len += sprintf(buf + len, "pdn          0x%x\n", mfc_dev->priv_pdn);
	len += sprintf(buf + len, "mr_key       0x%x\n", mfc_dev->mr.key);
	return len;
#endif
	return 0;
}

static CLASS_DEVICE_ATTR(dev_debug_info, S_IRUGO, show_mfc_dev_debug_info, NULL);

static struct class_device_attribute *mfc_dev_class_attributes[] = {
	&class_device_attr_dev_debug_info,
};

static void mfc_device_release(struct class_device *cdev)
{
	struct mfc_dev *mfc_dev = container_of(cdev, struct mfc_dev, class_dev);
	kfree(mfc_dev);
}

static struct class mfc_class = {
	.name    = "mlxfc",
	.release = mfc_device_release,
	/* .uevent = mfc_device_uevent, */
};
#endif

#warning FIXME: mfc_device_register_sysfs disabled
int mfc_device_register_sysfs(struct mfc_dev *mfc_dev)
{
#if 0
	struct class_device *class_dev = &mfc_dev->class_dev;
	int ret;
	int i;

	class_dev->class      = &mfc_class;
	class_dev->class_data = mfc_dev;
	//class_dev->dev	      = device->dma_device;
	sprintf(class_dev->class_id, "mfc%d", mfc_dev->idx);

	ret = class_device_register(class_dev);
	if (ret)
		goto err;

	for (i = 0; i < ARRAY_SIZE(mfc_dev_class_attributes); ++i) {
		ret = class_device_create_file(class_dev, mfc_dev_class_attributes[i]);
		if (ret)
			goto err_unregister;
	}
#endif
	return 0;

#if 0
err_unregister:
	class_device_unregister(class_dev);
err:
	return ret;
#endif
}

void mfc_device_unregister_sysfs(struct mfc_dev *mfc_dev)
{
#if 0
	class_device_unregister(&mfc_dev->class_dev);
#endif
}

int mfc_sysfs_setup(void)
{
#if 0
	return class_register(&mfc_class);
#else
	return 0;
#endif
}

void mfc_sysfs_cleanup(void)
{
#if 0
	class_unregister(&mfc_class);
#endif
}
