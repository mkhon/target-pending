#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/version.h>
#include <generated/utsrelease.h>
#include <linux/utsname.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/configfs.h>
#include <linux/ctype.h>
#include <asm/unaligned.h>

#include <target/target_core_base.h>
#include <target/target_core_fabric.h>
#include <target/target_core_fabric_configfs.h>
#include <target/target_core_configfs.h>
#include <target/configfs_macros.h>
#if 1
#include "mfc.h"
#include "fip_ctlr_api.h"
#endif
#include "mlx4_fc_fabric.h"

/* Local pointer to allocated TCM configfs fabric module */
struct target_fabric_configfs *mlx4_fc_fabric_configfs;

static struct se_node_acl *mlx4_fc_make_nodeacl(
	struct se_portal_group *se_tpg,
	struct config_group *group,
	const char *name)
{
	struct se_node_acl *se_nacl, *se_nacl_new;
	struct mlx4_fc_nacl *nacl;
	u64 wwpn = 0;
	u32 nexus_depth;

	/* mlx4_fc_parse_wwn(name, &wwpn, 1) < 0)
		return ERR_PTR(-EINVAL); */
	se_nacl_new = mlx4_fc_alloc_fabric_acl(se_tpg);
	if (!se_nacl_new)
		return ERR_PTR(-ENOMEM);
//#warning FIXME: Hardcoded nexus depth in mlx4_fc_make_nodeacl()
	nexus_depth = 1;
	/*
	 * se_nacl_new may be released by core_tpg_add_initiator_node_acl()
	 * when converting a NodeACL from demo mode -> explict
	 */
	se_nacl = core_tpg_add_initiator_node_acl(se_tpg, se_nacl_new,
				name, nexus_depth);
	if (IS_ERR(se_nacl)) {
		mlx4_fc_release_fabric_acl(se_tpg, se_nacl_new);
		return se_nacl;
	}
	/*
	 * Locate our struct mlx4_fc_nacl and set the FC Nport WWPN
	 */
	nacl = container_of(se_nacl, struct mlx4_fc_nacl, se_node_acl);
	nacl->nport_wwpn = wwpn;
	/* mlx4_fc_format_wwn(&nacl->nport_name[0], MLX4_FC_NAMELEN, wwpn); */

	return se_nacl;
}

static void mlx4_fc_drop_nodeacl(struct se_node_acl *se_acl)
{
	struct mlx4_fc_nacl *nacl = container_of(se_acl,
				struct mlx4_fc_nacl, se_node_acl);
	core_tpg_del_initiator_node_acl(se_acl->se_tpg, se_acl, 1);
	kfree(nacl);
}

#define TPG_ATTR(_name, _mode) TF_TPG_ATTRIB_ATTR(mlx4_fc, _name, _mode);
#define TPG_ATTR_RO(_name) TF_TPG_ATTRIB_ATTR_RO(mlx4_fc, _name);

static ssize_t mlx4_fc_tpg_attrib_show_port(
	struct se_portal_group *se_tpg,
	char *page)
{
	struct mlx4_fc_tpg *tpg = container_of(se_tpg,
			struct mlx4_fc_tpg, se_tpg);
	struct mfc_port *mfc_port = tpg->mfc_port;

	return snprintf(page, PAGE_SIZE, "%d\n", mfc_port->port);
}
TPG_ATTR_RO(port);

static ssize_t mlx4_fc_tpg_attrib_show_net_type(
	struct se_portal_group *se_tpg,
	char *page)
{
	struct mlx4_fc_tpg *tpg = container_of(se_tpg,
			struct mlx4_fc_tpg, se_tpg);
	struct mfc_port *mfc_port = tpg->mfc_port;

	return snprintf(page, PAGE_SIZE, "%s\n", (mfc_port->net_type == NET_ETH) ?
			"NET_ETH" : "NET_IB");
}
TPG_ATTR_RO(net_type);

static ssize_t mlx4_fc_tpg_attrib_show_base_rfci_qpn(
	struct se_portal_group *se_tpg,
	char *page)
{
	struct mlx4_fc_tpg *tpg = container_of(se_tpg,
			struct mlx4_fc_tpg, se_tpg);
	struct mfc_port *mfc_port = tpg->mfc_port;

	return snprintf(page, PAGE_SIZE, "0x%x\n", mfc_port->base_rfci_qpn);
}
TPG_ATTR_RO(base_rfci_qpn);

static ssize_t mlx4_fc_tpg_attrib_show_num_rfci_qps(
	struct se_portal_group *se_tpg,
	char *page)
{
	struct mlx4_fc_tpg *tpg = container_of(se_tpg,
			struct mlx4_fc_tpg, se_tpg);
	struct mfc_port *mfc_port = tpg->mfc_port;

	return snprintf(page, PAGE_SIZE, "0x%x\n", mfc_port->num_rfci_qps);
}
TPG_ATTR_RO(num_rfci_qps);

static ssize_t mlx4_fc_tpg_attrib_show_base_fexch_qpn(
	struct se_portal_group *se_tpg,
	char *page)
{
	struct mlx4_fc_tpg *tpg = container_of(se_tpg,
			struct mlx4_fc_tpg, se_tpg);
	struct mfc_port *mfc_port = tpg->mfc_port;

	return snprintf(page, PAGE_SIZE, "0x%x\n", mfc_port->base_fexch_qpn);
}
TPG_ATTR_RO(base_fexch_qpn);

static ssize_t mlx4_fc_tpg_attrib_show_base_fexch_mpt(
	struct se_portal_group *se_tpg,
	char *page)
{
	struct mlx4_fc_tpg *tpg = container_of(se_tpg,
			struct mlx4_fc_tpg, se_tpg);
	struct mfc_port *mfc_port = tpg->mfc_port;

	return snprintf(page, PAGE_SIZE, "0x%x\n", mfc_port->base_fexch_mpt);
}
TPG_ATTR_RO(base_fexch_mpt);

static ssize_t mlx4_fc_tpg_attrib_show_num_fexch_qps(
	struct se_portal_group *se_tpg,
	char *page)
{
	struct mlx4_fc_tpg *tpg = container_of(se_tpg,
			struct mlx4_fc_tpg, se_tpg);
	struct mfc_port *mfc_port = tpg->mfc_port;

	return snprintf(page, PAGE_SIZE, "0x%x\n", mfc_port->num_fexch_qps);
}
TPG_ATTR_RO(num_fexch_qps);

static ssize_t mlx4_fc_tpg_attrib_show_log_num_fexch_per_vhba(
	struct se_portal_group *se_tpg,
	char *page)
{
	struct mlx4_fc_tpg *tpg = container_of(se_tpg,
			struct mlx4_fc_tpg, se_tpg);
	struct mfc_port *mfc_port = tpg->mfc_port;

	return snprintf(page, PAGE_SIZE, "0x%x\n", mfc_port->log_num_fexch_per_vhba);
}
TPG_ATTR_RO(log_num_fexch_per_vhba);

static ssize_t mlx4_fc_tpg_attrib_show_initialized(
	struct se_portal_group *se_tpg,
	char *page)
{
	struct mlx4_fc_tpg *tpg = container_of(se_tpg,
			struct mlx4_fc_tpg, se_tpg);
	struct mfc_port *mfc_port = tpg->mfc_port;

	return snprintf(page, PAGE_SIZE, "%d\n", mfc_port->initialized);
}
TPG_ATTR_RO(initialized);

static ssize_t mlx4_fc_tpg_attrib_show_link_up(
	struct se_portal_group *se_tpg,
	char *page)
{
	struct mlx4_fc_tpg *tpg = container_of(se_tpg,
			struct mlx4_fc_tpg, se_tpg);
	struct mfc_port *mfc_port = tpg->mfc_port;

	return snprintf(page, PAGE_SIZE, "%d\n", mfc_port->link_up);
}
TPG_ATTR_RO(link_up);

static ssize_t mlx4_fc_tpg_attrib_show_vn2vn(
	struct se_portal_group *se_tpg,
	char *page)
{
	struct mlx4_fc_tpg *tpg = container_of(se_tpg,
			struct mlx4_fc_tpg, se_tpg);
	struct mfc_port *mfc_port = tpg->mfc_port;

	return snprintf(page, PAGE_SIZE, "%d\n",
		       (mfc_port->fip_mode == FIP_MODE_VN2VN) ? 1 : 0);
}

static ssize_t mlx4_fc_tpg_attrib_store_vn2vn(
	struct se_portal_group *se_tpg,
	const char *page,
	size_t count)
{
	struct mlx4_fc_tpg *tpg = container_of(se_tpg,
			struct mlx4_fc_tpg, se_tpg);
	struct mlx4_fc_port *port = tpg->port;
	struct mfc_port *mfc_port = tpg->mfc_port;
	struct fc_lport *lp;
	u32 op;
	int ret;

	ret = kstrtou32(page, 0, &op);
	if (ret)
		return ret;
	if ((op != 1) && (op != 0)) {
		pr_err("Illegal value for vn2vn attribute: %u\n", op);
		return -EINVAL;
	}

	if (op) {
		if (mfc_port->fip_mode == FIP_MODE_VN2VN) {
			pr_warn("mfc_port fip_mode already set to"
				" FIP_MODE_VN2VN, ignoring\n");
			return count;
		}
		lp = mfc_create_lport(mfc_port, port->port_wwpn, port->port_wwpn,
				      THIS_MODULE);
		if (IS_ERR(lp))
			return PTR_ERR(lp);

		printk("mlx4_fc_tpg_attrib_store_vn2vn: After mfc_create_lport: %p !\n", lp);
	} else {


	}
	return count;
}
TPG_ATTR(vn2vn, S_IRUGO | S_IWUSR);

static struct configfs_attribute *mlx4_fc_tpg_attrib_attrs[] = {
	&mlx4_fc_tpg_attrib_port.attr,
	&mlx4_fc_tpg_attrib_net_type.attr,
	&mlx4_fc_tpg_attrib_base_rfci_qpn.attr,
	&mlx4_fc_tpg_attrib_num_rfci_qps.attr,
	&mlx4_fc_tpg_attrib_base_fexch_qpn.attr,
	&mlx4_fc_tpg_attrib_base_fexch_mpt.attr,
	&mlx4_fc_tpg_attrib_num_fexch_qps.attr,
	&mlx4_fc_tpg_attrib_log_num_fexch_per_vhba.attr,
	&mlx4_fc_tpg_attrib_initialized.attr,
	&mlx4_fc_tpg_attrib_link_up.attr,
	&mlx4_fc_tpg_attrib_vn2vn.attr,
	NULL,
};

static struct se_portal_group *mlx4_fc_make_tpg(
	struct se_wwn *wwn,
	struct config_group *group,
	const char *name)
{
	struct mlx4_fc_port *port = container_of(wwn,
			struct mlx4_fc_port, port_wwn);
	struct mfc_port *mfc_port = port->mfc_port;
	struct mlx4_fc_tpg *tpg;
	unsigned long tpgt;
	int ret;

	if (strstr(name, "tpgt_") != name)
		return ERR_PTR(-EINVAL);
	if (strict_strtoul(name + 5, 10, &tpgt) || tpgt > UINT_MAX)
		return ERR_PTR(-EINVAL);

	if (tpgt != 1) {
		pr_err("A single TPGT=1 is used for HW port mappings\n");
		return ERR_PTR(-ENOSYS);
	}
	tpg = &port->mfc_tpg_1;
	memset(&tpg, 0, sizeof(struct mlx4_fc_tpg));

	tpg->port = port;
	tpg->port_tpgt = tpgt;
	tpg->mfc_port = mfc_port;

	ret = core_tpg_register(&mlx4_fc_fabric_configfs->tf_ops, wwn,
				&tpg->se_tpg, (void *)tpg,
				TRANSPORT_TPG_TYPE_NORMAL);
	if (ret < 0)
		return NULL;

	return &tpg->se_tpg;
}

static void mlx4_fc_drop_tpg(struct se_portal_group *se_tpg)
{
	struct mlx4_fc_tpg *tpg = container_of(se_tpg,
				struct mlx4_fc_tpg, se_tpg);

	core_tpg_deregister(se_tpg);
}

static struct se_wwn *mlx4_fc_make_wwpn(
	struct target_fabric_configfs *tf,
	struct config_group *group,
	const char *name)
{
	struct mlx4_fc_port *port;
	struct mfc_port *mfc_port;
	struct mfc_dev *mfc_dev;
	u64 wwn;

	/* if (mlx4_fc_parse_wwn(name, &wwpn, 1) < 0)
		return ERR_PTR(-EINVAL); */

	/* mlx4_fc_format_wwn(&port->port_name[0], MLX4_FC_NAMELEN, wwpn); */

	mfc_port = mlx4_fc_get_port_by_wwpn(name);
	if (!mfc_port) {
		kfree(port);
		return ERR_PTR(-EINVAL);
	}
	port = &mfc_port->mlx4_fc_port;
	port->mfc_port = mfc_port;
	mfc_dev = mfc_port->mfc_dev;
	wwn = mfc_dev->dev->caps.def_mac[mfc_port->port];
	port->port_wwnn = wwn | ((u64) 0x10 << 56);
	port->port_wwpn = wwn | ((u64) 0x20 << 56);

	printk("Using mfc_port for configfs_wwpn wwpn: 0x%016lx wwnn: 0x%016lx\n",
		port->port_wwpn, port->port_wwnn);
	printk("mfc_port->mfc_dev->dev->caps.steering_mode: 0x%02x\n",
		mfc_port->mfc_dev->dev->caps.steering_mode);

	return &port->port_wwn;
}

static void mlx4_fc_drop_wwpn(struct se_wwn *wwn)
{
	struct mlx4_fc_port *port = container_of(wwn,
				struct mlx4_fc_port, port_wwn);
	kfree(port);
}

static ssize_t mlx4_fc_wwn_show_attr_version(
	struct target_fabric_configfs *tf,
	char *page)
{
	return sprintf(page, "MLX4_FC fabric module %s on %s/%s"
		" on "UTS_RELEASE"\n", MLX4_FC_VERSION, utsname()->sysname,
		utsname()->machine);
}
TF_WWN_ATTR_RO(mlx4_fc, version);

static struct configfs_attribute *mlx4_fc_wwn_attrs[] = {
	&mlx4_fc_wwn_version.attr,
	NULL,
};

static struct target_core_fabric_ops mlx4_fc_ops = {
	.get_fabric_name		= mlx4_fc_get_fabric_name,
	.get_fabric_proto_ident		= mlx4_fc_get_fabric_proto_ident,
	.tpg_get_wwn			= mlx4_fc_get_fabric_wwn,
	.tpg_get_tag			= mlx4_fc_get_tag,
	.tpg_get_default_depth		= mlx4_fc_get_default_depth,
	.tpg_get_pr_transport_id	= mlx4_fc_get_pr_transport_id,
	.tpg_get_pr_transport_id_len	= mlx4_fc_get_pr_transport_id_len,
	.tpg_parse_pr_out_transport_id	= mlx4_fc_parse_pr_out_transport_id,
	.tpg_check_demo_mode		= mlx4_fc_check_false,
	.tpg_check_demo_mode_cache	= mlx4_fc_check_true,
	.tpg_check_demo_mode_write_protect = mlx4_fc_check_true,
	.tpg_check_prod_mode_write_protect = mlx4_fc_check_false,
	.tpg_alloc_fabric_acl		= mlx4_fc_alloc_fabric_acl,
	.tpg_release_fabric_acl		= mlx4_fc_release_fabric_acl,
	.tpg_get_inst_index		= mlx4_fc_tpg_get_inst_index,
	.release_cmd			= mlx4_fc_release_cmd,
	.shutdown_session		= mlx4_fc_shutdown_session,
	.close_session			= mlx4_fc_close_session,
	.sess_get_index			= mlx4_fc_sess_get_index,
	.sess_get_initiator_sid		= NULL,
	.write_pending			= mlx4_fc_write_pending,
	.write_pending_status		= mlx4_fc_write_pending_status,
	.set_default_node_attributes	= mlx4_fc_set_default_node_attrs,
	.get_task_tag			= mlx4_fc_get_task_tag,
	.get_cmd_state			= mlx4_fc_get_cmd_state,
	.queue_data_in			= mlx4_fc_queue_data_in,
	.queue_status			= mlx4_fc_queue_status,
	.queue_tm_rsp			= mlx4_fc_queue_tm_rsp,
	/*
	 * Setup function pointers for generic logic in target_core_fabric_configfs.c
	 */
	.fabric_make_wwn		= mlx4_fc_make_wwpn,
	.fabric_drop_wwn		= mlx4_fc_drop_wwpn,
	.fabric_make_tpg		= mlx4_fc_make_tpg,
	.fabric_drop_tpg		= mlx4_fc_drop_tpg,
	.fabric_post_link		= NULL,
	.fabric_pre_unlink		= NULL,
	.fabric_make_np			= NULL,
	.fabric_drop_np			= NULL,
	.fabric_make_nodeacl		= mlx4_fc_make_nodeacl,
	.fabric_drop_nodeacl		= mlx4_fc_drop_nodeacl,
};

int mlx4_fc_register_configfs(void)
{
	struct target_fabric_configfs *fabric;
	int ret;

	printk(KERN_INFO "MLX4_FC fabric module %s on %s/%s"
		" on "UTS_RELEASE"\n",MLX4_FC_VERSION, utsname()->sysname,
		utsname()->machine);
	/*
	 * Register the top level struct config_item_type with TCM core
	 */
	fabric = target_fabric_configfs_init(THIS_MODULE, "mlx4_fc");
	if (IS_ERR(fabric)) {
		printk(KERN_ERR "target_fabric_configfs_init() failed\n");
		return PTR_ERR(fabric);
	}
	/*
	 * Setup fabric->tf_ops from our local mlx4_fc_ops
	 */
	fabric->tf_ops = mlx4_fc_ops;
	/*
	 * Setup default attribute lists for various fabric->tf_cit_tmpl
	 */
	TF_CIT_TMPL(fabric)->tfc_wwn_cit.ct_attrs = mlx4_fc_wwn_attrs;
	TF_CIT_TMPL(fabric)->tfc_tpg_base_cit.ct_attrs = NULL;
	TF_CIT_TMPL(fabric)->tfc_tpg_attrib_cit.ct_attrs = mlx4_fc_tpg_attrib_attrs;
	TF_CIT_TMPL(fabric)->tfc_tpg_param_cit.ct_attrs = NULL;
	TF_CIT_TMPL(fabric)->tfc_tpg_np_base_cit.ct_attrs = NULL;
	TF_CIT_TMPL(fabric)->tfc_tpg_nacl_base_cit.ct_attrs = NULL;
	TF_CIT_TMPL(fabric)->tfc_tpg_nacl_attrib_cit.ct_attrs = NULL;
	TF_CIT_TMPL(fabric)->tfc_tpg_nacl_auth_cit.ct_attrs = NULL;
	TF_CIT_TMPL(fabric)->tfc_tpg_nacl_param_cit.ct_attrs = NULL;
	/*
	 * Register the fabric for use within TCM
	 */
	ret = target_fabric_configfs_register(fabric);
	if (ret < 0) {
		printk(KERN_ERR "target_fabric_configfs_register() failed"
				" for MLX4_FC\n");
		return ret;
	}
	/*
	 * Setup our local pointer to *fabric
	 */
	mlx4_fc_fabric_configfs = fabric;
	printk(KERN_INFO "MLX4_FC[0] - Set fabric -> mlx4_fc_fabric_configfs\n");
	return 0;
};

void __exit mlx4_fc_deregister_configfs(void)
{
	if (!mlx4_fc_fabric_configfs)
		return;

	target_fabric_configfs_deregister(mlx4_fc_fabric_configfs);
	mlx4_fc_fabric_configfs = NULL;
	printk(KERN_INFO "MLX4_FC[0] - Cleared mlx4_fc_fabric_configfs\n");
};
