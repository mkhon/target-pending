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

#include "mlx4_fc_base.h"
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

static struct se_portal_group *mlx4_fc_make_tpg(
	struct se_wwn *wwn,
	struct config_group *group,
	const char *name)
{
	struct mlx4_fc_port*port = container_of(wwn,
			struct mlx4_fc_port, port_wwn);

	struct mlx4_fc_tpg *tpg;
	unsigned long tpgt;
	int ret;

	if (strstr(name, "tpgt_") != name)
		return ERR_PTR(-EINVAL);
	if (strict_strtoul(name + 5, 10, &tpgt) || tpgt > UINT_MAX)
		return ERR_PTR(-EINVAL);

	tpg = kzalloc(sizeof(struct mlx4_fc_tpg), GFP_KERNEL);
	if (!tpg) {
		printk(KERN_ERR "Unable to allocate struct mlx4_fc_tpg");
		return ERR_PTR(-ENOMEM);
	}
	tpg->port = port;
	tpg->port_tpgt = tpgt;

	ret = core_tpg_register(&mlx4_fc_fabric_configfs->tf_ops, wwn,
				&tpg->se_tpg, (void *)tpg,
				TRANSPORT_TPG_TYPE_NORMAL);
	if (ret < 0) {
		kfree(tpg);
		return NULL;
	}
	return &tpg->se_tpg;
}

static void mlx4_fc_drop_tpg(struct se_portal_group *se_tpg)
{
	struct mlx4_fc_tpg *tpg = container_of(se_tpg,
				struct mlx4_fc_tpg, se_tpg);

	core_tpg_deregister(se_tpg);
	kfree(tpg);
}

static struct se_wwn *mlx4_fc_make_wwpn(
	struct target_fabric_configfs *tf,
	struct config_group *group,
	const char *name)
{
	struct mlx4_fc_port *port;
	u64 wwpn = 0;

	/* if (mlx4_fc_parse_wwn(name, &wwpn, 1) < 0)
		return ERR_PTR(-EINVAL); */

	port = kzalloc(sizeof(struct mlx4_fc_port), GFP_KERNEL);
	if (!port) {
		printk(KERN_ERR "Unable to allocate struct mlx4_fc_wwpn");
		return ERR_PTR(-ENOMEM);
	}
	port->port_wwpn = wwpn;
	/* mlx4_fc_format_wwn(&port->port_name[0], MLX4_FC_NAMELEN, wwpn); */

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
		"on "UTS_RELEASE"\n", MLX4_FC_VERSION, utsname()->sysname,
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

static int mlx4_fc_register_configfs(void)
{
	struct target_fabric_configfs *fabric;
	int ret;

	printk(KERN_INFO "MLX4_FC fabric module %s on %s/%s"
		" on "UTS_RELEASE"\n",MLX4_FC_VERSION, utsname()->sysname,
		utsname()->machine);
	/*
	 * Register the top level struct config_item_type with TCM core
	 */
	fabric = target_fabric_configfs_init(THIS_MODULE, "_fc");
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
	TF_CIT_TMPL(fabric)->tfc_tpg_attrib_cit.ct_attrs = NULL;
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

static void __exit mlx4_fc_deregister_configfs(void)
{
	if (!mlx4_fc_fabric_configfs)
		return;

	target_fabric_configfs_deregister(mlx4_fc_fabric_configfs);
	mlx4_fc_fabric_configfs = NULL;
	printk(KERN_INFO "MLX4_FC[0] - Cleared mlx4_fc_fabric_configfs\n");
};

static int __init mlx4_fc_init(void)
{
	int ret;

	ret = mlx4_fc_register_configfs();
	if (ret < 0)
		return ret;

	return 0;
};

static void __exit mlx4_fc_exit(void)
{
	mlx4_fc_deregister_configfs();
};

MODULE_DESCRIPTION("MLX4_FC series fabric driver");
MODULE_LICENSE("GPL");
#if 0
module_init(mlx4_fc_init);
module_exit(mlx4_fc_exit);
#endif
