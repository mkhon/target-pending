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

#include "nvme_of_base.h"
#include "nvme_of_fabric.h"

/* Local pointer to allocated TCM configfs fabric module */
static struct target_fabric_configfs *nvme_of_fabric_configfs;

static struct se_node_acl *nvme_of_make_nodeacl(
	struct se_portal_group *se_tpg,
	struct config_group *group,
	const char *name)
{
	struct se_node_acl *se_nacl, *se_nacl_new;
	struct nvme_of_nacl *nacl;
	u64 wwpn = 0;
	u32 nexus_depth;

	/* nvme_of_parse_wwn(name, &wwpn, 1) < 0)
		return ERR_PTR(-EINVAL); */
	se_nacl_new = nvme_of_alloc_fabric_acl(se_tpg);
	if (!se_nacl_new)
		return ERR_PTR(-ENOMEM);
//#warning FIXME: Hardcoded nexus depth in nvme_of_make_nodeacl()
	nexus_depth = 1;
	/*
	 * se_nacl_new may be released by core_tpg_add_initiator_node_acl()
	 * when converting a NodeACL from demo mode -> explict
	 */
	se_nacl = core_tpg_add_initiator_node_acl(se_tpg, se_nacl_new,
				name, nexus_depth);
	if (IS_ERR(se_nacl)) {
		nvme_of_release_fabric_acl(se_tpg, se_nacl_new);
		return se_nacl;
	}
	/*
	 * Locate our struct nvme_of_nacl and set the NVMe-OF WWPN
	 */
	nacl = container_of(se_nacl, struct nvme_of_nacl, se_node_acl);
	nacl->iport_wwpn = wwpn;
	/* nvme_of_format_wwn(&nacl->iport_name[0], NVME_OF_NAMELEN, wwpn); */

	return se_nacl;
}

static void nvme_of_drop_nodeacl(struct se_node_acl *se_acl)
{
	struct nvme_of_nacl *nacl = container_of(se_acl,
				struct nvme_of_nacl, se_node_acl);
	core_tpg_del_initiator_node_acl(se_acl->se_tpg, se_acl, 1);
	kfree(nacl);
}

static struct se_portal_group *nvme_of_make_tpg(
	struct se_wwn *wwn,
	struct config_group *group,
	const char *name)
{
	struct nvme_of_tport*tport = container_of(wwn,
			struct nvme_of_tport, tport_wwn);

	struct nvme_of_tpg *tpg;
	unsigned long tpgt;
	int ret;

	if (strstr(name, "tpgt_") != name)
		return ERR_PTR(-EINVAL);
	if (kstrtoul(name + 5, 10, &tpgt) || tpgt > UINT_MAX)
		return ERR_PTR(-EINVAL);

	tpg = kzalloc(sizeof(struct nvme_of_tpg), GFP_KERNEL);
	if (!tpg) {
		printk(KERN_ERR "Unable to allocate struct nvme_of_tpg");
		return ERR_PTR(-ENOMEM);
	}
	tpg->tport = tport;
	tpg->tport_tpgt = tpgt;

	ret = core_tpg_register(&nvme_of_fabric_configfs->tf_ops, wwn,
				&tpg->se_tpg, (void *)tpg,
				TRANSPORT_TPG_TYPE_NORMAL);
	if (ret < 0) {
		kfree(tpg);
		return NULL;
	}
	return &tpg->se_tpg;
}

static void nvme_of_drop_tpg(struct se_portal_group *se_tpg)
{
	struct nvme_of_tpg *tpg = container_of(se_tpg,
				struct nvme_of_tpg, se_tpg);

	core_tpg_deregister(se_tpg);
	kfree(tpg);
}

static struct se_wwn *nvme_of_make_tport(
	struct target_fabric_configfs *tf,
	struct config_group *group,
	const char *name)
{
	struct nvme_of_tport *tport;
	u64 wwpn = 0;

	/* if (nvme_of_parse_wwn(name, &wwpn, 1) < 0)
		return ERR_PTR(-EINVAL); */

	tport = kzalloc(sizeof(struct nvme_of_tport), GFP_KERNEL);
	if (!tport) {
		printk(KERN_ERR "Unable to allocate struct nvme_of_tport");
		return ERR_PTR(-ENOMEM);
	}
	tport->tport_wwpn = wwpn;
	/* nvme_of_format_wwn(&tport->tport_name[0], NVME_OF_NAMELEN, wwpn); */

	return &tport->tport_wwn;
}

static void nvme_of_drop_tport(struct se_wwn *wwn)
{
	struct nvme_of_tport *tport = container_of(wwn,
				struct nvme_of_tport, tport_wwn);
	kfree(tport);
}

static ssize_t nvme_of_wwn_show_attr_version(
	struct target_fabric_configfs *tf,
	char *page)
{
	return sprintf(page, "NVME_OF fabric module %s on %s/%s"
		"on "UTS_RELEASE"\n", NVME_OF_VERSION, utsname()->sysname,
		utsname()->machine);
}

TF_WWN_ATTR_RO(nvme_of, version);

static struct configfs_attribute *nvme_of_wwn_attrs[] = {
	&nvme_of_wwn_version.attr,
	NULL,
};

static struct target_core_fabric_ops nvme_of_ops = {
	.get_fabric_name		= nvme_of_get_fabric_name,
	.get_fabric_proto_ident		= nvme_of_get_fabric_proto_ident,
	.tpg_get_wwn			= nvme_of_get_fabric_wwn,
	.tpg_get_tag			= nvme_of_get_tag,
	.tpg_get_default_depth		= nvme_of_get_default_depth,
	.tpg_get_pr_transport_id	= nvme_of_get_pr_transport_id,
	.tpg_get_pr_transport_id_len	= nvme_of_get_pr_transport_id_len,
	.tpg_parse_pr_out_transport_id	= nvme_of_parse_pr_out_transport_id,
	.tpg_check_demo_mode		= nvme_of_check_false,
	.tpg_check_demo_mode_cache	= nvme_of_check_true,
	.tpg_check_demo_mode_write_protect = nvme_of_check_true,
	.tpg_check_prod_mode_write_protect = nvme_of_check_false,
	.tpg_alloc_fabric_acl		= nvme_of_alloc_fabric_acl,
	.tpg_release_fabric_acl		= nvme_of_release_fabric_acl,
	.tpg_get_inst_index		= nvme_of_tpg_get_inst_index,
	.release_cmd			= nvme_of_release_cmd,
	.shutdown_session		= nvme_of_shutdown_session,
	.close_session			= nvme_of_close_session,
	.sess_get_index			= nvme_of_sess_get_index,
	.sess_get_initiator_sid		= NULL,
	.write_pending			= nvme_of_write_pending,
	.write_pending_status		= nvme_of_write_pending_status,
	.set_default_node_attributes	= nvme_of_set_default_node_attrs,
	.get_task_tag			= nvme_of_get_task_tag,
	.get_cmd_state			= nvme_of_get_cmd_state,
	.queue_data_in			= nvme_of_queue_data_in,
	.queue_status			= nvme_of_queue_status,
	.queue_tm_rsp			= nvme_of_queue_tm_rsp,
	.aborted_task			= nvme_of_aborted_task,
	/*
	 * Setup function pointers for generic logic in target_core_fabric_configfs.c
	 */
	.fabric_make_wwn		= nvme_of_make_tport,
	.fabric_drop_wwn		= nvme_of_drop_tport,
	.fabric_make_tpg		= nvme_of_make_tpg,
	.fabric_drop_tpg		= nvme_of_drop_tpg,
	.fabric_post_link		= NULL,
	.fabric_pre_unlink		= NULL,
	.fabric_make_np			= NULL,
	.fabric_drop_np			= NULL,
	.fabric_make_nodeacl		= nvme_of_make_nodeacl,
	.fabric_drop_nodeacl		= nvme_of_drop_nodeacl,
};

static int nvme_of_register_configfs(void)
{
	struct target_fabric_configfs *fabric;
	int ret;

	printk(KERN_INFO "NVME_OF fabric module %s on %s/%s"
		" on "UTS_RELEASE"\n",NVME_OF_VERSION, utsname()->sysname,
		utsname()->machine);
	/*
	 * Register the top level struct config_item_type with TCM core
	 */
	fabric = target_fabric_configfs_init(THIS_MODULE, "nvme");
	if (IS_ERR(fabric)) {
		printk(KERN_ERR "target_fabric_configfs_init() failed\n");
		return PTR_ERR(fabric);
	}
	/*
	 * Setup fabric->tf_ops from our local nvme_of_ops
	 */
	fabric->tf_ops = nvme_of_ops;
	/*
	 * Setup default attribute lists for various fabric->tf_cit_tmpl
	 */
	fabric->tf_cit_tmpl.tfc_wwn_cit.ct_attrs = nvme_of_wwn_attrs;
	fabric->tf_cit_tmpl.tfc_tpg_base_cit.ct_attrs = NULL;
	fabric->tf_cit_tmpl.tfc_tpg_attrib_cit.ct_attrs = NULL;
	fabric->tf_cit_tmpl.tfc_tpg_param_cit.ct_attrs = NULL;
	fabric->tf_cit_tmpl.tfc_tpg_np_base_cit.ct_attrs = NULL;
	fabric->tf_cit_tmpl.tfc_tpg_nacl_base_cit.ct_attrs = NULL;
	fabric->tf_cit_tmpl.tfc_tpg_nacl_attrib_cit.ct_attrs = NULL;
	fabric->tf_cit_tmpl.tfc_tpg_nacl_auth_cit.ct_attrs = NULL;
	fabric->tf_cit_tmpl.tfc_tpg_nacl_param_cit.ct_attrs = NULL;
	/*
	 * Register the fabric for use within TCM
	 */
	ret = target_fabric_configfs_register(fabric);
	if (ret < 0) {
		printk(KERN_ERR "target_fabric_configfs_register() failed"
				" for NVME_OF\n");
		return ret;
	}
	/*
	 * Setup our local pointer to *fabric
	 */
	nvme_of_fabric_configfs = fabric;
	printk(KERN_INFO "NVME_OF[0] - Set fabric -> nvme_of_fabric_configfs\n");
	return 0;
};

static void __exit nvme_of_deregister_configfs(void)
{
	if (!nvme_of_fabric_configfs)
		return;

	target_fabric_configfs_deregister(nvme_of_fabric_configfs);
	nvme_of_fabric_configfs = NULL;
	printk(KERN_INFO "NVME_OF[0] - Cleared nvme_of_fabric_configfs\n");
};

static int __init nvme_of_init(void)
{
	int ret;

	ret = nvme_of_register_configfs();
	if (ret < 0)
		return ret;

	return 0;
};

static void __exit nvme_of_exit(void)
{
	nvme_of_deregister_configfs();
};

MODULE_DESCRIPTION("NVME_OF series fabric driver");
MODULE_LICENSE("GPL");
module_init(nvme_of_init);
module_exit(nvme_of_exit);
