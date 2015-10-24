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
#include <linux/miscdevice.h>
#include <asm/unaligned.h>
#include <scsi/scsi_proto.h>
#include <scsi/scsi_proto.h>
#include <uapi/linux/vhost.h>

#include <target/target_core_base.h>
#include <target/target_core_fabric.h>
#include "vhost_nvme_base.h"
#include "vhost_nvme_fabric.h"

static const struct target_core_fabric_ops vhost_nvme_ops;

static struct se_portal_group *vhost_nvme_make_tpg(
	struct se_wwn *wwn,
	struct config_group *group,
	const char *name)
{
	struct vhost_nvme_tport*tport = container_of(wwn,
			struct vhost_nvme_tport, tport_wwn);

	struct vhost_nvme_tpg *tpg;
	unsigned long tpgt;
	int ret;

	if (strstr(name, "tpgt_") != name)
		return ERR_PTR(-EINVAL);
	if (kstrtoul(name + 5, 10, &tpgt) || tpgt > UINT_MAX)
		return ERR_PTR(-EINVAL);

	tpg = kzalloc(sizeof(struct vhost_nvme_tpg), GFP_KERNEL);
	if (!tpg) {
		printk(KERN_ERR "Unable to allocate struct vhost_nvme_tpg");
		return ERR_PTR(-ENOMEM);
	}
	tpg->tport = tport;
	tpg->tport_tpgt = tpgt;

	ret = core_tpg_register(wwn, &tpg->se_tpg, SCSI_PROTOCOL_SAS);
	if (ret < 0) {
		kfree(tpg);
		return NULL;
	}
	return &tpg->se_tpg;
}

static void vhost_nvme_drop_tpg(struct se_portal_group *se_tpg)
{
	struct vhost_nvme_tpg *tpg = container_of(se_tpg,
				struct vhost_nvme_tpg, se_tpg);

	core_tpg_deregister(se_tpg);
	kfree(tpg);
}

static struct se_wwn *vhost_nvme_make_tport(
	struct target_fabric_configfs *tf,
	struct config_group *group,
	const char *name)
{
	struct vhost_nvme_tport *tport;
	u64 wwpn = 0;

	/* if (vhost_nvme_parse_wwn(name, &wwpn, 1) < 0)
		return ERR_PTR(-EINVAL); */

	tport = kzalloc(sizeof(struct vhost_nvme_tport), GFP_KERNEL);
	if (!tport) {
		printk(KERN_ERR "Unable to allocate struct vhost_nvme_tport");
		return ERR_PTR(-ENOMEM);
	}
	tport->tport_wwpn = wwpn;
	/* vhost_nvme_format_wwn(&tport->tport_name[0], VHOST_NVME_NAMELEN, wwpn); */

	return &tport->tport_wwn;
}

static void vhost_nvme_drop_tport(struct se_wwn *wwn)
{
	struct vhost_nvme_tport *tport = container_of(wwn,
				struct vhost_nvme_tport, tport_wwn);
	kfree(tport);
}

static const struct target_core_fabric_ops vhost_nvme_ops = {
	.module				= THIS_MODULE,
	.name				= "vhost_nvme",
	.get_fabric_name		= vhost_nvme_get_fabric_name,
	.tpg_get_wwn			= vhost_nvme_get_fabric_wwn,
	.tpg_get_tag			= vhost_nvme_get_tag,
	.tpg_check_demo_mode		= vhost_nvme_check_false,
	.tpg_check_demo_mode_cache	= vhost_nvme_check_true,
	.tpg_check_demo_mode_write_protect = vhost_nvme_check_true,
	.tpg_check_prod_mode_write_protect = vhost_nvme_check_false,
	.tpg_get_inst_index		= vhost_nvme_tpg_get_inst_index,
	.release_cmd			= vhost_nvme_release_cmd,
	.shutdown_session		= vhost_nvme_shutdown_session,
	.close_session			= vhost_nvme_close_session,
	.sess_get_index			= vhost_nvme_sess_get_index,
	.sess_get_initiator_sid		= NULL,
	.write_pending			= vhost_nvme_write_pending,
	.write_pending_status		= vhost_nvme_write_pending_status,
	.set_default_node_attributes	= vhost_nvme_set_default_node_attrs,
	.get_cmd_state			= vhost_nvme_get_cmd_state,
	.queue_data_in			= vhost_nvme_queue_data_in,
	.queue_status			= vhost_nvme_queue_status,
	.queue_tm_rsp			= vhost_nvme_queue_tm_rsp,
	.aborted_task			= vhost_nvme_aborted_task,
	/*
	 * Setup function pointers for generic logic in target_core_fabric_configfs.c
	 */
	.fabric_make_wwn		= vhost_nvme_make_tport,
	.fabric_drop_wwn		= vhost_nvme_drop_tport,
	.fabric_make_tpg		= vhost_nvme_make_tpg,
	.fabric_drop_tpg		= vhost_nvme_drop_tpg,
};

static long
vhost_nvme_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	struct vhost_nvme_hba *hba = f->private_data;
	long ret = 0;

	switch (cmd) {
	case VHOST_SET_MEM_TABLE:
		break;
	default:
		ret = -ENOTTY;
		break;
	}

	return ret;
}

static const struct file_operations vhost_nvme_fops = {
	.owner		= THIS_MODULE,
#if 0
	.release	= vhost_nvme_release,
#endif
	.unlocked_ioctl	= vhost_nvme_ioctl,
#if 0
	.open		= vhost_nvme_open,
	.write		= vhost_nvme_write,
#endif
	.llseek		= noop_llseek,
};

static struct miscdevice vhost_nvme_misc = {
	.minor		= MISC_DYNAMIC_MINOR,
	.name		= "vhost_nvme",
	.fops		= &vhost_nvme_fops,
};

static int __init vhost_nvme_init(void)
{
	int ret;

	pr_debug("VHOST_NVME fabric module %s on %s/%s"
		" on "UTS_RELEASE"\n", VHOST_NVME_VERSION, utsname()->sysname,
		utsname()->machine);

	ret = misc_register(&vhost_nvme_misc);
	if (ret < 0) {
		pr_err("misc_register() failed for vhost_nvme_misc: %d\n", ret);
		return ret;
	}

	ret = target_register_template(&vhost_nvme_ops);
	if (ret)
		goto err_misc_unregister;

	return 0;

err_misc_unregister:
	misc_deregister(&vhost_nvme_misc);
	return ret;
};

static void __exit vhost_nvme_exit(void)
{
	target_unregister_template(&vhost_nvme_ops);
	misc_deregister(&vhost_nvme_misc);
};

MODULE_DESCRIPTION("VHOST_NVME series fabric driver");
MODULE_LICENSE("GPL");
module_init(vhost_nvme_init);
module_exit(vhost_nvme_exit);
