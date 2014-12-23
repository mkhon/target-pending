#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <asm/unaligned.h>
#include <scsi/scsi.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/libfc.h>

#include <target/target_core_base.h>
#include <target/target_core_fabric.h>
#include <target/target_core_configfs.h>

#include "nvme_of_base.h"
#include "nvme_of_fabric.h"

int nvme_of_check_true(struct se_portal_group *se_tpg)
{
	return 1;
}

int nvme_of_check_false(struct se_portal_group *se_tpg)
{
	return 0;
}

char *nvme_of_get_fabric_name(void)
{
	return "nvme";
}

u8 nvme_of_get_fabric_proto_ident(struct se_portal_group *se_tpg)
{
	struct nvme_of_tpg *tpg = container_of(se_tpg,
				struct nvme_of_tpg, se_tpg);
	struct nvme_of_tport *tport = tpg->tport;
	u8 proto_id;

	switch (tport->tport_proto_id) {
	case SCSI_PROTOCOL_SAS:
	default:
		proto_id = sas_get_fabric_proto_ident(se_tpg);
		break;
	}

	return proto_id;
}

char *nvme_of_get_fabric_wwn(struct se_portal_group *se_tpg)
{
	struct nvme_of_tpg *tpg = container_of(se_tpg,
				struct nvme_of_tpg, se_tpg);
	struct nvme_of_tport *tport = tpg->tport;

	return &tport->tport_name[0];
}

u16 nvme_of_get_tag(struct se_portal_group *se_tpg)
{
	struct nvme_of_tpg *tpg = container_of(se_tpg,
				struct nvme_of_tpg, se_tpg);
	return tpg->tport_tpgt;
}

u32 nvme_of_get_default_depth(struct se_portal_group *se_tpg)
{
	return 1;
}

u32 nvme_of_get_pr_transport_id(
	struct se_portal_group *se_tpg,
	struct se_node_acl *se_nacl,
	struct t10_pr_registration *pr_reg,
	int *format_code,
	unsigned char *buf)
{
	struct nvme_of_tpg *tpg = container_of(se_tpg,
				struct nvme_of_tpg, se_tpg);
	struct nvme_of_tport *tport = tpg->tport;
	int ret = 0;

	switch (tport->tport_proto_id) {
	case SCSI_PROTOCOL_SAS:
	default:
		ret = sas_get_pr_transport_id(se_tpg, se_nacl, pr_reg,
					format_code, buf);
		break;
	}

	return ret;
}

u32 nvme_of_get_pr_transport_id_len(
	struct se_portal_group *se_tpg,
	struct se_node_acl *se_nacl,
	struct t10_pr_registration *pr_reg,
	int *format_code)
{
	struct nvme_of_tpg *tpg = container_of(se_tpg,
				struct nvme_of_tpg, se_tpg);
	struct nvme_of_tport *tport = tpg->tport;
	int ret = 0;

	switch (tport->tport_proto_id) {
	case SCSI_PROTOCOL_SAS:
	default:
		ret = sas_get_pr_transport_id_len(se_tpg, se_nacl, pr_reg,
					format_code);
		break;
	}

	return ret;
}

char *nvme_of_parse_pr_out_transport_id(
	struct se_portal_group *se_tpg,
	const char *buf,
	u32 *out_tid_len,
	char **port_nexus_ptr)
{
	struct nvme_of_tpg *tpg = container_of(se_tpg,
				struct nvme_of_tpg, se_tpg);
	struct nvme_of_tport *tport = tpg->tport;
	char *tid = NULL;

	switch (tport->tport_proto_id) {
	case SCSI_PROTOCOL_SAS:
	default:
		tid = sas_parse_pr_out_transport_id(se_tpg, buf, out_tid_len,
					port_nexus_ptr);
	}

	return tid;
}

struct se_node_acl *nvme_of_alloc_fabric_acl(struct se_portal_group *se_tpg)
{
	struct nvme_of_nacl *nacl;

	nacl = kzalloc(sizeof(struct nvme_of_nacl), GFP_KERNEL);
	if (!nacl) {
		printk(KERN_ERR "Unable to allocate struct nvme_of_nacl\n");
		return NULL;
	}

	return &nacl->se_node_acl;
}

void nvme_of_release_fabric_acl(
	struct se_portal_group *se_tpg,
	struct se_node_acl *se_nacl)
{
	struct nvme_of_nacl *nacl = container_of(se_nacl,
			struct nvme_of_nacl, se_node_acl);
	kfree(nacl);
}

u32 nvme_of_tpg_get_inst_index(struct se_portal_group *se_tpg)
{
	return 1;
}

void nvme_of_release_cmd(struct se_cmd *se_cmd)
{
	return;
}

int nvme_of_shutdown_session(struct se_session *se_sess)
{
	return 0;
}

void nvme_of_close_session(struct se_session *se_sess)
{
	return;
}

u32 nvme_of_sess_get_index(struct se_session *se_sess)
{
	return 0;
}

int nvme_of_write_pending(struct se_cmd *se_cmd)
{
	return 0;
}

int nvme_of_write_pending_status(struct se_cmd *se_cmd)
{
	return 0;
}

void nvme_of_set_default_node_attrs(struct se_node_acl *nacl)
{
	return;
}

u32 nvme_of_get_task_tag(struct se_cmd *se_cmd)
{
	return 0;
}

int nvme_of_get_cmd_state(struct se_cmd *se_cmd)
{
	return 0;
}

int nvme_of_queue_data_in(struct se_cmd *se_cmd)
{
	return 0;
}

int nvme_of_queue_status(struct se_cmd *se_cmd)
{
	return 0;
}

void nvme_of_queue_tm_rsp(struct se_cmd *se_cmd)
{
	return;
}

void nvme_of_aborted_task(struct se_cmd *se_cmd)
{
	return;
}
