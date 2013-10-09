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

#include "mfc.h"
#include "mlx4_fc_fabric.h"

int mlx4_fc_check_true(struct se_portal_group *se_tpg)
{
	return 1;
}

int mlx4_fc_check_false(struct se_portal_group *se_tpg)
{
	return 0;
}

char *mlx4_fc_get_fabric_name(void)
{
	return "_fc";
}

u8 mlx4_fc_get_fabric_proto_ident(struct se_portal_group *se_tpg)
{
	struct mlx4_fc_tpg *tpg = container_of(se_tpg,
				struct mlx4_fc_tpg, se_tpg);
	struct mlx4_fc_port *port = tpg->port;
	u8 proto_id;

	switch (port->port_proto_id) {
	case SCSI_PROTOCOL_FCP:
	default:
		proto_id = fc_get_fabric_proto_ident(se_tpg);
		break;
	}

	return proto_id;
}

char *mlx4_fc_get_fabric_wwn(struct se_portal_group *se_tpg)
{
	struct mlx4_fc_tpg *tpg = container_of(se_tpg,
				struct mlx4_fc_tpg, se_tpg);
	struct mlx4_fc_port *port = tpg->port;

	return &port->port_name[0];
}

u16 mlx4_fc_get_tag(struct se_portal_group *se_tpg)
{
	struct mlx4_fc_tpg *tpg = container_of(se_tpg,
				struct mlx4_fc_tpg, se_tpg);
	return tpg->port_tpgt;
}

u32 mlx4_fc_get_default_depth(struct se_portal_group *se_tpg)
{
	return 1;
}

u32 mlx4_fc_get_pr_transport_id(
	struct se_portal_group *se_tpg,
	struct se_node_acl *se_nacl,
	struct t10_pr_registration *pr_reg,
	int *format_code,
	unsigned char *buf)
{
	struct mlx4_fc_tpg *tpg = container_of(se_tpg,
				struct mlx4_fc_tpg, se_tpg);
	struct mlx4_fc_port *port = tpg->port;
	int ret = 0;

	switch (port->port_proto_id) {
	case SCSI_PROTOCOL_FCP:
	default:
		ret = fc_get_pr_transport_id(se_tpg, se_nacl, pr_reg,
					format_code, buf);
		break;
	}

	return ret;
}

u32 mlx4_fc_get_pr_transport_id_len(
	struct se_portal_group *se_tpg,
	struct se_node_acl *se_nacl,
	struct t10_pr_registration *pr_reg,
	int *format_code)
{
	struct mlx4_fc_tpg *tpg = container_of(se_tpg,
				struct mlx4_fc_tpg, se_tpg);
	struct mlx4_fc_port *port = tpg->port;
	int ret = 0;

	switch (port->port_proto_id) {
	case SCSI_PROTOCOL_FCP:
	default:
		ret = fc_get_pr_transport_id_len(se_tpg, se_nacl, pr_reg,
					format_code);
		break;
	}

	return ret;
}

char *mlx4_fc_parse_pr_out_transport_id(
	struct se_portal_group *se_tpg,
	const char *buf,
	u32 *out_tid_len,
	char **port_nexus_ptr)
{
	struct mlx4_fc_tpg *tpg = container_of(se_tpg,
				struct mlx4_fc_tpg, se_tpg);
	struct mlx4_fc_port *port = tpg->port;
	char *tid = NULL;

	switch (port->port_proto_id) {
	case SCSI_PROTOCOL_FCP:
	default:
		tid = fc_parse_pr_out_transport_id(se_tpg, buf, out_tid_len,
					port_nexus_ptr);
	}

	return tid;
}

struct se_node_acl *mlx4_fc_alloc_fabric_acl(struct se_portal_group *se_tpg)
{
	struct mlx4_fc_nacl *nacl;

	nacl = kzalloc(sizeof(struct mlx4_fc_nacl), GFP_KERNEL);
	if (!nacl) {
		printk(KERN_ERR "Unable to allocate struct mlx4_fc_nacl\n");
		return NULL;
	}

	return &nacl->se_node_acl;
}

void mlx4_fc_release_fabric_acl(
	struct se_portal_group *se_tpg,
	struct se_node_acl *se_nacl)
{
	struct mlx4_fc_nacl *nacl = container_of(se_nacl,
			struct mlx4_fc_nacl, se_node_acl);
	kfree(nacl);
}

u32 mlx4_fc_tpg_get_inst_index(struct se_portal_group *se_tpg)
{
	return 1;
}

void mlx4_fc_release_cmd(struct se_cmd *se_cmd)
{
	return;
}

int mlx4_fc_shutdown_session(struct se_session *se_sess)
{
	return 0;
}

void mlx4_fc_close_session(struct se_session *se_sess)
{
	return;
}

u32 mlx4_fc_sess_get_index(struct se_session *se_sess)
{
	return 0;
}

int mlx4_fc_write_pending(struct se_cmd *se_cmd)
{
	struct mfc_cmd *mfc_cmd = container_of(se_cmd, struct mfc_cmd, se_cmd);
	struct trans_start *ts = &mfc_cmd->ts;
	struct mfc_vhba *vhba = se_cmd->se_sess->fabric_sess_ptr;
	int rc;

#warning FIXME: Fill in rest of *ts for RDMA_READ
	rc = mfc_send_data(vhba, ts);
	if (rc)
		return rc;

	return 0;
}

int mlx4_fc_write_pending_status(struct se_cmd *se_cmd)
{
	return 0;
}

void mlx4_fc_set_default_node_attrs(struct se_node_acl *nacl)
{
	return;
}

u32 mlx4_fc_get_task_tag(struct se_cmd *se_cmd)
{
	return 0;
}

int mlx4_fc_get_cmd_state(struct se_cmd *se_cmd)
{
	return 0;
}

int mlx4_fc_queue_data_in(struct se_cmd *se_cmd)
{
	struct mfc_cmd *mfc_cmd = container_of(se_cmd, struct mfc_cmd, se_cmd);
	struct trans_start *ts = &mfc_cmd->ts;
	struct mfc_vhba *vhba = se_cmd->se_sess->fabric_sess_ptr;
	int rc;

#warning FIXME: Fill in rest of *ts for RDMA_WRITE
	rc = mfc_send_data(vhba, ts);
	if (rc)
		return rc;

#warning FIXME: Fill in rest of *ts for SCSI response
	rc = mfc_send_resp(vhba, ts);
	if (rc)
		return rc;

	return 0;
}

int mlx4_fc_queue_status(struct se_cmd *se_cmd)
{
	struct mfc_cmd *mfc_cmd = container_of(se_cmd, struct mfc_cmd, se_cmd);
	struct trans_start *ts = &mfc_cmd->ts;
	struct mfc_vhba *vhba = se_cmd->se_sess->fabric_sess_ptr;
	int rc;

#warning FIXME: Fill in rest of *ts for SCSI response
	rc = mfc_send_resp(vhba, ts);
	if (rc)
		return rc;

	return 0;
}

void mlx4_fc_queue_tm_rsp(struct se_cmd *se_cmd)
{
	return;
}
