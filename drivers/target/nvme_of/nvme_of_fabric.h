int nvme_of_check_true(struct se_portal_group *);
int nvme_of_check_false(struct se_portal_group *);
char *nvme_of_get_fabric_name(void);
u8 nvme_of_get_fabric_proto_ident(struct se_portal_group *);
char *nvme_of_get_fabric_wwn(struct se_portal_group *);
u16 nvme_of_get_tag(struct se_portal_group *);
u32 nvme_of_get_default_depth(struct se_portal_group *);
u32 nvme_of_get_pr_transport_id(struct se_portal_group *,
			struct se_node_acl *, struct t10_pr_registration *,
			int *, unsigned char *);
u32 nvme_of_get_pr_transport_id_len(struct se_portal_group *,
			struct se_node_acl *, struct t10_pr_registration *,
			int *);
char *nvme_of_parse_pr_out_transport_id(struct se_portal_group *,
			const char *, u32 *, char **);
struct se_node_acl *nvme_of_alloc_fabric_acl(struct se_portal_group *);
void nvme_of_release_fabric_acl(struct se_portal_group *,
			struct se_node_acl *);
u32 nvme_of_tpg_get_inst_index(struct se_portal_group *);
void nvme_of_release_cmd(struct se_cmd *);
int nvme_of_shutdown_session(struct se_session *);
void nvme_of_close_session(struct se_session *);
u32 nvme_of_sess_get_index(struct se_session *);
int nvme_of_write_pending(struct se_cmd *);
int nvme_of_write_pending_status(struct se_cmd *);
void nvme_of_set_default_node_attrs(struct se_node_acl *);
u32 nvme_of_get_task_tag(struct se_cmd *);
int nvme_of_get_cmd_state(struct se_cmd *);
int nvme_of_queue_data_in(struct se_cmd *);
int nvme_of_queue_status(struct se_cmd *);
void nvme_of_queue_tm_rsp(struct se_cmd *);
void nvme_of_aborted_task(struct se_cmd *);
