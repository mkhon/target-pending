int mlx4_fc_check_true(struct se_portal_group *);
int mlx4_fc_check_false(struct se_portal_group *);
char *mlx4_fc_get_fabric_name(void);
u8 mlx4_fc_get_fabric_proto_ident(struct se_portal_group *);
char *mlx4_fc_get_fabric_wwn(struct se_portal_group *);
u16 mlx4_fc_get_tag(struct se_portal_group *);
u32 mlx4_fc_get_default_depth(struct se_portal_group *);
u32 mlx4_fc_get_pr_transport_id(struct se_portal_group *,
			struct se_node_acl *, struct t10_pr_registration *,
			int *, unsigned char *);
u32 mlx4_fc_get_pr_transport_id_len(struct se_portal_group *,
			struct se_node_acl *, struct t10_pr_registration *,
			int *);
char *mlx4_fc_parse_pr_out_transport_id(struct se_portal_group *,
			const char *, u32 *, char **);
struct se_node_acl *mlx4_fc_alloc_fabric_acl(struct se_portal_group *);
void mlx4_fc_release_fabric_acl(struct se_portal_group *,
			struct se_node_acl *);
u32 mlx4_fc_tpg_get_inst_index(struct se_portal_group *);
void mlx4_fc_release_cmd(struct se_cmd *);
int mlx4_fc_shutdown_session(struct se_session *);
void mlx4_fc_close_session(struct se_session *);
u32 mlx4_fc_sess_get_index(struct se_session *);
int mlx4_fc_write_pending(struct se_cmd *);
int mlx4_fc_write_pending_status(struct se_cmd *);
void mlx4_fc_set_default_node_attrs(struct se_node_acl *);
u32 mlx4_fc_get_task_tag(struct se_cmd *);
int mlx4_fc_get_cmd_state(struct se_cmd *);
int mlx4_fc_queue_data_in(struct se_cmd *);
int mlx4_fc_queue_status(struct se_cmd *);
void mlx4_fc_queue_tm_rsp(struct se_cmd *);
