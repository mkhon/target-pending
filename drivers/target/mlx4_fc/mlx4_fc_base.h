#define MLX4_FC_VERSION	"v0.1"
#define MLX4_FC_NAMELEN	32

struct mlx4_fc_nacl {
	/* Binary World Wide unique Port Name for FC Initiator Nport */
	u64 nport_wwpn;
	/* ASCII formatted WWPN for FC Initiator Nport */
	char nport_name[MLX4_FC_NAMELEN];
	/* Returned by mlx4_fc_make_nodeacl() */
	struct se_node_acl se_node_acl;
};

struct mlx4_fc_tpg {
	/* FC port target portal group tag for TCM */
	u16 port_tpgt;
	/* Pointer back to mlx4_fc_port */
	struct mlx4_fc_port *port;
	/* Pointer to mfc_port */
	struct mfc_port *mfc_port;
	/* Returned by mlx4_fc_make_tpg() */
	struct se_portal_group se_tpg;
};

struct mlx4_fc_port {
	/* SCSI protocol the port is providing */
	u8 port_proto_id;
	/* Binary World Wide unique Port Name for FC Target Lport */
	u64 port_wwpn;
	/* Binary World Wide unique Node Name for FC Target Lport */
	u64 port_wwnn;
	/* ASCII formatted WWPN for FC Target Lport */
	char port_name[MLX4_FC_NAMELEN];
	/* Pointer to mfc_port created by mlx4 interface ->add_dev */
	struct mfc_port *mfc_port;
	/* Returned by mlx4_fc_make_port() */
	struct se_wwn port_wwn;
};
