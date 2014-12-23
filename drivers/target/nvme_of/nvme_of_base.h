#define NVME_OF_VERSION  "v0.1"
#define NVME_OF_NAMELEN 32

struct nvme_of_nacl {
	/* Binary World Wide unique Port Name for NVME_OF Initiator port */
	u64 iport_wwpn;
	/* ASCII formatted WWPN for Sas Initiator port */
	char iport_name[NVME_OF_NAMELEN];
	/* Returned by nvme_of_make_nodeacl() */
	struct se_node_acl se_node_acl;
};

struct nvme_of_tpg {
	/* NVME_OF port target portal group tag for TCM */
	u16 tport_tpgt;
	/* Pointer back to nvme_of_tport */
	struct nvme_of_tport *tport;
	/* Returned by nvme_of_make_tpg() */
	struct se_portal_group se_tpg;
};

struct nvme_of_tport {
	/* SCSI protocol the tport is providing */
	u8 tport_proto_id;
	/* Binary World Wide unique Port Name for NVME_OF Target port */
	u64 tport_wwpn;
	/* ASCII formatted WWPN for NVME_OF Target port */
	char tport_name[NVME_OF_NAMELEN];
	/* Returned by nvme_of_make_tport() */
	struct se_wwn tport_wwn;
};
