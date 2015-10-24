#define VHOST_NVME_VERSION  "v0.01"
#define VHOST_NVME_NAMELEN 32

struct vhost_nvme_tpg {
	/* SAS port target portal group tag for TCM */
	u16 tport_tpgt;
	/* Pointer back to vhost_nvme_tport */
	struct vhost_nvme_tport *tport;
	/* Returned by vhost_nvme_make_tpg() */
	struct se_portal_group se_tpg;
};

struct vhost_nvme_tport {
	/* Binary World Wide unique Port Name for SAS Target port */
	u64 tport_wwpn;
	/* ASCII formatted WWPN for SAS Target port */
	char tport_name[VHOST_NVME_NAMELEN];
	/* Returned by vhost_nvme_make_tport() */
	struct se_wwn tport_wwn;
};

struct vhost_nvme_hba {
	bool active;
	struct vhost_memory __rcu *memory;
};

/*
 * From vhost_nvme_mem.c
 */
long vhost_nvme_set_memory(struct vhost_nvme_hba *,
                           struct vhost_memory __user *);
