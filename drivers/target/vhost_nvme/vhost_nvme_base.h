#define VHOST_NVME_VERSION  "v0.01"
#define VHOST_NVME_NAMELEN 32

#include "vhost_nvme_hwi.h"

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

	struct vhost_nvme_tpg *tpg;

	void *cq_queue_ptr;
	int cq_pgcount;
	struct page **cq_pages;

	struct file *irqfd;
	struct eventfd_ctx *irqfd_ctx;
	struct file *doorbell_fd;
	struct eventfd_ctx *doorbell_ctx;
	struct mm_struct *mm;
	struct vhost_memory __rcu *memory;

	struct NvmeBar bar;
};

struct vhost_nvme_controller {
	struct se_session *se_sess;
};

struct vhost_nvme_cmd {
	u64 context;

	void __user *pa;
	void *hwi_frame_ptr;
	struct page *hwi_frame_page[2];

	struct scatterlist *sgl;
	size_t sgl_size;

	struct vhost_nvme_controller *ctrl;

	struct se_cmd cmd;
	struct work_struct work;
};

struct vhost_nvme_eventfd {
	int irqfd;
	int doorbellfd;
} __attribute__ ((packed));

#define VHOST_NVME_IOC_EVENTFD	_IOWR('M', 4, struct vhost_nvme_eventfd)
#define VHOST_NVME_IOC_ENDPOINT	_IOWR('M', 5, unsigned long)
#define VHOST_NVME_IOC_CC_FRAME	_IOWR('M', 6, unsigned long)
#define VHOST_NVME_IOC_Q_FRAME	_IOWR('M', 7, unsigned long)

/*
 * From vhost_nvme_mem.c
 */
long vhost_nvme_set_memory(struct vhost_nvme_hba *,
                      struct vhost_memory __user *);
const struct vhost_memory_region *vhost_find_region(struct vhost_nvme_hba *,
						    __u64, __u32);
void __user *vhost_map_guest_to_host(struct vhost_nvme_hba *, uint64_t, int);

/*
 * From vhost_nvme_hwi.c
 */
int vhost_nvme_hwi_queue(struct vhost_nvme_hba *, u8 __user *, u8);

/*
 * From vhost_nvme_ioctl.c
 */
#include <linux/miscdevice.h>

extern struct miscdevice vhost_nvme_misc;
