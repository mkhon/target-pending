#ifndef __FCOE_TGT_API_H__
#define __FCOE_TGT_API_H__

#include <linux/types.h>

/* control driver messages */

enum fcoetgt_ctl_msg_type {
	CTL_START = 0,  	/* tgt -> kernel */
	CTL_STOP,       	/* tgt -> kernel */
	CTL_HBA_CREATED,	/* kernel -> tgt */
	CTL_HBA_REMOVED,	/* kernel -> tgt */

	CTL_NUM_MSGS
};

struct fcoetgt_ctl_hdr {
	__u8 msg_type;
	__u8 hba_id;
	__u16 msg_len; /* length - sizeof(struct fcoetgt_ctl_hdr) */
	__u16 flags;
	__u16 reserved;
} __attribute__((__packed__));


struct fcoetgt_ctl_msg {
	struct fcoetgt_ctl_hdr hdr;

	union {
		struct { /* CTL_HBA_CREATED */
			__u64 wwpn;
			__u64 wwnn;
		} hba_created;

		struct { /* CTL_HBA_REMOVED */
			__u32 reason;
		} hba_removed;
	};
} __attribute__((__packed__));

/* hba driver messages */

enum fcoetgt_hba_msg_type {
	HBA_REG_BUFF_REQ = 0,   /* tgt -> kernel */
	HBA_REG_BUFF_RSP,       /* kernel -> tgt */
	HBA_START,      	/* tgt -> kernel */
	HBA_STOP,       	/* tgt -> kernel */
	HBA_IS_OFFLINE, 	/* kernel -> tgt */
	HBA_IS_ONLINE,  	/* kernel -> tgt */
	HBA_RPORT_UP,   	/* kernel -> tgt */
	HBA_RPORT_DOWN, 	/* kernel -> tgt */
	HBA_SCSI_REQ,   	/* kernel -> tgt */
	HBA_RDMA_READ_START,    /* tgt -> kernel */
	HBA_RDMA_READ_DONE,     /* kernel -> tgt */
	HBA_RDMA_WRITE_START,   /* tgt -> kernel */
	HBA_RDMA_WRITE_DONE,    /* kernel -> tgt */
	HBA_SCSI_RESP,  	/* tgt -> kernel */
	HBA_FLOGI_ACC,		/* kernel -> tgt */


	HBA_NUM_MSGS
};

/* generic HBA msg header format */

struct fcoetgt_hba_hdr {
	__u8 msg_type;
	__u8 reserved1;
	__u16 msg_len; /* length - sizeof(struct fcoetgt_hba_hdr) */
	__u16 flags;
	__u16 reserved2;
} __attribute__((__packed__));

/* specific msg formats where there are additional data fields */

struct fcoetgt_hba_msg {
	struct fcoetgt_hba_hdr hdr;

	union {
		struct { /* REG_BUF_REQ */
			__u64 tgt_buff_id;
			__u64 addr;
			__u32 size;

		} reg_buf_req;

		struct { /* REG_BUF_RSP */
			__u64 tgt_buff_id;
			__u64 krn_buff_id;
		} reg_buf_rsp;

		struct { /* HBA_RPORT_UP, HBA_RPORT_DOWN */
			__u32 rport; /* more? */
		} rport_state;

		struct { /* HBA_SCSI_REQ */
			__u64 krn_cmd_id;
			__u8 fcp_cmd[FCP_CMND_LEN];
		} scsi_req;

		struct { /* HBA_RDMA_READ_START, HBA_RDMA_WRITE_START */
			__u64 krn_cmd_id;
			__u64 krn_buf_id;
			__u32 xfer_len;
		} rdma_req;

		struct { /* HBA_RDMA_READ_DONE, HBA_RDMA_WRITE_DONE */
			__u64 tgt_buf_id;
		} rdma_done;

		struct { /* HBA_SCSI_RESP */
			__u64 krn_cmd_id;
			__u32 fcp_resp_len;
			__u8 fcp_resp[FCP_RESP_WITH_EXT + 32];
		} scsi_resp;
	};
} __attribute__((__packed__));

#define fld_sizeof(s, f)   sizeof(((s *)0)->f)

#define fcoetgt_ctl_msg_len(m) (sizeof(struct fcoetgt_ctl_hdr) + \
            fld_sizeof(struct fcoetgt_ctl_msg, m))

#define fcoetgt_hba_msg_len(m) (sizeof(struct fcoetgt_hba_hdr) + \
            fld_sizeof(struct fcoetgt_hba_msg, m))

#endif
