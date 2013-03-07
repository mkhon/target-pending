#include <linux/socket.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <rdma/ib_verbs.h>
#include <rdma/ib_fmr_pool.h>
#include <rdma/rdma_cm.h>

extern void iser_cq_tx_tasklet(unsigned long);
extern void isert_cq_tx_callback(struct ib_cq *, void *);
extern void iser_cq_rx_tasklet(unsigned long);
extern void isert_cq_rx_callback(struct ib_cq *, void *);
extern void isert_free_rx_descriptors(struct isert_conn *);
