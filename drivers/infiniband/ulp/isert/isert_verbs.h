extern void isert_connect_release(struct isert_conn *);
extern void isert_put_conn(struct isert_conn *);
extern int isert_cma_handler(struct rdma_cm_id *, struct rdma_cm_event *);
extern int isert_post_recv(struct isert_conn *, u32);
extern int isert_post_send(struct isert_conn *, struct iser_tx_desc *);
