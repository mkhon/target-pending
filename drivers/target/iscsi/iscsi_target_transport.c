#include <linux/spinlock.h>
#include <linux/list.h>
#include <target/iscsi/iscsi_transport.h>

static LIST_HEAD(g_transport_list);
static DEFINE_MUTEX(transport_mutex);

struct iscsit_transport *iscsit_get_transport(int type)
{
	struct iscsit_transport *t;

	mutex_lock(&transport_mutex);
	list_for_each_entry(t, &g_transport_list, t_node) {
		if (t->transport_type == type) {
			if (t->owner && !try_module_get(t->owner)) {
				t = NULL;
			}
			mutex_unlock(&transport_mutex);
			return t;
		}
	}
	mutex_unlock(&transport_mutex);

	return NULL;
}
EXPORT_SYMBOL(iscsit_get_transport);

void iscsit_put_transport(struct iscsit_transport *t)
{
	if (t->owner)
		module_put(t->owner);
}
EXPORT_SYMBOL(iscsit_put_transport);

int iscsit_create_transport(struct iscsit_transport *t)
{
	INIT_LIST_HEAD(&t->t_node);

	mutex_lock(&transport_mutex);
	list_add_tail(&t->t_node, &g_transport_list);
	mutex_unlock(&transport_mutex);

	printk("Created iSCSI transport: %s\n", t->name);

	return 0;
}
EXPORT_SYMBOL(iscsit_create_transport);

void iscsit_destroy_transport(struct iscsit_transport *t)
{
	mutex_lock(&transport_mutex);
	list_del(&t->t_node);
	mutex_unlock(&transport_mutex);

	printk("Destroyed iSCSI transport: %s\n", t->name);
}
EXPORT_SYMBOL(iscsit_destroy_transport);
