#include "rdma_footprint.h"
#include "rbtree_core.h"

struct gid_qpn_node {
	union ib_gid					gid;
	uint32_t						qpn;
	struct rb_node					node;
};

static declare_and_init_rbtree(paused_gid_qpn_tree);

static int compare(const struct rb_node *n1, const struct rb_node *n2) {
	struct gid_qpn_node *ent1 =
					n1? container_of(n1, struct gid_qpn_node, node): NULL;
	struct gid_qpn_node *ent2 =
					n2? container_of(n2, struct gid_qpn_node, node): NULL;
	int compare;

	compare = memcmp(&ent1->gid, &ent2->gid, sizeof(union ib_gid));
	if(compare)
		return compare;
	
	return memcmp(&ent1->qpn, &ent2->qpn, sizeof(uint32_t));
}

static struct gid_qpn_node *search(union ib_gid *gid, uint32_t qpn,
					struct rb_node **p_parent, struct rb_node ***p_insert) {
	struct gid_qpn_node my_node;
	struct rb_node *node;

	memcpy(&my_node.gid, gid, sizeof(*gid));
	my_node.qpn = qpn;

	node = ___search(&my_node.node, &paused_gid_qpn_tree, p_parent, p_insert,
						SEARCH_EXACTLY, compare);
	
	return node? container_of(node, struct gid_qpn_node, node): NULL;
}

enum write_opcode {
	GID_QPN_ADD,
	GID_QPN_DEL,
};

struct gid_qpn_node_write {
	union ib_gid					gid;
	uint32_t						qpn;
};

struct header {
	enum write_opcode				opcode;
	struct gid_qpn_node_write		nodes[0];
};

static wait_queue_head_t pause_wait_queue;

static ssize_t pause_entry_kernel_write(struct file *filep, const char __user *buf,
								size_t size, loff_t *off) {
	struct gid_qpn_node_write *kbuf;
	struct header *opcode;
	struct gid_qpn_node *node;
	struct rb_node *parent, **insert;
	int n_node, i;
	int err;

	if((size - sizeof(struct header)) % sizeof(struct gid_qpn_node_write)) {
		return -EINVAL;
	}

	n_node = (size - sizeof(struct header)) / sizeof(struct gid_qpn_node_write);

	kbuf = kzalloc(size, GFP_KERNEL);
	if(!kbuf)
		return -ENOMEM;
	
	err = copy_from_user(kbuf, buf, size);
	if(err) {
		kfree(kbuf);
		return err;
	}

	opcode = (struct header *)kbuf;
	kbuf = (void*)kbuf + offsetof(struct header, nodes);

	write_lock(&paused_gid_qpn_tree.rwlock);
	for(i = 0; i < n_node; i++) {
		node = search(&kbuf[i].gid, kbuf[i].qpn, &parent, &insert);

		switch(opcode->opcode) {
			case GID_QPN_ADD:
				if(!node) {
					node = kzalloc(sizeof(*node), GFP_KERNEL);
					if(!node) {
						write_unlock(&paused_gid_qpn_tree.rwlock);
						kfree(opcode);
						return -ENOMEM;
					}

					memcpy(&node->gid, &kbuf[i].gid, sizeof(union ib_gid));
					node->qpn = kbuf[i].qpn;
					rbtree_add_node(&node->node, parent, insert, &paused_gid_qpn_tree);
				}
				break;

			case GID_QPN_DEL:
				if(node) {
					rbtree_rm_node(&node->node, &paused_gid_qpn_tree);
				}
				break;
		}
	}
	write_unlock(&paused_gid_qpn_tree.rwlock);

	if(opcode->opcode == GID_QPN_DEL) {
		wake_up_interruptible(&pause_wait_queue);
	}

	kfree(opcode);
	return size;
}

static struct gid_qpn_node *search_with_lock(union ib_gid *gid, uint32_t qpn) {
	struct gid_qpn_node my_node;
	struct rb_node *node;

	memcpy(&my_node.gid, gid, sizeof(*gid));
	my_node.qpn = qpn;

	read_lock(&paused_gid_qpn_tree.rwlock);
	node = ___search(&my_node.node, &paused_gid_qpn_tree, NULL, NULL,
						SEARCH_EXACTLY, compare);
	read_unlock(&paused_gid_qpn_tree.rwlock);
	
	return node? container_of(node, struct gid_qpn_node, node): NULL;
}

static ssize_t pause_entry_user_write(struct file *filep, const char __user *buf,
								size_t size, loff_t *off) {
	struct gid_qpn_node_write kbuf;
	struct gid_qpn_node *node;
	int err;

	if(size != sizeof(struct gid_qpn_node_write))
		return -EINVAL;
	
	err = copy_from_user(&kbuf, buf, size);
	if(err)
		return err;
	
	wait_event_interruptible(pause_wait_queue,
							!search_with_lock(&kbuf.gid, kbuf.qpn));
	
	return size;
}

struct proc_ops pause_entry_ops = {
	.proc_write				= pause_entry_kernel_write,
};

struct proc_ops pause_uwrite_entry_ops = {
	.proc_write				= pause_entry_user_write,
};

int init_ud_qp_pause_signal(void) {
	init_waitqueue_head(&pause_wait_queue);
	return 0;
}
