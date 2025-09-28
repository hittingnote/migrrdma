#include "rdma_footprint.h"
#include "rbtree_core.h"

struct rkey_mapping_node {
	pid_t					pid;
	uint32_t				vrkey;
	uint32_t				rkey;
	struct rb_node			node;
};

declare_and_init_rbtree(rkey_mapping_table);

static int rkey_mapping_node_compare(const struct rb_node *n1, const struct rb_node *n2) {
	struct rkey_mapping_node *ent1 =
					n1? container_of(n1, struct rkey_mapping_node, node): NULL;
	struct rkey_mapping_node *ent2 =
					n2? container_of(n2, struct rkey_mapping_node, node): NULL;

	return memcmp(ent1, ent2, offsetof(struct rkey_mapping_node, rkey));
}

static struct rkey_mapping_node *search(pid_t pid, uint32_t vrkey,
					struct rb_node **p_parent, struct rb_node ***p_insert) {
	struct rkey_mapping_node my_node;
	struct rb_node *node;

	memset(&my_node, 0, sizeof(my_node));
	my_node.pid = pid;
	my_node.vrkey = vrkey;

	node = ___search(&my_node.node, &rkey_mapping_table, p_parent, p_insert,
					SEARCH_EXACTLY, rkey_mapping_node_compare);
	
	return node? container_of(node, struct rkey_mapping_node, node): NULL;
}

int service_register_rkey_mapping(pid_t pid, uint32_t vrkey, uint32_t rkey) {
	struct rkey_mapping_node *mapping_node;
	struct rb_node *parent, **insert;

	write_lock(&rkey_mapping_table.rwlock);
	mapping_node = search(pid, vrkey, &parent, &insert);
	if(mapping_node) {
		mapping_node->rkey = rkey;
		write_unlock(&rkey_mapping_table.rwlock);
		return 0;
	}

	mapping_node = kzalloc(sizeof(*mapping_node), GFP_KERNEL);
	if(!mapping_node) {
		write_unlock(&rkey_mapping_table.rwlock);
		return -ENOMEM;
	}

	mapping_node->pid = pid;
	mapping_node->vrkey = vrkey;
	mapping_node->rkey = rkey;
	rbtree_add_node(&mapping_node->node, parent, insert, &rkey_mapping_table);
	write_unlock(&rkey_mapping_table.rwlock);

	return 0;
}

int service_delete_rkey_mapping(pid_t pid, uint32_t vrkey) {
	struct rkey_mapping_node *mapping_node;

	write_lock(&rkey_mapping_table.rwlock);
	mapping_node = search(pid, vrkey, NULL, NULL);
	if(mapping_node) {
		rbtree_rm_node(&mapping_node->node, &rkey_mapping_table);
		kfree(mapping_node);
	}
	write_unlock(&rkey_mapping_table.rwlock);

	return 0;
}

struct msg_fmt {
	pid_t					pid;
	uint32_t				vrkey;
};

static struct task_struct *rkey_service_task;
static struct socket *sock;

static int rkey_translate_service(void *unused) {
	int err;
	struct sockaddr_in local_addr, remote_addr;
	struct msghdr msg;
	struct kvec vec;
	struct msg_fmt msg_content;
	uint32_t rkey;
	struct rkey_mapping_node *mapping_node;

	err = sock_create_kern(&init_net, AF_INET, SOCK_DGRAM, 0, &sock);
	if(err) {
		err_info("socket create error\n");
		return err;
	}

	local_addr.sin_family = AF_INET;
	local_addr.sin_port = htons(45645);
	local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	err = kernel_bind(sock, (struct sockaddr*)&local_addr, sizeof(local_addr));
	if(err) {
		err_info("kernel_bind error\n");
		return err;
	}

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = (struct sockaddr *)&remote_addr;

	while(1) {
		memset(&vec, 0, sizeof(vec));

		vec.iov_base = &msg_content;
		vec.iov_len = sizeof(msg_content);
		err = kernel_recvmsg(sock, &msg, &vec, 1, sizeof(msg_content), 0);
		if(err < 0) {
			err_info("kernel_recvmsg error\n");
			continue;
		}

		read_lock(&rkey_mapping_table.rwlock);
		mapping_node = search(msg_content.pid, msg_content.vrkey, NULL, NULL);
		rkey = mapping_node? mapping_node->rkey: -1;
		read_unlock(&rkey_mapping_table.rwlock);

		memset(&vec, 0, sizeof(vec));

		vec.iov_base = &rkey;
		vec.iov_len = sizeof(rkey);
		err = kernel_sendmsg(sock, &msg, &vec, 1, sizeof(rkey));
		if(err < 0) {
			err_info("kernel_sendmsg error\n");
			continue;
		}
	}

	return 0;
}

int init_rkey_translate_service(void) {
	rkey_service_task = kthread_run(rkey_translate_service, NULL, "rkey_translate_service");
	return !rkey_service_task;
}

void exit_rkey_translate_service(void) {
	sock_release(sock);
	kthread_stop(rkey_service_task);
}
