#include <linux/sched.h>
#include "rdma_footprint.h"
#include "rbtree_core.h"

struct ufile_mapping_node {
	struct ib_uverbs_file			*ufile;
	struct rbtree_struct			pd_mapping;
	struct rbtree_struct			cq_mapping;
	struct rbtree_struct			mr_mapping;
	struct rbtree_struct			qp_mapping;
	struct rbtree_struct			srq_mapping;
	struct rb_node					node;
};

struct mapping_node {
	struct rb_node					node;
	int								vhandle;
	int								handle;
};

static void free_mapping_node(struct rb_node *node) {
	struct mapping_node *nd = node?
				container_of(node, struct mapping_node, node): NULL;
	if(nd)
		kfree(nd);
}

static int mapping_compare(const struct rb_node *n1, const struct rb_node *n2) {
	struct mapping_node *ent1 =
				n1? container_of(n1, struct mapping_node, node): NULL;
	struct mapping_node *ent2 =
				n2? container_of(n2, struct mapping_node, node): NULL;
	
	return ent1->vhandle - ent2->vhandle;
}

static int ufile_mapping_compare(const struct rb_node *n1, const struct rb_node *n2) {
	struct ufile_mapping_node *ent1 =
				n1? container_of(n1, struct ufile_mapping_node, node): NULL;
	struct ufile_mapping_node *ent2 =
				n2? container_of(n2, struct ufile_mapping_node, node): NULL;

	if(!ent1 || !ent2) {
		return -1;
	}

	if(ent1->ufile < ent2->ufile) {
		return -1;
	}
	else if(ent1->ufile > ent2->ufile) {
		return 1;
	}
	else {
		return 0;
	}
}

static declare_and_init_rbtree(per_ufile_mapping);

static struct mapping_node *search_mapping(int vhandle, const struct rbtree_struct *rbtree,
					struct rb_node **p_parent, struct rb_node ***p_insert) {
	struct mapping_node my_node = {.vhandle = vhandle};
	struct rb_node *node;

	node = ___search(&my_node.node, rbtree, p_parent, p_insert, SEARCH_EXACTLY, mapping_compare);

	return node? container_of(node, struct mapping_node, node): NULL;
}

static struct ufile_mapping_node *search_ufile_mapping(struct ib_uverbs_file *ufile,
					struct rb_node **p_parent, struct rb_node ***p_insert) {
	struct ufile_mapping_node my_node = {.ufile = ufile};
	struct rb_node *node;

	node = ___search(&my_node.node, &per_ufile_mapping, p_parent, p_insert,
						SEARCH_EXACTLY, ufile_mapping_compare);
	
	return node? container_of(node, struct ufile_mapping_node, node): NULL;
}

int register_new_ufile_mapping(struct ib_uverbs_file *ufile) {
	struct ufile_mapping_node *ufile_mapping;
	struct rb_node *parent, **insert;

	write_lock(&per_ufile_mapping.rwlock);
	ufile_mapping = search_ufile_mapping(ufile, &parent, &insert);
	if(ufile_mapping) {
		write_unlock(&per_ufile_mapping.rwlock);
		return -EEXIST;
	}

	ufile_mapping = kzalloc(sizeof(*ufile_mapping), GFP_KERNEL);
	if(!ufile_mapping) {
		write_unlock(&per_ufile_mapping.rwlock);
		return -ENOMEM;
	}

	ufile_mapping->ufile = ufile;
	ufile_mapping->pd_mapping.tree = RB_ROOT;
	ufile_mapping->pd_mapping.rwlock =
			__RW_LOCK_UNLOCKED(ufile_mapping->pd_mapping.rwlock);
	ufile_mapping->cq_mapping.tree = RB_ROOT;
	ufile_mapping->cq_mapping.rwlock =
			__RW_LOCK_UNLOCKED(ufile_mapping->cq_mapping.rwlock);
	ufile_mapping->mr_mapping.tree = RB_ROOT;
	ufile_mapping->mr_mapping.rwlock =
			__RW_LOCK_UNLOCKED(ufile_mapping->mr_mapping.rwlock);
	ufile_mapping->qp_mapping.tree = RB_ROOT;
	ufile_mapping->qp_mapping.rwlock =
			__RW_LOCK_UNLOCKED(ufile_mapping->qp_mapping.rwlock);
	ufile_mapping->srq_mapping.tree = RB_ROOT;
	ufile_mapping->srq_mapping.rwlock =
			__RW_LOCK_UNLOCKED(ufile_mapping->srq_mapping.rwlock);
	rbtree_add_node(&ufile_mapping->node, parent, insert, &per_ufile_mapping);
	write_unlock(&per_ufile_mapping.rwlock);

	return 0;
}

void deregister_new_ufile_mapping(struct ib_uverbs_file *ufile) {
	struct ufile_mapping_node *ufile_mapping;

	write_lock(&per_ufile_mapping.rwlock);
	ufile_mapping = search_ufile_mapping(ufile, NULL, NULL);
	if(!ufile_mapping) {
		write_unlock(&per_ufile_mapping.rwlock);
		return;
	}

	clean_rbtree(&ufile_mapping->pd_mapping, free_mapping_node);
	clean_rbtree(&ufile_mapping->cq_mapping, free_mapping_node);
	clean_rbtree(&ufile_mapping->mr_mapping, free_mapping_node);
	clean_rbtree(&ufile_mapping->qp_mapping, free_mapping_node);
	clean_rbtree(&ufile_mapping->srq_mapping, free_mapping_node);
	rbtree_rm_node(&ufile_mapping->node, &per_ufile_mapping);
	kfree(ufile_mapping);
	write_unlock(&per_ufile_mapping.rwlock);
}

static inline void unregister_handle_mapping_fn(struct ib_qp *qp) {
	char symlink_name[128];

	sprintf(symlink_name, "qpn_%d_%d_%d", current->tgid, qp->vqpn, qp->qp_num);
	remove_proc_entry(symlink_name, qp->device->proc_ent);
	unregister_qp_symlink(qp->qp_num);
}

#define def_handle_mapping_func(res_type, res, unregister_mapping_fn)				\
int register_##res##_handle_mapping(struct ib_uverbs_file *ufile,					\
					res_type *res, int vhandle, int handle) {						\
	struct ufile_mapping_node *ufile_mapping;										\
	struct mapping_node *res##_map_ent;												\
	struct rbtree_struct *rbtree;													\
	struct rb_node *parent, **insert;												\
																					\
	write_lock(&per_ufile_mapping.rwlock);											\
	ufile_mapping = search_ufile_mapping(ufile, NULL, NULL);						\
	if(!ufile_mapping) {															\
		write_unlock(&per_ufile_mapping.rwlock);									\
		return -ENOENT;																\
	}																				\
																					\
	rbtree = &ufile_mapping->res##_mapping;											\
																					\
	write_lock(&rbtree->rwlock);													\
	res##_map_ent = search_mapping(vhandle, rbtree, &parent, &insert);				\
	if(!res##_map_ent) {															\
		res##_map_ent = kzalloc(sizeof(*res##_map_ent), GFP_KERNEL);				\
		if(!res##_map_ent) {														\
			write_unlock(&rbtree->rwlock);											\
			write_unlock(&per_ufile_mapping.rwlock);								\
			return -ENOMEM;															\
		}																			\
																					\
		res##_map_ent->vhandle = vhandle;											\
		res##_map_ent->handle = handle;												\
		rbtree_add_node(&res##_map_ent->node, parent, insert, rbtree);				\
	}																				\
	else {																			\
		res##_map_ent->handle = handle;												\
	}																				\
																					\
	write_unlock(&rbtree->rwlock);													\
	write_unlock(&per_ufile_mapping.rwlock);										\
	res->res##_map_ent = res##_map_ent;												\
	printk(KERN_NOTICE "Add " #res " mapping: vhandle: %d, handle: %d\n",			\
						res##_map_ent->vhandle, res##_map_ent->handle);				\
																					\
	return 0;																		\
}																					\
																					\
void unregister_##res##_handle_mapping(struct ib_uverbs_file *ufile,				\
								res_type *res) {									\
	struct ufile_mapping_node *ufile_mapping;										\
	struct mapping_node *res##_map_ent;												\
	struct rbtree_struct *rbtree;													\
	void (*__unregister_fn)(res_type *res);											\
																					\
	__unregister_fn = unregister_mapping_fn;										\
	write_lock(&per_ufile_mapping.rwlock);											\
	ufile_mapping = search_ufile_mapping(ufile, NULL, NULL);						\
	if(!ufile_mapping) {															\
		write_unlock(&per_ufile_mapping.rwlock);									\
		return;																		\
	}																				\
																					\
	rbtree = &ufile_mapping->res##_mapping;											\
																					\
	write_lock(&rbtree->rwlock);													\
	res##_map_ent = res->res##_map_ent;												\
	res##_map_ent = search_mapping(res##_map_ent->vhandle, rbtree, NULL, NULL);		\
	if(!res##_map_ent) {															\
		write_unlock(&rbtree->rwlock);												\
		write_unlock(&per_ufile_mapping.rwlock);									\
		return;																		\
	}																				\
	printk(KERN_NOTICE "Del " #res " map: vhandle: %d, handle: %d\n",				\
					res##_map_ent->vhandle, res##_map_ent->handle);					\
	rbtree_rm_node(&res##_map_ent->node, rbtree);									\
	kfree(res##_map_ent);															\
	res->res##_map_ent = NULL;														\
																					\
	write_unlock(&rbtree->rwlock);													\
	write_unlock(&per_ufile_mapping.rwlock);										\
																					\
	if(__unregister_fn) {															\
		__unregister_fn(res);														\
	}																				\
}																					\
																					\
int get_##res##_handle(struct ib_uverbs_file *ufile,								\
					int vhandle, int *handle) {										\
	struct ufile_mapping_node *ufile_mapping;										\
	struct mapping_node *res##_map_ent;												\
	struct rbtree_struct *rbtree;													\
																					\
	read_lock(&per_ufile_mapping.rwlock);											\
	ufile_mapping = search_ufile_mapping(ufile, NULL, NULL);						\
	if(!ufile_mapping) {															\
		read_unlock(&per_ufile_mapping.rwlock);										\
		return -ENOENT;																\
	}																				\
																					\
	rbtree = &ufile_mapping->res##_mapping;											\
																					\
	read_lock(&rbtree->rwlock);														\
	res##_map_ent = search_mapping(vhandle, rbtree, NULL, NULL);					\
	if(!res##_map_ent) {															\
		read_unlock(&rbtree->rwlock);												\
		read_unlock(&per_ufile_mapping.rwlock);										\
		return -ENOENT;																\
	}																				\
																					\
	printk(KERN_NOTICE "Get " #res " mapping: vhandle: %d, handle: %d\n",			\
							res##_map_ent->vhandle, res##_map_ent->handle);			\
																					\
	if(handle)																		\
		*handle = res##_map_ent->handle;											\
																					\
	read_unlock(&rbtree->rwlock);													\
	read_unlock(&per_ufile_mapping.rwlock);											\
																					\
	return 0;																		\
}

def_handle_mapping_func(struct ib_pd, pd, NULL);
def_handle_mapping_func(struct ib_cq, cq, NULL);
def_handle_mapping_func(struct ib_mr, mr, NULL);
def_handle_mapping_func(struct ib_qp, qp, unregister_handle_mapping_fn);
def_handle_mapping_func(struct ib_srq, srq, NULL);
