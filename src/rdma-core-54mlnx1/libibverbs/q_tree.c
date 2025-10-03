#include "verbs.h"
#include "rbtree.h"
#include "driver.h"

struct cq_entry {
	struct ibv_cq			*cq;
	int						cons_index;
	struct rb_node			rb_node;
};

static inline struct cq_entry *to_cq_entry(struct rb_node *n) {
	return n? container_of(n, struct cq_entry, rb_node): NULL;
}

static inline int cq_entry_compare(const struct rb_node *n1, const struct rb_node *n2) {
	struct cq_entry *cq_ent1 = to_cq_entry(n1);
	struct cq_entry *cq_ent2 = to_cq_entry(n2);

	if(cq_ent1->cq < cq_ent2->cq)
		return -1;
	else if(cq_ent1->cq > cq_ent2->cq)
		return 1;
	else
		return 0;
}

struct qp_entry {
	struct ibv_qp			*qp;
	struct rb_node			rb_node;
};

static inline struct qp_entry *to_qp_entry(struct rb_node *n) {
	return n? container_of(n, struct qp_entry, rb_node): NULL;
}

static inline int qp_entry_compare(const struct rb_node *n1, const struct rb_node *n2) {
	struct qp_entry *qp_ent1 = to_qp_entry(n1);
	struct qp_entry *qp_ent2 = to_qp_entry(n2);

	if(qp_ent1->qp->qp_num < qp_ent2->qp->qp_num)
		return -1;
	else if(qp_ent1->qp->qp_num > qp_ent2->qp->qp_num)
		return 1;
	else
		return 0;
}

static struct cq_entry *search_cq_entry(struct ibv_cq *cq, const struct rbtree_struct *rbtree,
						struct rb_node **p_parent, struct rb_node ***p_insert) {
	struct cq_entry target = {.cq = cq};
	struct rb_node *match = ___search(&target.rb_node, rbtree, p_parent, p_insert,
					SEARCH_EXACTLY, cq_entry_compare);
	return to_cq_entry(match);
}

static struct qp_entry *search_qp_entry(struct ibv_qp *qp, const struct rbtree_struct *rbtree,
						struct rb_node **p_parent, struct rb_node ***p_insert) {
	struct qp_entry target = {.qp = qp};
	struct rb_node *match = ___search(&target.rb_node, rbtree, p_parent, p_insert,
					SEARCH_EXACTLY, qp_entry_compare);
	return to_qp_entry(match);
}

static declare_and_init_rbtree(qp_tree);
static declare_and_init_rbtree(cq_tree);

int rbtree_search_cq(struct ibv_cq *cq) {
	struct cq_entry *cq_entry;

	if(ibv_get_signal())
		pthread_rwlock_rdlock(&cq_tree.rwlock);
	cq_entry = search_cq_entry(cq, &cq_tree, NULL, NULL);
	if(ibv_get_signal())
		pthread_rwlock_unlock(&cq_tree.rwlock);
	
	if(cq_entry)
		return 0;
	else
		return -ENOENT;
}

int rbtree_add_cq(struct ibv_cq *cq) {
	struct cq_entry *cq_entry;
	struct rb_node *parent, **insert;
	struct cq_entry *new_cq_entry;

	if(ibv_get_signal())
		pthread_rwlock_wrlock(&cq_tree.rwlock);
	cq_entry = search_cq_entry(cq, &cq_tree, &parent, &insert);
	if(cq_entry) {
		if(ibv_get_signal())
			pthread_rwlock_unlock(&cq_tree.rwlock);
		return -EEXIST;
	}

	new_cq_entry = malloc(sizeof(*new_cq_entry));
	if(!new_cq_entry) {
		if(ibv_get_signal())
			pthread_rwlock_unlock(&cq_tree.rwlock);
		return -ENOMEM;
	}

	new_cq_entry->cq = cq;
	rbtree_add_node(&new_cq_entry->rb_node, parent, insert, &cq_tree);
	if(ibv_get_signal())
		pthread_rwlock_unlock(&cq_tree.rwlock);

	return 0;
}

void rbtree_del_cq(struct ibv_cq *cq) {
	struct cq_entry *cq_entry;

	if(ibv_get_signal())
		pthread_rwlock_wrlock(&cq_tree.rwlock);
	cq_entry = search_cq_entry(cq, &cq_tree, NULL, NULL);
	if(!cq_entry) {
		if(ibv_get_signal())
			pthread_rwlock_unlock(&cq_tree.rwlock);
		return;
	}

	rbtree_rm_node(&cq_entry->rb_node, &cq_tree);
	free(cq_entry);
	if(ibv_get_signal())
		pthread_rwlock_unlock(&cq_tree.rwlock);
}

int rbtree_search_qp(struct ibv_qp *qp) {
	struct qp_entry *qp_entry;

	if(ibv_get_signal())
		pthread_rwlock_rdlock(&qp_tree.rwlock);
	qp_entry = search_qp_entry(qp, &qp_tree, NULL, NULL);
	if(ibv_get_signal())
		pthread_rwlock_unlock(&qp_tree.rwlock);

	if(qp_entry)
		return 0;
	else
		return -ENOENT;
}

int rbtree_add_qp(struct ibv_qp *qp) {
	struct qp_entry *qp_entry;
	struct rb_node *parent, **insert;
	struct qp_entry *new_qp_entry;

	if(ibv_get_signal())
		pthread_rwlock_wrlock(&qp_tree.rwlock);
	qp_entry = search_qp_entry(qp, &qp_tree, &parent, &insert);
	if(qp_entry) {
		if(ibv_get_signal())
			pthread_rwlock_unlock(&qp_tree.rwlock);
		return -EEXIST;
	}

	new_qp_entry = malloc(sizeof(*new_qp_entry));
	if(!new_qp_entry) {
		if(ibv_get_signal())
			pthread_rwlock_unlock(&qp_tree.rwlock);
		return -ENOMEM;
	}

	new_qp_entry->qp = qp;
	rbtree_add_node(&new_qp_entry->rb_node, parent, insert, &qp_tree);
	if(ibv_get_signal())
		pthread_rwlock_unlock(&qp_tree.rwlock);

	return 0;
}

void rbtree_del_qp(struct ibv_qp *qp) {
	struct qp_entry *qp_entry;

	if(ibv_get_signal())
		pthread_rwlock_wrlock(&qp_tree.rwlock);
	qp_entry = search_qp_entry(qp, &qp_tree, NULL, NULL);
	if(!qp_entry) {
		if(ibv_get_signal())
			pthread_rwlock_unlock(&qp_tree.rwlock);
		return;
	}

	rbtree_rm_node(&qp_entry->rb_node, &qp_tree);
	free(qp_entry);
	if(ibv_get_signal())
		pthread_rwlock_unlock(&qp_tree.rwlock);
}

int rbtree_traverse_cq(int (*iter_cq_fn)(struct ibv_cq *cq,
					void *entry, void *in_param), void *in_param) {
	struct cq_entry *cq_entry;

	if(ibv_get_signal())
		pthread_rwlock_rdlock(&cq_tree.rwlock);
	for_each_rbtree_entry(cq_entry, &cq_tree, to_cq_entry, rb_node) {
		if(iter_cq_fn(cq_entry->cq, cq_entry, in_param)) {
			if(ibv_get_signal())
				pthread_rwlock_unlock(&cq_tree.rwlock);
			return -1;
		}
	}
	if(ibv_get_signal())
		pthread_rwlock_unlock(&cq_tree.rwlock);
	return 0;
}

int rbtree_traverse_qp(int (*iter_qp_fn)(struct ibv_qp *qp,
					void *entry, void *in_param), void *in_param) {
	struct qp_entry *qp_entry;

	if(ibv_get_signal())
		pthread_rwlock_rdlock(&qp_tree.rwlock);
	for_each_rbtree_entry(qp_entry, &qp_tree, to_qp_entry, rb_node) {
		if(iter_qp_fn(qp_entry->qp, qp_entry, in_param)) {
			if(ibv_get_signal())
				pthread_rwlock_unlock(&qp_tree.rwlock);
			return -1;
		}
	}
	if(ibv_get_signal())
		pthread_rwlock_unlock(&qp_tree.rwlock);
	return 0;
}

struct context_entry {
	struct ibv_context				*context;
	struct rb_node					rb_node;
};

static inline struct context_entry *to_context_entry(struct rb_node *n) {
	return n? container_of(n, struct context_entry, rb_node): NULL;
}

static inline int context_entry_compare(const struct rb_node *n1, const struct rb_node *n2) {
	struct context_entry *ctx_ent1 = to_context_entry(n1);
	struct context_entry *ctx_ent2 = to_context_entry(n2);

	if(ctx_ent1->context < ctx_ent2->context)
		return -1;
	else if(ctx_ent1->context > ctx_ent2->context)
		return 1;
	else
		return 0;
}

static struct context_entry *search_context_entry(struct ibv_context *ctx, const struct rbtree_struct *rbtree,
					struct rb_node **p_parent, struct rb_node ***p_insert) {
	struct context_entry target = {.context = ctx};
	struct rb_node *match = ___search(&target.rb_node, rbtree, p_parent, p_insert,
					SEARCH_EXACTLY, context_entry_compare);
	return to_context_entry(match);
}

static declare_and_init_rbtree(ctx_tree);

int rbtree_search_context(struct ibv_context *ctx) {
	struct context_entry *ctx_entry;

	if(ibv_get_signal())
		pthread_rwlock_rdlock(&ctx_tree.rwlock);
	ctx_entry = search_context_entry(ctx, &ctx_tree, NULL, NULL);
	if(ibv_get_signal())
		pthread_rwlock_unlock(&ctx_tree.rwlock);
	
	if(ctx_entry)
		return 0;
	else
		return -ENOENT;
}

int rbtree_add_context(struct ibv_context *ctx) {
	struct context_entry *ctx_entry;
	struct rb_node *parent, **insert;
	struct context_entry *new_ctx_entry;

	if(ibv_get_signal())
		pthread_rwlock_wrlock(&ctx_tree.rwlock);
	ctx_entry = search_context_entry(ctx, &ctx_tree, &parent, &insert);
	if(ctx_entry) {
		if(ibv_get_signal())
			pthread_rwlock_unlock(&ctx_tree.rwlock);
		return -EEXIST;
	}

	new_ctx_entry = malloc(sizeof(*new_ctx_entry));
	if(!new_ctx_entry) {
		if(ibv_get_signal())
			pthread_rwlock_unlock(&ctx_tree.rwlock);
		return -ENOMEM;
	}

	new_ctx_entry->context = ctx;
	rbtree_add_node(&new_ctx_entry->rb_node, parent, insert, &ctx_tree);
	if(ibv_get_signal())
		pthread_rwlock_unlock(&ctx_tree.rwlock);
	
	return 0;
}

void rbtree_del_context(struct ibv_context *ctx) {
	struct context_entry *ctx_entry;

	if(ibv_get_signal())
		pthread_rwlock_wrlock(&ctx_tree.rwlock);
	ctx_entry = search_context_entry(ctx, &ctx_tree, NULL, NULL);
	if(!ctx_entry) {
		if(ibv_get_signal())
			pthread_rwlock_unlock(&ctx_tree.rwlock);
		return;
	}

	rbtree_rm_node(&ctx_entry->rb_node, &ctx_tree);
	free(ctx_entry);
	if(ibv_get_signal())
		pthread_rwlock_unlock(&ctx_tree.rwlock);
}

int rbtree_traverse_context(int (*iter_context_fn)(struct ibv_context *ctx,
					void *entry, void *in_param), void *in_param) {
	struct context_entry *ctx_entry;

	if(ibv_get_signal())
		pthread_rwlock_rdlock(&ctx_tree.rwlock);
	for_each_rbtree_entry(ctx_entry, &ctx_tree, to_context_entry, rb_node) {
		if(iter_context_fn(ctx_entry->context, ctx_entry, in_param)) {
			if(ibv_get_signal())
				pthread_rwlock_unlock(&ctx_tree.rwlock);
			return -1;
		}
	}
	if(ibv_get_signal())
		pthread_rwlock_unlock(&ctx_tree.rwlock);
	return 0;
}

static declare_and_init_rbtree(qpn_dict);

struct qpn_dict_node {
	uint32_t				pqpn;
	int						cmd_fd;
	int						qp_vhandle;
	struct rb_node			node;
};

static inline struct qpn_dict_node *to_qpn_dict_node(struct rb_node *node) {
	return node? container_of(node, struct qpn_dict_node, node): NULL;
}

static int qpn_dict_node_compare(const struct rb_node *n1, const struct rb_node *n2) {
	struct qpn_dict_node *node1 = to_qpn_dict_node((struct rb_node *)n1);
	struct qpn_dict_node *node2 = to_qpn_dict_node((struct rb_node *)n2);

	if(node1->pqpn < node2->pqpn)
		return -1;
	else if(node1->pqpn > node2->pqpn)
		return 1;
	else
		return 0;
}

static struct qpn_dict_node *search_qpn_dict_node(uint32_t pqpn,
					struct rb_node **p_parent, struct rb_node ***p_insert) {
	struct qpn_dict_node target = {.pqpn = pqpn};
	struct rb_node *match = ___search(&target.node, &qpn_dict, p_parent, p_insert,
								SEARCH_EXACTLY, qpn_dict_node_compare);
	return to_qpn_dict_node(match);
}

int add_qpn_dict_node(struct ibv_qp *qp) {
	struct qpn_dict_node	*this_node;
	struct rb_node			*parent;
	struct rb_node			**insert;
	uint32_t				pqpn;
	int						cmd_fd;
	int						qp_vhandle;

	pqpn = qp->real_qpn;
	cmd_fd = qp->context->cmd_fd;
	qp_vhandle = qp->handle;

	pthread_rwlock_wrlock(&qpn_dict.rwlock);
	this_node = search_qpn_dict_node(pqpn, &parent, &insert);
	if(this_node) {
		pthread_rwlock_unlock(&qpn_dict.rwlock);
		return -EEXIST;
	}

	this_node = calloc(1, sizeof(*this_node));
	if(!this_node) {
		pthread_rwlock_unlock(&qpn_dict.rwlock);
		return -ENOMEM;
	}

	this_node->pqpn = pqpn;
	this_node->cmd_fd = cmd_fd;
	this_node->qp_vhandle = qp_vhandle;
	rbtree_add_node(&this_node->node, parent, insert, &qpn_dict);
	pthread_rwlock_unlock(&qpn_dict.rwlock);

	return 0;
}

int get_qpn_dict(uint32_t pqpn, int *cmd_fd, int *qp_vhandle) {
	struct qpn_dict_node	*this_node;

	pthread_rwlock_rdlock(&qpn_dict.rwlock);
	this_node = search_qpn_dict_node(pqpn, NULL, NULL);
	if(!this_node) {
		pthread_rwlock_unlock(&qpn_dict.rwlock);
		return -ENOENT;
	}

	if(cmd_fd) {
		*cmd_fd = this_node->cmd_fd;
	}

	if(qp_vhandle) {
		*qp_vhandle = this_node->qp_vhandle;
	}

	pthread_rwlock_unlock(&qpn_dict.rwlock);
	return 0;
}

void del_qpn_dict_node(struct ibv_qp *qp) {
	struct qpn_dict_node	*this_node;

	pthread_rwlock_wrlock(&qpn_dict.rwlock);
	this_node = search_qpn_dict_node(qp->real_qpn, NULL, NULL);
	if(!this_node) {
		pthread_rwlock_unlock(&qpn_dict.rwlock);
		return;
	}

	rbtree_rm_node(&this_node->node, &qpn_dict);
	free(this_node);
	pthread_rwlock_unlock(&qpn_dict.rwlock);
}

void del_qpn_dict_node_2(struct ibv_qp *qp) {
	struct qpn_dict_node	*this_node;

	pthread_rwlock_wrlock(&qpn_dict.rwlock);
	this_node = search_qpn_dict_node(qp->orig_real_qpn, NULL, NULL);
	if(!this_node) {
		pthread_rwlock_unlock(&qpn_dict.rwlock);
		return;
	}

	rbtree_rm_node(&this_node->node, &qpn_dict);
	free(this_node);
	pthread_rwlock_unlock(&qpn_dict.rwlock);
}

static declare_and_init_rbtree(switch_list);

struct switch_list_node {
	uint32_t				new_pqpn;
	struct ibv_qp			*orig_qp;
	struct ibv_qp			*new_qp;
	struct rb_node			node;
};

static inline struct switch_list_node *to_switch_list_node(struct rb_node *node) {
	return node? container_of(node, struct switch_list_node, node): NULL;
}

static int switch_list_node_compare(const struct rb_node *n1, const struct rb_node *n2) {
	struct switch_list_node *node1 = to_switch_list_node((struct rb_node *)n1);
	struct switch_list_node *node2 = to_switch_list_node((struct rb_node *)n2);

	if(node1->new_pqpn < node2->new_pqpn)
		return -1;
	else if(node1->new_pqpn > node2->new_pqpn)
		return 1;
	else
		return 0;
}

static struct switch_list_node *search_switch_list_node(uint32_t pqpn,
						struct rb_node **p_parent, struct rb_node ***p_insert) {
	struct switch_list_node target = {.new_pqpn = pqpn};
	struct rb_node *match = ___search(&target.node, &switch_list, p_parent, p_insert,
								SEARCH_EXACTLY, switch_list_node_compare);
	return to_switch_list_node(match);
}

int add_switch_list_node(uint32_t pqpn, struct ibv_qp *orig_qp, struct ibv_qp *new_qp) {
	struct switch_list_node		*this_node;
	struct rb_node				*parent;
	struct rb_node				**insert;

	pthread_rwlock_wrlock(&switch_list.rwlock);
	this_node = search_switch_list_node(pqpn, &parent, &insert);
	if(this_node) {
		pthread_rwlock_unlock(&switch_list.rwlock);
		return -EEXIST;
	}

	this_node = calloc(1, sizeof(*this_node));
	if(!this_node) {
		pthread_rwlock_unlock(&switch_list.rwlock);
		return -ENOMEM;
	}

	this_node->new_pqpn = pqpn;
	this_node->orig_qp = orig_qp;
	this_node->new_qp = new_qp;
	rbtree_add_node(&this_node->node, parent, insert, &switch_list);
	pthread_rwlock_unlock(&switch_list.rwlock);

	return 0;
}

int switch_to_new_qp(uint32_t pqpn, void *param,
				int (*switch_cb)(struct ibv_qp *orig_qp,
				struct ibv_qp *new_qp,
				void *param)) {
	struct switch_list_node		*this_node;
	int err;

	pthread_rwlock_wrlock(&switch_list.rwlock);
	this_node = search_switch_list_node(pqpn, NULL, NULL);
	if(!this_node) {
		pthread_rwlock_unlock(&switch_list.rwlock);
		return -ENOENT;
	}

	err = switch_cb(this_node->orig_qp, this_node->new_qp, param);
	if(err) {
		pthread_rwlock_unlock(&switch_list.rwlock);
		return err;
	}

	rbtree_rm_node(&this_node->node, &switch_list);
	free(this_node);
	pthread_rwlock_unlock(&switch_list.rwlock);

	return 0;
}

#include "ibverbs.h"

int switch_all_qps(int (*switch_cb)(struct ibv_qp *orig_qp, struct ibv_qp *new_qp),
				int (*load_cb)(struct ibv_qp *orig_qp, void *replay_fn)) {
	struct switch_list_node *this_node;
	struct switch_list_node *tmp;
	int err;

	pthread_rwlock_wrlock(&switch_list.rwlock);
	for_each_rbtree_entry_safe(this_node, tmp, &switch_list,
					to_switch_list_node, node) {
		err = switch_cb(this_node->orig_qp, this_node->new_qp);
		if(err) {
			pthread_rwlock_unlock(&switch_list.rwlock);
			return err;
		}

		err = load_cb(this_node->orig_qp, get_ops(this_node->orig_qp->context)->replay_recv_wr);
		if(err) {
			pthread_rwlock_unlock(&switch_list.rwlock);
			return err;
		}

		rbtree_rm_node(&this_node->node, &switch_list);
		free(this_node);
	}
	pthread_rwlock_unlock(&switch_list.rwlock);

	return 0;
}

struct srq_entry {
	struct ibv_srq			*srq;
	struct rb_node			rb_node;
};

static inline struct srq_entry *to_srq_entry(struct rb_node *n) {
	return n? container_of(n, struct srq_entry, rb_node): NULL;
}

static inline int srq_entry_compare(const struct rb_node *n1, const struct rb_node *n2) {
	struct srq_entry *srq_ent1 = to_srq_entry(n1);
	struct srq_entry *srq_ent2 = to_srq_entry(n2);

	if(srq_ent1->srq < srq_ent2->srq)
		return -1;
	else if(srq_ent1->srq > srq_ent2->srq)
		return 1;
	else
		return 0;
}

static struct srq_entry *search_srq_entry(struct ibv_srq *srq, const struct rbtree_struct *rbtree,
						struct rb_node **p_parent, struct rb_node ***p_insert) {
	struct srq_entry target = {.srq = srq};
	struct rb_node *match = ___search(&target.rb_node, rbtree, p_parent, p_insert,
							SEARCH_EXACTLY, srq_entry_compare);
	return to_srq_entry(match);
}

static declare_and_init_rbtree(srq_tree);

int rbtree_search_srq(struct ibv_srq *srq) {
	struct srq_entry *srq_entry;

	if(ibv_get_signal())
		pthread_rwlock_rdlock(&srq_tree.rwlock);
	srq_entry = search_srq_entry(srq, &srq_tree, NULL, NULL);
	if(ibv_get_signal())
		pthread_rwlock_unlock(&srq_tree.rwlock);

	if(srq_entry)
		return 0;
	else
		return -ENOENT;
}

int rbtree_add_srq(struct ibv_srq *srq) {
	struct srq_entry *srq_entry;
	struct rb_node *parent, **insert;

	if(ibv_get_signal())
		pthread_rwlock_wrlock(&srq_tree.rwlock);
	srq_entry = search_srq_entry(srq, &srq_tree, &parent, &insert);
	if(srq_entry) {
		if(ibv_get_signal())
			pthread_rwlock_unlock(&srq_tree.rwlock);
		return -EEXIST;
	}

	srq_entry = malloc(sizeof(*srq_entry));
	if(!srq_entry) {
		if(ibv_get_signal())
			pthread_rwlock_unlock(&srq_tree.rwlock);
		return -ENOMEM;
	}

	srq_entry->srq = srq;
	rbtree_add_node(&srq_entry->rb_node, parent, insert, &srq_tree);
	if(ibv_get_signal())
		pthread_rwlock_unlock(&srq_tree.rwlock);

	return 0;
}

void rbtree_del_srq(struct ibv_srq *srq) {
	struct srq_entry *srq_entry;

	if(ibv_get_signal())
		pthread_rwlock_wrlock(&srq_tree.rwlock);
	srq_entry = search_srq_entry(srq, &srq_tree, NULL, NULL);
	if(!srq_entry) {
		if(ibv_get_signal())
			pthread_rwlock_unlock(&srq_tree.rwlock);
		return;
	}

	rbtree_rm_node(&srq_entry->rb_node, &srq_tree);
	free(srq_entry);
	if(ibv_get_signal())
		pthread_rwlock_unlock(&srq_tree.rwlock);
}

int rbtree_traverse_srq(int (*iter_srq_fn)(struct ibv_srq *srq,
						void *entry, void *in_param), void *in_param) {
	struct srq_entry *srq_entry;

	if(ibv_get_signal())
		pthread_rwlock_rdlock(&srq_tree.rwlock);
	for_each_rbtree_entry(srq_entry, &srq_tree, to_srq_entry, rb_node) {
		if(iter_srq_fn(srq_entry->srq, srq_entry, in_param)) {
			if(ibv_get_signal())
				pthread_rwlock_unlock(&srq_tree.rwlock);
			return -1;
		}
	}
	if(ibv_get_signal())
		pthread_rwlock_unlock(&srq_tree.rwlock);
	return 0;
}

static declare_and_init_rbtree(srq_switch_list);

struct srq_switch_node {
	struct ibv_srq				*new_srq;
	struct ibv_srq				*orig_srq;
	struct rb_node				node;
};

static inline struct srq_switch_node *to_srq_switch_node(struct rb_node *node) {
	return node? container_of(node, struct srq_switch_node, node): NULL;
}

static int srq_switch_node_compare(const struct rb_node *n1, const struct rb_node *n2) {
	struct srq_switch_node *node1 = to_srq_switch_node(n1);
	struct srq_switch_node *node2 = to_srq_switch_node(n2);

	if(node1->new_srq < node2->new_srq)
		return -1;
	else if(node1->new_srq > node2->new_srq)
		return 1;
	else
		return 0;
}

static struct srq_switch_node *search_srq_switch_node(struct ibv_srq *new_srq,
					struct rb_node **p_parent, struct rb_node ***p_insert) {
	struct srq_switch_node target = {.new_srq = new_srq};
	struct rb_node *match = ___search(&target.node, &srq_switch_list, p_parent, p_insert,
							SEARCH_EXACTLY, srq_switch_node_compare);
	return to_srq_switch_node(match);
}

int add_srq_switch_node(struct ibv_srq *new_srq, struct ibv_srq *orig_srq) {
	struct srq_switch_node *this_node;
	struct rb_node *parent;
	struct rb_node **insert;

	pthread_rwlock_wrlock(&srq_switch_list.rwlock);
	this_node = search_srq_switch_node(new_srq, &parent, &insert);
	if(this_node) {
		pthread_rwlock_unlock(&srq_switch_list.rwlock);
		return -EEXIST;
	}

	this_node = calloc(1, sizeof(*this_node));
	if(!this_node) {
		pthread_rwlock_unlock(&srq_switch_list.rwlock);
		return -ENOMEM;
	}

	this_node->new_srq = new_srq;
	this_node->orig_srq = orig_srq;
	rbtree_add_node(&this_node->node, parent, insert, &srq_switch_list);
	pthread_rwlock_unlock(&srq_switch_list.rwlock);

	return 0;
}

int switch_all_srqs(int (*switch_cb)(struct ibv_srq *orig_srq, struct ibv_srq *new_srq, int *head, int *tail),
			int (*srq_load_cb)(struct ibv_srq *orig_srq, void *replay_fn, int head, int tail)) {
	struct srq_switch_node *this_node, *tmp;
	int err;
	int head, tail;

	pthread_rwlock_wrlock(&srq_switch_list.rwlock);
	for_each_rbtree_entry_safe(this_node, tmp, &srq_switch_list,
						to_srq_switch_node, node) {
		err = switch_cb(this_node->orig_srq, this_node->new_srq, &head, &tail);
		if(err) {
			pthread_rwlock_unlock(&srq_switch_list.rwlock);
			return err;
		}

		err = srq_load_cb(this_node->orig_srq, get_ops(this_node->orig_srq->context)->replay_srq_recv_wr, head, tail);
		if(err) {
			pthread_rwlock_unlock(&srq_switch_list.rwlock);
			return err;
		}

		rbtree_rm_node(&this_node->node, &srq_switch_list);
		free(this_node);
	}
	pthread_rwlock_unlock(&srq_switch_list.rwlock);
	return 0;
}

static declare_and_init_rbtree(old_qpndict);

struct old_dict_node {
	uint32_t			real_qpn;
	uint32_t			virt_qpn;
	struct rb_node		node;
};

static inline struct old_dict_node *to_old_dict_node(struct rb_node *node) {
	return node? container_of(node, struct old_dict_node, node): NULL;
}

static int old_dict_node_compare(const struct rb_node *n1, const struct rb_node *n2) {
	struct old_dict_node *node1 = to_old_dict_node(n1);
	struct old_dict_node *node2 = to_old_dict_node(n2);

	if(node1->real_qpn < node2->real_qpn)
		return -1;
	else if(node1->real_qpn > node2->real_qpn)
		return 1;
	else
		return 0;
}

static struct old_dict_node *search_old_dict_node(uint32_t real_qpn,
					struct rb_node **p_parent, struct rb_node ***p_insert) {
	struct old_dict_node target = {.real_qpn = real_qpn};
	struct rb_node *match = ___search(&target.node, &old_qpndict, p_parent, p_insert,
						SEARCH_EXACTLY, old_dict_node_compare);
	return to_old_dict_node(match);
}

int get_vqpn_from_old(uint32_t real_qpn, uint32_t *vqpn) {
	struct old_dict_node *this_node;

	pthread_rwlock_rdlock(&old_qpndict.rwlock);
	this_node = search_old_dict_node(real_qpn, NULL, NULL);
	if(!this_node) {
		pthread_rwlock_unlock(&old_qpndict.rwlock);
		return -ENOENT;
	}

	if(vqpn)
		*vqpn = this_node->virt_qpn;
	pthread_rwlock_unlock(&old_qpndict.rwlock);
	return 0;
}

int add_old_dict_node(struct ibv_qp *qp,
				uint32_t real_qpn, uint32_t virt_qpn) {
	struct old_dict_node *this_node;
	struct rb_node *parent;
	struct rb_node **insert;

	pthread_rwlock_wrlock(&old_qpndict.rwlock);
	this_node = search_old_dict_node(real_qpn, &parent, &insert);
	if(this_node) {
		pthread_rwlock_unlock(&old_qpndict.rwlock);
		return 0;
	}

	this_node = (struct old_dict_node *)&qp->old_dict_node;
	this_node->real_qpn = real_qpn;
	this_node->virt_qpn = virt_qpn;
	rbtree_add_node(&this_node->node, parent, insert, &old_qpndict);
	pthread_rwlock_unlock(&old_qpndict.rwlock);
	return 0;
}

static void free_old_qpn_dict(struct rb_node *node) {
	return;
}

void clear_old_qpndict(void) {
	clean_rbtree(&old_qpndict, free_old_qpn_dict);
}

static declare_and_init_rbtree(comp_channel_tree);

struct comp_channel_node {
	int									fd;
	struct ibv_comp_channel				*channel;
	struct rb_node						node;
};

static inline struct comp_channel_node *to_comp_channel_node(struct rb_node *node) {
	return node? container_of(node, struct comp_channel_node, node): NULL;
}

static int comp_channel_node_compare(const struct rb_node *n1, const struct rb_node *n2) {
	struct comp_channel_node *node1 = to_comp_channel_node(n1);
	struct comp_channel_node *node2 = to_comp_channel_node(n2);

	return node1->fd - node2->fd;
}

static struct comp_channel_node *search_comp_channel_node(int fd,
					struct rb_node **p_parent, struct rb_node ***p_insert) {
	struct comp_channel_node target = {.fd = fd};
	struct rb_node *match = ___search(&target.node, &comp_channel_tree, p_parent, p_insert,
							SEARCH_EXACTLY, comp_channel_node_compare);
	return to_comp_channel_node(match);
}

struct ibv_comp_channel *get_comp_channel_from_fd(int fd) {
	struct comp_channel_node *this_node;

	pthread_rwlock_rdlock(&comp_channel_tree.rwlock);
	this_node = search_comp_channel_node(fd, NULL, NULL);
	if(!this_node) {
		pthread_rwlock_unlock(&comp_channel_tree.rwlock);
		return NULL;
	}

	pthread_rwlock_unlock(&comp_channel_tree.rwlock);
	return this_node->channel;
}

int add_comp_channel(int fd, struct ibv_comp_channel *channel) {
	struct comp_channel_node *this_node;
	struct rb_node *parent;
	struct rb_node **insert;

	pthread_rwlock_wrlock(&comp_channel_tree.rwlock);
	this_node = search_comp_channel_node(fd, &parent, &insert);
	if(this_node) {
		pthread_rwlock_unlock(&comp_channel_tree.rwlock);
		return -1;
	}

	this_node = calloc(1, sizeof(*this_node));
	if(!this_node) {
		pthread_rwlock_unlock(&comp_channel_tree.rwlock);
		return -1;
	}

	this_node->fd				= fd;
	this_node->channel			= channel;
	rbtree_add_node(&this_node->node, parent, insert, &comp_channel_tree);
	pthread_rwlock_unlock(&comp_channel_tree.rwlock);
	return 0;
}

static declare_and_init_rbtree(update_mem);

struct update_mem_node {
	void					*ptr;
	size_t					size;
	void					*content_p;
	struct rb_node			node;
};

static inline struct update_mem_node *to_update_mem_node(struct rb_node *node) {
	return node? container_of(node, struct update_mem_node, node): NULL;
}

static int comp_update_mem_node(const struct rb_node *n1, const struct rb_node *n2) {
	struct update_mem_node *node1 = to_update_mem_node(n1);
	struct update_mem_node *node2 = to_update_mem_node(n2);

	if(node1->ptr < node2->ptr)
		return -1;
	else if(node1->ptr > node2->ptr)
		return 1;
	else
		return 0;
}

static struct update_mem_node *search_update_mem_node(void *ptr,
					struct rb_node **p_parent, struct rb_node ***p_insert) {
	struct update_mem_node target = {.ptr = ptr};
	struct rb_node *match = ___search(&target.node, &update_mem, p_parent, p_insert,
					SEARCH_LAST_PRECURSOR_INC_ITSELF, comp_update_mem_node);
	return to_update_mem_node(match);
}

static inline
struct update_mem_node *get_next_update_mem_node(struct update_mem_node *this_node) {
	struct rb_node *next = rb_next(&this_node->node);
	return to_update_mem_node(next);
}

static inline
struct update_mem_node *get_first_update_mem_node(void) {
	struct rb_node *first = rb_first(&update_mem.tree);
	return to_update_mem_node(first);
}

int register_update_mem(void *ptr, size_t size, void *content_p) {
	struct update_mem_node *this_node;
	struct rb_node *parent;
	struct rb_node **insert;

	pthread_rwlock_wrlock(&update_mem.rwlock);
	this_node = search_update_mem_node(ptr, &parent, &insert);
	if(this_node && this_node->ptr + this_node->size > ptr) {
		pthread_rwlock_unlock(&update_mem.rwlock);
		return -EEXIST;
	}

	this_node = this_node?
				get_next_update_mem_node(this_node):
				get_first_update_mem_node();
	if(this_node && ptr + size > this_node->ptr) {
		pthread_rwlock_unlock(&update_mem.rwlock);
		return -EEXIST;
	}

	this_node = malloc(sizeof(*this_node));
	if(!this_node) {
		pthread_rwlock_unlock(&update_mem.rwlock);
		return -ENOMEM;
	}

	this_node->ptr				= ptr;
	this_node->size				= size;
	this_node->content_p		= content_p;
	rbtree_add_node(&this_node->node, parent, insert, &update_mem);
	pthread_rwlock_unlock(&update_mem.rwlock);

	return 0;
}

int update_all_mem(int (*update_mem_fn)(void *ptr, size_t size,
								void *content_p)) {
	struct update_mem_node *this_node;

	for_each_rbtree_entry(this_node, &update_mem,
					to_update_mem_node, node) {
		if(update_mem_fn(this_node->ptr, this_node->size,
						this_node->content_p)) {
			return -1;
		}
	}

	return 0;
}

static declare_and_init_rbtree(keep_mmap);

struct keep_mmap_node {
	void						*ptr;
	size_t						size;
	struct rb_node				node;
};

static inline struct keep_mmap_node *to_keep_mmap_node(struct rb_node *node) {
	return node? container_of(node, struct keep_mmap_node, node): NULL;
}

static int comp_keep_mmap_node(const struct rb_node *n1, const struct rb_node *n2) {
	struct keep_mmap_node *node1 = to_keep_mmap_node(n1);
	struct keep_mmap_node *node2 = to_keep_mmap_node(n2);

	if(node1->ptr < node2->ptr)
		return -1;
	else if(node1->ptr > node2->ptr)
		return 1;
	else
		return 0;
}

static struct keep_mmap_node *search_keep_mmap_node(void *ptr,
					struct rb_node **p_parent, struct rb_node ***p_insert) {
	struct keep_mmap_node target = {.ptr = ptr};
	struct rb_node *match = ___search(&target.node, &keep_mmap, p_parent, p_insert,
						SEARCH_LAST_PRECURSOR_INC_ITSELF, comp_keep_mmap_node);
	return to_keep_mmap_node(match);
}

static inline
struct keep_mmap_node *get_next_keep_mmap_node(struct keep_mmap_node *this_node) {
	struct rb_node *next = rb_next(&this_node->node);
	return to_keep_mmap_node(next);
}

static inline
struct keep_mmap_node *get_first_keep_mmap_node(void) {
	struct rb_node *first = rb_first(&keep_mmap.tree);
	return to_keep_mmap_node(first);
}

int register_keep_mmap_region(void *ptr, size_t size) {
	struct keep_mmap_node *this_node;
	struct rb_node *parent;
	struct rb_node **insert;

	pthread_rwlock_wrlock(&keep_mmap.rwlock);
	this_node = search_keep_mmap_node(ptr, &parent, &insert);
	if(this_node && this_node->ptr + this_node->size > ptr) {
		pthread_rwlock_unlock(&keep_mmap.rwlock);
		return -EEXIST;
	}

	this_node = this_node?
				get_next_keep_mmap_node(this_node):
				get_first_keep_mmap_node();
	if(this_node && ptr + size > this_node->ptr) {
		pthread_rwlock_unlock(&keep_mmap.rwlock);
		return -EEXIST;
	}

	this_node = malloc(sizeof(*this_node));
	if(!this_node) {
		pthread_rwlock_unlock(&keep_mmap.rwlock);
		return -ENOMEM;
	}

	this_node->ptr			= ptr;
	this_node->size			= size;
	rbtree_add_node(&this_node->node, parent, insert, &keep_mmap);
	pthread_rwlock_unlock(&keep_mmap.rwlock);

	return 0;
}

int keep_all_mmap(int (*keep_mmap_fn)(unsigned long long start,
								unsigned long long end)) {
	struct keep_mmap_node *this_node;

	for_each_rbtree_entry(this_node, &keep_mmap,
					to_keep_mmap_node, node) {
		keep_mmap_fn((unsigned long long)this_node->ptr,
					(unsigned long long)(this_node->ptr + this_node->size));
	}

	return 0;
}

static declare_and_init_rbtree(bf_addr_map);

struct bf_addr_map_entry {
	void					*new_bf;
	void					*alloc_bf;
	struct rb_node			node;
};

static inline struct bf_addr_map_entry *to_bf_addr_map_entry(struct rb_node *node) {
	return node? container_of(node, struct bf_addr_map_entry, node): NULL;
}

static int bf_addr_map_entry_compare(const struct rb_node *n1, const struct rb_node *n2) {
	struct bf_addr_map_entry *ent1 = to_bf_addr_map_entry(n1);
	struct bf_addr_map_entry *ent2 = to_bf_addr_map_entry(n2);

	if(ent1->new_bf < ent2->new_bf)
		return -1;
	else if(ent1->new_bf > ent2->new_bf)
		return 1;
	else
		return 0;
}

static struct bf_addr_map_entry *search_bf_addr_map_entry(void *new_bf,
					struct rb_node **p_parent, struct rb_node ***p_insert) {
	struct bf_addr_map_entry target = {.new_bf = new_bf};
	struct rb_node *match = ___search(&target.node, &bf_addr_map, p_parent, p_insert,
						SEARCH_EXACTLY, bf_addr_map_entry_compare);
	return to_bf_addr_map_entry(match);
}

int add_bf_addr_map_entry(void *new_bf, void *alloc_bf) {
	struct bf_addr_map_entry *ent;
	struct rb_node *parent, **insert;

	pthread_rwlock_wrlock(&bf_addr_map.rwlock);
	ent = search_bf_addr_map_entry(new_bf, &parent, &insert);
	if(ent) {
		pthread_rwlock_unlock(&bf_addr_map.rwlock);
		return -EEXIST;
	}

	ent = malloc(sizeof(*ent));
	if(!ent) {
		pthread_rwlock_unlock(&bf_addr_map.rwlock);
		return -ENOMEM;
	}

	ent->new_bf = new_bf;
	ent->alloc_bf = alloc_bf;
	rbtree_add_node(&ent->node, parent, insert, &bf_addr_map);
	pthread_rwlock_unlock(&bf_addr_map.rwlock);
	return 0;
}

void *get_alloc_bf(void *new_bf) {
	struct bf_addr_map_entry *ent;
	void *ret;

	pthread_rwlock_rdlock(&bf_addr_map.rwlock);
	ent = search_bf_addr_map_entry(new_bf, NULL, NULL);
	if(!ent) {
		pthread_rwlock_unlock(&bf_addr_map.rwlock);
		return NULL;
	}

	ret = ent->alloc_bf;
	pthread_rwlock_unlock(&bf_addr_map.rwlock);
	return ret;
}
