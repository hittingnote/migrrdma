/*
 * RBtree implementation adopted from the Linux kernel sources.
 */

#ifndef __CR_RBTREE_H__
#define __CR_RBTREE_H__

#include <stddef.h>

#include "common/compiler.h"

#define RB_RED	 0
#define RB_BLACK 1
#define RB_MASK	 3

struct rb_node {
	unsigned long rb_parent_color; /* Keeps both parent anc color */
	struct rb_node *rb_right;
	struct rb_node *rb_left;
} __aligned(sizeof(long));

struct rb_root {
	struct rb_node *rb_node;
};

#define rb_parent(r)   ((struct rb_node *)((r)->rb_parent_color & ~RB_MASK))
#define rb_color(r)    ((r)->rb_parent_color & RB_BLACK)
#define rb_is_red(r)   (!rb_color(r))
#define rb_is_black(r) (rb_color(r))
#define rb_set_red(r)                              \
	do {                                       \
		(r)->rb_parent_color &= ~RB_BLACK; \
	} while (0)
#define rb_set_black(r)                           \
	do {                                      \
		(r)->rb_parent_color |= RB_BLACK; \
	} while (0)

static inline void rb_set_parent(struct rb_node *rb, struct rb_node *p)
{
	rb->rb_parent_color = (rb->rb_parent_color & RB_MASK) | (unsigned long)p;
}

static inline void rb_set_color(struct rb_node *rb, int color)
{
	rb->rb_parent_color = (rb->rb_parent_color & ~RB_BLACK) | color;
}

#define RB_ROOT          \
	(struct rb_root) \
	{                \
		NULL,    \
	}
#define rb_entry(ptr, type, member) container_of(ptr, type, member)

#define RB_EMPTY_ROOT(root) ((root)->rb_node == NULL)
#define RB_EMPTY_NODE(node) (rb_parent(node) == node)
#define RB_CLEAR_NODE(node) (rb_set_parent(node, node))

static inline void rb_init_node(struct rb_node *node)
{
	*node = (struct rb_node){};

	RB_CLEAR_NODE(node);
}

extern void rb_insert_color(struct rb_node *node, struct rb_root *root);
extern void rb_erase(struct rb_node *node, struct rb_root *root);

/* Find logical next and previous nodes in a tree */
extern struct rb_node *rb_first(const struct rb_root *root);
extern struct rb_node *rb_last(const struct rb_root *root);
extern struct rb_node *rb_next(const struct rb_node *node);
extern struct rb_node *rb_prev(const struct rb_node *node);

/* Fast replacement of a single node without remove/rebalance/add/rebalance */
extern void rb_replace_node(struct rb_node *victim, struct rb_node *new, struct rb_root *root);

static inline void rb_link_node(struct rb_node *node, struct rb_node *parent, struct rb_node **rb_link)
{
	node->rb_parent_color = (unsigned long)parent;
	node->rb_left = node->rb_right = NULL;

	*rb_link = node;
}

static inline void rb_link_and_balance(struct rb_root *root, struct rb_node *node, struct rb_node *parent,
				       struct rb_node **rb_link)
{
	rb_link_node(node, parent, rb_link);
	rb_insert_color(node, root);
}

/* rbtree_wrap */
#include <pthread.h>

struct rbtree_struct {
	struct rb_root				tree;
	pthread_rwlock_t			rwlock;
};

enum search_ops {
	/* Search the element exactly the same as what is specified */
	SEARCH_EXACTLY									= 0,
	/* Search the last precursor of the specified item */
	SEARCH_LAST_PRECURSOR							= 2,
	/* Search the last precursor of the specified item.
	 * If there is the item exactly the same as what is specified,
	 * then return it */
	SEARCH_LAST_PRECURSOR_INC_ITSELF				= 3,
	/* Search the first successor of the specified item */
	SEARCH_FIRST_SUCCESSOR							= 4,
	/* Search the first successor of the specified item.
	 * If there is the item exactly the same as what is specified,
	 * then return it */
	SEARCH_FIRST_SUCCESSOR_INC_ITSELF				= 5,
};

enum TRACE_DIRECTION {
	LEFT,
	RIGHT,
};

#define declare_and_init_rbtree(var)								\
	struct rbtree_struct var = {									\
		.tree				= RB_ROOT,								\
		.rwlock				= PTHREAD_RWLOCK_INITIALIZER,			\
	}

extern struct rb_node *___search(const struct rb_node *target, struct rbtree_struct *rbtree,
						struct rb_node **p_parent, struct rb_node ***p_insert, enum search_ops ops,
						int (*compare)(const struct rb_node*, const struct rb_node*));

static inline void rbtree_add_node(struct rb_node *new_node, struct rb_node *parent,
					struct rb_node **insert, struct rbtree_struct *rbtree) {
	rb_link_node(new_node, parent, insert);
	rb_insert_color(new_node, &rbtree->tree);
}

static inline void rbtree_rm_node(struct rb_node *target, struct rbtree_struct *rbtree) {
	rb_erase(target, &rbtree->tree);
}

static inline void clean_rbtree(struct rbtree_struct *rbtree,
				void (*free_fn)(struct rb_node *node)) {
	struct rb_node *root_node;
	while((root_node = rbtree->tree.rb_node)) {
		rb_erase(root_node, &rbtree->tree);
		free_fn(root_node);
	}
}

#define for_each_rbtree_entry(entry, rbtree, to_entry_fn, member)					\
	for(entry = to_entry_fn(rb_first(&(rbtree)->tree));								\
			entry; entry = to_entry_fn(rb_next(&entry->member)))

#define for_each_rbtree_entry_safe(entry, tmp, rbtree, to_entry_fn, member)			\
	for(entry = to_entry_fn(rb_first(&(rbtree)->tree)),								\
			tmp = entry? to_entry_fn(rb_next(&entry->member)): NULL;				\
			entry; entry = tmp, tmp = entry? to_entry_fn(rb_next(&entry->member)): NULL)

#endif /* __CR_RBTREE_H__ */
