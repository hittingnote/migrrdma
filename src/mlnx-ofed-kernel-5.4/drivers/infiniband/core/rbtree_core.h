#ifndef __RB_TREE_CORE_H__
#define __RB_TREE_CORE_H__

#include <linux/rbtree.h>
#include <linux/spinlock.h>
#include <linux/rwlock.h>

struct rbtree_struct {
	struct rb_root				tree;
	rwlock_t					rwlock;
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
		.rwlock				= __RW_LOCK_UNLOCKED(var.rwlock),		\
	}

extern struct rb_node *___search(const struct rb_node *target, const struct rbtree_struct *rbtree,
						struct rb_node **p_parent, struct rb_node ***p_insert, enum search_ops ops,
						int (*compare)(const struct rb_node*, const struct rb_node*));

extern void ___traverse(const struct rbtree_struct *rbtree,
		void (*go_forward)(struct rb_node *cur, struct rb_node *child, enum TRACE_DIRECTION,
						struct rb_node *start, struct rb_node *end),
		void (*go_backward)(struct rb_node *cur, struct rb_node *parent, enum TRACE_DIRECTION,
						struct rb_node *start, struct rb_node *end));

extern void ___traverse_range(const struct rb_node *start,
		const struct rb_node *end, const struct rbtree_struct *rbtree,
		int (*compare)(const struct rb_node*, const struct rb_node*),
		void (*go_forward)(struct rb_node *cur, struct rb_node *child, enum TRACE_DIRECTION dir,
						struct rb_node *start, struct rb_node *end),
		void (*go_backward)(struct rb_node *cur, struct rb_node *parent, enum TRACE_DIRECTION dir,
						struct rb_node *start, struct rb_node *end));

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

#endif
