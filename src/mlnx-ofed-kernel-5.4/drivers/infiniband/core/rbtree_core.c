#include "rbtree_core.h"
#include <linux/slab.h>
#include <linux/list.h>

enum TRAV_DIRECTION {
	GO_LEFT,
	GO_RIGHT,
	NO_DIRECTION,
};

struct stack_elem {
	struct rb_node				*current_node;
	struct rb_node				*parent;
	int							flag;
	struct list_head			list;
};

static inline int push_stack(struct rb_node *cur,
						struct rb_node *parent,
						const int flag,
						const struct list_head *stack) {
	struct stack_elem *elem;
	elem = kzalloc(sizeof(*elem), GFP_KERNEL);
	if(!elem)
		return -ENOMEM;
	
	elem->current_node = cur;
	elem->parent = parent;
	elem->flag = flag;
	list_add(&elem->list, stack);
	return 0;
}

static inline void pop_stack(const struct list_head *stack) {
	struct stack_elem *first =
			list_first_entry_or_null(stack, struct stack_elem, list);
	if(!first)
		return;
	list_del(&first->list);
	kfree(first);
}

static inline struct stack_elem *top_stack(const struct list_head *stack) {
	return list_first_entry_or_null(stack, struct stack_elem, list);
}

static inline int stack_is_empty(const struct list_head *stack) {
	return (list_first_entry_or_null(stack, struct stack_elem, list) == NULL);
}

struct rb_node *___search(const struct rb_node *target, const struct rbtree_struct *rbtree,
						struct rb_node **p_parent, struct rb_node ***p_insert, enum search_ops ops,
						int (*compare)(const struct rb_node*, const struct rb_node*)) {
	struct rb_node *parent = NULL;
	struct rb_node **insert = &rbtree->tree.rb_node;
	struct rb_node *node = rbtree->tree.rb_node;
	enum TRAV_DIRECTION direction = NO_DIRECTION;

	while(node) {
		parent = node;

		if(compare(target, node) < 0) {
			node = node->rb_left;
			insert = &(*insert)->rb_left;
			direction = GO_LEFT;
		}
		else if(compare(target, node) > 0) {
			node = node->rb_right;
			insert = &(*insert)->rb_right;
			direction = GO_RIGHT;
		}
		else {
			switch(ops) {
			case SEARCH_EXACTLY:
			case SEARCH_LAST_PRECURSOR_INC_ITSELF:
			case SEARCH_FIRST_SUCCESSOR_INC_ITSELF:
				parent = NULL;
				insert = NULL;
				goto out;
			case SEARCH_LAST_PRECURSOR:
				node = node->rb_left;
				insert = &(*insert)->rb_left;
				direction = GO_LEFT;
				break;
			case SEARCH_FIRST_SUCCESSOR:
				node = node->rb_right;
				insert = &(*insert)->rb_right;
				direction = GO_RIGHT;
				break;
			}
		}
	}

	if((!parent) || (ops == SEARCH_EXACTLY))
		goto out;

	if(p_parent)
		*p_parent = parent;

	while(parent && (((ops & SEARCH_LAST_PRECURSOR) && direction == GO_LEFT) ||
				((ops & SEARCH_FIRST_SUCCESSOR) && direction == GO_RIGHT))) {
		struct rb_node *grandpa = rb_parent(parent);
		if(!grandpa)
			direction = NO_DIRECTION;
		else if(grandpa->rb_left == parent)
			direction = GO_LEFT;
		else
			direction = GO_RIGHT;
		parent = grandpa;
	}

	node = parent;

	if(p_insert)
		*p_insert = insert;
	
	return node;

out:
	if(p_parent)
		*p_parent = parent;
	if(p_insert)
		*p_insert = insert;
	return node;
}

void ___traverse(const struct rbtree_struct *rbtree,
		void (*go_forward)(struct rb_node *cur, struct rb_node *child,
						enum TRACE_DIRECTION dir,
						struct rb_node *start, struct rb_node *end),
		void (*go_backward)(struct rb_node *cur, struct rb_node *parent,
						enum TRACE_DIRECTION dir,
						struct rb_node *start, struct rb_node *end))
{
	struct list_head stack;
	int err = 0;
	INIT_LIST_HEAD(&stack);

	if(!rbtree->tree.rb_node)
		printk(KERN_NOTICE "In %s(%d): Empty traverse\n",
								__FILE__, __LINE__);

	err = push_stack(rbtree->tree.rb_node, NULL, 0, &stack);
	if(err)
		return;
	
	while(!stack_is_empty(&stack)) {
		struct stack_elem *top = top_stack(&stack);
		if(!top->current_node) {
			pop_stack(&stack);
				top = top_stack(&stack);
			if(top && top->flag == 0 && go_backward)
				go_backward(top->current_node->rb_left,
							top->current_node, LEFT, NULL, NULL);
			else if(top && top->flag == 1 && go_backward)
				go_backward(top->current_node->rb_right,
							top->current_node, RIGHT, NULL, NULL);
			if(top)
				top->flag++;
			continue;
		}

		if(top->flag == 0) {
			err = push_stack(top->current_node->rb_left,
					top->current_node, 0, &stack);
			if(err)
				goto out;
			
			if(go_forward)
				go_forward(top->current_node,
						top->current_node->rb_left, LEFT, NULL, NULL);
		}
		else if(top->flag == 1) {
			err = push_stack(top->current_node->rb_right,
					top->current_node, 0, &stack);
			if(err)
				goto out;
			
			if(go_forward)
				go_forward(top->current_node,
						top->current_node->rb_right, RIGHT, NULL, NULL);
		}
		else {
			pop_stack(&stack);
			top = top_stack(&stack);
			if(top && top->flag == 0 && go_backward)
				go_backward(top->current_node->rb_left,
							top->current_node, LEFT, NULL, NULL);
			else if(top && top->flag == 1 && go_backward)
				go_backward(top->current_node->rb_right,
							top->current_node, RIGHT, NULL, NULL);
			if(top)
				top->flag++;
		}
	}

out:
	while(!stack_is_empty(&stack))
		pop_stack(&stack);
	return;
}

static inline struct rb_node *get_child(struct stack_elem *top,
				enum TRACE_DIRECTION dir, struct rb_node *start, struct rb_node *end,
				int (*compare)(const struct rb_node*, const struct rb_node*)) {
	switch(dir) {
	case LEFT:
		if(top->parent && top->parent->rb_right == top->current_node &&
						compare(end, top->parent) < 0)
			return NULL;
		else if(compare(top->current_node, start) < 0)
			return NULL;
		else
			return top->current_node->rb_left;
	case RIGHT:
		if(top->parent && top->parent->rb_left == top->current_node &&
							compare(top->parent, start) < 0)
			return NULL;
		else if(compare(end, top->current_node) < 0)
			return NULL;
		else
			return top->current_node->rb_right;
	}
	return NULL;
}

void ___traverse_range(const struct rb_node *start,
		const struct rb_node *end, const struct rbtree_struct *rbtree,
		int (*compare)(const struct rb_node*, const struct rb_node*),
		void (*go_forward)(struct rb_node *cur, struct rb_node *child,
						enum TRACE_DIRECTION dir,
						struct rb_node *start, struct rb_node *end),
		void (*go_backward)(struct rb_node *cur, struct rb_node *parent,
						enum TRACE_DIRECTION dir,
						struct rb_node *start, struct rb_node *end))
{
	struct list_head stack;
	int err = 0;
	INIT_LIST_HEAD(&stack);

	if(compare(start, end) > 0)
		return;

	if(!rbtree->tree.rb_node)
		printk(KERN_NOTICE "In %s(%d): Empty traverse\n",
								__FILE__, __LINE__);

	err = push_stack(rbtree->tree.rb_node, NULL, 0, &stack);
	if(err)
		return;
	
	while(!stack_is_empty(&stack)) {
		struct stack_elem *top = top_stack(&stack);
		if(!top->current_node) {
			pop_stack(&stack);
				top = top_stack(&stack);
			if(top && top->flag == 0 && go_backward)
				go_backward(NULL, top->current_node, LEFT, start, end);
			else if(top && top->flag == 1 && go_backward)
				go_backward(NULL, top->current_node, RIGHT, start, end);
			if(top)
				top->flag++;
			continue;
		}

		if(top->flag == 0) {
			struct rb_node *child = get_child(top, LEFT, start, end, compare);
			err = push_stack(child, top->current_node, 0, &stack);
			if(err)
				goto out;
			
			if(go_forward)
				go_forward(top->current_node, child, LEFT, start, end);
		}
		else if(top->flag == 1) {
			struct rb_node *child = get_child(top, RIGHT, start, end, compare);
			err = push_stack(child, top->current_node, 0, &stack);
			if(err)
				goto out;
			
			if(go_forward)
				go_forward(top->current_node, child, RIGHT, start, end);
		}
		else {
			pop_stack(&stack);
			top = top_stack(&stack);
			if(top && top->flag == 0 && go_backward)
				go_backward(get_child(top, LEFT, start, end, compare),
							top->current_node, LEFT, start, end);
			else if(top && top->flag == 1 && go_backward)
				go_backward(get_child(top, RIGHT, start, end, compare),
							top->current_node, RIGHT, start, end);
			if(top)
				top->flag++;
		}
	}

out:
	while(!stack_is_empty(&stack))
		pop_stack(&stack);
	return;
}

