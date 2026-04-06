#include "rdma_migr.h"
#include "include/rbtree.h"

static declare_and_init_rbtree(id_fe_map);

struct id_fe_map_entry {
	struct rb_node				entry;
	uint32_t					id;
	void						*ptr;
};

static inline struct id_fe_map_entry *to_id_fe_map_entry(struct rb_node *node) {
	return node? container_of(node, struct id_fe_map_entry, entry): NULL;
}

static int id_fe_map_entry_compare(const struct rb_node *node1, const struct rb_node *node2) {
	struct id_fe_map_entry *ent1 = node1? container_of(node1, struct id_fe_map_entry, entry): NULL;
	struct id_fe_map_entry *ent2 = node2? container_of(node2, struct id_fe_map_entry, entry): NULL;
	if(ent1->id < ent2->id) {
		return -1;
	}
	else if(ent1->id > ent2->id) {
		return 1;
	}

	return 0;
}

static struct id_fe_map_entry *search_id_fe_map_entry(uint32_t id,
				struct rb_node **p_parent, struct rb_node ***p_insert) {
	struct id_fe_map_entry target = {.id = id};
	struct rb_node *match = ___search(&target.entry, &id_fe_map, p_parent, p_insert,
					SEARCH_EXACTLY, id_fe_map_entry_compare);
	return to_id_fe_map_entry(match);
}

int insert_id_fe_map_entry(uint32_t id, void *ptr) {
	struct id_fe_map_entry *ent;
	struct rb_node *parent, **insert;

	pthread_rwlock_wrlock(&id_fe_map.rwlock);
	ent = search_id_fe_map_entry(id, &parent, &insert);
	if(ent) {
		pthread_rwlock_unlock(&id_fe_map.rwlock);
		return -EEXIST;
	}

	ent = malloc(sizeof(*ent));
	if(!ent) {
		pthread_rwlock_unlock(&id_fe_map.rwlock);
		return -ENOMEM;
	}

	ent->id = id;
	ent->ptr = ptr;
	rbtree_add_node(&ent->entry, parent, insert, &id_fe_map);
	pthread_rwlock_unlock(&id_fe_map.rwlock);

	return 0;
}

void *get_fe_ptr_from_id(uint32_t id) {
	struct id_fe_map_entry *ent;
	void *ptr;

	pthread_rwlock_rdlock(&id_fe_map.rwlock);
	ent = search_id_fe_map_entry(id, NULL, NULL);
	if(!ent) {
		pthread_rwlock_unlock(&id_fe_map.rwlock);
		return NULL;
	}

	ptr = ent->ptr;
	pthread_rwlock_unlock(&id_fe_map.rwlock);

	return ptr;
}
