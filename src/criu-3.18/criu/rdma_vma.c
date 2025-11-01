#include "rdma_migr.h"
#include "rbtree.h"

static declare_and_init_rbtree(rdma_vma);

struct rdma_vma_node {
	struct rb_node				node;
	unsigned long long			start;
	unsigned long long			end;
};

static int rdma_vma_node_compare(const struct rb_node *n1, const struct rb_node *n2) {
	struct rdma_vma_node *ent1 = n1? container_of(n1, struct rdma_vma_node, node): NULL;
	struct rdma_vma_node *ent2 = n2? container_of(n2, struct rdma_vma_node, node): NULL;
	if(ent1->start < ent2->start)
		return -1;
	else if(ent1->start > ent2->start)
		return 1;
	else
		return 0;
}

static struct rdma_vma_node *to_rdma_vma_node(struct rb_node *n) {
	return n? container_of(n, struct rdma_vma_node, node): NULL;
}

static struct rdma_vma_node *search_rdma_vma_node(unsigned long long start,
							struct rb_node **p_parent, struct rb_node ***p_insert) {
	struct rdma_vma_node my_node = {.start = start};
	struct rb_node *node;

	node = ___search(&my_node.node, &rdma_vma, p_parent, p_insert,
							SEARCH_EXACTLY, rdma_vma_node_compare);
	
	return node? container_of(node, struct rdma_vma_node, node): NULL;
}

int add_one_rdma_vma_node(unsigned long long start, unsigned long long end) {
	struct rb_node *parent, **insert;
	struct rdma_vma_node *vma_node;

	pthread_rwlock_wrlock(&rdma_vma.rwlock);
	vma_node = search_rdma_vma_node(start, &parent, &insert);
	if(vma_node) {
		pthread_rwlock_unlock(&rdma_vma.rwlock);
		return -EEXIST;
	}

	vma_node = malloc(sizeof(*vma_node));
	if(!vma_node) {
		pthread_rwlock_unlock(&rdma_vma.rwlock);
		return -ENOMEM;
	}

	vma_node->start = start;
	vma_node->end = end;
	rbtree_add_node(&vma_node->node, parent, insert, &rdma_vma);

	pthread_rwlock_unlock(&rdma_vma.rwlock);
	pr_info("Add mapping (start: %llx, end: %llx)\n", start, end);
	return 0;
}

/* Transfer the data structure of RDMA vma from list to array */
struct unmapped_node *get_rdma_unmapped_node(int *pn_unmapped, int *err) {
	int n_unmapped = 0;
	struct unmapped_node *unmapped;
	struct rdma_vma_node *iter_vma;
	FILE *f_proc_smap;
	char *fgets_proc;
	char strln_proc_smap[1024];
	int proc_pipe[2];
	int curp = 0;
	int __err;

	*err = 1;

	/* RDMA vma maintained in rbtree */
	for_each_rbtree_entry(iter_vma, &rdma_vma, to_rdma_vma_node, node) {
		n_unmapped++;
	}

	f_proc_smap = fopen("/proc/self/smaps", "r");
	__err = pipe(proc_pipe);
	if(!f_proc_smap || __err) {
		return NULL;
	}

	/* Memory mapping created during RDMA establishment should also be considered */
	while(fgets(strln_proc_smap, 1024, f_proc_smap)) {
		unsigned long long start, end;
		char str_3[128], str_4[128], str_5[128], str_6[128], str_7[512];
		if(sscanf(strln_proc_smap, "%llx-%llx", &start, &end) < 2)
			continue;

		if(sscanf(strln_proc_smap, "%llx-%llx%s%s%s%s%s", &start, &end,
							str_3, str_4, str_5, str_6, str_7) < 7 ||
					strncmp(str_7, "/proc/rdma_uwrite/", strlen("/proc/rdma_uwrite/")))
			continue;

		dprintf(proc_pipe[1], "%s", strln_proc_smap);
		n_unmapped++;
	}

	fclose(f_proc_smap);
	close(proc_pipe[1]);

	f_proc_smap = fdopen(proc_pipe[0], "r");

	unmapped = malloc(n_unmapped * sizeof(*unmapped));
	if(!unmapped) {
		return NULL;
	}

	fgets_proc = fgets(strln_proc_smap, 1024, f_proc_smap);
	iter_vma = to_rdma_vma_node(rb_first(&rdma_vma.tree));
	while(iter_vma && fgets_proc) {
		unsigned long long rdma_start, rdma_end, proc_start, proc_end;

		sscanf(strln_proc_smap, "%llx-%llx", &proc_start, &proc_end);
		rdma_start = iter_vma->start;
		rdma_end = iter_vma->end;

		if(rdma_start < proc_start) {
			unmapped[curp].start = rdma_start;
			unmapped[curp].end = rdma_end;
			curp++;

			iter_vma = to_rdma_vma_node(rb_next(&iter_vma->node));
		}
		else {
			unmapped[curp].start = proc_start;
			unmapped[curp].end = proc_end;
			curp++;

			while((fgets_proc = fgets(strln_proc_smap, 1024, f_proc_smap)) != NULL) {
				if(sscanf(strln_proc_smap, "%llx-%llx", &proc_start, &proc_end) >= 2) {
					break;
				}
			}
		}
	}

	while(iter_vma) {
		unsigned long long rdma_start, rdma_end;
		rdma_start = iter_vma->start;
		rdma_end = iter_vma->end;

		unmapped[curp].start = rdma_start;
		unmapped[curp].end = rdma_end;
		curp++;

		iter_vma = to_rdma_vma_node(rb_next(&iter_vma->node));
	}

	while(fgets_proc) {
		unsigned long long proc_start, proc_end;
		sscanf(strln_proc_smap, "%llx-%llx", &proc_start, &proc_end);
		unmapped[curp].start = proc_start;
		unmapped[curp].end = proc_end;
		curp++;

		while((fgets_proc = fgets(strln_proc_smap, 1024, f_proc_smap)) != NULL) {
			if(sscanf(strln_proc_smap, "%llx-%llx", &proc_start, &proc_end) >= 2) {
				break;
			}
		}
	}

	close(proc_pipe[0]);

	*err = 0;
	*pn_unmapped = n_unmapped;
	return unmapped;
}

static declare_and_init_rbtree(second_premap);

struct second_premap_node {
	struct rb_node					node;
	unsigned long long				second_premap_addr;
	unsigned long long				first_premap_addr;
	size_t							size;
};

static int second_premap_node_compare(const struct rb_node *n1, const struct rb_node *n2) {
	struct second_premap_node *ent1 = n1? container_of(n1, struct second_premap_node, node): NULL;
	struct second_premap_node *ent2 = n2? container_of(n2, struct second_premap_node, node): NULL;

	if(ent1->second_premap_addr < ent2->second_premap_addr)
		return -1;
	else if(ent1->second_premap_addr > ent2->second_premap_addr)
		return 1;
	else
		return 0;
}

static struct second_premap_node *to_second_premap_node(struct rb_node *n) {
	return n? container_of(n, struct second_premap_node, node): NULL;
}

static struct second_premap_node *search_second_premap_node(unsigned long long second_addr,
							struct rb_node **p_parent, struct rb_node ***p_insert) {
	struct second_premap_node my_node = {.second_premap_addr = second_addr};
	struct rb_node *node;

	node = ___search(&my_node.node, &second_premap, p_parent, p_insert,
						SEARCH_EXACTLY, second_premap_node_compare);

	return node? container_of(node, struct second_premap_node, node): NULL;
}

int add_one_premap_node(unsigned long long second_addr,
						unsigned long long first_addr, size_t size) {
	struct rb_node *parent, **insert;
	struct second_premap_node *premap_node;

	pthread_rwlock_wrlock(&second_premap.rwlock);
	premap_node = search_second_premap_node(second_addr,
							&parent, &insert);
	if(premap_node) {
		pthread_rwlock_unlock(&second_premap.rwlock);
		return -EEXIST;
	}

	premap_node = malloc(sizeof(*premap_node));
	if(!premap_node) {
		pthread_rwlock_unlock(&second_premap.rwlock);
		return -ENOMEM;
	}

	premap_node->second_premap_addr = second_addr;
	premap_node->first_premap_addr = first_addr;
	premap_node->size = size;
	rbtree_add_node(&premap_node->node, parent, insert, &second_premap);

	pthread_rwlock_unlock(&second_premap.rwlock);
	return 0;
}

int get_premap_node(unsigned long long second_addr,
					unsigned long long *first_addr, size_t *size) {
	struct second_premap_node *premap_node;

	pthread_rwlock_rdlock(&second_premap.rwlock);
	premap_node = search_second_premap_node(second_addr,
							NULL, NULL);
	if(!premap_node) {
		pthread_rwlock_unlock(&second_premap.rwlock);
		return -ENOENT;
	}

	if(first_addr)
		*first_addr = premap_node->first_premap_addr;
	if(size)
		*size = premap_node->size;

	pthread_rwlock_unlock(&second_premap.rwlock);
	return 0;
}

int del_one_premap_node(unsigned long long second_addr) {
	struct second_premap_node *premap_node;

	pthread_rwlock_wrlock(&second_premap.rwlock);
	premap_node = search_second_premap_node(second_addr,
							NULL, NULL);
	if(!premap_node) {
		pthread_rwlock_unlock(&second_premap.rwlock);
		return -ENOENT;
	}

	rbtree_rm_node(premap_node, &second_premap);
	pthread_rwlock_unlock(&second_premap.rwlock);
	return 0;
}

#include "include/cr_options.h"

int add_premap_node(pid_t pid) {
	char fname[4096 + 512];
	FILE *f_smap;
	char strln[1024];

	sprintf(fname, "%s/rdma_pid_%d/rdma_smap", images_dir, pid);
	f_smap = fopen(fname, "r");
	if(!f_smap)
		return 0;

	while(fgets(strln, 1024, f_smap) != NULL) {
		unsigned long long start, end;
		if(sscanf(strln, "%llx-%llx", &start, &end) < 2)
			continue;

		if(add_one_premap_node(start, 0, end - start)) {
			fclose(f_smap);
			return -1;
		}
	}

	fclose(f_smap);
	return 0;
}

struct rdma_premap_node *get_rdma_premap_node(int *n_arr, int *err) {
	int cnt = 0;
	struct rdma_premap_node *premap_node_arr;
	struct second_premap_node *iter_node;

	*err = 0;

	for_each_rbtree_entry(iter_node, &second_premap,
					to_second_premap_node, node) {
		cnt++;
	}

	premap_node_arr = malloc(sizeof(*premap_node_arr) * cnt);
	if(!premap_node_arr) {
		*err = -ENOMEM;
		return NULL;
	}

	cnt = 0;
	for_each_rbtree_entry(iter_node, &second_premap,
					to_second_premap_node, node) {
		premap_node_arr[cnt].second_addr = iter_node->second_premap_addr;
		premap_node_arr[cnt].first_addr = iter_node->first_premap_addr;
		premap_node_arr[cnt].size = iter_node->size;
		cnt++;
	}

	*n_arr = cnt;
	return premap_node_arr;
}
