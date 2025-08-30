#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include "rdma_migr.h"
#include "../include/rbtree.h"

#define RB_MASK					3

static declare_and_init_rbtree(rdma_vma);

struct rdma_vma_node {
	struct rb_node				node;
	unsigned long long			start;
	unsigned long long			end;
	char						type_str[128];
};

static int rdma_vma_node_compare(const struct rb_node *n1, const struct rb_node *n2) {
	struct rdma_vma_node *ent1 = n1? container_of(n1, struct rdma_vma_node, node): NULL;
	struct rdma_vma_node *ent2 = n1? container_of(n2, struct rdma_vma_node, node): NULL;
	if(ent1->start < ent2->start)
		return -1;
	else if(ent1->start > ent2->start)
		return 1;
	else
		return 0;
}

static struct rdma_vma_node *search_rdma_vma_node(unsigned long long start,
							struct rb_node **p_parent, struct rb_node ***p_insert) {
	struct rdma_vma_node my_node = {.start = start};
	struct rb_node *node;

	node = ___search(&my_node.node, &rdma_vma, p_parent, p_insert,
							SEARCH_LAST_PRECURSOR_INC_ITSELF, rdma_vma_node_compare);
	
	return node? container_of(node, struct rdma_vma_node, node): NULL;
}

static struct rdma_vma_node *get_next_node(struct rdma_vma_node *vma_node) {
	struct rb_node *node = &vma_node->node;

	if(node->rb_right != NULL) {
		struct rb_node *cur_node = node->rb_right;
		while(cur_node->rb_left) {
			cur_node = cur_node->rb_left;
		}

		return container_of(cur_node, struct rdma_vma_node, node);
	}

	while(rb_parent(node) && rb_parent(node)->rb_right == node) {
		node = rb_parent(node);
	}

	node = rb_parent(node);
	return node? container_of(node, struct rdma_vma_node, node): NULL;
}

static struct rdma_vma_node *get_first_node(void) {
	struct rb_node *cur_node = rdma_vma.tree.rb_node;
	while(cur_node && cur_node->rb_left) {
		cur_node = cur_node->rb_left;
	}

	return cur_node? container_of(cur_node, struct rdma_vma_node, node): NULL;
}

static char *check_interleave(unsigned long long start, unsigned long long end) {
	struct rdma_vma_node *vma_node;

	pthread_rwlock_rdlock(&rdma_vma.rwlock);
	vma_node = search_rdma_vma_node(start, NULL, NULL);
	if(vma_node && start < vma_node->end) {
		pthread_rwlock_unlock(&rdma_vma.rwlock);
		return vma_node->type_str;
	}

	if(vma_node) {
		vma_node = get_next_node(vma_node);
	}
	else {
		vma_node = get_first_node();
	}

	if(vma_node && vma_node->start < end) {
		pthread_rwlock_unlock(&rdma_vma.rwlock);
		return vma_node->type_str;
	}

	pthread_rwlock_unlock(&rdma_vma.rwlock);
	return NULL;
}

int add_rdma_vma(unsigned long long start, unsigned long long end, char *type_str) {
	struct rb_node *parent, **insert;
	struct rdma_vma_node *vma_node;
	struct rdma_vma_node *next_vma;

	pthread_rwlock_wrlock(&rdma_vma.rwlock);
	vma_node = search_rdma_vma_node(start, &parent, &insert);
	if(vma_node && start <= vma_node->end) {
		vma_node->end = (vma_node->end > end)? vma_node->end: end;
	}
	else {
		vma_node = malloc(sizeof(*vma_node));
		if(!vma_node) {
			pthread_rwlock_unlock(&rdma_vma.rwlock);
			return -1;
		}

		vma_node->start = start;
		vma_node->end = end;
		strcpy(vma_node->type_str, type_str);
		rbtree_add_node(&vma_node->node, parent, insert, &rdma_vma);
	}

	next_vma = get_next_node(vma_node);
	if(next_vma && next_vma->start <= vma_node->end) {
		vma_node->end = (vma_node->end > next_vma->end)? vma_node->end: next_vma->end;
		rbtree_rm_node(&next_vma->node, &rdma_vma);
	}
	pthread_rwlock_unlock(&rdma_vma.rwlock);

	return 0;
}

int dump_smap_with_rdma(pid_t pid, int pid_fd) {
	FILE *f_smap;
	int fd_output;
	char fname[128];
	char strln[1024];

	sprintf(fname, "/proc/%d/smaps", pid);
	f_smap = fopen(fname, "r");
	fd_output = openat(pid_fd, "rdma_smap", O_WRONLY | O_CREAT, 00666);
	if(!f_smap || fd_output < 0) {
		return -1;
	}

	while(fgets(strln, 1024, f_smap)) {
		unsigned long long start, end;

		if(sscanf(strln, "%llx-%llx", &start, &end) == 2) {
			char *type_str = check_interleave(start, end);
			char *ln_break = strrchr(strln, '\n');
			*ln_break = '\0';

			if(type_str) {
				dprintf(fd_output, "%-128s%s\n", strln, type_str);
			}
		}
	}

	fclose(f_smap);
	close(fd_output);
	return 0;
}

struct rdma_mmap_item {
	unsigned long					start;
	unsigned long					end;
	int								prot;
	int								flag;
};

int dump_rdma_mmap(pid_t pid, char *img_path) {
	char fname[128];
	FILE *fp;
	int fd_out;
	int info_fd;
	int virt_pid;
	char strln[1024];
	struct rdma_mmap_item item;

	sprintf(fname, "/proc/rdma/%d/user_pid", pid);
	info_fd = open(fname, O_RDONLY);
	if(read(info_fd, &virt_pid, sizeof(virt_pid)) < 0) {
		return -1;
	}
	close(info_fd);

	sprintf(fname, "%s/rdma_mmap_%d.raw", img_path, virt_pid);
	fd_out = open(fname, O_RDWR | O_CREAT | O_TRUNC, 00666);

	sprintf(fname, "/proc/%d/smaps", pid);
	fp = fopen(fname, "r");
	while(fgets(strln, 1024, fp) != NULL) {
		unsigned long start, end;
		off_t off;
		char prots_and_flags[16];
		char file[1024];
		char arg[4][256];
		int len = strlen(strln);

		strln[len-1] = 0;
		len--;
		if(sscanf(strln, "%lx-%lx%ln", &start, &end, &off) < 2) {
			continue;
		}

		if(sscanf(strln + off, "%s%s%s%s%s", prots_and_flags,
					arg[0], arg[1], arg[2], file) < 5) {
			continue;
		}

		if(strncmp(file, "/dev/infiniband/uverbs",
					strlen("/dev/infiniband/uverbs"))) {
			continue;
		}

		item.start = start;
		item.end = end;
		item.prot = 0;
		item.flag = 0;

		if(prots_and_flags[0] == 'r') {
			item.prot |= PROT_READ;
		}
		if(prots_and_flags[1] == 'w') {
			item.prot |= PROT_WRITE;
		}
		if(prots_and_flags[2] == 'x') {
			item.prot |= PROT_EXEC;
		}
		if(prots_and_flags[3] == 'p') {
			item.flag = MAP_PRIVATE;
		}
		else {
			item.flag = MAP_SHARED;
		}

		if(write(fd_out, &item, sizeof(item)) < 0)
			return -1;
	}

	fclose(fp);
	close(fd_out);
	return 0;
}
