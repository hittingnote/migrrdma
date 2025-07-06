#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include "rbtree.h"

static inline double get_timestamp(char *strln) {
	double ret;
	sscanf(strln, "(%lf)", &ret);
	ret = ret * 1000.0;
	return ret;
}

struct pid_to_range_node {
	pid_t						pid;
	double						start;
	double						end;
	struct rb_node				node;
};

static declare_and_init_rbtree(pid_to_range_tree);

static struct pid_to_range_node *to_pid_range_node(const struct rb_node *n) {
	return n? container_of(n, struct pid_to_range_node, node): NULL;
}

static int pid_to_range_node_compare(const struct rb_node *n1, const struct rb_node *n2) {
	struct pid_to_range_node *ent1 = to_pid_range_node(n1);
	struct pid_to_range_node *ent2 = to_pid_range_node(n2);

	if(ent1->pid < ent2->pid) {
		return -1;
	}
	else if(ent1->pid > ent2->pid) {
		return 1;
	}
	else
		return 0;
}

static struct pid_to_range_node *search_pid_range_node(pid_t pid,
						struct rb_node **p_parent, struct rb_node ***p_insert) {
	struct pid_to_range_node target = {.pid = pid};
	struct rb_node *match = ___search(&target.node, &pid_to_range_tree, p_parent, p_insert,
							SEARCH_EXACTLY, pid_to_range_node_compare);
	return to_pid_range_node(match);
}

static struct pid_to_range_node *add_pid_to_range_node(pid_t pid) {
	struct pid_to_range_node *ent;
	struct rb_node *parent, **insert;

	ent = search_pid_range_node(pid, &parent, &insert);
	if(ent) {
		return NULL;
	}

	ent = malloc(sizeof(*ent));
	if(!ent) {
		return NULL;
	}

	ent->pid = pid;
	rbtree_add_node(&ent->node, parent, insert, &pid_to_range_tree);
	return ent;
}

static struct pid_to_range_node *get_pid_to_range_node(pid_t pid) {
	struct pid_to_range_node *ent;

	ent = search_pid_range_node(pid, NULL, NULL);
	return ent;
}

struct range_node {
	double						start;
	double						end;
	struct rb_node				node;
};

static declare_and_init_rbtree(range_tree);

static struct range_node *to_range_node(const struct rb_node *n) {
	return n? container_of(n, struct range_node, node): NULL;
}

static int range_node_compare(const struct rb_node *n1, const struct rb_node *n2) {
	struct range_node *ent1 = to_range_node(n1);
	struct range_node *ent2 = to_range_node(n2);

	double delta = ent1->start - ent2->start;
	if(delta > -1e-6 && delta < 1e-6) {
		delta = ent1->end - ent2->end;
		if(delta > -1e-6 && delta < 1e-6)
			return 0;
		else if(delta < 0) {
			return -1;
		}
		else
			return 1;
	}
	else if(delta < 0) {
		return -1;
	}
	else
		return 1;
}

static struct range_node *search_range_node(double start, double end,
						struct rb_node **p_parent, struct rb_node ***p_insert) {
	struct pid_to_range_node target = {.start = start, .end = end};
	struct rb_node *match = ___search(&target.node, &range_tree, p_parent, p_insert,
							SEARCH_EXACTLY, range_node_compare);
	return to_range_node(match);
}

static int add_range_node(double start, double end) {
	struct range_node *ent;
	struct rb_node *parent, **insert;

	ent = search_range_node(start, end, &parent, &insert);
	if(ent) {
		return -1;
	}

	ent = malloc(sizeof(*ent));
	if(!ent) {
		return -1;
	}

	ent->start = start;
	ent->end = end;
	rbtree_add_node(&ent->node, parent, insert, &range_tree);
	return 0;
}

static inline void parse_raw_str(char *s1, char *s2, char *s3, const char *strln) {
	sscanf(strln, "%s%s%s", s1, s2, s3);
}

int main(int argc, char *argv[]) {
	int fd_dir;
	DIR *fd_DIR;
	int fd;
	FILE *fp;
	struct dirent *dirent;
	char dump_log[256];
	char restore_log[256];
	char strln[32768];
	double checkpoint_time;
	double start, end, restore_total, restore_time;
	struct pid_to_range_node *node;
	struct range_node *r_node;
	double restore_comm = 0.0;

	fd_dir = open("/dev/shm/", O_DIRECTORY);
	if(fd_dir < 0) {
		fprintf(stderr, "Failed to open /dev/shm/\n");
		exit(-1);
	}

	fd_DIR = fdopendir(fd_dir);
	while((dirent = readdir(fd_DIR)) != NULL) {
		unsigned long long id;
		if(!strncmp(dirent->d_name, ".", 1))
			continue;

		if(sscanf(dirent->d_name, "dump_%lld.log", &id) >= 1) {
			sprintf(dump_log, "%s", dirent->d_name);
		}

		if(sscanf(dirent->d_name, "restore_%lld.log", &id) >= 1) {
			sprintf(restore_log, "%s", dirent->d_name);
		}
	}

	fd = openat(fd_dir, dump_log, O_RDONLY);
	if(fd < 0) {
		fprintf(stderr, "Failed to open /dev/shm/%s\n", dump_log);
		exit(-1);
	}

	fp = fdopen(fd, "r");
	while(fgets(strln, 32768, fp) != NULL);

	checkpoint_time = get_timestamp(strln);
	printf("Checkpoint time: %lf ms\n", checkpoint_time);

	close(fd);

	fd = openat(fd_dir, restore_log, O_RDONLY);
	if(fd < 0) {
		fprintf(stderr, "Failed to open /dev/shm/%s\n", restore_log);
		exit(-1);
	}

	fp = fdopen(fd, "r");
	while(fgets(strln, 32768, fp) != NULL) {
		if(strstr(strln, "Full restore")) {
			start = get_timestamp(strln);
			break;
		}
	}

	while(fgets(strln, 32768, fp) != NULL);

	end = get_timestamp(strln);
	restore_total = end - start;

	fseek(fp, 0, SEEK_SET);
	while(fgets(strln, 32768, fp) != NULL) {
		struct pid_to_range_node *node;
		pid_t pid;
		double start;
		char str[4][256];

		if(!strstr(strln, "metadata")) {
			continue;
		}

		parse_raw_str(str[0], str[1], str[2], strln);
		sscanf(str[0], "(%lf)", &start);
		sscanf(str[2], "%d", &pid);

		if(pid == 1) {
			continue;
		}

		node = add_pid_to_range_node(pid);
		if(!node) {
			fprintf(stderr, "Parse log error\n");
			exit(-1);
		}

		node->start = start * 1000.0;
	}

	fseek(fp, 0, SEEK_SET);
	while(fgets(strln, 32768, fp) != NULL) {
		struct pid_to_range_node *node;
		pid_t pid;
		double end;
		char str[4][256];

		if(!strstr(strln, "Restore RDMA communication")) {
			continue;
		}

		parse_raw_str(str[0], str[1], str[2], strln);
		sscanf(str[0], "(%lf)", &end);
		sscanf(str[2], "%d", &pid);

		if(pid == 1) {
			continue;
		}

		node = get_pid_to_range_node(pid);
		if(!node) {
			fprintf(stderr, "Parse log error\n");
			exit(-1);
		}

		node->end = end * 1000.0;
	}

	for_each_rbtree_entry(node, &pid_to_range_tree, to_pid_range_node, node) {
		if(add_range_node(node->start, node->end)) {
			fprintf(stderr, "Parse log error\n");
			exit(-1);
		}
	}

	start = -1.0;
	end = -1.0;
	for_each_rbtree_entry(r_node, &range_tree, to_range_node, node) {
		if(r_node->start > end && r_node->start - end > 1e-6) {
			restore_comm += end - start;
			start = r_node->start;
			end = start;
		}

		if(end < r_node->end && r_node->end - end > 1e-6) {
			end = r_node->end;
		}
	}

	restore_comm += end - start;
	restore_time = restore_total - restore_comm;

	printf("Restore time: %lf ms\n", restore_time);
	return 0;
}

