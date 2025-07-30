#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <infiniband/verbs.h>
#include "rbtree.h"

static pthread_t wait_thread_id[16384];
static int cur_wait = 0;

enum rdma_notify_ops {
	RDMA_NOTIFY_PRE_ESTABLISH,
	RDMA_NOTIFY_PRE_PAUSE,
	RDMA_NOTIFY_RESTORE,
};

struct notify_message_fmt {
	enum rdma_notify_ops				ops;
	char								msg[0];
};

struct msg_fmt {
	union ibv_gid						migr_dest_gid;
	int									cnt;
	char								msg[0];
};

static inline int up_to_pow_two(int n) {
	int tmp = n;
	while(tmp & (tmp - 1))
		tmp = (tmp & (tmp - 1));
	
	if(n > tmp)
		return 2*tmp;
	else
		return tmp;
}

static void *expand_buf(void *buf, size_t orig_size, size_t new_size) {
	void *buf_tmp = NULL;

	if(up_to_pow_two(new_size) <= up_to_pow_two(orig_size))
		return buf;
	
	buf_tmp = malloc(up_to_pow_two(new_size));
	if(!buf_tmp) {
		if(buf)
			free(buf);
		return NULL;
	}

	memset(buf_tmp, 0, up_to_pow_two(new_size));
	memcpy(buf_tmp, buf, up_to_pow_two(orig_size));
	if(buf)
		free(buf);
	buf = buf_tmp;
	return buf;
}

struct notify_item {
	union ibv_gid			dest_gid;
	uint32_t				dest_qpn;
	pid_t					pid;
};

struct notify_msg_item {
	uint32_t				dest_qpn;
	pid_t					pid;
};

struct notify_msg_item_restore {
	uint32_t				dest_qpn;
	pid_t					pid;
	uint64_t				n_posted;
};

static int notify_msg_item_compare(const void *v1, const void *v2) {
	const struct notify_msg_item *item1 = v1;
	const struct notify_msg_item *item2 = v2;
	
	if(item1->pid < item2->pid)
		return -1;
	else if(item1->pid > item2->pid)
		return 1;
	else
		return 0;
}

static int notify_msg_item_restore_compare(const void *v1, const void *v2) {
	const struct notify_msg_item_restore *item1 = v1;
	const struct notify_msg_item_restore *item2 = v2;
	
	if(item1->pid < item2->pid)
		return -1;
	else if(item1->pid > item2->pid)
		return 1;
	else
		return 0;
}

static declare_and_init_rbtree(qpn_dict);

struct qpn_dict_node {
	uint32_t				pqpn;
	uint32_t				vqpn;
	pid_t					local_pid;
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

static void free_qpn_dict_node(struct rb_node *node) {
	struct qpn_dict_node *nd = to_qpn_dict_node(node);
	if(nd)
		free(nd);
}

static int add_qpn_dict_node(char *symlink) {
	struct qpn_dict_node	*this_node;
	struct rb_node			*parent;
	struct rb_node			**insert;
	uint32_t				pqpn;
	uint32_t				vqpn;
	pid_t					local_pid;

	sscanf(symlink, "qpn_%d_%d_%d", &local_pid, &vqpn, &pqpn);

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
	this_node->vqpn = vqpn;
	this_node->local_pid = local_pid;
	rbtree_add_node(&this_node->node, parent, insert, &qpn_dict);
	pthread_rwlock_unlock(&qpn_dict.rwlock);

	return 0;
}

static int get_qpn_dict(uint32_t pqpn, uint32_t *vqpn, pid_t *local_pid) {
	struct qpn_dict_node	*this_node;

	pthread_rwlock_rdlock(&qpn_dict.rwlock);
	this_node = search_qpn_dict_node(pqpn, NULL, NULL);
	if(!this_node) {
		pthread_rwlock_unlock(&qpn_dict.rwlock);
		return -ENOENT;
	}

	if(vqpn) {
		*vqpn = this_node->vqpn;
	}

	if(local_pid) {
		*local_pid = this_node->local_pid;
	}

	pthread_rwlock_unlock(&qpn_dict.rwlock);
	return 0;
}

static int init_qpn_dict(char *dev_name) {
	char fname[128];
	sprintf(fname, "/proc/rdma/%s/", dev_name);
	DIR *dir = opendir(fname);
	struct dirent *dirent;

	if(!dir) {
		return -ENOENT;
	}

	while((dirent = readdir(dir)) != NULL) {
		int err;

		if(!strncmp(dirent->d_name, ".", strlen("."))) {
			continue;
		}

		err = add_qpn_dict_node(dirent->d_name);
		if(err) {
			clean_rbtree(&qpn_dict, free_qpn_dict_node);
			return err;
		}
	}

	return 0;
}

static pid_t pqpn_to_pid(uint32_t pqpn) {
	pid_t pid;

	if(get_qpn_dict(pqpn, NULL, &pid)) {
		return -1;
	}

	return pid;
}

struct notify_param {
	pid_t		pid;
	void		*buf;
	int			size;
	int			need_wait;
	void		*out_buf;
};

static struct notify_param *params[16384];

struct reply_hdr_fmt {
	int								cnt;
	char							msg[0];
};

struct reply_item_fmt {
	uint32_t						qpn;
	uint64_t						n_posted;
};

static int get_all_thread_ids(pid_t pid, pid_t **tids,
					int *n_tids) {
	char fname[128];
	int fd_dir;
	DIR *dir;
	struct dirent *ent;
	int ret_n_tids = 0;
	pid_t *tids_arr;
	int curp = 0;

	sprintf(fname, "/proc/%d/task", pid);
	fd_dir = open(fname, O_DIRECTORY);
	dir = fdopendir(fd_dir);

	for(int i = 0; i < 2; i++) {
		if(i == 1) {
			tids_arr = malloc(sizeof(pid_t) * ret_n_tids);
		}

		lseek(fd_dir, 0, SEEK_SET);
		while((ent = readdir(dir)) != NULL) {
			pid_t this_tid;

			if(ent->d_name[0] == '.')
				continue;

			if(sscanf(ent->d_name, "%d", &this_tid) < 1)
				continue;

			if(i == 0) {
				ret_n_tids++;
			}
			else {
				tids_arr[curp++] = this_tid;
			}
		}
	}

	close(fd_dir);

	if(tids)
		*tids = tids_arr;

	if(n_tids)
		*n_tids = ret_n_tids;

	return 0;
}

static int notify_pre_establish(pid_t pid, void *buf, int size,
					int need_wait, void **out_buf) {
	int fd_to_proc;
	int fd_partner_buf;
	char fname[128];
	int ntids = 0;
	pid_t *tids;

	sprintf(fname, "/proc/rdma/%d/to_proc", pid);
	fd_to_proc = open(fname, O_RDWR);
	sprintf(fname, "/proc/rdma/%d/partner_buf", pid);
	fd_partner_buf = open(fname, O_WRONLY);
	if(fd_to_proc < 0 || fd_partner_buf < 0) {
		if(fd_to_proc >= 0)
			close(fd_to_proc);
		return -1;
	}

	if(write(fd_partner_buf, buf, size) < 0) {
		close(fd_to_proc);
		close(fd_partner_buf);
		return -1;
	}

	close(fd_partner_buf);

	if(get_all_thread_ids(pid, &tids, &ntids)) {
		fprintf(stderr, "Error occurs\n");
		return -1;
	}

	ntids--;
	ntids = 0;
	if(write(fd_to_proc, &ntids, sizeof(int)) < 0) {
		close(fd_to_proc);
		return -1;
	}

	dprintf(1, "ntids: %d\n", ntids);
	for(int i = 0; i < ntids + 1; i++) {
		dprintf(1, "tids[i]: %d\n", tids[i]);
		usleep(1);
		kill(tids[i], SIGUSR2);
	}

	free(tids);

	if(need_wait) {
		void *buf = NULL;
		void *read_buf = NULL;
		ssize_t read_size = 0;
		ssize_t cur_size;
		struct reply_hdr_fmt *reply_hdr;
		struct reply_item_fmt *arr;

		if(read(fd_to_proc, &ntids, sizeof(ntids)) < 0) {
			close(fd_to_proc);
			return -1;
		}

		sprintf(fname, "/proc/rdma/%d/frm_buf", pid);
		fd_partner_buf = open(fname, O_RDONLY);
		if(fd_partner_buf < 0) {
			perror("open");
			close(fd_to_proc);
			return -1;
		}

		while(1) {
			void *tmp_buf;

			read_buf = malloc(1024);
			if(!read_buf) {
				if(buf)
					free(buf);
				perror("malloc");
				close(fd_to_proc);
				close(fd_partner_buf);
				return -1;
			}

			memset(read_buf, 0, 1024);
			cur_size = read(fd_partner_buf, read_buf, 1024);
			if(cur_size < 0) {
				perror("read");
				free(read_buf);
				if(buf)
					free(buf);
				close(fd_to_proc);
				close(fd_partner_buf);
				return -1;
			}
			if(cur_size == 0) {
				free(read_buf);
				break;
			}

			tmp_buf = malloc(read_size + cur_size);
			if(!tmp_buf) {
				free(read_buf);
				if(buf)
					free(buf);
				perror("malloc");
				close(fd_to_proc);
				close(fd_partner_buf);
				return -1;
			}

			memcpy(tmp_buf, buf, read_size);
			memcpy(tmp_buf + read_size, read_buf, cur_size);

			free(read_buf);
			if(buf)
				free(buf);

			buf = tmp_buf;
			tmp_buf = NULL;

			read_size += cur_size;
		}

		close(fd_partner_buf);

		if(out_buf) {
			*out_buf = buf;
		}
	}

	close(fd_to_proc);

	printf("In %s(%d): Notify OK!\n", __FILE__, __LINE__);
	return 0;
}

void *pthread_notify(void *arg) {
	struct notify_param *param = arg;
	pid_t pid = param->pid;
	void *buf = param->buf;
	int size = param->size;
	int need_wait = param->need_wait;

	notify_pre_establish(pid, buf, size, need_wait, &param->out_buf);
	free(buf);
}

static int process_msg(const struct sockaddr_in *addr, void *buf, int size) {
	struct notify_message_fmt *header;
	struct msg_fmt *per_ops_header;
	struct notify_msg_item *arr;
	struct notify_msg_item_restore *arr_rst;
	enum rdma_notify_ops ops;
	int start = 0;
	pid_t last_pid;
	int i;

	header = buf;
	ops = header->ops;
	per_ops_header = (struct msg_fmt*)(header + 1);
	if(ops == RDMA_NOTIFY_RESTORE) {
		arr_rst = (struct notify_msg_item_restore *)&per_ops_header->msg;
		for(i = 0; i < per_ops_header->cnt; i++) {
			printf("In %s(%d): dest_qpn: %d, pid: %d\n", __FILE__, __LINE__, arr_rst[i].dest_qpn, arr_rst[i].pid);
		}
		qsort(arr_rst, per_ops_header->cnt, sizeof(*arr_rst), notify_msg_item_restore_compare);
		last_pid = pqpn_to_pid(arr_rst[start].dest_qpn);
	}
	else {
		arr = (struct notify_msg_item *)&per_ops_header->msg;
		for(i = 0; i < per_ops_header->cnt; i++) {
			printf("In %s(%d): dest_qpn: %d, pid: %d\n", __FILE__, __LINE__, arr[i].dest_qpn, arr[i].pid);
		}
		qsort(arr, per_ops_header->cnt, sizeof(*arr), notify_msg_item_compare);
		last_pid = pqpn_to_pid(arr[start].dest_qpn);
	}

	for(i = 0; i < per_ops_header->cnt + 1; i++) {
		void *partner_buf = NULL;
		int cur_size = 0;
		struct notify_message_fmt *header;
		struct msg_fmt *partner_ops_header;
		uint32_t *partner_arr;
		struct reply_item_fmt *partner_arr_rst;
		int curp = 0;
		int j;

		if(i == start)
			continue;

		if(ops == RDMA_NOTIFY_RESTORE) {
			if(i < per_ops_header->cnt && pqpn_to_pid(arr_rst[i].dest_qpn) == last_pid)
				continue;
		}
		else {
			if(i < per_ops_header->cnt && pqpn_to_pid(arr[i].dest_qpn) == last_pid)
				continue;
		}

		/* The item from index start to index (i-1) belongs to the same pid,
		 * We need to merge them into one, and notify the pid.
		 */
		if(ops == RDMA_NOTIFY_RESTORE) {
			partner_buf = expand_buf(partner_buf, cur_size, cur_size + sizeof(struct notify_message_fmt)
								+ sizeof(struct msg_fmt) + (i - start) * sizeof(struct reply_item_fmt));
			cur_size = cur_size + sizeof(struct notify_message_fmt)
								+ sizeof(struct msg_fmt) + (i - start) * sizeof(struct reply_item_fmt);
		}
		else {
			partner_buf = expand_buf(partner_buf, cur_size, cur_size + sizeof(struct notify_message_fmt)
								+ sizeof(struct msg_fmt) + (i - start) * sizeof(uint32_t));
			cur_size = cur_size + sizeof(struct notify_message_fmt)
								+ sizeof(struct msg_fmt) + (i - start) * sizeof(uint32_t);
		}
		if(!partner_buf)
			return -1;

		header = partner_buf;
		header->ops = ops;

		partner_ops_header = (struct msg_fmt*)(header + 1);
		partner_ops_header->cnt = i - start;
		memcpy(&partner_ops_header->migr_dest_gid, &per_ops_header->migr_dest_gid, sizeof(union ibv_gid));

		if(ops == RDMA_NOTIFY_RESTORE) {
			partner_arr_rst = (struct reply_item_fmt *)&partner_ops_header->msg;
			for(j = start; j < i; j++) {
				partner_arr_rst[curp].qpn = arr_rst[j].dest_qpn;
				partner_arr_rst[curp].n_posted = arr_rst[j].n_posted;
				curp++;
			}
		}
		else {
			partner_arr = (uint32_t *)&partner_ops_header->msg;
			for(j = start; j < i; j++) {
				partner_arr[curp] = arr[j].dest_qpn;
				curp++;
			}
		}

		if(ops == RDMA_NOTIFY_PRE_PAUSE) {
			struct notify_param *param;
			void *buf = malloc(cur_size);

			memcpy(buf, partner_buf, cur_size);

			param = calloc(1, sizeof(*param));
			param->pid = last_pid;
			param->buf = buf;
			param->size = cur_size;
			param->need_wait = 1;
			params[cur_wait] = param;
			pthread_create(wait_thread_id + (cur_wait++), NULL, pthread_notify, param);
		}
		else if(notify_pre_establish(last_pid, partner_buf, cur_size, 0, NULL)) {
			return -1;
		}

		free(partner_buf);
		partner_buf = NULL;
		cur_size = 0;
		if(ops == RDMA_NOTIFY_RESTORE)
			last_pid = pqpn_to_pid(arr_rst[start].dest_qpn);
		else
			last_pid = pqpn_to_pid(arr[start].dest_qpn);
		start = i;
	}

	return 0;
}

static int pthread_close_sk(int socket);

int main(int argc, char *argv[]) {
    int sk = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in local_addr;
    struct sockaddr_in remote_addr;
    socklen_t addrlen = sizeof(remote_addr);
    char recvbuf[1024];
    void *buf = NULL;
    int cur_size = 0;
    int recv_size;
	int reuse = 1;
	int size;
	int sent_size = 0;
	int this_size;
	int acc_sk;

	if(argc < 2) {
		fprintf(stderr, "Please specify the ibv_dev name in argv[1]. exiting...\n");
		exit(-1);
	}

	printf("MigrRDMA Daemon start...\n");

    if(sk < 0) {
        perror("socket");
        return -1;
    }

	if(setsockopt(sk, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(int))) {
		close(sk);
		perror("setsockopt");
		return -1;
	}

    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(50505);
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if(bind(sk, (struct sockaddr*)&local_addr, sizeof(local_addr))) {
		perror("bind");
		close(sk);
		return -1;
	}

	if(listen(sk, 1024)) {
		perror("listen");
		close(sk);
		return -1;
	}

    while((acc_sk = accept(sk,
					(struct sockaddr *)&remote_addr, &addrlen)) >= 0) {
		while(1) {
			recv_size = recv(acc_sk, recvbuf, sizeof(recvbuf), 0);
			if(recv_size < 0) {
				perror("recv");
			}

			/* receive message.
			 * The message termintes at string "that's all"
			 */
			buf = expand_buf(buf, cur_size, cur_size + recv_size);
			memcpy(buf + cur_size, recvbuf, recv_size);
			cur_size += recv_size;

			if(!strcmp(buf + cur_size - sizeof("that's all"), "that's all")) {
				cur_size -= sizeof("that's all");
				break;
			}
		}

		if(buf) {
			int i;

			init_qpn_dict(argv[1]);
        	process_msg(&remote_addr, buf, cur_size);
            free(buf);
            cur_size = 0;
			buf = NULL;

			for(i = 0; i < cur_wait; i++) {
				pthread_join(wait_thread_id[i], NULL);
			}

			if(cur_wait > 0) {
				int total_cnt = 0;
				struct reply_hdr_fmt *merged_reply_hdr;
				struct reply_item_fmt *merged_arr;
				int curp = 0;

				for(i = 0; i < cur_wait; i++) {
					struct reply_hdr_fmt *reply_hdr = params[i]->out_buf;
					total_cnt += reply_hdr->cnt;
				}

				merged_reply_hdr = malloc(sizeof(struct reply_hdr_fmt) +
								total_cnt * sizeof(struct reply_item_fmt));
				merged_reply_hdr->cnt = total_cnt;
				merged_arr = (struct reply_item_fmt *)&merged_reply_hdr->msg;

				for(i = 0; i < cur_wait; i++) {
					struct reply_hdr_fmt *reply_hdr = params[i]->out_buf;
					struct reply_item_fmt *arr = (struct reply_item_fmt *)&reply_hdr->msg;

					free(params[i]);
					memcpy(&merged_arr[curp], &arr[0], reply_hdr->cnt * sizeof(struct reply_item_fmt));
					curp += reply_hdr->cnt;

					free(reply_hdr);
				}

				size = sizeof(struct reply_hdr_fmt) +
								total_cnt * sizeof(struct reply_item_fmt);

				while(sent_size < size) {
					this_size = send(acc_sk, (void *)merged_reply_hdr + sent_size,
									size - sent_size > 1024? 1024: size - sent_size,
									0);
					if(this_size < 0) {
						perror("sendto");
						return -1;
					}

					sent_size += this_size;
				}

				/* Send a null message to mark the end */
				send(acc_sk, "that's all", sizeof("that's all"), 0);
				free(merged_reply_hdr);
				sent_size = 0;
			}

			cur_wait = 0;
			clean_rbtree(&qpn_dict, free_qpn_dict_node);
        }

		pthread_close_sk(acc_sk);
    }

	return 0;
}

static void *__close_sk(void *arg) {
	int *sk = (int *)arg;
	sleep(5);
	close(*sk);
	free(sk);
	return NULL;
}

static int pthread_close_sk(int socket) {
	int *sk;
	pthread_t thread_id;

	sk = malloc(sizeof(int));
	*sk = socket;

	pthread_create(&thread_id, NULL, __close_sk, sk);
	return 0;
}
