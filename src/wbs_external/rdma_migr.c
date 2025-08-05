#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <stdlib.h>
#include <sys/sysmacros.h>
#include <arpa/inet.h>

#include <infiniband/verbs.h>
#include "rdma_migr.h"
#include "debug.h"

pthread_t wait_thread[16384];
int n_threads = 0;

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

static int notify_item_compare(const void *i1, const void *i2) {
	const struct notify_item *item1 = i1;
	const struct notify_item *item2 = i2;

	return memcmp(&item1->dest_gid, &item2->dest_gid, sizeof(union ibv_gid));
}

struct reply_hdr_fmt {
	int								cnt;
	char							msg[0];
};

struct reply_item_fmt {
	uint32_t						qpn;
	uint64_t						n_posted;
};

struct pthread_param {
	int			sock;
	void		*out_buf;
};

static struct pthread_param *params[16384];

static void *wait_fn(void *arg) {
	struct pthread_param *param = (struct pthread_param *)arg;
	int sk = param->sock;
	char recvbuf[1024];
	void *buf = NULL;
	int cur_size = 0;
	int recv_size;

	while(1) {
		recv_size = recv(sk, recvbuf, sizeof(recvbuf), 0);
		if(recv_size < 0) {
			perror("recv");
		}

		buf = expand_buf(buf, cur_size, cur_size + recv_size);
		memcpy(buf + cur_size, recvbuf, recv_size);
		cur_size += recv_size;

		if(!strcmp(buf + cur_size - sizeof("that's all"), "that's all")) {
			cur_size -= sizeof("that's all");
			break;
		}
	}

	if(buf) {
		param->out_buf = buf;
	}

	close(sk);
}

static int send_msg(union ibv_gid *dest_gid, void *buf, int size, int need_wait) {
	int sk = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in remote_addr;
	int sent_size = 0;
	int this_size;

	if(sk < 0) {
		perror("socket");
		return -1;
	}

	remote_addr.sin_family = AF_INET;
	remote_addr.sin_port = htons(50505);
	memcpy(&remote_addr.sin_addr.s_addr, &dest_gid->raw[12], sizeof(uint32_t));

	if(connect(sk, (struct sockaddr *)&remote_addr, sizeof(remote_addr))) {
		perror("connect");
		return -1;
	}

	while(sent_size < size) {
		this_size = send(sk, buf + sent_size, size - sent_size > 1024? 1024: size - sent_size,
								0);
		if(this_size < 0) {
			perror("send");
			return -1;
		}

		sent_size += this_size;
	}

	/* Send a null message to mark the end */
	send(sk, "that's all", sizeof("that's all"), 0);

	if(!need_wait) {
		close(sk);
	}
	else {
		struct pthread_param *param = malloc(sizeof(*param));
		if(!param) {
			close(sk);
			perror("malloc");
			return -1;
		}

		param->sock = sk;
		pthread_create(wait_thread + n_threads, NULL, wait_fn, param);
		params[n_threads++] = param;
	}

	return 0;
}

static int notify_merge(struct notify_item *item_list, int n_item,
				struct sockaddr_in *migr_dest_addr, enum rdma_notify_ops ops,
				int need_wait) {
	int i;
	int start = 0;
	for(i = 0; i < n_item + 1; i++) {
		int j;
		void *buf = NULL;
		struct notify_message_fmt *header;
		struct msg_fmt *per_ops_header;
		struct notify_msg_item *arr;
		int cur_size = 0;

		if(i == start)
			continue;

		if(i < n_item && !memcmp(&item_list[i].dest_gid, &item_list[start].dest_gid, sizeof(union ibv_gid)))
			continue;

		/* The item from index start to index (i-1) belongs to the same destination network address,
		 * We need to merge them.
		 */
		buf = expand_buf(buf, cur_size, cur_size + sizeof(struct notify_message_fmt)
								+ sizeof(struct msg_fmt) + (i - start) * sizeof(struct notify_msg_item));
		if(!buf) {
			return -1;
		}

		cur_size = cur_size + sizeof(struct notify_message_fmt)
						+ sizeof(struct msg_fmt) + (i - start) * sizeof(struct notify_msg_item);

		header = buf;
		header->ops = ops;
		per_ops_header = (struct msg_fmt*)(header + 1);
		memset(&per_ops_header->migr_dest_gid, 0, sizeof(union ibv_gid));
		per_ops_header->migr_dest_gid.raw[10] = 0xff;
		per_ops_header->migr_dest_gid.raw[11] = 0xff;
		memcpy(&per_ops_header->migr_dest_gid.raw[12], &migr_dest_addr->sin_addr.s_addr, sizeof(uint32_t));
		per_ops_header->cnt = i - start;
		arr = (struct notify_msg_item *)&per_ops_header->msg;

		for(j = start; j < i; j++) {
			arr->dest_qpn = item_list[j].dest_qpn;
			arr->pid = item_list[j].pid;
			arr++;
		}

		send_msg(&item_list[start].dest_gid, buf, cur_size, need_wait);
		free(buf);
		buf = NULL;
		cur_size = 0;
		start = i;
	}

	return 0;
}

static int notify_partners(pid_t pid, struct sockaddr_in *migr_dest_addr,
						enum rdma_notify_ops ops, int need_wait) {
	char fname[128];
	int rdma_proc_fd;
	DIR *rdma_proc_DIR;
	struct dirent *rdma_proc_dirent;
	int n_item = 0;
	struct notify_item *item_list;
	int curp = 0;

	sprintf(fname, "/proc/rdma/%d", pid);
	rdma_proc_fd = open(fname, O_DIRECTORY);
	if(rdma_proc_fd < 0) {
		return 0;
	}

	dbg_info("PID %d: Now notify partners\n", pid);

	rdma_proc_DIR = fdopendir(rdma_proc_fd);
	while((rdma_proc_dirent = readdir(rdma_proc_DIR)) != NULL) {
		int ctx_fd;
		DIR *ctx_DIR;
		struct dirent *ctx_dirent;
		struct stat st;

		if(!strncmp(rdma_proc_dirent->d_name, ".", 1))
			continue;

		if(fstatat(rdma_proc_fd, rdma_proc_dirent->d_name, &st, 0)) {
			close(rdma_proc_fd);
			return -1;
		}

		if(!S_ISDIR(st.st_mode))
			continue;

		ctx_fd = openat(rdma_proc_fd, rdma_proc_dirent->d_name, O_DIRECTORY);
		if(ctx_fd < 0) {
			close(rdma_proc_fd);
			return -1;
		}

		ctx_DIR = fdopendir(ctx_fd);
		while((ctx_dirent = readdir(ctx_DIR)) != NULL) {
			int pd_fd;
			DIR *pd_DIR;
			struct dirent *pd_dirent;

			if(strncmp(ctx_dirent->d_name, "pd", 2))
				continue;

			pd_fd = openat(ctx_fd, ctx_dirent->d_name, O_DIRECTORY);
			if(pd_fd < 0) {
				close(ctx_fd);
				close(rdma_proc_fd);
				return -1;
			}

			pd_DIR = fdopendir(pd_fd);
			while((pd_dirent = readdir(pd_DIR)) != NULL) {
				struct ibv_resume_qp_param param;
				char fname[128];
				int info_fd;

				if(strncmp(pd_dirent->d_name, "qp", 2))
					continue;

				sprintf(fname, "%.100s/qp_ctx", pd_dirent->d_name);
				info_fd = openat(pd_fd, fname, O_RDONLY);
				if(info_fd < 0) {
					continue;
				}

				if(read(info_fd, &param, sizeof(param)) < 0) {
					close(info_fd);
					continue;
				}

				close(info_fd);

				if(param.init_attr.qp_type == IBV_QPT_UD)
					continue;

				if(param.qp_state < 2)
					continue;

				n_item++;
			}
			
			close(pd_fd);
		}

		close(ctx_fd);
	}

	item_list = calloc(n_item, sizeof(*item_list));
	if(!item_list) {
		close(rdma_proc_fd);
		return -1;
	}

	lseek(rdma_proc_fd, 0, SEEK_SET);
	while((rdma_proc_dirent = readdir(rdma_proc_DIR)) != NULL) {
		int ctx_fd;
		DIR *ctx_DIR;
		struct dirent *ctx_dirent;
		struct stat st;

		if(!strncmp(rdma_proc_dirent->d_name, ".", 1))
			continue;

		if(fstatat(rdma_proc_fd, rdma_proc_dirent->d_name, &st, 0)) {
			close(rdma_proc_fd);
			return -1;
		}

		if(!S_ISDIR(st.st_mode))
			continue;

		ctx_fd = openat(rdma_proc_fd, rdma_proc_dirent->d_name, O_DIRECTORY);
		if(ctx_fd < 0) {
			close(rdma_proc_fd);
			return -1;
		}

		ctx_DIR = fdopendir(ctx_fd);
		while((ctx_dirent = readdir(ctx_DIR)) != NULL) {
			int pd_fd;
			DIR *pd_DIR;
			struct dirent *pd_dirent;

			if(strncmp(ctx_dirent->d_name, "pd", 2))
				continue;

			pd_fd = openat(ctx_fd, ctx_dirent->d_name, O_DIRECTORY);
			if(pd_fd < 0) {
				close(ctx_fd);
				close(rdma_proc_fd);
				return -1;
			}

			pd_DIR = fdopendir(pd_fd);
			while((pd_dirent = readdir(pd_DIR)) != NULL) {
				int qp_fd;
				union ibv_gid dest_gid;
				uint32_t dest_qpn;
				int info_fd;
				struct ibv_resume_qp_param param;
				char fname[128];

				if(strncmp(pd_dirent->d_name, "qp", 2))
					continue;

				sprintf(fname, "%.100s/qp_ctx", pd_dirent->d_name);
				info_fd = openat(pd_fd, fname, O_RDONLY);
				if(info_fd < 0) {
					continue;
				}

				if(read(info_fd, &param, sizeof(param)) < 0) {
					close(info_fd);
					continue;
				}

				close(info_fd);

				if(param.init_attr.qp_type == IBV_QPT_UD)
					continue;

				if(param.qp_state < 2)
					continue;

				qp_fd = openat(pd_fd, pd_dirent->d_name, O_DIRECTORY);
				if(qp_fd < 0) {
					close(pd_fd);
					close(ctx_fd);
					close(rdma_proc_fd);
					return -1;
				}

				info_fd = openat(qp_fd, "rc_dest_pgid", O_RDONLY);
				if(info_fd < 0) {
					close(qp_fd);
					close(pd_fd);
					close(ctx_fd);
					close(rdma_proc_fd);
				return -1;
				}

				if(read(info_fd, &dest_gid, sizeof(dest_gid)) < 0) {
					close(info_fd);
					close(qp_fd);
					close(pd_fd);
					close(ctx_fd);
					close(rdma_proc_fd);
					return -1;
				}

				close(info_fd);

				info_fd = openat(qp_fd, "dest_pqpn", O_RDONLY);
				if(info_fd < 0) {
					close(qp_fd);
					close(pd_fd);
					close(ctx_fd);
					close(rdma_proc_fd);
					return -1;
				}

				if(read(info_fd, &dest_qpn, sizeof(dest_qpn)) < 0) {
					close(info_fd);
					close(qp_fd);
					close(pd_fd);
					close(ctx_fd);
					close(rdma_proc_fd);
					return -1;
				}

				close(info_fd);

				memcpy(&item_list[curp].dest_gid, &dest_gid, sizeof(dest_gid));
				item_list[curp].dest_qpn = dest_qpn;
				item_list[curp].pid = pid;
				curp++;

				close(qp_fd);
			}
			
			close(pd_fd);
		}

		close(ctx_fd);
	}

	close(rdma_proc_fd);

	qsort(item_list, n_item, sizeof(*item_list), notify_item_compare);

	for(int i = 0; i < n_item; i++) {
		printf("In %s(%d): dest_gid: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x, "
					"dest_qpn: %d, pid: %d\n", __FILE__, __LINE__,
						item_list[i].dest_gid.raw[0], item_list[i].dest_gid.raw[1], item_list[i].dest_gid.raw[2], item_list[i].dest_gid.raw[3],
						item_list[i].dest_gid.raw[4], item_list[i].dest_gid.raw[5], item_list[i].dest_gid.raw[6], item_list[i].dest_gid.raw[7],
						item_list[i].dest_gid.raw[8], item_list[i].dest_gid.raw[9], item_list[i].dest_gid.raw[10], item_list[i].dest_gid.raw[11],
						item_list[i].dest_gid.raw[12], item_list[i].dest_gid.raw[13], item_list[i].dest_gid.raw[14], item_list[i].dest_gid.raw[15],
						item_list[i].dest_qpn, item_list[i].pid);
	}

	/* Merge the item of the same destination network address into one message */
	notify_merge(item_list, n_item, migr_dest_addr, ops, need_wait);

	if(need_wait) {
		int i;
		struct reply_hdr_fmt *merged_reply_hdr;
		struct reply_item_fmt *merged_arr;
		int total_cnt = 0;
		int merged_curp = 0;
		int fd_partner_buf;
		char fname[128];

		for(i = 0; i < n_threads; i++) {
			pthread_join(wait_thread[i], NULL);
		}

		for(int i = 0; i < n_threads; i++) {
			struct reply_hdr_fmt *reply_hdr = (struct reply_hdr_fmt *)params[i]->out_buf;
			total_cnt += reply_hdr->cnt;
		}

		merged_reply_hdr = malloc(sizeof(struct reply_hdr_fmt) + total_cnt * sizeof(struct reply_item_fmt));
		merged_reply_hdr->cnt = total_cnt;
		merged_arr = (struct reply_item_fmt *)&merged_reply_hdr->msg;
		for(i = 0; i < n_threads; i++) {
			struct reply_hdr_fmt *reply_hdr = (struct reply_hdr_fmt *)params[i]->out_buf;
			struct reply_item_fmt *arr = (struct reply_item_fmt *)&reply_hdr->msg;

			memcpy(&merged_arr[merged_curp], &arr[0], reply_hdr->cnt * sizeof(struct reply_item_fmt));
			merged_curp += reply_hdr->cnt;
		}

		sprintf(fname, "/proc/rdma/%d/partner_buf", pid);
		fd_partner_buf = open(fname, O_WRONLY);
		if(fd_partner_buf < 0) {
			perror("open");
			return -1;
		}

		if(write(fd_partner_buf, merged_reply_hdr, sizeof(struct reply_hdr_fmt) +
						total_cnt * sizeof(struct reply_item_fmt)) < 0) {
			close(fd_partner_buf);
			return -1;
		}

		close(fd_partner_buf);
		free(merged_reply_hdr);
	}

	return 0;
}

inline int notify_partners_suspend(pid_t pid) {
	struct sockaddr_in migr_dest_addr;

	inet_pton(AF_INET, "0.0.0.0", &migr_dest_addr.sin_addr);
	return notify_partners(pid, &migr_dest_addr, RDMA_NOTIFY_PRE_PAUSE, 1);
}

