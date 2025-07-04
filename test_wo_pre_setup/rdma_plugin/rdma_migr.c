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

int is_rdma_dev(unsigned long st_rdev) {
	int cdev_dir_fd;
	DIR *cdev_dir;
	struct dirent *cdev_ent;
	char fname[128];

	sprintf(fname, "/dev/infiniband/");
	cdev_dir_fd = open(fname, O_DIRECTORY);
	if(cdev_dir_fd < 0) {
		return -1;
	}

	cdev_dir = fdopendir(cdev_dir_fd);
	if(!cdev_dir) {
		close(cdev_dir_fd);
		return -1;
	}

	while((cdev_ent = readdir(cdev_dir)) != NULL) {
		struct stat st;
		int err;
		int fd;

		if(strncmp(cdev_ent->d_name, "uverbs", strlen("uverbs")))
			continue;
		
		fd = openat(cdev_dir_fd, cdev_ent->d_name, O_WRONLY);
		if(fd < 0) {
			close(cdev_dir_fd);
			return -1;
		}

		err = fstat(fd, &st);
		if(err < 0) {
			close(fd);
			close(cdev_dir_fd);
			return -1;
		}

		close(fd);

		if(major(st_rdev) == major(st.st_rdev)) {
			close(cdev_dir_fd);
			return 1;
		}
	}

	close(cdev_dir_fd);
	return 0;
}

#define dump_rdma_param(img_fd, rdma_fd, param_type, member)							\
	__dump_rdma_info(img_fd, rdma_fd, #member, sizeof(((param_type*)NULL)->member))

static int __dump_rdma_info(int img_fd, int rdma_fd, char *fname, size_t size) {
	int pipefd[2];
	int fd_in = -1;
	int fd_out = -1;
	int err = 0;
	loff_t off_in = 0, off_out = 0;

	fd_in = openat(rdma_fd, fname, O_RDONLY);
	fd_out = openat(img_fd, fname, O_WRONLY | O_CREAT, 00644);
	if(fd_in < 0 || fd_out < 0) {
		if(fd_in >= 0)
			close(fd_in);
		err_info("fname: %s: error occurs\n", fname);
		return -1;
	}

	if(pipe(pipefd)) {
		close(fd_in);
		close(fd_out);
		return -1;
	}

	while(1) {
		size_t this_size;
		this_size = splice(fd_in, &off_in, pipefd[1], NULL,
							size > 4096? 4096: size, SPLICE_F_MOVE);
		if(this_size < 0) {
			err = -1;
			break;
		}
		if(!this_size)
			break;
		
		if(splice(pipefd[0], NULL, fd_out, &off_out, this_size, SPLICE_F_MOVE) < 0) {
			err = -1;
			break;
		}

		size -= this_size;
	}

	close(pipefd[0]);
	close(pipefd[1]);
	close(fd_in);
	close(fd_out);
	return err;
}

#define def_dump(res, dump_cur_fn, dump_sub_fn)											\
static int dump_rdma_##res(int img_fd, int rdma_fd, char *path) {						\
	int sub_img_fd;																		\
	int sub_rdma_fd;																	\
	DIR *sub_rdma_DIR;																	\
	struct dirent *sub_rdma_dirent;														\
	int (*__dump_cur_fn)(int, int);														\
	int (*__dump_sub_fn)(int, int, char*);												\
																						\
	__dump_cur_fn = dump_cur_fn;														\
	__dump_sub_fn = dump_sub_fn;														\
																						\
	sub_rdma_fd = openat(rdma_fd, path, O_DIRECTORY);									\
	if(sub_rdma_fd < 0)																	\
		return -1;																		\
																						\
	if(mkdirat(img_fd, path, 00644) ||													\
					(sub_img_fd = openat(img_fd, path, O_DIRECTORY)) < 0) {				\
		close(sub_rdma_fd);																\
		return -1;																		\
	}																					\
																						\
	sub_rdma_DIR = fdopendir(sub_rdma_fd);												\
	if(!sub_rdma_DIR) {																	\
		close(sub_rdma_fd);																\
		close(sub_img_fd);																\
		return -1;																		\
	}																					\
																						\
	if(__dump_cur_fn && __dump_cur_fn(sub_img_fd, sub_rdma_fd)) {						\
		close(sub_rdma_fd);																\
		close(sub_img_fd);																\
		return -1;																		\
	}																					\
																						\
	while(__dump_sub_fn && (sub_rdma_dirent = readdir(sub_rdma_DIR)) != NULL) {			\
		if(__dump_sub_fn(sub_img_fd, sub_rdma_fd, sub_rdma_dirent->d_name)) {			\
			close(sub_rdma_fd);															\
			close(sub_img_fd);															\
			return -1;																	\
		}																				\
	}																					\
																						\
	close(sub_rdma_fd);																	\
	close(sub_img_fd);																	\
	return 0;																			\
}

static int dump_context_cur_fn(int img_cmd_fd, int rdma_cmd_fd) {
	struct ibv_resume_context_param param;
	int info_fd;
	void *nc_uar;

	info_fd = openat(rdma_cmd_fd, "ctx_uaddr", O_RDONLY);
	if(info_fd < 0) {
		return -1;
	}

	if(read(info_fd, &param.ctx_uaddr, sizeof(param.ctx_uaddr)) < 0) {
		close(info_fd);
		return -1;
	}

	close(info_fd);

	info_fd = openat(rdma_cmd_fd, "nc_uar", O_RDONLY);
	if(info_fd < 0) {
		return -1;
	}

	if(read(info_fd, &nc_uar, sizeof(nc_uar)) < 0) {
		close(info_fd);
		return -1;
	}

	close(info_fd);

	return dump_rdma_param(img_cmd_fd, rdma_cmd_fd,
					struct ibv_resume_context_param, cdev) ||
				dump_rdma_param(img_cmd_fd, rdma_cmd_fd,
					struct ibv_resume_context_param, ctx_uaddr) ||
				dump_rdma_param(img_cmd_fd, rdma_cmd_fd,
					struct ibv_resume_context_param, async_fd) ||
				dump_rdma_param(img_cmd_fd, rdma_cmd_fd,
					struct ibv_resume_context_param, lkey_mmap_fd) ||
				dump_rdma_param(img_cmd_fd, rdma_cmd_fd,
					struct ibv_resume_context_param, lkey_map) ||
				dump_rdma_param(img_cmd_fd, rdma_cmd_fd,
					struct ibv_resume_context_param, rkey_mmap_fd) ||
				dump_rdma_param(img_cmd_fd, rdma_cmd_fd,
					struct ibv_resume_context_param, rkey_map) ||
				add_rdma_vma((unsigned long long)param.ctx_uaddr,
				(unsigned long long)param.ctx_uaddr + sizeof(struct ibv_context), "[RDMA Q]") ||
				add_rdma_vma((unsigned long long)nc_uar, (unsigned long long)nc_uar + 4096, "[RDMA Q]");
}

static int dump_mr_cur_fn(int img_cmd_fd, int rdma_cmd_fd) {
	unsigned long long iova;
	size_t size;
	int fd;

	fd = openat(rdma_cmd_fd, "iova", O_RDONLY);
	if(fd < 0) {
		return -1;
	}

	if(read(fd, &iova, sizeof(iova)) < 0) {
		close(fd);
		return -1;
	}

	close(fd);
	fd = openat(rdma_cmd_fd, "length", O_RDONLY);
	if(fd < 0) {
		return -1;
	}

	if(read(fd, &size, sizeof(size)) < 0) {
		close(fd);
		return -1;
	}

	close(fd);

	return dump_rdma_param(img_cmd_fd, rdma_cmd_fd,
					struct ibv_resume_mr_param, access_flags) ||
			dump_rdma_param(img_cmd_fd, rdma_cmd_fd,
					struct ibv_resume_mr_param, iova) ||
			dump_rdma_param(img_cmd_fd, rdma_cmd_fd,
					struct ibv_resume_mr_param, length) ||
			dump_rdma_param(img_cmd_fd, rdma_cmd_fd,
					struct ibv_resume_mr_param, vlkey) ||
			dump_rdma_param(img_cmd_fd, rdma_cmd_fd,
					struct ibv_resume_mr_param, vrkey) ||
			add_rdma_vma(iova, iova + size, "[RDMA MR]");
}

def_dump(mr, dump_mr_cur_fn, NULL);

#define ROUND_UP_POW_OF_TWO(num)	({													\
	typeof(num) __num__ = (num);														\
	while(__num__ & (__num__ - 1)) {													\
		__num__ = __num__ & (__num__ - 1);												\
	}																					\
																						\
	__num__ + ((num & (__num__ - 1))? __num__: 0);										\
})

static int dump_qp_cur_fn(int img_cmd_fd, int rdma_cmd_fd) {
	char linkname[128];
	char buf[128];
	ssize_t size;
	int fd_in = -1;
	int fd_out = -1;
	int err, i;
	int qp_state;
	int info_fd;
	char info_name[32];
	struct ibv_resume_qp_param param;

	fd_in = openat(rdma_cmd_fd, "qp_ctx", O_RDONLY);
	fd_out = openat(img_cmd_fd, "qp_ctx", O_WRONLY | O_CREAT, 00644);
	if(fd_in < 0 || fd_out < 0) {
		if(fd_in >= 0)
			close(fd_in);
		return -1;
	}

	if(read(fd_in, &param, sizeof(param)) < 0) {
		close(fd_in);
		close(fd_out);
		return -1;
	}

	if(write(fd_out, &param, sizeof(param)) < 0) {
		close(fd_in);
		close(fd_out);
		return -1;
	}

	close(fd_in);
	close(fd_out);

	err = dump_rdma_param(img_cmd_fd, rdma_cmd_fd,
					struct ibv_resume_qp_param, qp_state) ||
			dump_rdma_param(img_cmd_fd, rdma_cmd_fd,
					struct ibv_resume_qp_param, init_attr) ||
			dump_rdma_param(img_cmd_fd, rdma_cmd_fd,
					struct ibv_resume_qp_param, meta_uaddr) ||
			dump_rdma_param(img_cmd_fd, rdma_cmd_fd,
					struct ibv_resume_qp_param, vqpn) ||
			dump_rdma_param(img_cmd_fd, rdma_cmd_fd,
					struct ibv_resume_qp_param, buf_addr) ||
			dump_rdma_param(img_cmd_fd, rdma_cmd_fd,
					struct ibv_resume_qp_param, db_addr) ||
			dump_rdma_param(img_cmd_fd, rdma_cmd_fd,
					struct ibv_resume_qp_param, usr_idx) ||
			dump_rdma_param(img_cmd_fd, rdma_cmd_fd,
					struct ibv_resume_qp_param, send_cq_handle) ||
			dump_rdma_param(img_cmd_fd, rdma_cmd_fd,
					struct ibv_resume_qp_param, recv_cq_handle);
	if(err)
		return -1;

	info_fd = openat(img_cmd_fd, "qp_state", O_RDONLY);
	if(info_fd < 0)
		return -1;
	
	if(read(info_fd, &qp_state, sizeof(qp_state)) < 0) {
		close(info_fd);
		return -1;
	}
	
	close(info_fd);
	for(i = 0; i < qp_state; i++) {
		sprintf(info_name, "attr_%d", i);
		err = __dump_rdma_info(img_cmd_fd, rdma_cmd_fd, info_name,
				sizeof(((struct ibv_resume_qp_param*)NULL)->modify_qp_attr[0]));
		if(err)
			return -1;

		sprintf(info_name, "mask_%d", i);
		err = __dump_rdma_info(img_cmd_fd, rdma_cmd_fd, info_name,
				sizeof(((struct ibv_resume_qp_param*)NULL)->modify_qp_mask[0]));
		if(err)
			return -1;
	}

	return add_rdma_vma((unsigned long long)param.meta_uaddr,
				(unsigned long long)param.meta_uaddr + sizeof(struct ibv_qp), "[RDMA Q]") ||
			add_rdma_vma((unsigned long long)param.buf_addr,
				(unsigned long long)param.buf_addr +
					ROUND_UP_POW_OF_TWO(param.init_attr.cap.max_send_wr * 256) +
					ROUND_UP_POW_OF_TWO(param.init_attr.cap.max_recv_wr) * 16, "[RDMA Q]") ||
			add_rdma_vma((unsigned long long)param.db_addr,
						(unsigned long long)param.db_addr + 4096, "[RDMA Q]");
}

def_dump(qp, dump_qp_cur_fn, NULL);

static int dump_srq_cur_fn(int img_cmd_fd, int rdma_cmd_fd) {
	struct ibv_resume_srq_param param;
	int fd_in = -1;
	int fd_out = -1;

	fd_in = openat(rdma_cmd_fd, "srq_ctx", O_RDONLY);
	fd_out = openat(img_cmd_fd, "srq_ctx", O_WRONLY | O_CREAT, 00644);
	if(fd_in < 0 || fd_out < 0) {
		if(fd_in >= 0)
			close(fd_in);
		return -1;
	}

	if(read(fd_in, &param, sizeof(param)) < 0) {
		close(fd_in);
		close(fd_out);
		return -1;
	}

	if(write(fd_out, &param, sizeof(param)) < 0) {
		close(fd_in);
		close(fd_out);
		return -1;
	}

	close(fd_in);
	close(fd_out);

	return 0;
}

def_dump(srq, dump_srq_cur_fn, NULL);

static int dump_pd_sub_fn(int img_cmd_fd, int rdma_cmd_fd, char *path) {
	if(!strncmp(path, "mr", strlen("mr"))) {
		return dump_rdma_mr(img_cmd_fd, rdma_cmd_fd, path);
	}

	if(!strncmp(path, "qp", strlen("qp"))) {
		return dump_rdma_qp(img_cmd_fd, rdma_cmd_fd, path);
	}

	if(!strncmp(path, "srq", strlen("srq"))) {
		return dump_rdma_srq(img_cmd_fd, rdma_cmd_fd, path);
	}

	return 0;
}

def_dump(pd, NULL, dump_pd_sub_fn);

static int dump_cq_cur_fn(int img_cmd_fd, int rdma_cmd_fd) {
	int cq_size;
	unsigned long long buf_addr;
	unsigned long long dbrec;
	int fd;

	fd = openat(rdma_cmd_fd, "buf_addr", O_RDONLY);
	if(fd < 0) {
		return -1;
	}

	if(read(fd, &buf_addr, sizeof(buf_addr)) < 0) {
		close(fd);
		return -1;
	}

	close(fd);
	fd = openat(rdma_cmd_fd, "cq_size", O_RDONLY);
	if(fd < 0) {
		return -1;
	}

	if(read(fd, &cq_size, sizeof(cq_size)) < 0) {
		close(fd);
		return -1;
	}

	close(fd);
	fd = openat(rdma_cmd_fd, "db_addr", O_RDONLY);
	if(fd < 0) {
		return -1;
	}

	if(read(fd, &dbrec, sizeof(dbrec)) < 0) {
		close(fd);
		return -1;
	}

	close(fd);

	return dump_rdma_param(img_cmd_fd, rdma_cmd_fd,
					struct ibv_resume_cq_param, cq_size) ||
			dump_rdma_param(img_cmd_fd, rdma_cmd_fd,
					struct ibv_resume_cq_param, meta_uaddr) ||
			dump_rdma_param(img_cmd_fd, rdma_cmd_fd,
					struct ibv_resume_cq_param, buf_addr) ||
			dump_rdma_param(img_cmd_fd, rdma_cmd_fd,
					struct ibv_resume_cq_param, db_addr) ||
			dump_rdma_param(img_cmd_fd, rdma_cmd_fd,
					struct ibv_resume_cq_param, comp_fd) ||
			add_rdma_vma(buf_addr, buf_addr + 64 * cq_size, "[RDMA Q]") ||
			add_rdma_vma(dbrec, dbrec + 4096, "[RDMA Q]");
}

def_dump(cq, dump_cq_cur_fn, NULL);

static int dump_comp_channel_fn(int img_cmd_fd, int rdma_cmd_fd) {
	return 0;
}

def_dump(uverbs_completion_event_file, dump_comp_channel_fn, NULL);

static int dump_context_sub_fn(int img_cmd_fd, int rdma_cmd_fd, char *path) {
	if(!strncmp(path, "pd", strlen("pd"))) {
		return dump_rdma_pd(img_cmd_fd, rdma_cmd_fd, path);
	}

	if(!strncmp(path, "cq", strlen("cq"))) {
		return dump_rdma_cq(img_cmd_fd, rdma_cmd_fd, path);
	}

	if(!strncmp(path, "uverbs_completion_event_file",
				strlen("uverbs_completion_event_file"))) {
		return dump_rdma_uverbs_completion_event_file(img_cmd_fd, rdma_cmd_fd, path);
	}

	return 0;
}

def_dump(context, dump_context_cur_fn, dump_context_sub_fn);

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
		recv_size = recvfrom(sk, recvbuf, sizeof(recvbuf), 0, NULL, NULL);
		if(recv_size < 0) {
			perror("recvfrom");
		}

		if(recv_size > 0) {
			buf = expand_buf(buf, cur_size, cur_size + recv_size);
			memcpy(buf + cur_size, recvbuf, recv_size);
			cur_size += recv_size;
			continue;
		}

		break;
	}

	if(buf) {
		param->out_buf = buf;
	}

	close(sk);
}

static int send_msg(union ibv_gid *dest_gid, void *buf, int size, int need_wait) {
	int sk = socket(AF_INET, SOCK_DGRAM, 0);
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

	while(sent_size < size) {
		this_size = sendto(sk, buf + sent_size, size - sent_size > 1024? 1024: size - sent_size,
								0, &remote_addr, sizeof(remote_addr));
		if(this_size < 0) {
			perror("sendto");
			return -1;
		}

		sent_size += this_size;
	}

	/* Send a null message to mark the end */
	sendto(sk, NULL, 0, 0, &remote_addr, sizeof(remote_addr));

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

int dump_rdma(pid_t rdma_pid, char *img_dir_path, struct sockaddr_in *migr_dest_addr) {
	pid_t pid;
	int img_fd;
	int img_pid_fd;
	int rdma_pid_fd;
	DIR *rdma_pid_DIR;
	struct dirent *rdma_pid_dirent;
	char fname[1024];
	int info_fd;

	if(notify_partners(rdma_pid, migr_dest_addr, RDMA_NOTIFY_PRE_ESTABLISH, 0)) {
		return -1;
	}

	img_fd = open(img_dir_path, O_DIRECTORY);
	if(img_fd < 0) {
		return -1;
	}

	sprintf(fname, "/proc/rdma/%d/", rdma_pid);
	rdma_pid_fd = open(fname, O_DIRECTORY);
	if(rdma_pid_fd < 0) {
		close(img_fd);
		return 0;
	}

	dbg_info("RDMA detected for PID %d. Now dumping RDMA info...\n", rdma_pid);

	info_fd = openat(rdma_pid_fd, "user_pid", O_RDONLY);
	if(info_fd < 0) {
		close(rdma_pid_fd);
		close(img_fd);
		return -1;
	}

	if(read(info_fd, &pid, sizeof(pid_t)) < 0) {
		close(info_fd);
		close(rdma_pid_fd);
		close(img_fd);
		return -1;
	}

	close(info_fd);

	sprintf(fname, "rdma_pid_%d", pid);
	if(mkdirat(img_fd, fname, 00644) ||
			(img_pid_fd = openat(img_fd, fname, O_DIRECTORY)) < 0) {
		close(rdma_pid_fd);
		close(img_fd);
		return -1;
	}

	rdma_pid_DIR = fdopendir(rdma_pid_fd);
	if(!rdma_pid_DIR) {
		close(img_pid_fd);
		close(rdma_pid_fd);
		close(img_fd);
		return -1;
	}

	while((rdma_pid_dirent = readdir(rdma_pid_DIR)) != NULL) {
		struct stat st;

		if(!strncmp(rdma_pid_dirent->d_name, ".", strlen(".")))
			continue;
		
		if(fstatat(rdma_pid_fd, rdma_pid_dirent->d_name, &st, 0)) {
			close(img_pid_fd);
			close(rdma_pid_fd);
			close(img_fd);
			return -1;
		}

		if(!S_ISDIR(st.st_mode))
			continue;

		if(dump_rdma_context(img_pid_fd, rdma_pid_fd, rdma_pid_dirent->d_name)) {
			close(img_pid_fd);
			close(rdma_pid_fd);
			close(img_fd);
			return -1;
		}
	}

	if(dump_smap_with_rdma(rdma_pid, img_pid_fd)) {
		close(img_pid_fd);
		close(rdma_pid_fd);
		close(img_fd);
		return -1;
	}

	close(img_pid_fd);
	close(rdma_pid_fd);
	close(img_fd);
	return 0;
}
