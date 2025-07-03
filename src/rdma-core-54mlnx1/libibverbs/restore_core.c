#if 0
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include "driver.h"

#define mv_fd(old_fd, new_fd) {									\
	struct stat statbuf;										\
	int __new_fd = (new_fd);									\
	for(; !fstat(__new_fd, &statbuf); __new_fd++);				\
																\
	if(dup2(old_fd, __new_fd) < 0) {							\
		if(old_fd >= 0)											\
			close(old_fd);										\
		old_fd = -1;											\
	}															\
	else {														\
		close(old_fd);											\
		old_fd = __new_fd;										\
	}															\
}

#define def_restore(res, restore_info_fn, restore_sub_fn, free_fn)						\
static int restore_rdma_##res(void *parent, int img_fd,									\
						char *path, char *parent_path) {								\
	void *(*__restore_info_fn)(void *, int, char *, char *, int *);						\
	int (*__restore_sub_fn)(void *, int, char *);										\
	void (*__free_fn)(void *);															\
	int sub_img_fd;																		\
	void *p_res;																		\
	int err;																			\
																						\
	__restore_info_fn = restore_info_fn;												\
	__restore_sub_fn = restore_sub_fn;													\
	__free_fn = free_fn;																\
																						\
	if(!__restore_info_fn)																\
		return -1;																		\
																						\
	sub_img_fd = openat(img_fd, path, O_DIRECTORY);										\
	mv_fd(sub_img_fd, sub_img_fd + 1350);												\
	if(sub_img_fd < 0) {																\
		return -1;																		\
	}																					\
																						\
	p_res = __restore_info_fn(parent, sub_img_fd, path, parent_path, &err);				\
	if(err) {																			\
		close(sub_img_fd);																\
		return -1;																		\
	}																					\
																						\
	if(__restore_sub_fn && __restore_sub_fn(p_res, sub_img_fd, path)) {					\
		if(__free_fn)																	\
			__free_fn(p_res);															\
		close(sub_img_fd);																\
		return -1;																		\
	}																					\
																						\
	if(__free_fn)																		\
		__free_fn(p_res);																\
	close(sub_img_fd);																	\
	return 0;																			\
}

#define dump_info(dir_fd, info_fd, param, info_name)									\
	info_fd = openat(dir_fd, #info_name, O_RDONLY);										\
	mv_fd(info_fd, info_fd + 1350);														\
	if(info_fd < 0) {																	\
		*p_err = -1;																	\
		return NULL;																	\
	}																					\
																						\
	if(read(info_fd, &(param)->info_name, sizeof((param)->info_name)) < 0) {			\
		close(info_fd);																	\
		*p_err = -1;																	\
		return NULL;																	\
	}																					\
																						\
	close(info_fd)

#define dump_mmap(dir_fd, info_fd, param, map_field)									\
	dump_info(dir_fd, info_fd, param, map_field##_mmap_fd);								\
	/* dump_info(dir_fd, info_fd, param, map_field##_mmap_addr); */							\
	dump_info(dir_fd, info_fd, param, map_field##_map)

static void *restore_mr(void *parent, int mr_fd,
						char *mr_path, char *parent_path, int *p_err) {
	struct ibv_context *tmp_context = parent;
	struct ibv_resume_mr_param mr_param;
	int info_fd;
	int pd_handle;
	int mr_handle;

	sscanf(parent_path, "pd_%d", &pd_handle);
	sscanf(mr_path, "mr_%d", &mr_handle);
	mr_param.pd_vhandle = pd_handle;
	mr_param.mr_vhandle = mr_handle;
	dump_info(mr_fd, info_fd, &mr_param, access_flags);
	dump_info(mr_fd, info_fd, &mr_param, iova);
	dump_info(mr_fd, info_fd, &mr_param, length);
	dump_info(mr_fd, info_fd, &mr_param, vlkey);
	dump_info(mr_fd, info_fd, &mr_param, vrkey);

	*p_err = ibv_resume_mr(tmp_context, &mr_param);
	return (*p_err)? NULL: parent;
}

def_restore(mr, restore_mr, NULL, NULL);

#define get_cq_handle(qp_dir_fd, cq) ({													\
	char linkbuf[128];																	\
	char tmp_buf[128];																	\
	ssize_t linkbuf_sz;																	\
	int cq_handle = -1;																	\
																						\
	linkbuf_sz = readlinkat(qp_dir_fd, #cq, linkbuf, sizeof(linkbuf));					\
	if(linkbuf_sz >= 0) {																\
		sprintf(tmp_buf, "%.*s", (int)linkbuf_sz, linkbuf);								\
		sscanf(tmp_buf, "../../cq_%d", &cq_handle);										\
	}																					\
	cq_handle;																			\
})

#define dump_info_var(dir_fd, info_fd, var, info_name)									\
	info_fd = openat(dir_fd, info_name, O_RDONLY);										\
	mv_fd(info_fd, info_fd + 1350);														\
	if(info_fd < 0) {																	\
		*p_err = -1;																	\
		return NULL;																	\
	}																					\
																						\
	if(read(info_fd, var, sizeof(*var)) < 0) {											\
		close(info_fd);																	\
		*p_err = -1;																	\
		return NULL;																	\
	}																					\
																						\
	close(info_fd)

static void *restore_qp(void *parent, int qp_fd,
						char *qp_path, char *parent_path, int *p_err) {
	struct ibv_context *tmp_context = parent;
	struct ibv_qp *tmp_qp;
	struct ibv_resume_qp_param qp_param;
	int info_fd;
	int pd_handle;
	int qp_handle;
	char info_name[32];
	int i;

	memset(&qp_param, 0, sizeof(qp_param));
	info_fd = openat(qp_fd, "qp_ctx", O_RDONLY);
	if(info_fd < 0) {
		*p_err = -1;
		return NULL;
	}

	if(read(info_fd, &qp_param, sizeof(qp_param)) < 0) {
		close(info_fd);
		*p_err = -1;
		return NULL;
	}

	close(info_fd);

	sscanf(parent_path, "pd_%d", &pd_handle);
	sscanf(qp_path, "qp_%d", &qp_handle);
	qp_param.pd_vhandle = pd_handle;
	qp_param.qp_vhandle = qp_handle;
	qp_param.send_cq_vhandle = get_cq_handle(qp_fd, send_cq);
	qp_param.recv_cq_vhandle = get_cq_handle(qp_fd, recv_cq);

#if 0
	dump_info(qp_fd, info_fd, &qp_param, qp_state);
	dump_info(qp_fd, info_fd, &qp_param, init_attr);
	dump_info(qp_fd, info_fd, &qp_param, meta_uaddr);
	dump_info(qp_fd, info_fd, &qp_param, vqpn);
	dump_info(qp_fd, info_fd, &qp_param, buf_addr);
	dump_info(qp_fd, info_fd, &qp_param, db_addr);
	dump_info(qp_fd, info_fd, &qp_param, usr_idx);
	dump_info(qp_fd, info_fd, &qp_param, signal_fd);

	for(i = 0; i < qp_param.qp_state; i++) {
		sprintf(info_name, "attr_%d", i);
		dump_info_var(qp_fd, info_fd, &qp_param.modify_qp_attr[i], info_name);
		sprintf(info_name, "mask_%d", i);
		dump_info_var(qp_fd, info_fd, &qp_param.modify_qp_mask[i], info_name);
	}
#endif

	tmp_qp = ibv_resume_create_qp(tmp_context, &qp_param);
	if(!tmp_qp) {
		*p_err = -1;
		return NULL;
	}

	for(i = 0; i < qp_param.qp_state; i++) {
		if(ibv_modify_qp(tmp_qp, &qp_param.modify_qp_attr[i],
							qp_param.modify_qp_mask[i])) {
			*p_err = -1;
			return NULL;
		}
	}

	ibv_resume_free_qp(tmp_qp);
	*p_err = 0;
	return parent;
}

def_restore(qp, restore_qp, NULL, NULL);

static void *restore_cq(void *parent, int cq_fd,
						char *cq_path, char *parent_path, int *p_err) {
	struct ibv_context *tmp_context = parent;
	struct ibv_resume_cq_param cq_param;
	int info_fd;
	int cq_handle;

	sscanf(cq_path, "cq_%d", &cq_handle);

	cq_param.cq_vhandle = cq_handle;

	dump_info(cq_fd, info_fd, &cq_param, cq_size);
	dump_info(cq_fd, info_fd, &cq_param, meta_uaddr);
	dump_info(cq_fd, info_fd, &cq_param, buf_addr);
	dump_info(cq_fd, info_fd, &cq_param, db_addr);

	*p_err = ibv_resume_cq(tmp_context, &cq_param);
	return (*p_err)? NULL: parent;
}

def_restore(cq, restore_cq, NULL, NULL);

static void *restore_pd(void *parent, int pd_fd,
				char *pd_path, char *parent_path, int *p_err) {
	struct ibv_context *tmp_context = parent;
	int pd_handle;

	sscanf(pd_path, "pd_%d", &pd_handle);
	*p_err = ibv_resume_pd(tmp_context, pd_handle);
	return (*p_err)? NULL: parent;
}

static int restore_pd_sub(void *parent, int pd_fd, char *path) {
	struct ibv_context *tmp_context = parent;
	DIR *pd_dir;
	struct dirent *pd_dirent;

	pd_dir = fdopendir(pd_fd);
	if(!pd_dir)
		return -1;
	
	while((pd_dirent = readdir(pd_dir)) != NULL) {
		if(!strncmp(pd_dirent->d_name, "mr", strlen("mr"))) {
			if(restore_rdma_mr(tmp_context, pd_fd, pd_dirent->d_name, path)) {
				return -1;
			}
		}

		if(!strncmp(pd_dirent->d_name, "qp", strlen("qp"))) {
			if(restore_rdma_qp(tmp_context, pd_fd, pd_dirent->d_name, path)) {
				return -1;
			}
		}
	}

	return 0;
}

def_restore(pd, restore_pd, restore_pd_sub, NULL);

static void *restore_context(void *parent, int cmd_fd,
					char *cmd_fd_path, char *parent_path, int *p_err) {
	struct ibv_context *tmp_context;
	struct ibv_resume_context_param context_param;
	char fname[128];
	int info_fd;

	if(parent) {
		*p_err = -1;
		return NULL;
	}

	memset(&context_param, 0, sizeof(context_param));
	context_param.cmd_fd = atoi(cmd_fd_path);

	dump_info(cmd_fd, info_fd, &context_param, cdev);
	dump_info(cmd_fd, info_fd, &context_param, async_fd);
	dump_info(cmd_fd, info_fd, &context_param, gid_table);

	dump_mmap(cmd_fd, info_fd, &context_param, lkey);
	dump_mmap(cmd_fd, info_fd, &context_param, local_rkey);
	dump_mmap(cmd_fd, info_fd, &context_param, lqpn);
	dump_mmap(cmd_fd, info_fd, &context_param, rkey);
	dump_mmap(cmd_fd, info_fd, &context_param, rqpn);

	sprintf(fname, "/proc/rdma_uwrite/%d/%d/lkey_mmap_addr",
					getpid(), context_param.cmd_fd);
	info_fd = open(fname, O_RDONLY);
	if(info_fd < 0) {
		return -1;
	}

	if(read(info_fd, &context_param.lkey_mmap_addr,
				sizeof(context_param.lkey_mmap_addr)) < 0) {
		close(info_fd);
		return -1;
	}

	sprintf(fname, "/proc/rdma_uwrite/%d/%d/local_rkey_mmap_addr",
					getpid(), context_param.cmd_fd);
	info_fd = open(fname, O_RDONLY);
	if(info_fd < 0) {
		return -1;
	}

	if(read(info_fd, &context_param.local_rkey_mmap_addr,
				sizeof(context_param.local_rkey_mmap_addr)) < 0) {
		close(info_fd);
		return -1;
	}

	sprintf(fname, "/proc/rdma_uwrite/%d/%d/lqpn_mmap_addr",
					getpid(), context_param.cmd_fd);
	info_fd = open(fname, O_RDONLY);
	if(info_fd < 0) {
		return -1;
	}

	if(read(info_fd, &context_param.lqpn_mmap_addr,
				sizeof(context_param.lqpn_mmap_addr)) < 0) {
		close(info_fd);
		return -1;
	}

	sprintf(fname, "/proc/rdma_uwrite/%d/%d/rkey_mmap_addr",
					getpid(), context_param.cmd_fd);
	info_fd = open(fname, O_RDONLY);
	if(info_fd < 0) {
		return -1;
	}

	if(read(info_fd, &context_param.rkey_mmap_addr,
				sizeof(context_param.rkey_mmap_addr)) < 0) {
		close(info_fd);
		return -1;
	}

	sprintf(fname, "/proc/rdma_uwrite/%d/%d/rqpn_mmap_addr",
					getpid(), context_param.cmd_fd);
	info_fd = open(fname, O_RDONLY);
	if(info_fd < 0) {
		return -1;
	}

	if(read(info_fd, &context_param.rqpn_mmap_addr,
				sizeof(context_param.rqpn_mmap_addr)) < 0) {
		close(info_fd);
		return -1;
	}

	tmp_context = ibv_resume_context(&context_param);
	if(!tmp_context) {
		*p_err = -1;
		return NULL;
	}

	*p_err = 0;
	return tmp_context;
}

static int restore_context_sub(void *g_tmp_context, int cmd_fd, char *path) {
	struct ibv_context *tmp_context = g_tmp_context;
	DIR *cmd_dir;
	struct dirent *cmd_dirent;

	cmd_dir = fdopendir(cmd_fd);
	if(!cmd_dir)
		return -1;
	
	while((cmd_dirent = readdir(cmd_dir)) != NULL) {
		if(!strncmp(cmd_dirent->d_name, "cq", strlen("cq"))) {
			if(restore_rdma_cq(tmp_context, cmd_fd, cmd_dirent->d_name, path)) {
				return -1;
			}
		}
	}

	if(lseek(cmd_fd, 0, SEEK_SET) < 0) {
		return -1;
	}

	while((cmd_dirent = readdir(cmd_dir)) != NULL) {
		if(!strncmp(cmd_dirent->d_name, "pd", strlen("pd"))) {
			if(restore_rdma_pd(tmp_context, cmd_fd, cmd_dirent->d_name, path)) {
				return -1;
			}
		}
	}

	return 0;
}

static inline void free_context(void *g_tmp_context) {
	struct ibv_context *tmp_context = g_tmp_context;
	ibv_free_tmp_context(tmp_context);
}

def_restore(context, restore_context, restore_context_sub, free_context);

int restore_rdma(void) {
	char fname[128];
	int img_pid_fd = 5000;
	DIR *img_pid_DIR;
	struct dirent *img_pid_dirent;
	struct stat st;

	if(fstat(img_pid_fd, &st))
		return 0;
	
	sprintf(fname, "rdma_pid_%d", getpid());

	img_pid_DIR = fdopendir(img_pid_fd);
	if(!img_pid_DIR) {
		close(img_pid_fd);
		return -1;
	}

	if(lseek(img_pid_fd, 0, SEEK_SET) < 0) {
		return -1;
	}

	while((img_pid_dirent = readdir(img_pid_DIR)) != NULL) {
		struct stat st;

		if(!strncmp(img_pid_dirent->d_name, ".", strlen(".")))
			continue;

		if(fstatat(img_pid_fd, img_pid_dirent->d_name, &st, 0)) {
			close(img_pid_fd);
			return -1;
		}

		if(!S_ISDIR(st.st_mode))
			continue;

		if(restore_rdma_context(NULL, img_pid_fd,
						img_pid_dirent->d_name, fname)) {
			close(img_pid_fd);
			return -1;
		}
	}

	close(img_pid_fd);

	return 0;
}
#endif
