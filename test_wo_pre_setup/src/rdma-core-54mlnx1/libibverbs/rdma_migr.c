#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/un.h>
#include <string.h>
#include "rbtree.h"
#include "rdma_migr.h"
//#include "debug.h"
//#include "include/rbtree.h"
//#include "include/mem.h"
//#include "include/pstree.h"
//#include "include/namespaces.h"
//#include "include/timens.h"
//#include "include/cr_options.h"

struct ibv_device **ibv_device_list = NULL;
static int max_fd;

static declare_and_init_rbtree(cq_dict);

struct cq_dict_node {
	struct rb_node				node;
	int							cq_handle;
	void						*cq_ptr;
};

static int cq_dict_node_compare(const struct rb_node *n1, const struct rb_node *n2) {
	struct cq_dict_node *ent1 = n1? container_of(n1, struct cq_dict_node, node): NULL;
	struct cq_dict_node *ent2 = n2? container_of(n2, struct cq_dict_node, node): NULL;

	return ent1->cq_handle - ent2->cq_handle;
}

static struct cq_dict_node *search_cq_dict_node(int cq_handle,
						struct rb_node **p_parent, struct rb_node ***p_insert) {
	struct cq_dict_node my_node = {.cq_handle = cq_handle};
	struct rb_node *node;

	node = ___search(&my_node.node, &cq_dict, p_parent, p_insert,
								SEARCH_EXACTLY, cq_dict_node_compare);
	return node? container_of(node, struct cq_dict_node, node): NULL;
}

static int add_one_cq_dict_node(int cq_handle, struct ibv_cq *cq_ptr) {
	struct rb_node *parent, **insert;
	struct cq_dict_node *this_node;

	pthread_rwlock_wrlock(&cq_dict.rwlock);
	this_node = search_cq_dict_node(cq_handle, &parent, &insert);
	if(this_node) {
		pthread_rwlock_unlock(&cq_dict.rwlock);
		return 0;
	}

	this_node = malloc(sizeof(*this_node));
	if(!this_node) {
		pthread_rwlock_unlock(&cq_dict.rwlock);
		return -1;
	}

	this_node->cq_handle = cq_handle;
	this_node->cq_ptr = cq_ptr;
	rbtree_add_node(&this_node->node, parent, insert, &cq_dict);

	pthread_rwlock_unlock(&cq_dict.rwlock);
	return 0;
}

static struct ibv_cq *get_cq_ptr_from_handle(int cq_handle) {
	struct cq_dict_node *this_node;

	pthread_rwlock_rdlock(&cq_dict.rwlock);
	this_node = search_cq_dict_node(cq_handle, NULL, NULL);
	if(!this_node) {
		pthread_rwlock_unlock(&cq_dict.rwlock);
		return NULL;
	}

	pthread_rwlock_unlock(&cq_dict.rwlock);
	return this_node->cq_ptr;
}

static declare_and_init_rbtree(srq_dict);

struct srq_dict_node {
	struct rb_node				node;
	int							srq_handle;
	void						*srq_ptr;
};

static int srq_dict_node_compare(const struct rb_node *n1, const struct rb_node *n2) {
	struct srq_dict_node *ent1 = n1? container_of(n1, struct srq_dict_node, node): NULL;
	struct srq_dict_node *ent2 = n2? container_of(n2, struct srq_dict_node, node): NULL;

	return ent1->srq_handle - ent2->srq_handle;
}

static struct srq_dict_node *search_srq_dict_node(int srq_handle,
					struct rb_node **p_parent, struct rb_node ***p_insert) {
	struct srq_dict_node my_node = {.srq_handle = srq_handle};
	struct rb_node *node;

	node = ___search(&my_node.node, &srq_dict, p_parent, p_insert,
							SEARCH_EXACTLY, srq_dict_node_compare);
	return node? container_of(node, struct srq_dict_node, node): NULL;
}

static int add_one_srq_dict_node(int srq_handle, struct ibv_srq *srq_ptr) {
	struct rb_node *parent, **insert;
	struct srq_dict_node *this_node;

	pthread_rwlock_wrlock(&srq_dict.rwlock);
	this_node = search_srq_dict_node(srq_handle, &parent, &insert);
	if(this_node) {
		pthread_rwlock_unlock(&srq_dict.rwlock);
		return 0;
	}

	this_node = malloc(sizeof(*this_node));
	if(!this_node) {
		pthread_rwlock_unlock(&srq_dict.rwlock);
		return -1;
	}

	this_node->srq_handle = srq_handle;
	this_node->srq_ptr = srq_ptr;
	rbtree_add_node(&this_node->node, parent, insert, &srq_dict);

	pthread_rwlock_unlock(&srq_dict.rwlock);
	return 0;
}

static struct ibv_srq *get_srq_ptr_from_handle(int srq_handle) {
	struct srq_dict_node *this_node;

	pthread_rwlock_rdlock(&srq_dict.rwlock);
	this_node = search_srq_dict_node(srq_handle, NULL, NULL);
	if(!this_node) {
		pthread_rwlock_unlock(&srq_dict.rwlock);
		return NULL;
	}

	pthread_rwlock_unlock(&srq_dict.rwlock);
	return this_node->srq_ptr;
}

//static pid_t __rdma_pid__;

#define mv_fd(pid_fd, new_pid)									\
	if(dup2(pid_fd, new_pid) < 0) {								\
		if(pid_fd >= 0)											\
			close(pid_fd);										\
		pid_fd = -1;											\
	}															\
	else {														\
		close(pid_fd);											\
		pid_fd = new_pid;										\
	}

static int __wait_for_proc_complete(pid_t pid) {
	char fname[128];
	int channel_fd;
	int sig;

	sprintf(fname, "/proc/rdma/%d/to_proc", pid);
	channel_fd = open(fname, O_RDONLY);
	if(channel_fd < 0) {
		return -1;
	}

	printf("Ready to get the signal from channel FD\n");
	if(read(channel_fd, &sig, sizeof(int)) < 0) {
		printf("Error occurs. errno: %d\n", -errno);
		close(channel_fd);
		return -1;
	}
	printf("Finish get the signal from channel FD\n");

	close(channel_fd);
	return 0;
}

int wait_for_proc_complete(pid_t pid) {
	char fname[512];
	int task_fd;
	DIR *task_DIR;
	struct dirent *task_dirent;
	struct stat statbuf;

	sprintf(fname, "/proc/rdma/%d", pid);
	if(!stat(fname, &statbuf) && __wait_for_proc_complete(pid)) {
		return -1;
	}

	sprintf(fname, "/proc/%d/task", pid);
	task_fd = open(fname, O_DIRECTORY);
	if(task_fd < 0) {
		return -1;
	}

	task_DIR = fdopendir(task_fd);
	while((task_dirent = readdir(task_DIR)) != NULL) {
		int child_fd;
		FILE *child_fp;
		pid_t child_pid;

		if(!strncmp(task_dirent->d_name, ".", strlen(".")))
			continue;
		
		sprintf(fname, "%s/children", task_dirent->d_name);
		child_fd = openat(task_fd, fname, O_RDONLY);
		if(child_fd < 0) {
			close(task_fd);
			return -1;
		}

		child_fp = fdopen(child_fd, "r");
		while(fscanf(child_fp, "%d", &child_pid) != EOF) {
			sprintf(fname, "/proc/rdma/%d", child_pid);
			if(stat(fname, &statbuf))
				continue;
			
			if(__wait_for_proc_complete(child_pid)) {
				close(child_fd);
				close(task_fd);
				return -1;
			}
		}
		close(child_fd);
	}

	close(task_fd);
	return 0;
}

#if 0
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
#endif

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
	if(sub_img_fd < 0) {																\
		return -1;																		\
	}																					\
																						\
	if(dup2(sub_img_fd, max_fd) < 0) {													\
		close(sub_img_fd);																\
		return -1;																		\
	}																					\
																						\
	close(sub_img_fd);																	\
	sub_img_fd = max_fd;																\
	max_fd++;																			\
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
	dump_info(dir_fd, info_fd, param, map_field##_map)

static void *restore_mr(void *parent, int mr_fd,
						char *mr_path, char *parent_path, int *p_err) {
//	struct ibv_context *tmp_context = parent;
	struct ibv_pd *tmp_pd = parent;
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

	*p_err = ibv_resume_mr(tmp_pd->context, tmp_pd, &mr_param);
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
	struct ibv_pd *tmp_pd = parent;
	struct ibv_cq *send_cq, *recv_cq;
	struct ibv_qp *tmp_qp;
	struct ibv_qp *qp_ptr;
	struct ibv_srq *srq;
	struct ibv_resume_qp_param qp_param;
	int info_fd;
	int pd_handle;
	int qp_handle;
	unsigned long long bf_reg;
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

	info_fd = openat(qp_fd, "send_cq_handle", O_RDONLY);
	if(info_fd < 0) {
		*p_err = -1;
		return NULL;
	}

	if(read(info_fd, &qp_param.send_cq_handle, sizeof(qp_param.send_cq_handle)) < 0) {
		close(info_fd);
		*p_err = -1;
		return NULL;
	}

	close(info_fd);

	info_fd = openat(qp_fd, "recv_cq_handle", O_RDONLY);
	if(info_fd < 0) {
		*p_err = -1;
		return NULL;
	}

	if(read(info_fd, &qp_param.recv_cq_handle, sizeof(qp_param.recv_cq_handle)) < 0) {
		close(info_fd);
		*p_err = -1;
		return NULL;
	}

	close(info_fd);

	qp_ptr = qp_param.meta_uaddr;
	send_cq = get_cq_ptr_from_handle(qp_param.send_cq_handle);
	recv_cq = get_cq_ptr_from_handle(qp_param.recv_cq_handle);
	if(qp_ptr->srq) {
		srq = get_srq_ptr_from_handle(qp_ptr->srq->handle);
		srq->handle = qp_ptr->srq->handle;
	}
	else {
		srq = NULL;
	}
	tmp_qp = ibv_resume_create_qp(tmp_pd->context, tmp_pd,
						send_cq, recv_cq, srq, &qp_param, &bf_reg);
	if(!tmp_qp) {
		*p_err = -1;
		return NULL;
	}

//	add_one_rdma_vma_node(bf_reg & PAGE_MASK, (bf_reg & PAGE_MASK) + 4096);

	for(i = 0; i < qp_param.qp_state; i++) {
		if(ibv_modify_qp(tmp_qp, &qp_param.modify_qp_attr[i],
							qp_param.modify_qp_mask[i])) {
			*p_err = -1;
			return NULL;
		}
	}

	qp_ptr->dest_qpn = tmp_qp->dest_qpn;
	qp_ptr->dest_pid = tmp_qp->dest_pid;
	memcpy(&qp_ptr->rc_dest_gid, &tmp_qp->rc_dest_gid, sizeof(union ibv_gid));
	qp_ptr->rkey_arr = tmp_qp->rkey_arr;

//	ibv_resume_free_qp(tmp_qp);
	*p_err = 0;
	return parent;
}

def_restore(qp, restore_qp, NULL, NULL);

static void *restore_srq(void *parent, int srq_fd,
			char *srq_path, char *parent_path, int *p_err) {
	struct ibv_resume_srq_param srq_param;
	struct ibv_pd *tmp_pd = parent;
	struct ibv_srq *srq;
	int info_fd;

	memset(&srq_param, 0, sizeof(srq_param));
	info_fd = openat(srq_fd, "srq_ctx", O_RDONLY);
	if(info_fd < 0) {
		*p_err = -1;
		return NULL;
	}

	if(read(info_fd, &srq_param, sizeof(srq_param)) < 0) {
		close(info_fd);
		*p_err = -1;
		return NULL;
	}

	close(info_fd);

	sscanf(parent_path, "pd_%d", &srq_param.pd_vhandle);
	sscanf(srq_path, "srq_%d", &srq_param.vhandle);

	srq = ibv_resume_srq(tmp_pd, &srq_param);
	if(!srq) {
		*p_err = -1;
		return NULL;
	}

	*p_err = add_one_srq_dict_node(srq_param.vhandle, srq);
	if(*p_err) {
		return NULL;
	}

	*p_err = 0;
	return parent;
}

def_restore(srq, restore_srq, NULL, NULL);

static void *restore_cq(void *parent, int cq_fd,
						char *cq_path, char *parent_path, int *p_err) {
	struct ibv_context *tmp_context = parent;
	struct ibv_cq *tmp_cq;
	struct ibv_resume_cq_param cq_param;
	int info_fd;
	int cq_handle;

	sscanf(cq_path, "cq_%d", &cq_handle);

	cq_param.cq_vhandle = cq_handle;

	dump_info(cq_fd, info_fd, &cq_param, cq_size);
	dump_info(cq_fd, info_fd, &cq_param, meta_uaddr);
	dump_info(cq_fd, info_fd, &cq_param, buf_addr);
	dump_info(cq_fd, info_fd, &cq_param, db_addr);
	dump_info(cq_fd, info_fd, &cq_param, comp_fd);

	tmp_cq = ibv_resume_cq(tmp_context, &cq_param);
	if(!tmp_cq) {
		*p_err = -1;
		return NULL;
	}

	*p_err = add_one_cq_dict_node(cq_param.cq_vhandle, tmp_cq);
	if(*p_err) {
		return NULL;
	}

	*p_err = 0;
	return tmp_cq;
}

static inline void free_cq(void *g_tmp_cq) {
	return;
}

def_restore(cq, restore_cq, NULL, free_cq);

static void *restore_comp_channel(void *parent, int comp_channel_fd,
						char *comp_path, char *parent_path, int *p_err) {
	struct ibv_context *tmp_context = parent;
	int comp_fd;

	sscanf(comp_path, "uverbs_completion_event_file_%d", &comp_fd);
	*p_err = ibv_resume_comp_channel(tmp_context, comp_fd);
	if(*p_err) {
		return NULL;
	}

	return NULL;
}

def_restore(uverbs_completion_event_file, restore_comp_channel, NULL, NULL);

static void *restore_pd(void *parent, int pd_fd,
				char *pd_path, char *parent_path, int *p_err) {
	struct ibv_context *tmp_context = parent;
	struct ibv_pd *tmp_pd;
	int pd_handle;

	sscanf(pd_path, "pd_%d", &pd_handle);
	tmp_pd = ibv_resume_pd(tmp_context, pd_handle);
	if(!tmp_pd) {
		*p_err = -1;
		return NULL;
	}
	
	*p_err = 0;
	return tmp_pd;
}

static int restore_pd_sub(void *parent, int pd_fd, char *path) {
	struct ibv_context *tmp_context = parent;
	DIR *pd_dir;
	struct dirent *pd_dirent;

	pd_dir = fdopendir(pd_fd);
	if(!pd_dir)
		return -1;

	while((pd_dirent = readdir(pd_dir)) != NULL) {
		if(!strncmp(pd_dirent->d_name, "srq", strlen("srq"))) {
			if(restore_rdma_srq(tmp_context, pd_fd, pd_dirent->d_name, path)) {
				return -1;
			}
		}
	}

	lseek(pd_fd, 0, SEEK_SET);

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

static inline void free_pd(void *g_tmp_pd) {
	return;
}

def_restore(pd, restore_pd, restore_pd_sub, free_pd);

#include "driver.h"

static void *restore_context(void *parent, int cmd_fd,
					char *cmd_fd_path, char *parent_path, int *p_err) {
	struct ibv_resume_context_param context_param;
	int info_fd;
	struct ibv_context *context;

	if(parent) {
		*p_err = -1;
		return NULL;
	}

	memset(&context_param, 0, sizeof(context_param));
	context_param.cmd_fd = atoi(cmd_fd_path);

	dump_info(cmd_fd, info_fd, &context_param, cdev);
	dump_info(cmd_fd, info_fd, &context_param, async_fd);
	dump_info(cmd_fd, info_fd, &context_param, ctx_uaddr);

	dump_mmap(cmd_fd, info_fd, &context_param, lkey);
	dump_mmap(cmd_fd, info_fd, &context_param, rkey);

	context = ibv_resume_context(ibv_device_list, &context_param);
	if(!context)
		*p_err = -1;
	else
		*p_err = 0;

	__rdma_pid__ = rdma_getpid(context);

	return context;
}

static int restore_context_sub(void *g_tmp_context, int cmd_fd, char *path) {
	struct ibv_context *tmp_context = g_tmp_context;
	DIR *cmd_dir;
	struct dirent *cmd_dirent;
	struct ibv_resume_context_param context_param;
	int info_fd;

	memset(&context_param, 0, sizeof(context_param));

	info_fd = openat(cmd_fd, "ctx_uaddr", O_RDONLY);
	if(info_fd < 0) {
		return -1;
	}

	if(read(info_fd, &context_param.ctx_uaddr, sizeof(context_param.ctx_uaddr)) < 0) {
		close(info_fd);
		return -1;
	}

	close(info_fd);

	cmd_dir = fdopendir(cmd_fd);
	if(!cmd_dir)
		return -1;

	while((cmd_dirent = readdir(cmd_dir)) != NULL) {
		if(!strncmp(cmd_dirent->d_name, "uverbs_completion_event_file",
						strlen("uverbs_completion_event_file"))) {
			if(restore_rdma_uverbs_completion_event_file(tmp_context, cmd_fd,
								cmd_dirent->d_name, path)) {
				return -1;
			}
		}
	}

	if(lseek(cmd_fd, 0, SEEK_SET) < 0) {
		return -1;
	}
	
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

	return ibv_post_resume_context(context_param.ctx_uaddr, tmp_context);
}

static inline void free_context(void *g_tmp_context) {
	return;
}

def_restore(context, restore_context, restore_context_sub, free_context);

#include "ibverbs.h"

static int do_notify_partners(void);

static int prepare_qp_replay(struct ibv_qp *orig_qp, struct ibv_qp *new_qp) {
	return get_ops(new_qp->context)->prepare_qp_recv_replay(orig_qp, new_qp);
}

static int do_prepare_qp(struct ibv_qp *orig_qp, void *replay_fn) {
	return get_ops(orig_qp->context)->replay_recv_wr(orig_qp);
}

static int prepare_srq_replay(struct ibv_srq *orig_srq, struct ibv_srq *new_srq,
						int *head, int *tail) {
	return get_ops(new_srq->context)->prepare_srq_replay(orig_srq, new_srq, head, tail);
}

static int do_prepare_srq(struct ibv_srq *orig_srq, void *replay_fn, int head, int tail) {
	return get_ops(orig_srq->context)->replay_srq_recv_wr(orig_srq, head, tail);
}

int restore_rdma(pid_t pid, char *img_dir_path) {
	char fname[128];
	int img_fd;
	int img_pid_fd;
	DIR *img_pid_DIR;
	struct dirent *img_pid_dirent;
	int num_devices;

	ibv_device_list = ibv_get_device_list(&num_devices);
	max_fd = 2000;

	clear_rendpoint_tree();
#if 0
	for(int i = 0; i < num_devices; i++) {
		munmap(ibv_device_list[i]->qpn_dict, 4096 * 4096 * sizeof(uint32_t));
	}
#endif

	img_fd = open(img_dir_path, O_DIRECTORY);
	if(img_fd < 0) {
		return 0;
	}

	if(dup2(img_fd, max_fd) < 0) {
		close(img_fd);
		return -1;
	}

	close(img_fd);
	img_fd = max_fd;
	max_fd++;

	sprintf(fname, "rdma_pid_%d", pid);
	img_pid_fd = openat(img_fd, fname, O_DIRECTORY);
	if(img_pid_fd < 0) {
		close(img_fd);
		return 0;
	}

	if(dup2(img_pid_fd, max_fd) < 0) {
		close(img_pid_fd);
		return -1;
	}

	close(img_pid_fd);
	img_pid_fd = max_fd;
	max_fd++;

	printf("Pre-restoring RDMA information...\n");

	img_pid_DIR = fdopendir(img_pid_fd);
	if(!img_pid_DIR) {
		close(img_pid_fd);
		close(img_fd);
		return -1;
	}

	while((img_pid_dirent = readdir(img_pid_DIR)) != NULL) {
		struct stat st;

		if(!strncmp(img_pid_dirent->d_name, ".", strlen(".")))
			continue;
		
		if(fstatat(img_pid_fd, img_pid_dirent->d_name, &st, 0)) {
			close(img_pid_fd);
			close(img_fd);
			return -1;
		}

		if(!S_ISDIR(st.st_mode))
			continue;
		
		if(restore_rdma_context(NULL, img_pid_fd,
						img_pid_dirent->d_name, fname)) {
			close(img_pid_fd);
			close(img_fd);
			return -1;
		}
	}

	close(img_fd);
	close(img_pid_fd);

	if(rbtree_traverse_cq(iter_cq_insert_fake_comp_event, NULL)) {
		return -1;
	}

	if(switch_all_qps(prepare_qp_replay, do_prepare_qp)) {
		return -1;
	}

	if(switch_all_srqs(prepare_srq_replay, do_prepare_srq)) {
		return -1;
	}

	if(prepare_for_partners_restore(__rdma_pid__, img_dir_path)) {
		return -1;
	}

	return do_notify_partners();
}

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

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
	uint64_t				n_posted;
};

struct notify_msg_item {
	uint32_t				dest_qpn;
	pid_t					pid;
	uint64_t				n_posted;
};

static int notify_item_compare(const void *i1, const void *i2) {
	const struct notify_item *item1 = i1;
	const struct notify_item *item2 = i2;

	return memcmp(&item1->dest_gid, &item2->dest_gid, sizeof(union ibv_gid));
}

#define up_align_four(n) ({								\
	typeof(n) __tmp__ = ~0x11;							\
	(((n)-1) & __tmp__) + 4;							\
})

struct send_msg_entry {
	struct sockaddr_in		remote_addr;
	size_t					size;
	void					*buf;
};

static struct send_msg_entry send_msgs[16384];
static int n_msgs = 0;

static int do_notify_partners(void) {
	int sk = socket(AF_INET, SOCK_DGRAM, 0);
	for(int i = 0; i < n_msgs; i++) {
		int sent_size = 0;
		int this_size;
		size_t size = send_msgs[i].size;
		void *buf = send_msgs[i].buf;
		struct sockaddr_in remote_addr;

		memcpy(&remote_addr, &send_msgs[i].remote_addr,
							sizeof(remote_addr));
		while(sent_size < size) {
			this_size = sendto(sk, buf + sent_size, size - sent_size > 1024? 1024: size - sent_size,
								0, (struct sockaddr *)&remote_addr, sizeof(remote_addr));
			if(this_size < 0) {
				return -1;
			}

			sent_size += this_size;
		}

		sendto(sk, NULL, 0, 0, (struct sockaddr *)&remote_addr, sizeof(remote_addr));
	}

	close(sk);
	return 0;
}

inline size_t get_send_msg_meta_size(int *pn_msgs) {
	if(pn_msgs) {
		*pn_msgs = n_msgs;
	}

	return sizeof(struct send_msg_entry) * n_msgs;
}

size_t get_send_msg_size(void) {
	size_t ret = 0;
	for(int i = 0; i < n_msgs; i++) {
		ret += up_align_four(send_msgs[i].size);
	}

	return ret;
}

inline void copy_send_msg_meta(void *to) {
	memcpy(to, send_msgs, sizeof(struct send_msg_entry) * n_msgs);
}

static int send_msg(union ibv_gid *dest_gid, void *buf, int size, int need_wait) {
	struct sockaddr_in remote_addr;

	remote_addr.sin_family = AF_INET;
	remote_addr.sin_port = htons(50505);
	memcpy(&remote_addr.sin_addr.s_addr, &dest_gid->raw[12], sizeof(uint32_t));

	memcpy(&send_msgs[n_msgs].remote_addr, &remote_addr, sizeof(remote_addr));
	send_msgs[n_msgs].size = size;
	send_msgs[n_msgs].buf = buf;
	n_msgs++;

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
			arr->n_posted = item_list[j].n_posted;
			arr++;
		}

		send_msg(&item_list[start].dest_gid, buf, cur_size, need_wait);
		buf = NULL;
		cur_size = 0;
		start = i;
	}

	return 0;
}

static uint64_t get_n_posted_from_qpn(uint32_t this_qpn);

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

	printf("PID %d: Now prepare to notify partners\n", pid);

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
				struct ibv_qp *qp;

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

				info_fd = openat(qp_fd, "meta_uaddr", O_RDONLY);
				if(info_fd < 0) {
					close(qp_fd);
					close(pd_fd);
					close(ctx_fd);
					close(rdma_proc_fd);
					return -1;
				}

				if(read(info_fd, &qp, sizeof(qp)) < 0) {
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
				item_list[curp].n_posted = get_n_posted_from_qpn(qp->qp_num);
				curp++;

				close(qp_fd);
			}
			
			close(pd_fd);
		}

		close(ctx_fd);
	}

	close(rdma_proc_fd);

	qsort(item_list, n_item, sizeof(*item_list), notify_item_compare);

	notify_merge(item_list, n_item, migr_dest_addr, ops, need_wait);

	return 0;
}

struct reply_hdr_fmt {
	int								cnt;
	char							msg[0];
};

struct reply_item_fmt {
	uint32_t						qpn;
	uint64_t						n_posted;
};

static declare_and_init_rbtree(qpn_n_posted_tree);

struct qpn_n_posted_entry {
	uint32_t						this_qpn;
	uint64_t						n_posted;
	struct rb_node					node;
};

static inline struct qpn_n_posted_entry *to_qpn_n_posted_entry(struct rb_node *node) {
	return node? container_of(node, struct qpn_n_posted_entry, node): NULL;
}

static int qpn_n_posted_compare(const struct rb_node *n1, const struct rb_node *n2) {
	struct qpn_n_posted_entry *ent1 = to_qpn_n_posted_entry((struct rb_node *)n1);
	struct qpn_n_posted_entry *ent2 = to_qpn_n_posted_entry((struct rb_node *)n2);

	if(ent1->this_qpn < ent2->this_qpn) {
		return -1;
	}
	else if(ent1->this_qpn > ent2->this_qpn) {
		return 1;
	}
	else {
		return 0;
	}
}

static struct qpn_n_posted_entry *search_qpn_n_posted_entry(uint32_t this_qpn,
				struct rb_node **p_parent, struct rb_node ***p_insert) {
	struct qpn_n_posted_entry my_node = {.this_qpn = this_qpn};
	struct rb_node *node;

	node = ___search(&my_node.node, &qpn_n_posted_tree, p_parent, p_insert,
							SEARCH_EXACTLY, qpn_n_posted_compare);
	return to_qpn_n_posted_entry(node);
}

static int add_one_qpn_n_posted(uint32_t this_qpn, uint64_t n_posted) {
	struct rb_node *parent, **insert;
	struct qpn_n_posted_entry *ent;

	ent = search_qpn_n_posted_entry(this_qpn, &parent, &insert);
	if(ent) {
		return -1;
	}

	ent = malloc(sizeof(*ent));
	if(!ent) {
		return -1;
	}

	ent->this_qpn = this_qpn;
	ent->n_posted = n_posted;
	rbtree_add_node(&ent->node, parent, insert, &qpn_n_posted_tree);

	return 0;
}

static uint64_t get_n_posted_from_qpn(uint32_t this_qpn) {
	struct qpn_n_posted_entry *ent;

	ent = search_qpn_n_posted_entry(this_qpn, NULL, NULL);
	if(!ent) {
		return -1;
	}

	return ent->n_posted;
}

int prepare_for_partners_restore(pid_t pid, char *images_dir) {
	struct sockaddr_in migr_dest_addr;
	char fname[256];
	int info_fd;
	char recvbuf[1024];
	void *buf = NULL;
	int cur_size = 0;
	int recv_size;
	struct reply_hdr_fmt *reply_hdr;
	struct reply_item_fmt *arr;

	sprintf(fname, "%.110s/qp_n_posted_%d.raw", images_dir, getpid());
	info_fd = open(fname, O_RDONLY);
	if(info_fd < 0) {
		return 0;
	}

	while(1) {
		recv_size = read(info_fd, recvbuf, sizeof(recvbuf));
		if(recv_size < 0) {
			perror("read");
			close(info_fd);
			return -1;
		}

		if(recv_size > 0) {
			buf = expand_buf(buf, cur_size, cur_size + recv_size);
			memcpy(buf + cur_size, recvbuf, recv_size);
			cur_size += recv_size;
			continue;
		}

		break;
	}

	reply_hdr = buf;
	arr = (typeof(arr))&reply_hdr->msg;

	for(int i = 0; i < reply_hdr->cnt; i++) {
		if(add_one_qpn_n_posted(arr[i].qpn, arr[i].n_posted)) {
			return -1;
		}
	}

	close(info_fd);
	if(buf)
		free(buf);

	inet_pton(AF_INET, "0.0.0.0", &migr_dest_addr.sin_addr);
	return notify_partners(pid, &migr_dest_addr, RDMA_NOTIFY_RESTORE, 0);
}

#if 0
int stop_and_copy_update_state(struct pstree_item *current,
					void *clone_arg) {
	struct vm_area_list vmas;
	struct vma_area *vma1, *vma2;
	MmEntry *new_mm;
	unsigned long nr_pages;
	unsigned long end;
	void *addr;
	struct rst_info *ri = rsti(current);

	if(current == root_item) {
		struct pstree_item *pi;

#if 1
#if 0
		/* Update PB_TIMENS. Only once */
		if (root_ns_mask & CLONE_NEWTIME) {
			if (prepare_timens(current->ids->time_ns_id))
				return -1;
		} else if (kdat.has_timens) {
			if (prepare_timens(0))
				return -1;
		}
#endif
#else
		/* Update PB_TIMENS. Only once */
		if (root_ns_mask & CLONE_NEWTIME) {
			if (prepare_timens_v2(current->ids->time_ns_id,
							timens_helper_pid))
				return -1;
		} else if (kdat.has_timens) {
			if (prepare_timens_v2(0, timens_helper_pid))
				return -1;
		}
#endif

		for_each_pstree_item(pi) {
			int sock, err;
			struct sockaddr_un sock_un;

			if(pi == root_item) {
				continue;
			}

			sock = socket(AF_UNIX, SOCK_DGRAM, 0);
			if(sock < 0) {
				pr_perror("socket");
				return -1;
			}

			memset(&sock_un, 0, sizeof(sock_un));
			sock_un.sun_family = AF_UNIX;
			sprintf(sock_un.sun_path, "/dev/shm/pid_%d.sock", vpid(pi));

			err = sendto(sock, "hi", 3, 0, (struct sockaddr *)&sock_un, sizeof(sock_un));
			if(err < 0) {
				pr_perror("sendto");
				return -1;
			}

			close(sock);
		}
	}

	{
		char fname[128];
		FILE *fp;
		FileEntry fe;
		FileEntry *fe_ptr;

		/* Update PB_FILES */
		sprintf(fname, "%.110s/update_files.raw", images_dir);
		fp = fopen(fname, "r");
		if(!fp) {
			pr_perror("fopen");
			return -1;
		}

		while(fread(&fe, sizeof(fe), 1, fp) > 0) {
			RegFileEntry reg;
			FownEntry fwn;

			if(!fe.id)
				break;

			if(fread(&reg, sizeof(reg), 1, fp) <= 0) {
				pr_perror("fread");
				return -1;
			}

			if(fread(&fwn, sizeof(fwn), 1, fp) <= 0) {
				pr_perror("fread");
				return -1;
			}

			fe_ptr = get_fe_ptr_from_id(fe.id);
			if(!fe_ptr) {
				continue;
				pr_err("No fe_ptr found\n");
				return -1;
			}

			fe_ptr->reg->pos = reg.pos;
			fe_ptr->reg->size = reg.size;
		}

		fclose(fp);
	}

	/* Update PB_CORE */
	if(current->pid->state != TASK_HELPER
				&& stop_and_copy_update_core(clone_arg)) {
		return -1;
	}

	/* Update PB_MM */
	if(current->pid->state != TASK_HELPER
				&& get_vm_area_list(current, &vmas, &new_mm)) {
		return -1;
	}

	if(current->pid->state == TASK_HELPER) {
		goto exit;
	}

	vma1 = list_entry(&rsti(current)->vmas.h, struct vma_area, list);
	vma2 = list_entry(&vmas.h, struct vma_area, list);

	vma1 = list_entry(vma1->list.next, struct vma_area, list);
	vma2 = list_entry(vma2->list.next, struct vma_area, list);
	while(&vma1->list != &rsti(current)->vmas.h &&
					&vma2->list != &vmas.h) {
		if(vma1->e->start == vma2->e->start &&
						vma1->e->end == vma2->e->end) {
			vma2->e->status = vma1->e->status;
			nr_pages = vma_entry_len(vma2->e) / PAGE_SIZE;
			if(vma1->page_bitmap) {
				vma2->page_bitmap = xzalloc(BITS_TO_LONGS(nr_pages) * sizeof(long));
				if(vma2->page_bitmap == NULL) {
					return -1;
				}
				memcpy(vma2->page_bitmap, vma1->page_bitmap, BITS_TO_LONGS(nr_pages) * sizeof(long));
			}
			vma2->premmaped_addr = vma1->premmaped_addr;

#if 0
//			vma2->e->status = vma1->e->status;
			memcpy(vma2->e, vma1->e, sizeof(*vma1->e));
			vma1->e = vma2->e;
#endif

			vma1 = list_entry(vma1->list.next, struct vma_area, list);
			vma2 = list_entry(vma2->list.next, struct vma_area, list);
			continue;
		}

		/* If two regions do not intersect */
		if(!((vma2->e->start >= vma1->e->start && vma2->e->start < vma1->e->end) ||
					(vma2->e->end > vma1->e->start && vma2->e->end <= vma1->e->end))) {
			if(vma1->e->start < vma2->e->start) {
				/* vma1 is new */
				pr_err("Detect new vma1: %lx-%lx\n", vma1->e->start, vma1->e->end);
				if(vma1->premmaped_addr) {
					munmap((void *)vma1->premmaped_addr, vma1->e->end - vma1->e->start);
					vma1->premmaped_addr = 0;
				}

				vma1 = list_entry(vma1->list.next, struct vma_area, list);
			}
			else {
				struct vma_area *vma2_tmp;
				pr_err("Detect new vma2: %lx-%lx\n", vma2->e->start, vma2->e->end);
				vma2_tmp = list_entry(vma2->list.next, struct vma_area, list);
				list_del(&vma2->list);
				list_add_tail(&vma2->list, &vma1->list);
				pr_err("(%lx-%lx) before (%lx-%lx)\n", vma2->e->start, vma2->e->end, vma1->e->start, vma1->e->end);
				vma2 = vma2_tmp;
			}

			continue;
		}

		/* Two regions intersect */
		pr_err("Detect two intersected reagions\n");
		pr_err("vma1: %lx-%lx, vma2: %lx-%lx\n",
						vma1->e->start, vma1->e->end,
						vma2->e->start, vma2->e->end);
		vma2->e->status = vma1->e->status;
		nr_pages = vma_entry_len(vma2->e) / PAGE_SIZE;
		if(vma1->page_bitmap) {
			vma2->page_bitmap = xzalloc(BITS_TO_LONGS(nr_pages) * sizeof(long));
			if(vma2->page_bitmap == NULL) {
				return -1;
			}
			memcpy(vma2->page_bitmap, vma1->page_bitmap, BITS_TO_LONGS(nr_pages) * sizeof(long));
		}
		vma2->premmaped_addr = vma1->premmaped_addr;

		if(!vma_area_is(vma1, VMA_PREMMAPED)) {
			vma1 = list_entry(vma1->list.next, struct vma_area, list);
			vma2 = list_entry(vma2->list.next, struct vma_area, list);
			continue;
		}

		/* The vma1 has been premapped, so we need to remap it */
		pr_err("Re-map %lx-%lx to %lx-%lx\n",
						vma1->e->start, vma1->e->end,
						vma2->e->start, vma2->e->end);

		/* Align the end of the vma1 and vma2
		 * Case 1:
		 * vma1:          |xxxxxxxxxxxxxxxxxxx|                  ==>      |xxxxxxxxxxxxxxxxxxxxxxxxxxxx|
		 * vma2:  (start point not critical) ..xxxxxxxxxxxxx|    ==>                    ..xxxxxxxxxxxxx|
		 *
		 * Case 2 (do nothing):
		 * vma1:        |xxxxxxxxxxxxxxxxxxxxxx|    ==> |xxxxxxxxxxxxx|
		 * vma2:           ..xxxxxxxxx|             ==>    ..xxxxxxxxx|
		 */
		end = (vma1->e->end < vma2->e->end)?
						vma2->e->end: vma1->e->end;
		if(end != vma1->e->end) {
			/* Case 1 */
			addr = mremap((void *)vma1->e->start, vma1->e->end - vma1->e->start,
									end - vma1->e->start, 0);
			if(addr == MAP_FAILED || addr != (void *)vma1->e->start) {
				pr_err("Failed to expand vma1\n");
				return -1;
			}

			vma2->premmaped_addr = (unsigned long)addr;
			vma1->premmaped_addr = (unsigned long)addr;
		}
		else {
			/* Case 2 */
			if(vma1->e->end != vma2->e->end) {
				munmap((void *)vma2->e->end, vma1->e->end - vma2->e->end);
			}
		}

		/* Align the start of vma1 and vma2
		 * Case 1:
		 * vma1: |xxxxxxxxxxxxxx| ==>        |xxxxxxx|
		 * vma2:        |xxxxxxx| ==>        |xxxxxxx|
		 * Case 2:
		 * vma1:       |xxxxxxxx| ==> |xxxxxxxxxxxxxx|
		 * vma2: |xxxxxxxxxxxxxx| ==> |xxxxxxxxxxxxxx|
		 */
		if(vma1->e->start < vma2->e->start) {
			/* Case 1 */
			munmap((void *)vma1->e->start, vma2->e->start - vma1->e->start);
		}
		else {
			/* Case 2 */
			if(vma1->e->start != vma2->e->start) {
				int flag = 0;
				if(vma_entry_is(vma1->e, VMA_AREA_AIORING))
					flag |= MAP_ANONYMOUS;
				addr = mmap((void *)vma2->e->start, vma1->e->start - vma2->e->start,
							vma1->e->prot | PROT_WRITE, vma1->e->flags | MAP_FIXED | flag,
							vma1->e->fd, 0);
				if(addr == MAP_FAILED || addr != (void *)vma2->e->start) {
					pr_err("Failed to mmap part of vma2\n");
					return -1;
				}

				vma2->premmaped_addr = (unsigned long)addr;
				vma1->premmaped_addr = (unsigned long)addr;
			}
		}

		vma1 = list_entry(vma1->list.next, struct vma_area, list);
		vma2 = list_entry(vma2->list.next, struct vma_area, list);
	}

#if 0
	for(int idx = 0; idx < ri->mm->n_vmas; idx++) {
//		memcpy(ri->mm->vmas[idx], new_mm->vmas[idx], sizeof(VmaEntry));
		ri->mm->vmas[idx]->start = new_mm->vmas[idx]->start;
		ri->mm->vmas[idx]->end = new_mm->vmas[idx]->end;
	}
#endif

	ri->mm = new_mm;
	rsti(current)->vmas.nr = ri->mm->n_vmas;

	{
		struct vma_area *vma;
		struct list_head *vmas = &rsti(current)->vmas.h;

		list_for_each_entry(vma, vmas, list) {
			pr_err("vma->e->start: %lx, vma->e->end: %lx\n", vma->e->start, vma->e->end);
		}
	}

	INIT_LIST_HEAD(&rsti(current)->vma_io);

exit:
	return 0;
}

static struct update_mem_node update_arr[16384];
static int n_update = 0;

int add_update_node(void *ptr, size_t size, void *content_p) {
	update_arr[n_update].ptr				= ptr;
	update_arr[n_update].size				= size;
	update_arr[n_update].content_p			= content_p;
	n_update++;
	return 0;
}

inline size_t get_update_node_size(int *n_node) {
	if(n_node)
		*n_node = n_update;

	return n_update * sizeof(struct update_mem_node);
}

size_t get_total_content_size(void) {
	size_t ret = 0;

	for(int i = 0; i < n_update; i++) {
		ret += up_align_four(update_arr[i].size);
	}

	return ret;
}

inline void copy_update_nodes(void *to) {
	memcpy(to, update_arr, sizeof(struct update_mem_node) * n_update);
}

static struct qp_replay_call_entry qp_replay_arr[16384];
static int n_qp_replay = 0;

int load_qp_callback(struct ibv_qp *orig_qp, void *replay_fn) {
	qp_replay_arr[n_qp_replay].qp = orig_qp;
	qp_replay_arr[n_qp_replay].cb = replay_fn;
	n_qp_replay++;
	return 0;
}

inline size_t get_qp_replay_size(int *n_node) {
	if(n_node)
		*n_node = n_qp_replay;

	return n_qp_replay * sizeof(struct qp_replay_call_entry);
}

inline void copy_qp_replay_nodes(void *to) {
	memcpy(to, qp_replay_arr, sizeof(struct qp_replay_call_entry) * n_qp_replay);
}

static struct srq_replay_call_entry srq_replay_arr[16384];
static int n_srq_replay = 0;

int load_srq_callback(struct ibv_srq *srq, void *replay_fn, int head, int tail) {
	srq_replay_arr[n_srq_replay].srq = srq;
	srq_replay_arr[n_srq_replay].cb = replay_fn;
	srq_replay_arr[n_srq_replay].head = head;
	srq_replay_arr[n_srq_replay].tail = tail;
	n_srq_replay++;
	return 0;
}

inline size_t get_srq_replay_size(int *n) {
	if(n)
		*n = n_srq_replay;

	return sizeof(struct srq_replay_call_entry) * n_srq_replay;
}

inline void copy_srq_replay_nodes(void *to) {
	memcpy(to, srq_replay_arr, sizeof(struct srq_replay_call_entry) * n_srq_replay);
}
#endif
