#ifndef __RDMA_FOOTPRINT_H__
#define __RDMA_FOOTPRINT_H__

#include <rdma/ib_verbs.h>
#include <rdma/ib_cache.h>
#include <linux/proc_fs.h>

#define dbg_info(fmt, args...)												\
	printk(KERN_NOTICE "In %s(%d): " fmt, __FILE__, __LINE__, ##args)

#define err_info(fmt, args...)												\
	printk(KERN_ERR, "Err at %s(%d): " fmt, __FILE__, __LINE__, ##args)

#define CHECK(cond) ({														\
	int ___r = !!(cond);													\
	dbg_info("CHECK (%s)? %s\n", #cond, ___r? "true": "false");				\
	___r;																	\
})

#define PRINT(var, fmt) ({													\
	typeof(var) ___r = (var);												\
	dbg_info("PRINT (%s): " fmt "\n", #var, ___r);							\
	___r;																	\
})

struct proc_task_node;

struct footprint_gid_entry {
	__aligned_u64					gid[2];
	__u32							gid_index;
	__u32							gid_type;
};

#include "uverbs.h"

#define declare_res_footprint_func(res_type, res, parent_type, parent)		\
extern int register_##res##_to_footprint(res_type *res,						\
				parent_type *parent, int vhandle);							\
extern void deregister_##res##_from_footprint(res_type *res)

#define declare_res_uwrite_footprint_func(res_type, res, parent_type, parent)			\
extern int register_##res##_to_uwrite_footprint(res_type *res,							\
				parent_type *parent, int vhandle);										\
extern void deregister_##res##_from_uwrite_footprint(res_type *res)

#define declare_handle_mapping_func(res_type, res)										\
extern int register_##res##_handle_mapping(struct ib_uverbs_file *ufile,				\
			res_type *res, int vhandle, int handle);									\
extern void unregister_##res##_handle_mapping(struct ib_uverbs_file *ufile,				\
									res_type *res);										\
extern int get_##res##_handle(struct ib_uverbs_file *ufile, int vhandle, int *handle)

#define declare_user_mmap(map_field, key_type, value_type)								\
extern int add_##map_field##_mapping(struct ib_uverbs_file *ufile,						\
										key_type key, value_type value);				\
extern int update_##map_field##_mapping(struct ib_uverbs_file *ufile,					\
										key_type key, value_type value);				\
extern void del_##map_field##_mapping(struct ib_uverbs_file *ufile, key_type key)

extern int rdma_footprint_init(void);
extern void rdma_footprint_exit(void);
extern int init_rkey_translate_service(void);
extern void exit_rkey_translate_service(void);
extern int register_rdma_dev_fd_entry(int cmd_fd,
			struct ib_uverbs_file *ufile);
extern void deregister_rdma_dev_fd_entry(struct ib_uverbs_file *ufile);
extern int register_async_fd(struct ib_uverbs_file *ufile, int async_fd);
extern int register_new_ufile_mapping(struct ib_uverbs_file *ufile);
extern void deregister_new_ufile_mapping(struct ib_uverbs_file *ufile);

extern ssize_t channel_to_proc_write(void **channel_buf, size_t *orig_size,
					const char __user *buf, size_t size);
extern ssize_t channel_from_frm_read(void **channel_buf, size_t *orig_size,
					char __user *buf, size_t size, loff_t *off);

declare_res_footprint_func(struct ib_pd, pd, struct ib_uverbs_file, ufile);
declare_res_footprint_func(struct ib_cq, cq, struct ib_uverbs_file, ufile);
declare_res_footprint_func(struct ib_mr, mr, struct ib_pd, pd);
declare_res_footprint_func(struct ib_qp, qp, struct ib_pd, pd);
declare_res_footprint_func(struct ib_srq, srq, struct ib_pd, pd);
declare_res_footprint_func(struct ib_uverbs_completion_event_file, uverbs_completion_event_file,
							struct ib_uverbs_file, ufile);

declare_res_uwrite_footprint_func(struct ib_cq, cq, struct ib_uverbs_file, ufile);
declare_res_uwrite_footprint_func(struct ib_qp, qp, struct ib_uverbs_file, ufile);
declare_res_uwrite_footprint_func(struct ib_mr, mr, struct ib_uverbs_file, ufile);
declare_res_uwrite_footprint_func(struct ib_srq, srq, struct ib_uverbs_file, ufile);

declare_handle_mapping_func(struct ib_pd, pd);
declare_handle_mapping_func(struct ib_cq, cq);
declare_handle_mapping_func(struct ib_mr, mr);
declare_handle_mapping_func(struct ib_qp, qp);
declare_handle_mapping_func(struct ib_srq, srq);

declare_user_mmap(lkey, uint32_t, uint32_t);
declare_user_mmap(lqpn, uint32_t, uint32_t);
declare_user_mmap(local_rkey, uint32_t, uint32_t);

#undef declare_res_footprint_func
#undef declare_handle_mapping_func
#undef declare_res_uwrite_footprint_func
#undef declare_user_mmap

extern int ufile_alloc_mapping(struct ib_uverbs_file *ufile);
extern void ufile_dealloc_mapping(struct ib_uverbs_file *ufile);

extern int mkdir_ibdev_sig_link(struct ib_device *ibdev);
extern void rmdir_ibdev_sig_link(struct ib_device *ibdev);

//extern struct proc_ops pause_entry_ops;
//extern struct proc_ops pause_uwrite_entry_ops;
extern int init_ud_qp_pause_signal(void);

extern int install_ctx_resp(struct ib_uverbs_file *ufile,
				char __user *buf, size_t size);

extern void unregister_qp_symlink(u32 vqpn);

extern int register_remote_rkey_mapping(struct ib_uverbs_file *ufile,
						union ib_gid *gid, pid_t pid);
extern int service_register_rkey_mapping(pid_t pid, uint32_t vrkey, uint32_t rkey);
extern int service_delete_rkey_mapping(pid_t pid, uint32_t vrkey);

#endif
