#include <linux/proc_fs.h>
#include "rdma_footprint.h"

#define register_user_mmap(map_field, is_write)														\
static int ufile_##map_field##_mmap_open(struct inode *inode, struct file *filep) {					\
	filep->private_data = PDE_DATA(inode);															\
	return 0;																						\
}																									\
																									\
static int ufile_##map_field##_mmap_mmap(struct file *filep, struct vm_area_struct *vma) {			\
	struct ib_uverbs_file *ufile = filep->private_data;												\
	ufile->map_field##_mmap_addr = vma->vm_start;													\
	return remap_vmalloc_range(vma, ufile->map_field##_mapping, 0);									\
}																									\
																									\
static struct proc_ops ufile_##map_field##_mmap_ops = {												\
	.proc_open						= ufile_##map_field##_mmap_open,								\
	.proc_mmap						= ufile_##map_field##_mmap_mmap,								\
};																									\
																									\
static ssize_t ufile_##map_field##_mmap_kern_read(struct file *filep,								\
					char __user *buf, size_t size, loff_t *off) {									\
	struct ib_uverbs_file *ufile = filep->private_data;												\
																									\
	return copy_to_user(buf, ufile->map_field##_mapping, size)? : size;								\
}																									\
																									\
static ssize_t ufile_##map_field##_mmap_kern_write(struct file *filep,								\
						const char __user *buf, size_t size, loff_t *off) {							\
	struct ib_uverbs_file *ufile = filep->private_data;												\
																									\
	return copy_from_user(ufile->map_field##_mapping, buf, size)? : size;							\
}																									\
																									\
static ssize_t ufile_##map_field##_mmap_addr_read(struct file *filep,								\
					char __user *buf, size_t size, loff_t *off) {									\
	struct ib_uverbs_file *ufile = filep->private_data;												\
																									\
	if(size != sizeof(ufile->map_field##_mmap_addr))												\
		return -EINVAL;																				\
																									\
	return copy_to_user(buf, &ufile->map_field##_mmap_addr, size)? : size;							\
}																									\
																									\
static ssize_t ufile_##map_field##_mmap_fd_write(struct file *filep,								\
						const char __user *buf, size_t size, loff_t *off) {							\
	struct ib_uverbs_file *ufile = filep->private_data;												\
	int err;																						\
																									\
	if(size != sizeof(ufile->map_field##_fd))														\
		return -EINVAL;																				\
																									\
	if(!ufile->map_field##_fd_wait_flag)															\
		return -EEXIST;																				\
																									\
	err = copy_from_user(&ufile->map_field##_fd, buf, size);										\
	ufile->map_field##_fd_wait_flag = 0;															\
	wake_up_interruptible(&ufile->map_field##_fd_wait_queue);										\
	return err? err: size;																			\
}																									\
																									\
static ssize_t ufile_##map_field##_mmap_fd_read(struct file *filep,									\
					char __user *buf, size_t size, loff_t *off) {									\
	struct ib_uverbs_file *ufile = filep->private_data;												\
	int err;																						\
																									\
	if(size != sizeof(ufile->map_field##_fd))														\
		return -EINVAL;																				\
																									\
	wait_event_interruptible(ufile->map_field##_fd_wait_queue,										\
							!ufile->map_field##_fd_wait_flag);										\
																									\
	if(ufile->map_field##_fd_wait_flag)																\
		return -EPIPE;																				\
																									\
	err = copy_to_user(buf, &ufile->map_field##_fd, size);											\
	return err? err: size;																			\
}																									\
																									\
static int ufile_##map_field##_mmap_fd_release(struct inode *inode,									\
									struct file *filep) {											\
	struct ib_uverbs_file *ufile = filep->private_data;												\
	wake_up_interruptible(&ufile->map_field##_fd_wait_queue);										\
	return 0;																						\
}																									\
																									\
static struct proc_ops ufile_##map_field##_mmap_kern_ops = {										\
	.proc_open						= ufile_##map_field##_mmap_open,								\
	.proc_read						= ufile_##map_field##_mmap_kern_read,							\
	.proc_write						= ufile_##map_field##_mmap_kern_write,							\
};																									\
/*																									\
static struct proc_ops ufile_##map_field##_mmap_addr_ops = {										\
	.proc_open						= ufile_##map_field##_mmap_open,								\
	.proc_read						= ufile_##map_field##_mmap_addr_read,							\
};																									\
*/																									\
static struct proc_ops ufile_##map_field##_mmap_fd_ops = {											\
	.proc_open						= ufile_##map_field##_mmap_open,								\
	.proc_write						= ufile_##map_field##_mmap_fd_write,							\
	.proc_release					= ufile_##map_field##_mmap_fd_release,							\
};																									\
																									\
static struct proc_ops ufile_##map_field##_mmap_fd_kern_ops = {										\
	.proc_open						= ufile_##map_field##_mmap_open,								\
	.proc_read						= ufile_##map_field##_mmap_fd_read,								\
	.proc_release					= ufile_##map_field##_mmap_fd_release,							\
};																									\
																									\
static int __register_ufile_##map_field##_mmap(struct ib_uverbs_file *ufile) {						\
	struct proc_dir_entry *proc_ent;																\
	struct proc_dir_entry *proc_ent_kern;															\
	struct proc_dir_entry *proc_ent_mmap;															\
	struct proc_dir_entry *proc_ent_mmap_user;														\
	struct proc_dir_entry *proc_ent_fd;																\
																									\
	proc_ent = proc_create_data(#map_field "_map",													\
								(is_write)? 00666: 00644, ufile->ufile_proc_uwrite_ent,				\
								&ufile_##map_field##_mmap_ops, ufile);								\
	if(!proc_ent) {																					\
		return -ENOENT;																				\
	}																								\
																									\
	proc_ent_kern = proc_create_data(#map_field "_map", 00400, ufile->ufile_proc_ent,				\
								&ufile_##map_field##_mmap_kern_ops, ufile);							\
	if(!proc_ent_kern) {																			\
		proc_remove(proc_ent);																		\
		return -ENOENT;																				\
	}																								\
/*																									\
	proc_ent_mmap = proc_create_data(#map_field "_mmap_addr", 00400, ufile->ufile_proc_ent,			\
								&ufile_##map_field##_mmap_addr_ops, ufile);							\
	if(!proc_ent_mmap) {																			\
		proc_remove(proc_ent_kern);																	\
		proc_remove(proc_ent);																		\
		return -ENOENT;																				\
	}																								\
*/																									\
	proc_ent_fd = proc_create_data(#map_field "_mmap_fd", 00666, ufile->ufile_proc_uwrite_ent,		\
								&ufile_##map_field##_mmap_fd_ops, ufile);							\
	if(!proc_ent_fd) {																				\
		proc_remove(proc_ent_mmap);																	\
		proc_remove(proc_ent_kern);																	\
		proc_remove(proc_ent);																		\
		return -ENOENT;																				\
	}																								\
/*																									\
	proc_ent_mmap_user = proc_create_data(#map_field "_mmap_addr", 00666,							\
								ufile->ufile_proc_uwrite_ent,										\
								&ufile_##map_field##_mmap_addr_ops, ufile);							\
	if(!proc_ent_mmap_user) {																		\
		proc_remove(proc_ent_fd);																	\
		proc_remove(proc_ent_mmap);																	\
		proc_remove(proc_ent_kern);																	\
		proc_remove(proc_ent);																		\
		return -ENOENT;																				\
	}																								\
*/																									\
	if(!proc_create_data(#map_field "_mmap_fd", 00400, ufile->ufile_proc_ent,						\
								&ufile_##map_field##_mmap_fd_kern_ops, ufile)) {					\
		proc_remove(proc_ent_mmap_user);															\
		proc_remove(proc_ent_fd);																	\
		proc_remove(proc_ent_mmap);																	\
		proc_remove(proc_ent_kern);																	\
		proc_remove(proc_ent);																		\
		return -ENOENT;																				\
	}																								\
																									\
	init_waitqueue_head(&ufile->map_field##_fd_wait_queue);											\
	ufile->map_field##_fd_wait_flag = 1;															\
																									\
	return 0;																						\
}

register_user_mmap(lkey, false);
register_user_mmap(rkey, false);

int ufile_alloc_mapping(struct ib_uverbs_file *ufile) {
	ufile->lkey_mapping = vmalloc_user(PAGE_SIZE);
	if(!ufile->lkey_mapping)
		return -ENOMEM;
	memset(ufile->lkey_mapping, 0, PAGE_SIZE);

	ufile->rkey_mapping = vmalloc_user(PAGE_SIZE);
	if(!ufile->rkey_mapping) {
		vfree(ufile->lkey_mapping);
		return -ENOMEM;
	}
	memset(ufile->rkey_mapping, 0, PAGE_SIZE);

	if(__register_ufile_lkey_mmap(ufile) || __register_ufile_rkey_mmap(ufile)) {
		vfree(ufile->rkey_mapping);
		vfree(ufile->lkey_mapping);
		return -ENOENT;
	}

	return 0;
}

void ufile_dealloc_mapping(struct ib_uverbs_file *ufile) {
	vfree(ufile->rkey_mapping);
	vfree(ufile->lkey_mapping);
}

struct remote_rkey_trans_node {
	union ib_gid					remote_gid;
	pid_t							remote_pid;
	void							*mmap_user;
	int								refcnt;
	struct list_head				list;
};

static int remote_rkey_mapping_open(struct inode *inode, struct file *filep) {
	filep->private_data = PDE_DATA(inode);
	return 0;
}

static int remote_rkey_mapping_mmap(struct file *filep, struct vm_area_struct *vma) {
	struct remote_rkey_trans_node *rkey_trans = filep->private_data;
	return remap_vmalloc_range(vma, rkey_trans->mmap_user, 0);
}

static ssize_t remote_rkey_mapping_kern_read(struct file *filep,								\
				char __user *buf, size_t size, loff_t *off) {
	struct remote_rkey_trans_node *rkey_trans = filep->private_data;
	return copy_to_user(buf, rkey_trans->mmap_user, size)? : size;
}

static ssize_t remote_rkey_mapping_kern_write(struct file *filep,								\
				const char __user *buf, size_t size, loff_t *off) {
	struct remote_rkey_trans_node *rkey_trans = filep->private_data;
	return copy_from_user(rkey_trans->mmap_user, buf, size)? : size;
}

static int remote_rkey_mapping_release(struct inode *inode, struct file *filep) {
	struct remote_rkey_trans_node *rkey_trans = filep->private_data;
	rkey_trans->refcnt--;
	if(!rkey_trans->refcnt) {
		list_del(&rkey_trans->list);
	}

	return 0;
}

static struct proc_ops remote_rkey_mapping_ops = {
	.proc_open					= remote_rkey_mapping_open,
	.proc_mmap					= remote_rkey_mapping_mmap,
	.proc_release				= remote_rkey_mapping_release,
};

static struct proc_ops remote_rkey_mmaping_kern_ops = {
	.proc_open					= remote_rkey_mapping_open,
	.proc_read					= remote_rkey_mapping_kern_read,
	.proc_write					= remote_rkey_mapping_kern_write,
};

int register_remote_rkey_mapping(struct ib_uverbs_file *ufile,
						union ib_gid *gid, pid_t pid) {
	struct proc_dir_entry *proc_ent;
	struct proc_dir_entry *proc_ent_kern;
	struct remote_rkey_trans_node *node;
	char fname[1024];

	write_lock(&ufile->trans_list_lock);
	list_for_each_entry(node, &ufile->remote_rkey_trans_list, list) {
		if(!memcmp(&node->remote_gid, gid, sizeof(*gid)) && node->remote_pid == pid)
			break;
	}

	if(&node->list != &ufile->remote_rkey_trans_list) {
		node->refcnt++;
		write_unlock(&ufile->trans_list_lock);
		return 0;
	}

	node = kzalloc(sizeof(*node), GFP_KERNEL);
	if(!node) {
		write_unlock(&ufile->trans_list_lock);
		return -ENOMEM;
	}

	memcpy(&node->remote_gid, gid, sizeof(*gid));
	node->remote_pid = pid;
	node->mmap_user = vmalloc_user(PAGE_SIZE);
	if(!node->mmap_user) {
		write_unlock(&ufile->trans_list_lock);
		kfree(node);
		return -ENOMEM;
	}
	node->refcnt = 1;
	memset(node->mmap_user, 0, PAGE_SIZE);

	list_add_tail(&node->list, &ufile->remote_rkey_trans_list);
	write_unlock(&ufile->trans_list_lock);

	sprintf(fname, "<%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x>_%d",
				gid->raw[0], gid->raw[1], gid->raw[2], gid->raw[3], gid->raw[4], gid->raw[5], gid->raw[6], gid->raw[7],
				gid->raw[8], gid->raw[9], gid->raw[10], gid->raw[11], gid->raw[12], gid->raw[13], gid->raw[14], gid->raw[15], pid);
	proc_ent = proc_create_data(fname, 00666, ufile->ufile_proc_uwrite_ent, &remote_rkey_mapping_ops, node);
	if(!proc_ent) {
		return -ENOENT;
	}

	proc_ent_kern = proc_create_data(fname, 00400, ufile->ufile_proc_ent, &remote_rkey_mmaping_kern_ops, node);
	if(!proc_ent_kern) {
		proc_remove(proc_ent);
		return -ENOENT;
	}

	return 0;
}
