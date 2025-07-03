#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/device.h>
#include <linux/kthread.h>
#include <linux/ktime.h>
#include <linux/delay.h>
#include "rdma_footprint.h"
#include "rbtree_core.h"
#include "uverbs.h"

#define FP_ACCESS_MODE					00400
#define FP_UWRITE_MODE					S_IRUGO | S_IWUGO | S_IXUGO

static struct proc_dir_entry *procfs_dir_ent;
static struct proc_dir_entry *procfs_dir_uwrite_ent;

struct proc_task_node {
	struct task_struct				*task;
	struct proc_dir_entry			*task_dir_ent;
	struct proc_dir_entry			*task_dir_uwrite_ent;
	uint32_t						proc_to_frm;
	wait_queue_head_t				proc_to_frm_wait_queue;
	int								proc_to_frm_wait_flag;
	uint32_t						frm_to_proc;
	wait_queue_head_t				frm_to_proc_wait_queue;
	int								frm_to_proc_wait_flag;
	void							*partner_buf;
	int								partner_buf_size;

	struct rb_node					node;
	u64								refcnt;
	struct rbtree_struct			qp_pause_symlink_tree;
	pid_t							user_pid;
};

struct qp_symlink_node {
	u32								vqpn;
	u32								qp_num;
	struct proc_dir_entry			*parent;
	struct rb_node					node;
};

static declare_and_init_rbtree(proc_task_tree);

static int compare(const struct rb_node *n1, const struct rb_node *n2) {
	struct proc_task_node *ent1 =
				n1? container_of(n1, struct proc_task_node, node): NULL;
	struct proc_task_node *ent2 =
				n2? container_of(n2, struct proc_task_node, node): NULL;
	
	if(!ent1 && !ent2)
		return 0;
	else if(!ent1)
		return -1;
	else if(!ent2)
		return 1;
	
	return ent1->task->tgid - ent2->task->tgid;
}

static int qp_symlink_compare(const struct rb_node *n1, const struct rb_node *n2) {
	struct qp_symlink_node *ent1 =
				n1? container_of(n1, struct qp_symlink_node, node): NULL;
	struct qp_symlink_node *ent2 =
				n2? container_of(n2, struct qp_symlink_node, node): NULL;
	
	if(ent1->qp_num < ent2->qp_num)
		return -1;
	else if(ent1->qp_num > ent2->qp_num)
		return 1;
	else
		return 0;
}

static struct proc_task_node *search(struct task_struct *task, struct rb_node **p_parent,
						struct rb_node ***p_insert) {
	struct proc_task_node my_node = {.task = task};
	struct rb_node *node;

	node = ___search(&my_node.node, &proc_task_tree, p_parent, p_insert,
						SEARCH_EXACTLY, compare);
	
	return node? container_of(node, struct proc_task_node, node): NULL;
}

static void free_qp_symlink_node(struct rb_node *node) {
	struct qp_symlink_node *qp_symlink_node =
				node? container_of(node, struct qp_symlink_node, node): NULL;
	char symlink_name[128];
	
	if(!qp_symlink_node)
		return;
	
	sprintf(symlink_name, "qpn_%d_%d_%d", current->tgid, qp_symlink_node->vqpn, qp_symlink_node->qp_num);
	remove_proc_entry(symlink_name, qp_symlink_node->parent);
	kfree(qp_symlink_node);
}

static struct qp_symlink_node *search_qp_symlink(u32 qp_num, struct proc_task_node *task_node,
						struct rb_node **p_parent, struct rb_node ***p_insert) {
	struct qp_symlink_node my_node = {.qp_num = qp_num};
	struct rb_node *node;

	node = ___search(&my_node.node, &task_node->qp_pause_symlink_tree, p_parent, p_insert,
						SEARCH_EXACTLY, qp_symlink_compare);
	
	return node? container_of(node, struct qp_symlink_node, node): NULL;
}

static int register_qp_symlink(struct proc_dir_entry *dir_parent, u32 vqpn, u32 qp_num) {
	struct proc_task_node *task_node;
	struct qp_symlink_node *symlink_node;
	struct rb_node *parent, **insert;

	write_lock(&proc_task_tree.rwlock);
	task_node = search(current, NULL, NULL);
	if(!task_node) {
		write_unlock(&proc_task_tree.rwlock);
		return -ENOENT;
	}

	write_lock(&task_node->qp_pause_symlink_tree.rwlock);
	symlink_node = search_qp_symlink(qp_num, task_node, &parent, &insert);
	if(symlink_node) {
		write_unlock(&task_node->qp_pause_symlink_tree.rwlock);
		write_unlock(&proc_task_tree.rwlock);
		return -EEXIST;
	}

	symlink_node = kzalloc(sizeof(*symlink_node), GFP_KERNEL);
	if(!symlink_node) {
		write_unlock(&task_node->qp_pause_symlink_tree.rwlock);
		write_unlock(&proc_task_tree.rwlock);
		return -ENOMEM;
	}

	symlink_node->vqpn = vqpn;
	symlink_node->qp_num = qp_num;
	symlink_node->parent = dir_parent;
	rbtree_add_node(&symlink_node->node, parent, insert,
				&task_node->qp_pause_symlink_tree);

	write_unlock(&task_node->qp_pause_symlink_tree.rwlock);
	write_unlock(&proc_task_tree.rwlock);

	return 0;
}

void unregister_qp_symlink(u32 qp_num) {
	struct proc_task_node *task_node;
	struct qp_symlink_node *symlink_node;

	write_lock(&proc_task_tree.rwlock);
	task_node = search(current, NULL, NULL);
	if(!task_node) {
		write_unlock(&proc_task_tree.rwlock);
		return;
	}

	write_lock(&task_node->qp_pause_symlink_tree.rwlock);
	symlink_node = search_qp_symlink(qp_num, task_node, NULL, NULL);
	if(symlink_node) {
		write_unlock(&task_node->qp_pause_symlink_tree.rwlock);
		write_unlock(&proc_task_tree.rwlock);
		return;
	}

	rbtree_rm_node(&symlink_node->node, &task_node->qp_pause_symlink_tree);
	write_unlock(&task_node->qp_pause_symlink_tree.rwlock);
	write_unlock(&proc_task_tree.rwlock);
}

static int __register_framework_process_channel(struct proc_task_node *task_node, struct proc_dir_entry *parent,
										struct proc_dir_entry *uwrite_parent);
static int __register_framework_partner_buf(struct proc_task_node *task_node, struct proc_dir_entry *parent,
										struct proc_dir_entry *uwrite_parent);

#define register_footprint_info_seq(res_type, res, info_name, print_what)					\
static void *seq_##res##_##info_name##_start(struct seq_file *m, loff_t *pos) {				\
	if(*pos == 0)																			\
		return m;																			\
	return NULL;																			\
}																							\
																							\
static void *seq_##res##_##info_name##_next(struct seq_file *m, void *v, loff_t *pos) {		\
	++(*pos);																				\
	return NULL;																			\
}																							\
																							\
static void seq_##res##_##info_name##_stop(struct seq_file *m, void *v) {					\
	return;																			\
}																							\
																							\
static int seq_##res##_##info_name##_show(struct seq_file *m, void *v) {					\
	res_type *res = m->private;																\
	seq_printf(m, "%s", print_what);														\
	return 0;																				\
}																							\
																							\
static struct seq_operations seq_##res##_##info_name##_info_ops = {							\
	.start								= seq_##res##_##info_name##_start,					\
	.next								= seq_##res##_##info_name##_next,					\
	.stop								= seq_##res##_##info_name##_stop,					\
	.show								= seq_##res##_##info_name##_show,					\
};																							\
																							\
static int res##_##info_name##_info_open(struct inode *inode, struct file *filep) {			\
	struct seq_file *sf;																	\
	int err;																				\
																							\
	err = seq_open(filep, &seq_##res##_##info_name##_info_ops);								\
	if(err)																					\
		return err;																			\
																							\
	sf = filep->private_data;																\
	sf->private = PDE_DATA(inode);															\
	return 0;																				\
}																							\
																							\
static struct proc_ops res##_##info_name##_info_ops = {										\
	.proc_open					= res##_##info_name##_info_open,							\
	.proc_read					= seq_read,													\
	.proc_lseek					= seq_lseek,												\
	.proc_release				= seq_release,												\
};																							\
																							\
static inline int __register_##res##_##info_name##_to_footprint(res_type *res,				\
								struct proc_dir_entry *parent) {							\
	struct proc_dir_entry *proc_ent;														\
	proc_ent = proc_create_data(#info_name, FP_ACCESS_MODE, parent,							\
					&res##_##info_name##_info_ops, res);									\
	if(!proc_ent)																			\
		return -ENOENT;																		\
																							\
	return 0;																				\
}

#define register_footprint_info_raw(res_type, res, info_name, print_addr, print_size)		\
static ssize_t res##_##info_name##_info_read(struct file *filep, char __user *buf,			\
						size_t size, loff_t *loff) {										\
	res_type *res = filep->private_data;													\
																							\
	if(size != print_size)																	\
		return -EINVAL;																		\
																							\
	return copy_to_user(buf, print_addr, print_size)? : size;								\
}																							\
																							\
static int res##_##info_name##_info_open(struct inode *inode, struct file *filep) {			\
	filep->private_data = PDE_DATA(inode);													\
	return 0;																				\
}																							\
																							\
static struct proc_ops res##_##info_name##_info_ops = {										\
	.proc_open					= res##_##info_name##_info_open,							\
	.proc_read					= res##_##info_name##_info_read,							\
};																							\
																							\
static inline int __register_##res##_##info_name##_to_footprint(res_type *res,				\
								struct proc_dir_entry *parent) {							\
	struct proc_dir_entry *proc_ent;														\
	proc_ent = proc_create_data(#info_name, FP_ACCESS_MODE, parent,							\
					&res##_##info_name##_info_ops, res);									\
	if(!proc_ent)																			\
		return -ENOENT;																		\
																							\
	return 0;																				\
}

register_footprint_info_raw(struct proc_task_node, task_node, user_pid,
					&task_node->user_pid, sizeof(pid_t));

static struct proc_task_node *register_pid_entry(struct ib_device *ibdev,
						struct task_struct *task) {
	struct proc_task_node *task_node;
	struct rb_node *parent, **insert;
	char dirname[128];

	write_lock(&proc_task_tree.rwlock);
	task_node = search(task, &parent, &insert);
	if(!task_node) {
		task_node = kzalloc(sizeof(*task_node), GFP_KERNEL);
		if(!task_node) {
			write_unlock(&proc_task_tree.rwlock);
			return ERR_PTR(-ENOMEM);
		}

		task_node->user_pid = task_tgid_nr_ns(current,
							current->nsproxy->pid_ns_for_children);

		task_node->task = task;
		sprintf(dirname, "%d", task->tgid);
		task_node->task_dir_ent = proc_mkdir_mode(dirname,
							FP_ACCESS_MODE, procfs_dir_ent);
		if(!task_node->task_dir_ent) {
			write_unlock(&proc_task_tree.rwlock);
			kfree(task_node);
			return ERR_PTR(-ENODEV);
		}

		if(__register_task_node_user_pid_to_footprint(task_node, task_node->task_dir_ent)) {
			write_unlock(&proc_task_tree.rwlock);
			proc_remove(task_node->task_dir_ent);
			kfree(task_node);
			return ERR_PTR(-ENOENT);
		}

		task_node->task_dir_uwrite_ent = proc_mkdir_mode(dirname,
							FP_UWRITE_MODE, procfs_dir_uwrite_ent);
		if(!task_node->task_dir_uwrite_ent) {
			write_unlock(&proc_task_tree.rwlock);
			proc_remove(task_node->task_dir_ent);
			kfree(task_node);
			return ERR_PTR(-ENODEV);
		}

		if(__register_framework_process_channel(task_node, task_node->task_dir_ent,
								task_node->task_dir_uwrite_ent)) {
			write_unlock(&proc_task_tree.rwlock);
			proc_remove(task_node->task_dir_uwrite_ent);
			proc_remove(task_node->task_dir_ent);
			kfree(task_node);
			return ERR_PTR(-ENOENT);
		}

		if(__register_framework_partner_buf(task_node, task_node->task_dir_ent,
								task_node->task_dir_uwrite_ent)) {
			write_unlock(&proc_task_tree.rwlock);
			proc_remove(task_node->task_dir_uwrite_ent);
			proc_remove(task_node->task_dir_ent);
			kfree(task_node);
			return ERR_PTR(-ENOENT);
		}

		task_node->refcnt = 0;
		rbtree_add_node(&task_node->node, parent, insert, &proc_task_tree);

		task_node->qp_pause_symlink_tree.tree = RB_ROOT;
		task_node->qp_pause_symlink_tree.rwlock =
					__RW_LOCK_UNLOCKED(task_node->qp_pause_symlink_tree.rwlock);
	}

	task_node->refcnt++;

	write_unlock(&proc_task_tree.rwlock);
	return task_node;
}

static inline int uwrite_footprint_fn(struct ib_qp *qp) {
	struct proc_dir_entry *uwrite_proc_ent;
	char symlink_name[128];
	char symlink_dest[128];

	sprintf(symlink_name, "qpn_%d_%d_%d", current->tgid, qp->vqpn, qp->qp_num);
	sprintf(symlink_dest, "/proc/rdma_uwrite/%d/%d/qp_%d/", current->tgid,
						qp->cmd_fd, qp->vhandle);

	uwrite_proc_ent = proc_symlink(symlink_name, qp->device->proc_ent, symlink_dest);
	if(!uwrite_proc_ent)
		return -ENOENT;

	return register_qp_symlink(qp->device->proc_ent, qp->vqpn, qp->qp_num);
}

#define register_uwrite_footprint(res_type, res, info_name, can_write, uwrite_fn)			\
static int res##_##info_name##_uwrite_and_kern_open(struct inode *inode,					\
										struct file *filep) {								\
	filep->private_data = PDE_DATA(inode);													\
	return 0;																				\
}																							\
static ssize_t res##_##info_name##_uwrite_and_kern_read(struct file *filep,					\
					char __user *buf, size_t size, loff_t *loff) {							\
	res_type *res = filep->private_data;													\
	int err;																				\
																							\
	if(can_write) {																			\
		wait_event_interruptible((res)->info_name##_wait_queue,								\
							!(res)->info_name##_wait_flag);									\
																							\
		if((res)->info_name##_wait_flag)													\
			return -EPIPE;																	\
	}																						\
																							\
	err = copy_to_user(buf, &res->info_name, size);											\
	return err? err: size;																	\
}																							\
																							\
static int res##_##info_name##_uwrite_and_kern_release(struct inode *inode,					\
								struct file *filep) {										\
	res_type *res = filep->private_data;													\
	if(can_write)																			\
		wake_up_interruptible(&(res)->info_name##_wait_queue);								\
	return 0;																				\
}																							\
																							\
static ssize_t res##_##info_name##_uwrite_write(struct file *filep,							\
					const char __user *buf, size_t size, loff_t *loff) {					\
	res_type *res = filep->private_data;													\
	int (*__uwrite_fn)(res_type *res);														\
	int err;																				\
																							\
	__uwrite_fn = uwrite_fn;																\
	if(size != sizeof(res->info_name))														\
		return -EINVAL;																		\
																							\
	err = copy_from_user(&res->info_name, buf, size);										\
	if(can_write) {																			\
		(res)->info_name##_wait_flag = 0;													\
		wake_up_interruptible(&(res)->info_name##_wait_queue);								\
	}																						\
																							\
	if(!err && __uwrite_fn)																	\
		err = __uwrite_fn(res);																\
	return err? err: size;																	\
}																							\
																							\
static struct proc_ops res##_##info_name##_uwrite_info_ops = {								\
	.proc_open				= res##_##info_name##_uwrite_and_kern_open,						\
	.proc_write				= (can_write)? res##_##info_name##_uwrite_write: NULL,			\
	.proc_read				= res##_##info_name##_uwrite_and_kern_read,						\
	.proc_release			= res##_##info_name##_uwrite_and_kern_release,					\
};																							\
																							\
static struct proc_ops res##_##info_name##_kern_info_ops = {								\
	.proc_open				= res##_##info_name##_uwrite_and_kern_open,						\
	.proc_read				= res##_##info_name##_uwrite_and_kern_read,						\
	.proc_write				= res##_##info_name##_uwrite_write,								\
	.proc_release			= res##_##info_name##_uwrite_and_kern_release,					\
};																							\
																							\
static int __register_##res##_##info_name##_to_uwrite_footprint(res_type *res,				\
			struct proc_dir_entry *parent, struct proc_dir_entry *uwrite_parent) {			\
	struct proc_dir_entry *uwrite_proc_ent;													\
	struct proc_dir_entry *proc_ent;														\
																							\
	init_waitqueue_head(&(res)->info_name##_wait_queue);									\
	(res)->info_name##_wait_flag = 1;														\
																							\
	uwrite_proc_ent = proc_create_data(#info_name, (can_write)?								\
						(S_IRUGO | S_IWUGO | S_IXUGO): 00444,								\
					uwrite_parent, &res##_##info_name##_uwrite_info_ops, res);				\
	if(!uwrite_proc_ent)																	\
		return -ENOENT;																		\
																							\
	proc_ent = proc_create_data(#info_name, FP_ACCESS_MODE, parent,							\
					&res##_##info_name##_kern_info_ops, res);								\
	if(!proc_ent) {																			\
		proc_remove(uwrite_proc_ent);														\
		return -ENOENT;																		\
	}																						\
																							\
	return 0;																				\
}

register_uwrite_footprint(struct ib_uverbs_file, ufile, ctx_resp, false, NULL);
register_uwrite_footprint(struct ib_uverbs_file, ufile, ctx_uaddr, true, NULL);
register_uwrite_footprint(struct ib_uverbs_file, ufile, nc_uar, true, NULL);

inline int install_ctx_resp(struct ib_uverbs_file *ufile,
				char __user *buf, size_t size) {
	return copy_from_user(&ufile->ctx_resp, buf, size)? :
					__register_ufile_ctx_resp_to_uwrite_footprint(ufile,
					ufile->ufile_proc_ent, ufile->ufile_proc_uwrite_ent);
}

static int qp_pause_signal_open(struct inode *inode, struct file *filep) {
	filep->private_data = PDE_DATA(inode);
	return 0;
}

static ssize_t qp_pause_signal_read(struct file *filep, char __user *buf, size_t size, loff_t *loff) {
	struct ib_qp *qp = filep->private_data;

	if(size)
		return -EINVAL;
	
	wait_event_interruptible(qp->signal_pause_wait_queue, qp->signal_pause_wait_flag);

	return 0;
}

static ssize_t qp_pause_signal_write(struct file *filep, const char __user *buf, size_t size, loff_t *loff) {
	struct ib_qp *qp = filep->private_data;
	char kbuf[1024];
	int err;

	err = kstrtoint_from_user(buf, size, 10, &qp->signal_pause_wait_flag);
	if(err)
		return err;

	if(qp->signal_pause_wait_flag) {
		qp->signal_pause_wait_flag = 1;
		wake_up_interruptible(&qp->signal_pause_wait_queue);
	}

	return size;
}

static int qp_pause_signal_release(struct inode *inode, struct file *filep) {
	struct ib_qp *qp = filep->private_data;
	wake_up_interruptible(&qp->signal_pause_wait_queue);
	return 0;
}

static struct proc_ops qp_pause_signal_ops = {
	.proc_open					= qp_pause_signal_open,
	.proc_read					= qp_pause_signal_read,
	.proc_write					= qp_pause_signal_write,
	.proc_release				= qp_pause_signal_release,
};

static int __register_qp_pause_signal(struct ib_qp *qp, struct proc_dir_entry *uwrite_parent) {
	struct proc_dir_entry *uwrite_proc_ent;

	init_waitqueue_head(&qp->signal_pause_wait_queue);
	qp->signal_pause_wait_flag = 1;

	uwrite_proc_ent = proc_create_data("pause_signal", 00644, uwrite_parent, &qp_pause_signal_ops, qp);
	if(!uwrite_proc_ent)
		return -ENOENT;

	return 0;
}

static int proc_frm_fifo_open(struct inode *inode, struct file *filep) {
	filep->private_data = PDE_DATA(inode);
	return 0;
}

static ssize_t to_proc_write(struct file *filep, const char __user *buf, size_t size, loff_t *loff) {
	struct proc_task_node *task_node = filep->private_data;
	int err;

	if(size != sizeof(task_node->frm_to_proc))
		return -EINVAL;
	
	wait_event_interruptible(task_node->frm_to_proc_wait_queue,
					task_node->frm_to_proc == -1 &&
					((err = copy_from_user(&task_node->frm_to_proc, buf, size)) || true));

	if(err)
		return err;

	task_node->frm_to_proc_wait_flag = 0;
	wake_up_interruptible(&task_node->frm_to_proc_wait_queue);

	return size;
}

static ssize_t to_frm_write(struct file *filep, const char __user *buf, size_t size, loff_t *loff) {
	struct proc_task_node *task_node = filep->private_data;
	int err;

	if(size != sizeof(task_node->proc_to_frm))
		return -EINVAL;
	
	wait_event_interruptible(task_node->proc_to_frm_wait_queue,
						task_node->proc_to_frm == -1 &&
						((err = copy_from_user(&task_node->proc_to_frm, buf, size)) || true));

	if(err) {
		return err;
	}

	task_node->proc_to_frm_wait_flag = 0;
	wake_up_interruptible(&task_node->proc_to_frm_wait_queue);

	return size;
}

static ssize_t from_proc_read(struct file *filep, char __user *buf, size_t size, loff_t *loff) {
	struct proc_task_node *task_node = filep->private_data;
	int err;

	if(size != sizeof(task_node->proc_to_frm))
		return -EINVAL;
	
	wait_event_interruptible(task_node->proc_to_frm_wait_queue,
				(!task_node->proc_to_frm_wait_flag) && (task_node->proc_to_frm_wait_flag = 1));

	if(task_node->proc_to_frm == -1)
		return -EPIPE;
	
	err = copy_to_user(buf, &task_node->proc_to_frm, size);
	if(err) {
		return err;
	}

	task_node->proc_to_frm = -1;
	wake_up_interruptible(&task_node->proc_to_frm_wait_queue);

	return size;
}

static ssize_t from_frm_read(struct file *filep, char __user *buf, size_t size, loff_t *loff) {
	struct proc_task_node *task_node = filep->private_data;
	int err;

	if(size != sizeof(task_node->frm_to_proc))
		return -EINVAL;
	
	wait_event_interruptible(task_node->frm_to_proc_wait_queue,
				(!task_node->frm_to_proc_wait_flag) && (task_node->frm_to_proc_wait_flag = 1));

	if(task_node->frm_to_proc == -1)
		return -EPIPE;

	err = copy_to_user(buf, &task_node->frm_to_proc, size);
	if(err)
		return err;
	
	task_node->frm_to_proc = -1;
	wake_up_interruptible(&task_node->frm_to_proc_wait_queue);

	return size;
}

static int to_frm_release(struct inode *inode, struct file *filep) {
	return 0;
}

static int to_proc_release(struct inode *inode, struct file *filep) {
	return 0;
}

static struct proc_ops to_proc_ops = {
	.proc_open					= proc_frm_fifo_open,
	.proc_read					= from_proc_read,
	.proc_write					= to_proc_write,
	.proc_release				= to_proc_release,
};

static struct proc_ops to_frm_ops = {
	.proc_open					= proc_frm_fifo_open,
	.proc_read					= from_frm_read,
	.proc_write					= to_frm_write,
	.proc_release				= to_frm_release,
};

static int __register_framework_process_channel(struct proc_task_node *task_node, struct proc_dir_entry *parent,
										struct proc_dir_entry *uwrite_parent) {
	struct proc_dir_entry *proc_ent = NULL;
	struct proc_dir_entry *uwrite_proc_ent = NULL;

	init_waitqueue_head(&task_node->proc_to_frm_wait_queue);
	init_waitqueue_head(&task_node->frm_to_proc_wait_queue);
	task_node->proc_to_frm_wait_flag = 1;
	task_node->frm_to_proc_wait_flag = 1;

	task_node->proc_to_frm = -1;
	task_node->frm_to_proc = -1;

	proc_ent = proc_create_data("to_proc", 00600, parent, &to_proc_ops, task_node);
	uwrite_proc_ent = proc_create_data("to_frm", S_IRUGO | S_IWUGO | S_IXUGO,
						uwrite_parent, &to_frm_ops, task_node);
	if(!proc_ent || !uwrite_proc_ent) {
		if(proc_ent)
			proc_remove(proc_ent);
		return -ENOENT;
	}

	return 0;
}

static int partner_buf_open(struct inode *inode, struct file *filep) {
	filep->private_data = PDE_DATA(inode);
	return 0;
}

static ssize_t partner_buf_write(struct file *filep, const char __user *buf, size_t size, loff_t *loff) {
	struct proc_task_node *task_node = filep->private_data;
	int err;

	task_node->partner_buf = kzalloc(size, GFP_KERNEL);
	if(!task_node->partner_buf)
		return -ENOMEM;
	
	err = copy_from_user(task_node->partner_buf, buf, size);
	if(err) {
		kfree(task_node->partner_buf);
		return err;
	}

	task_node->partner_buf_size = size;
	return size;
}

static ssize_t partner_buf_read(struct file *filep, char __user *buf, size_t size, loff_t *loff) {
	struct proc_task_node *task_node = filep->private_data;
	int err;
	ssize_t read_size = (task_node->partner_buf_size - *loff) > size?
					size: (task_node->partner_buf_size - *loff);
	
	err = copy_to_user(buf, task_node->partner_buf + *loff, read_size);
	if(err)
		return err;

	*loff += read_size;
	return read_size;
}

static int partner_buf_release(struct inode *inode, struct file *filep) {
	struct proc_task_node *task_node = filep->private_data;

	if(task_node->partner_buf) {
		kfree(task_node->partner_buf);
		task_node->partner_buf = NULL;
		task_node->partner_buf_size = 0;
	}

	return 0;
}

static struct proc_ops partner_buf_kern_ops = {
	.proc_open					= partner_buf_open,
	.proc_write					= partner_buf_write,
};

static struct proc_ops partner_buf_user_ops = {
	.proc_open					= partner_buf_open,
	.proc_read					= partner_buf_read,
	.proc_release				= partner_buf_release,
};

static int __register_framework_partner_buf(struct proc_task_node *task_node, struct proc_dir_entry *parent,
										struct proc_dir_entry *uwrite_parent) {
	struct proc_dir_entry *proc_ent = NULL;
	struct proc_dir_entry *uwrite_proc_ent = NULL;
	struct proc_dir_entry *proc_ent_frm = NULL;
	struct proc_dir_entry *uwrite_proc_ent_frm = NULL;

	task_node->partner_buf = NULL;
	task_node->partner_buf_size = 0;

	proc_ent = proc_create_data("partner_buf", 00600, parent, &partner_buf_kern_ops, task_node);
	uwrite_proc_ent = proc_create_data("partner_buf", S_IRUGO | S_IWUGO | S_IXUGO,
						uwrite_parent, &partner_buf_user_ops, task_node);
	if(!proc_ent || !uwrite_proc_ent) {
		if(proc_ent)
			proc_remove(proc_ent);
		return -ENOENT;
	}

	proc_ent_frm = proc_create_data("frm_buf", 00600, parent, &partner_buf_user_ops, task_node);
	uwrite_proc_ent_frm = proc_create_data("frm_buf", S_IRUGO | S_IWUGO | S_IXUGO,
						uwrite_parent, &partner_buf_kern_ops, task_node);
	if(!proc_ent_frm || !uwrite_proc_ent_frm) {
		proc_remove(proc_ent);
		proc_remove(uwrite_proc_ent);
		if(proc_ent_frm)
			proc_remove(proc_ent_frm);
		return -ENOENT;
	}

	return 0;
}

register_footprint_info_seq(struct ib_uverbs_file, ufile, cdev,
					dev_name(&ufile->device->dev));
register_uwrite_footprint(struct ib_uverbs_file, ufile, gid_table, false, NULL);

static int init_rdma_dev_fd_entry(struct ib_uverbs_file *ufile,
						struct proc_dir_entry *fd_entry) {
	return __register_ufile_cdev_to_footprint(ufile, fd_entry);
}

register_footprint_info_raw(struct ib_uverbs_file, ufile, async_fd,
					&ufile->default_async_file->async_fd, sizeof(int));

int register_async_fd(struct ib_uverbs_file *ufile, int async_fd) {
	struct ib_uverbs_async_event_file *event_file =
					ufile->default_async_file;

	event_file->async_fd = async_fd;
	return __register_ufile_async_fd_to_footprint(ufile, ufile->ufile_proc_ent);
}

#define def_res_footprint_func(res_type, res, parent_type, parent, init_fn, dump_fn)		\
static int res##_ctx_open(struct inode *inode, struct file *filep) {						\
	filep->private_data = PDE_DATA(inode);													\
	return 0;																				\
}																							\
																							\
static struct proc_ops res##_ctx_ops = {													\
	.proc_open				= res##_ctx_open,												\
	.proc_read				= dump_fn,														\
};																							\
																							\
int register_##res##_to_footprint(res_type *res, parent_type *parent, int vhandle) {		\
	struct proc_dir_entry *res##_ent;														\
	struct proc_dir_entry *dump_ent;														\
	char filename[128];																		\
	int err;																				\
																							\
	if(strcmp(#res, "ufile")) {																\
		sprintf(filename, #res "_%d", vhandle);												\
		res##_ent = proc_mkdir_mode(filename, FP_ACCESS_MODE, parent->parent##_proc_ent);	\
		if(!res##_ent)																		\
			return -ENODEV;																	\
																							\
		res->res##_proc_ent = res##_ent;													\
	}																						\
																							\
	if(res##_ctx_ops.proc_read) {															\
		dump_ent = proc_create_data(#res "_ctx", FP_ACCESS_MODE,							\
					res->res##_proc_ent, &res##_ctx_ops, res);								\
		if(!dump_ent) {																		\
			proc_remove(res##_ent);															\
			res->res##_proc_ent = NULL;														\
			return err;																		\
		}																					\
	}																						\
																							\
	err = init_fn(res, parent);																\
	if(err) {																				\
		if(res##_ctx_ops.proc_read)															\
			proc_remove(dump_ent);															\
		proc_remove(res##_ent);																\
		res->res##_proc_ent = NULL;															\
		return err;																			\
	}																						\
																							\
	return 0;																				\
}																							\
																							\
void deregister_##res##_from_footprint(res_type *res) {										\
	if(!res->res##_proc_ent)																\
		return;																				\
																							\
	proc_remove(res->res##_proc_ent);														\
	res->res##_proc_ent = NULL;																\
}

#define def_res_uwrite_footprint_func(res_type, res, parent_type, parent, init_fn)			\
int register_##res##_to_uwrite_footprint(													\
				res_type *res, parent_type *parent, int vhandle) {							\
	struct proc_dir_entry *res##_uwrite_ent;												\
	char filename[128];																		\
	int err;																				\
																							\
	sprintf(filename, #res "_%d", vhandle);													\
	res##_uwrite_ent = proc_mkdir_mode(filename, FP_UWRITE_MODE,							\
					parent->parent##_proc_uwrite_ent);										\
	if(!res##_uwrite_ent)																	\
		return -ENODEV;																		\
																							\
	res->res##_proc_uwrite_ent = res##_uwrite_ent;											\
																							\
	err = init_fn(res, parent);																\
	if(err) {																				\
		proc_remove(res##_uwrite_ent);														\
		res->res##_proc_uwrite_ent = NULL;													\
		return err;																			\
	}																						\
																							\
	return 0;																				\
}																							\
																							\
void deregister_##res##_from_uwrite_footprint(res_type *res) {								\
	if(!res->res##_proc_uwrite_ent)															\
		return;																				\
																							\
	proc_remove(res->res##_proc_uwrite_ent);												\
	res->res##_proc_uwrite_ent = NULL;														\
}

static inline int proc_pd_init_fn(struct ib_pd *pd, struct ib_uverbs_file *ufile) {
	return 0;
}

register_footprint_info_raw(struct ib_cq, cq, cq_size, &cq->cqe, sizeof(cq->cqe));
register_footprint_info_raw(struct ib_cq, cq, comp_fd, &cq->comp_fd, sizeof(cq->comp_fd));

static inline int proc_cq_init_fn(struct ib_cq *cq, struct ib_uverbs_file *ufile) {
	return __register_cq_cq_size_to_footprint(cq, cq->cq_proc_ent) ||
			__register_cq_comp_fd_to_footprint(cq, cq->cq_proc_ent);
}

static int cq_meta_uaddr_fn(struct ib_cq *cq) {
	cq->uobject->uevent.uobject.user_handle = cq->meta_uaddr;
	return 0;
}

register_uwrite_footprint(struct ib_cq, cq, meta_uaddr, true, cq_meta_uaddr_fn);
register_uwrite_footprint(struct ib_cq, cq, buf_addr, true, NULL);
register_uwrite_footprint(struct ib_cq, cq, db_addr, true, NULL);

static inline int proc_uwrite_cq_init_fn(struct ib_cq *cq, struct ib_uverbs_file *ufile) {
	return __register_cq_meta_uaddr_to_uwrite_footprint(cq, cq->cq_proc_ent,
							cq->cq_proc_uwrite_ent) ||
			__register_cq_buf_addr_to_uwrite_footprint(cq, cq->cq_proc_ent,
							cq->cq_proc_uwrite_ent) ||
			__register_cq_db_addr_to_uwrite_footprint(cq, cq->cq_proc_ent,
							cq->cq_proc_uwrite_ent);
}

register_uwrite_footprint(struct ib_qp, qp, meta_uaddr, true, NULL);
register_uwrite_footprint(struct ib_qp, qp, cur_qp_state, false, NULL);
register_uwrite_footprint(struct ib_qp, qp, init_attr, true, NULL);
register_uwrite_footprint(struct ib_qp, qp, attr_0, true, NULL);
register_uwrite_footprint(struct ib_qp, qp, attr_1, true, NULL);
register_uwrite_footprint(struct ib_qp, qp, attr_2, true, NULL);
register_uwrite_footprint(struct ib_qp, qp, mask_0, true, NULL);
register_uwrite_footprint(struct ib_qp, qp, mask_1, true, NULL);
register_uwrite_footprint(struct ib_qp, qp, mask_2, true, NULL);
register_uwrite_footprint(struct ib_qp, qp, send_cur_post, true, NULL);
register_uwrite_footprint(struct ib_qp, qp, recv_head, true, NULL);
register_uwrite_footprint(struct ib_qp, qp, recv_tail, true, NULL);
register_uwrite_footprint(struct ib_qp, qp, bf_uar_addr, true, NULL);
register_uwrite_footprint(struct ib_qp, qp, signal_fd, true, NULL);
register_uwrite_footprint(struct ib_qp, qp, rc_dest_pgid, true, NULL);
register_uwrite_footprint(struct ib_qp, qp, dest_pqpn, true, NULL);
register_uwrite_footprint(struct ib_qp, qp, send_cq_handle, true, NULL);
register_uwrite_footprint(struct ib_qp, qp, recv_cq_handle, true, NULL);
register_uwrite_footprint(struct ib_qp, qp, vqpn, true, uwrite_footprint_fn);
register_uwrite_footprint(struct ib_qp, qp, buf_addr, true, NULL);
register_uwrite_footprint(struct ib_qp, qp, db_addr, true, NULL);

static inline int proc_uwrite_qp_init_fn(struct ib_qp *qp, struct ib_uverbs_file *ufile) {
	return __register_qp_meta_uaddr_to_uwrite_footprint(qp, qp->qp_proc_ent,
							qp->qp_proc_uwrite_ent) ||
			__register_qp_cur_qp_state_to_uwrite_footprint(qp, qp->qp_proc_ent,
							qp->qp_proc_uwrite_ent) ||
			__register_qp_send_cur_post_to_uwrite_footprint(qp, qp->qp_proc_ent,
							qp->qp_proc_uwrite_ent) ||
			__register_qp_recv_head_to_uwrite_footprint(qp, qp->qp_proc_ent,
							qp->qp_proc_uwrite_ent) ||
			__register_qp_recv_tail_to_uwrite_footprint(qp, qp->qp_proc_ent,
							qp->qp_proc_uwrite_ent) ||
			__register_qp_send_cq_handle_to_uwrite_footprint(qp, qp->qp_proc_ent, qp->qp_proc_uwrite_ent) ||
			__register_qp_recv_cq_handle_to_uwrite_footprint(qp, qp->qp_proc_ent, qp->qp_proc_uwrite_ent) ||
			__register_qp_rc_dest_pgid_to_uwrite_footprint(qp, qp->qp_proc_ent, qp->qp_proc_uwrite_ent) ||
			__register_qp_dest_pqpn_to_uwrite_footprint(qp, qp->qp_proc_ent, qp->qp_proc_uwrite_ent) ||
			__register_qp_init_attr_to_uwrite_footprint(qp, qp->qp_proc_ent,
							qp->qp_proc_uwrite_ent) ||
			__register_qp_attr_0_to_uwrite_footprint(qp, qp->qp_proc_ent,
							qp->qp_proc_uwrite_ent) ||
			__register_qp_attr_1_to_uwrite_footprint(qp, qp->qp_proc_ent,
							qp->qp_proc_uwrite_ent) ||
			__register_qp_attr_2_to_uwrite_footprint(qp, qp->qp_proc_ent,
							qp->qp_proc_uwrite_ent) ||
			__register_qp_mask_0_to_uwrite_footprint(qp, qp->qp_proc_ent,
							qp->qp_proc_uwrite_ent) ||
			__register_qp_mask_1_to_uwrite_footprint(qp, qp->qp_proc_ent,
							qp->qp_proc_uwrite_ent) ||
			__register_qp_mask_2_to_uwrite_footprint(qp, qp->qp_proc_ent,
							qp->qp_proc_uwrite_ent) ||
			__register_qp_bf_uar_addr_to_uwrite_footprint(qp, qp->qp_proc_ent,
							qp->qp_proc_uwrite_ent) ||
			__register_qp_vqpn_to_uwrite_footprint(qp, qp->qp_proc_ent,
							qp->qp_proc_uwrite_ent) ||
			__register_qp_pause_signal(qp, qp->qp_proc_uwrite_ent) ||
			__register_qp_signal_fd_to_uwrite_footprint(qp, qp->qp_proc_ent,
							qp->qp_proc_uwrite_ent) ||
			__register_qp_buf_addr_to_uwrite_footprint(qp, qp->qp_proc_ent,
							qp->qp_proc_uwrite_ent) ||
			__register_qp_db_addr_to_uwrite_footprint(qp, qp->qp_proc_ent,
							qp->qp_proc_uwrite_ent);
}

register_footprint_info_raw(struct ib_mr, mr, iova, &mr->iova, sizeof(u64));
register_footprint_info_raw(struct ib_mr, mr, length, &mr->length, sizeof(u64));
register_footprint_info_raw(struct ib_mr, mr, access_flags,
						&mr->access_flags, sizeof(int));

register_uwrite_footprint(struct ib_mr, mr, vlkey, true, NULL);
register_uwrite_footprint(struct ib_mr, mr, vrkey, true, NULL);

static inline int proc_mr_init_fn(struct ib_mr *mr, struct ib_pd *pd) {
	return __register_mr_iova_to_footprint(mr, mr->mr_proc_ent) ||
			__register_mr_length_to_footprint(mr, mr->mr_proc_ent) ||
			__register_mr_access_flags_to_footprint(mr, mr->mr_proc_ent);
}

static inline int proc_uwrite_mr_init_fn(struct ib_mr *mr, struct ib_uverbs_file *ufile) {
	return __register_mr_vlkey_to_uwrite_footprint(mr, mr->mr_proc_ent,
								mr->mr_proc_uwrite_ent) ||
			__register_mr_vrkey_to_uwrite_footprint(mr, mr->mr_proc_ent,
								mr->mr_proc_uwrite_ent);
}

register_footprint_info_raw(struct ib_qp, qp, qp_state, &qp->cur_qp_state,
					sizeof(qp->cur_qp_state));
register_footprint_info_raw(struct ib_qp, qp, usr_idx, &qp->usr_idx,
					sizeof(qp->usr_idx));
register_footprint_info_raw(struct ib_qp, qp, rc_dest_gid, &qp->rc_dest_gid,
					sizeof(qp->rc_dest_gid));

static inline int proc_qp_init_fn(struct ib_qp *qp, struct ib_pd *pd) {
	qp->cur_qp_state = IB_QPS_RESET;
	return __register_qp_qp_state_to_footprint(qp, qp->qp_proc_ent) ||
			__register_qp_usr_idx_to_footprint(qp, qp->qp_proc_ent) ||
			__register_qp_rc_dest_gid_to_footprint(qp, qp->qp_proc_ent);
}

static ssize_t dump_qp_fn(struct file *filep, char __user *buf, size_t size, loff_t *loff) {
	struct char_64 {
		__aligned_u64						m[8];
	};
	struct char_144 {
		uint32_t							m[36];
	};
	struct ibv_resume_qp_param {
		int									pd_vhandle;
		int									qp_vhandle;
		int									send_cq_vhandle;
		int									recv_cq_vhandle;
		enum ib_qp_state					qp_state;
		struct char_64						init_attr;
		struct char_144						modify_qp_attr[3];
		int									modify_qp_mask[3];
		__aligned_u64						meta_uaddr;
		uint32_t							vqpn;
		__aligned_u64						buf_addr;
		__aligned_u64						db_addr;
		uint32_t							send_cur_post;
		uint32_t							recv_head;
		uint32_t							recv_tail;
		int32_t								usr_idx;
	} param;
	struct ib_qp *qp = filep->private_data;

	if(size != sizeof(param)) {
		return -EINVAL;
	}

	param.qp_state					= qp->cur_qp_state;
	memcpy(&param.init_attr, &qp->init_attr, sizeof(param.init_attr));
	memcpy(&param.modify_qp_attr[0], &qp->attr_0, sizeof(char_144));
	memcpy(&param.modify_qp_attr[1], &qp->attr_1, sizeof(char_144));
	memcpy(&param.modify_qp_attr[2], &qp->attr_2, sizeof(char_144));
	param.modify_qp_mask[0]			= qp->mask_0;
	param.modify_qp_mask[1]			= qp->mask_1;
	param.modify_qp_mask[2]			= qp->mask_2;
	param.meta_uaddr				= qp->meta_uaddr;
	param.vqpn						= qp->vqpn;
	param.buf_addr					= qp->buf_addr;
	param.db_addr					= qp->db_addr;
	param.usr_idx					= qp->usr_idx;

	return copy_to_user(buf, &param, size)? : size;
}

register_uwrite_footprint(struct ib_srq, srq, meta_uaddr, true, NULL);
register_uwrite_footprint(struct ib_srq, srq, buf_addr, true, NULL);
register_uwrite_footprint(struct ib_srq, srq, db_addr, true, NULL);
register_uwrite_footprint(struct ib_srq, srq, srq_init_attr, true, NULL);

static inline int proc_srq_init_fn(struct ib_srq *srq, struct ib_pd *pd) {
	return 0;
}

static inline int proc_uwrite_srq_init_fn(struct ib_srq *srq, struct ib_uverbs_file *ufile) {
	return __register_srq_meta_uaddr_to_uwrite_footprint(srq, srq->srq_proc_ent,
										srq->srq_proc_uwrite_ent) ||
			__register_srq_buf_addr_to_uwrite_footprint(srq, srq->srq_proc_ent,
										srq->srq_proc_uwrite_ent) ||
			__register_srq_db_addr_to_uwrite_footprint(srq, srq->srq_proc_ent,
										srq->srq_proc_uwrite_ent) ||
			__register_srq_srq_init_attr_to_uwrite_footprint(srq, srq->srq_proc_ent,
										srq->srq_proc_uwrite_ent);
}

static ssize_t dump_srq_fn(struct file *filep, char __user *buf, size_t size, loff_t *loff) {
	struct char_24 {
		uint64_t					m[3];
	};
	struct ibv_resume_srq_param {
		char_24					srq_init_attr;
		__aligned_u64			meta_uaddr;
		__aligned_u64			buf_addr;
		__aligned_u64			db_addr;
		int				pd_vhandle;
		int				vhandle;
	} param;
	struct ib_srq *srq = filep->private_data;

	if(size != sizeof(param))
		return -EINVAL;

	memcpy(&param.srq_init_attr, &srq->srq_init_attr, sizeof(srq->srq_init_attr));
	param.meta_uaddr	= srq->meta_uaddr;
	param.buf_addr		= srq->buf_addr;
	param.db_addr		= srq->db_addr;

	return copy_to_user(buf, &param, size)? : size;
}

static inline int proc_comp_channel_init_fn(struct ib_uverbs_completion_event_file *uverbs_completion_event_file,
							struct ib_uverbs_file *ufile) {
	return 0;
}

def_res_footprint_func(struct ib_pd, pd, struct ib_uverbs_file, ufile, proc_pd_init_fn, NULL);
def_res_footprint_func(struct ib_cq, cq, struct ib_uverbs_file, ufile, proc_cq_init_fn, NULL);
def_res_footprint_func(struct ib_mr, mr, struct ib_pd, pd, proc_mr_init_fn, NULL);
def_res_footprint_func(struct ib_qp, qp, struct ib_pd, pd, proc_qp_init_fn, dump_qp_fn);
def_res_footprint_func(struct ib_srq, srq, struct ib_pd, pd, proc_srq_init_fn, dump_srq_fn);
def_res_footprint_func(struct ib_uverbs_completion_event_file, uverbs_completion_event_file,
							struct ib_uverbs_file, ufile, proc_comp_channel_init_fn, NULL);
def_res_uwrite_footprint_func(struct ib_cq, cq, struct ib_uverbs_file, ufile, proc_uwrite_cq_init_fn);
def_res_uwrite_footprint_func(struct ib_qp, qp, struct ib_uverbs_file, ufile, proc_uwrite_qp_init_fn);
def_res_uwrite_footprint_func(struct ib_mr, mr, struct ib_uverbs_file, ufile, proc_uwrite_mr_init_fn);
def_res_uwrite_footprint_func(struct ib_srq, srq, struct ib_uverbs_file, ufile, proc_uwrite_srq_init_fn);

int register_rdma_dev_fd_entry(int cmd_fd,
						struct ib_uverbs_file *ufile) {
	struct proc_task_node *task_node;
	struct proc_dir_entry *fd_entry;
	struct proc_dir_entry *fd_uwrite_entry;
	struct ib_uverbs_gid_entry entries[256];
	ssize_t size;
	char dirname[128];
	int err, i;

	task_node = register_pid_entry(ufile->ucontext->device, current);
	if(IS_ERR(task_node))
		return PTR_ERR(task_node);

	sprintf(dirname, "%d", cmd_fd);
	fd_entry = proc_mkdir_mode(dirname, FP_ACCESS_MODE, task_node->task_dir_ent);
	if(!fd_entry)
		return -ENODEV;
	
	fd_uwrite_entry = proc_mkdir_mode(dirname, FP_UWRITE_MODE, task_node->task_dir_uwrite_ent);
	if(!fd_uwrite_entry) {
		proc_remove(fd_entry);
		return -ENODEV;
	}
	
	err = init_rdma_dev_fd_entry(ufile, fd_entry);
	if(err) {
		proc_remove(fd_uwrite_entry);
		proc_remove(fd_entry);
		write_lock(&proc_task_tree.rwlock);
		task_node->refcnt--;
		if(!task_node->refcnt) {
			proc_remove(task_node->task_dir_uwrite_ent);
			proc_remove(task_node->task_dir_ent);
			rbtree_rm_node(&task_node->node, &proc_task_tree);
			kfree(task_node);
		}
		write_unlock(&proc_task_tree.rwlock);
		return err;
	}
	
	ufile->ufile_proc_ent = fd_entry;
	ufile->ufile_proc_uwrite_ent = fd_uwrite_entry;
	ufile->task_node = task_node;

	size = rdma_query_gid_table(ufile->ucontext->device, entries, 256);
	if(size < 0) {
		proc_remove(fd_uwrite_entry);
		proc_remove(fd_entry);
		write_lock(&proc_task_tree.rwlock);
		task_node->refcnt--;
		if(!task_node->refcnt) {
			proc_remove(task_node->task_dir_uwrite_ent);
			proc_remove(task_node->task_dir_ent);
			rbtree_rm_node(&task_node->node, &proc_task_tree);
			kfree(task_node);
		}
		write_unlock(&proc_task_tree.rwlock);
		return size;
	}

	memset(ufile->gid_table, 0, sizeof(ufile->gid_table));
	for(i = 0; i < size; i++) {
		memcpy(&ufile->gid_table[i].gid, &entries[i].gid, sizeof(entries[i].gid));
		ufile->gid_table[i].gid_index = entries[i].gid_index;
		ufile->gid_table[i].gid_type = entries[i].gid_type;
	}

	err = __register_ufile_gid_table_to_uwrite_footprint(ufile,
					ufile->ufile_proc_ent, ufile->ufile_proc_uwrite_ent) ||
			__register_ufile_ctx_uaddr_to_uwrite_footprint(ufile,
					ufile->ufile_proc_ent, ufile->ufile_proc_uwrite_ent) ||
			__register_ufile_nc_uar_to_uwrite_footprint(ufile,
					ufile->ufile_proc_ent, ufile->ufile_proc_uwrite_ent);
	if(err) {
		proc_remove(fd_uwrite_entry);
		proc_remove(fd_entry);
		write_lock(&proc_task_tree.rwlock);
		task_node->refcnt--;
		if(!task_node->refcnt) {
			proc_remove(task_node->task_dir_uwrite_ent);
			proc_remove(task_node->task_dir_ent);
			rbtree_rm_node(&task_node->node, &proc_task_tree);
			kfree(task_node);
		}
		write_unlock(&proc_task_tree.rwlock);
		return err;
	}

	err = register_new_ufile_mapping(ufile);
	if(err) {
		proc_remove(fd_uwrite_entry);
		proc_remove(fd_entry);
		write_lock(&proc_task_tree.rwlock);
		task_node->refcnt--;
		if(!task_node->refcnt) {
			proc_remove(task_node->task_dir_uwrite_ent);
			proc_remove(task_node->task_dir_ent);
			rbtree_rm_node(&task_node->node, &proc_task_tree);
			kfree(task_node);
		}
		write_unlock(&proc_task_tree.rwlock);
		return err;
	}

	INIT_LIST_HEAD(&ufile->remote_rkey_trans_list);
	ufile->trans_list_lock = __RW_LOCK_UNLOCKED(ufile->trans_list_lock);
	ufile->cmd_fd = cmd_fd;

	return 0;
}

void deregister_rdma_dev_fd_entry(struct ib_uverbs_file *ufile) {
	struct proc_task_node *task_node;

	if(!ufile->ufile_proc_ent || !ufile->task_node)
		return;

	deregister_new_ufile_mapping(ufile);

	proc_remove(ufile->ufile_proc_uwrite_ent);
	proc_remove(ufile->ufile_proc_ent);
	ufile->ufile_proc_uwrite_ent = NULL;
	ufile->ufile_proc_ent = NULL;

	task_node = ufile->task_node;
	ufile->task_node = NULL;
	write_lock(&proc_task_tree.rwlock);
	task_node->refcnt--;
	if(!task_node->refcnt) {
		clean_rbtree(&task_node->qp_pause_symlink_tree,
						free_qp_symlink_node);
		proc_remove(task_node->task_dir_uwrite_ent);
		proc_remove(task_node->task_dir_ent);
		rbtree_rm_node(&task_node->node, &proc_task_tree);
		kfree(task_node);
	}
	write_unlock(&proc_task_tree.rwlock);
}

static inline struct proc_dir_entry *rdma_footprint_mkdir_data(const char *name,
									umode_t mode, void *data) {
	return proc_mkdir_data(name, mode, procfs_dir_ent, data);
}

static int proc_mmap_ops_open(struct inode *inode, struct file *filep) {
	filep->private_data = PDE_DATA(inode);
	return 0;
}

static int proc_mmap_ops_mmap(struct file *filep, struct vm_area_struct *vma) {
	struct ib_device *ibdev = filep->private_data;
	return remap_vmalloc_range(vma, ibdev->qpn_dict, 0);
}

static struct proc_ops proc_mmap_ops = {
	.proc_open				= proc_mmap_ops_open,
	.proc_mmap				= proc_mmap_ops_mmap,
};

int mkdir_ibdev_sig_link(struct ib_device *ibdev) {
	struct proc_dir_entry *ibdev_proc_ent;
	struct proc_dir_entry *ibdev_uwrite_proc_ent;
	struct proc_dir_entry *proc_mmap;

	ibdev_proc_ent = rdma_footprint_mkdir_data(ibdev->name, 00400, ibdev);
	if(!ibdev_proc_ent) {
		err_info("Failed to create proc_dir for ibdev\n");
		return -ENOENT;
	}

	ibdev_uwrite_proc_ent = proc_mkdir_data(ibdev->name, S_IRUGO | S_IWUGO | S_IXUGO,
						procfs_dir_uwrite_ent, ibdev);
	if(!ibdev_uwrite_proc_ent) {
		err_info("Failed to create proc_dir for ibdev\n");
		proc_remove(ibdev_proc_ent);
		return -ENOENT;
	}

	ibdev->qpn_dict = vmalloc_user(4096 * 4096 * sizeof(uint32_t));
	if(!ibdev->qpn_dict) {
		err_info("No enough memory for qpn_dict\n");
		proc_remove(ibdev_proc_ent);
		proc_remove(ibdev_uwrite_proc_ent);
		return -ENOMEM;
	}

	proc_mmap = proc_create_data("qpn_dict", S_IRUGO,
					ibdev_uwrite_proc_ent, &proc_mmap_ops, ibdev);
	if(!proc_mmap) {
		err_info("Failed to create proc_mmap\n");
		proc_remove(ibdev_proc_ent);
		proc_remove(ibdev_uwrite_proc_ent);
		vfree(ibdev->qpn_dict);
		return -ENOENT;
	}

	ibdev->proc_ent = ibdev_proc_ent;
	ibdev->uwrite_proc_ent = ibdev_uwrite_proc_ent;
	return 0;
}

inline void rmdir_ibdev_sig_link(struct ib_device *ibdev) {
	if(ibdev->proc_ent)
		proc_remove(ibdev->proc_ent);
	ibdev->proc_ent = NULL;

	if(ibdev->uwrite_proc_ent)
		proc_remove(ibdev->uwrite_proc_ent);
	ibdev->uwrite_proc_ent = NULL;

	if(ibdev->qpn_dict)
		vfree(ibdev->qpn_dict);
	ibdev->qpn_dict = NULL;
}

int rdma_footprint_init(void) {
	int err;

	procfs_dir_ent = proc_mkdir_mode("rdma", 00400, NULL);
	if(!procfs_dir_ent) {
		err_info("Failed to create rdma directory in procfs\n");
		return -ENOENT;
	}

	procfs_dir_uwrite_ent = proc_mkdir_mode("rdma_uwrite", FP_UWRITE_MODE, NULL);
	if(!procfs_dir_uwrite_ent) {
		proc_remove(procfs_dir_ent);
		err_info("Failed to create rdma_uwrite directory in procfs\n");
		return -ENOENT;
	}

	err = init_rkey_translate_service();
	if(err) {
		proc_remove(procfs_dir_uwrite_ent);
		proc_remove(procfs_dir_ent);
		err_info("Failed to init_rkey_translate_service\n");
		return err;
	}

	return 0;
}

void rdma_footprint_exit(void) {
	exit_rkey_translate_service();
	proc_remove(procfs_dir_uwrite_ent);
	proc_remove(procfs_dir_ent);
}
