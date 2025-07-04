/*
 * Copyright (c) 2004, 2005 Topspin Communications.  All rights reserved.
 * Copyright (c) 2006, 2007 Cisco Systems, Inc.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#define _GNU_SOURCE
#include <config.h>

#include <endian.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <alloca.h>
#include <errno.h>

#include <rdma/ib_user_ioctl_cmds.h>
#include <util/symver.h>
#include <util/util.h>
#include "ibverbs.h"

static pthread_mutex_t dev_list_lock = PTHREAD_MUTEX_INITIALIZER;
static struct list_head device_list = LIST_HEAD_INIT(device_list);

LATEST_SYMVER_FUNC(ibv_get_device_list, 1_1, "IBVERBS_1.1",
		   struct ibv_device **,
		   int *num)
{
	struct ibv_device **l = NULL;
	struct verbs_device *device;
	static bool initialized;
	int num_devices;
	int i = 0;

	if (num)
		*num = 0;

	pthread_mutex_lock(&dev_list_lock);
	if (!initialized) {
		if (ibverbs_init())
			goto out;
		initialized = true;
	}

	num_devices = ibverbs_get_device_list(&device_list);
	if (num_devices < 0) {
		errno = -num_devices;
		goto out;
	}

	l = calloc(num_devices + 1, sizeof (struct ibv_device *));
	if (!l) {
		errno = ENOMEM;
		goto out;
	}

	list_for_each(&device_list, device, entry) {
		l[i] = &device->device;
		ibverbs_device_hold(l[i]);
		i++;
	}
	if (num)
		*num = num_devices;
out:
	pthread_mutex_unlock(&dev_list_lock);
	return l;
}

LATEST_SYMVER_FUNC(ibv_free_device_list, 1_1, "IBVERBS_1.1",
		   void,
		   struct ibv_device **list)
{
	int i;

	for (i = 0; list[i]; i++)
		ibverbs_device_put(list[i]);
	free(list);
}

LATEST_SYMVER_FUNC(ibv_get_device_name, 1_1, "IBVERBS_1.1",
		   const char *,
		   struct ibv_device *device)
{
	return device->name;
}

LATEST_SYMVER_FUNC(ibv_get_device_guid, 1_1, "IBVERBS_1.1",
		   __be64,
		   struct ibv_device *device)
{
	struct verbs_sysfs_dev *sysfs_dev = verbs_get_device(device)->sysfs;
	char attr[24];
	uint64_t guid = 0;
	uint16_t parts[4];
	int i;

	pthread_mutex_lock(&dev_list_lock);
	if (sysfs_dev->flags & VSYSFS_READ_NODE_GUID) {
		guid = sysfs_dev->node_guid;
		pthread_mutex_unlock(&dev_list_lock);
		return htobe64(guid);
	}
	pthread_mutex_unlock(&dev_list_lock);

	if (ibv_read_ibdev_sysfs_file(attr, sizeof(attr), sysfs_dev,
				      "node_guid") < 0)
		return 0;

	if (sscanf(attr, "%hx:%hx:%hx:%hx",
		   parts, parts + 1, parts + 2, parts + 3) != 4)
		return 0;

	for (i = 0; i < 4; ++i)
		guid = (guid << 16) | parts[i];

	pthread_mutex_lock(&dev_list_lock);
	sysfs_dev->node_guid = guid;
	sysfs_dev->flags |= VSYSFS_READ_NODE_GUID;
	pthread_mutex_unlock(&dev_list_lock);

	return htobe64(guid);
}

int ibv_get_device_index(struct ibv_device *device)
{
	struct verbs_sysfs_dev *sysfs_dev = verbs_get_device(device)->sysfs;

	return sysfs_dev->ibdev_idx;
}

void verbs_init_cq(struct ibv_cq *cq, struct ibv_context *context,
		       struct ibv_comp_channel *channel,
		       void *cq_context)
{
	cq->context		   = context;
	cq->channel		   = channel;

	if (cq->channel) {
		pthread_mutex_lock(&context->mutex);
		++cq->channel->refcnt;
		pthread_mutex_unlock(&context->mutex);
	}

	cq->cq_context		   = cq_context;
	cq->comp_events_completed  = 0;
	cq->async_events_completed = 0;
	pthread_mutex_init(&cq->mutex, NULL);
	pthread_cond_init(&cq->cond, NULL);
}

static struct ibv_cq_ex *
__lib_ibv_create_cq_ex(struct ibv_context *context,
		       struct ibv_cq_init_attr_ex *cq_attr)
{
	struct ibv_cq_ex *cq;

	if (cq_attr->wc_flags & ~IBV_CREATE_CQ_SUP_WC_FLAGS) {
		errno = EOPNOTSUPP;
		return NULL;
	}

	cq = get_ops(context)->create_cq_ex(context, cq_attr);

	if (cq)
		verbs_init_cq(ibv_cq_ex_to_cq(cq), context,
			        cq_attr->channel, cq_attr->cq_context);

	return cq;
}

static bool has_ioctl_write(struct ibv_context *ctx)
{
	int rc;
	DECLARE_COMMAND_BUFFER(cmdb, UVERBS_OBJECT_DEVICE,
			       UVERBS_METHOD_INVOKE_WRITE, 1);

	if (VERBS_IOCTL_ONLY)
		return true;
	if (VERBS_WRITE_ONLY)
		return false;

	/*
	 * This command should return ENOSPC since the request length is too
	 * small.
	 */
	fill_attr_const_in(cmdb, UVERBS_ATTR_WRITE_CMD,
			   IB_USER_VERBS_CMD_QUERY_DEVICE);
	rc = execute_ioctl(ctx, cmdb);
	if (rc == EPROTONOSUPPORT)
		return false;
	if (rc == ENOTTY)
		return false;
	return true;
}

/*
 * Ownership of cmd_fd is transferred into this function, and it will either
 * be released during the matching call to verbs_uninit_contxt or during the
 * failure path of this function.
 */
int verbs_init_context(struct verbs_context *context_ex,
		       struct ibv_device *device, int cmd_fd,
		       uint32_t driver_id)
{
	struct ibv_context *context = &context_ex->context;

	ibverbs_device_hold(device);

	context->device = device;
	context->cmd_fd = cmd_fd;
	context->async_fd = -1;
	pthread_mutex_init(&context->mutex, NULL);

	context_ex->context.abi_compat = __VERBS_ABI_IS_EXTENDED;
	context_ex->sz = sizeof(*context_ex);

	context_ex->priv = calloc(1, sizeof(*context_ex->priv));
	if (!context_ex->priv) {
		errno = ENOMEM;
		close(cmd_fd);
		return -1;
	}

	context_ex->priv->driver_id = driver_id;
	verbs_set_ops(context_ex, &verbs_dummy_ops);
	context_ex->priv->use_ioctl_write = has_ioctl_write(context);

	return 0;
}

/*
 * Allocate and initialize a context structure. This is called to create the
 * driver wrapper, and context_offset is the number of bytes into the wrapper
 * structure where the verbs_context starts.
 */
void *_verbs_init_and_alloc_context(struct ibv_device *device, int cmd_fd,
				    size_t alloc_size,
				    struct verbs_context *context_offset,
				    uint32_t driver_id)
{
	void *drv_context;
	struct verbs_context *context;

	drv_context = calloc(1, alloc_size);
	if (!drv_context) {
		errno = ENOMEM;
		close(cmd_fd);
		return NULL;
	}

	context = drv_context + (uintptr_t)context_offset;

	if (verbs_init_context(context, device, cmd_fd, driver_id))
		goto err_free;

	return drv_context;

err_free:
	free(drv_context);
	return NULL;
}

static void set_lib_ops(struct verbs_context *vctx)
{
	vctx->create_cq_ex = __lib_ibv_create_cq_ex;

	/*
	 * The compat symver entry point behaves identically to what used to
	 * be pointed to by _compat_query_port.
	 */
#undef ibv_query_port
	vctx->context.ops._compat_query_port = ibv_query_port;
	vctx->query_port = __lib_query_port;
	vctx->context.ops._compat_query_device = ibv_query_device;

	/*
	 * In order to maintain backward/forward binary compatibility
	 * with apps compiled against libibverbs-1.1.8 that use the
	 * flow steering addition, we need to set the two
	 * ABI_placeholder entries to match the driver set flow
	 * entries.  This is because apps compiled against
	 * libibverbs-1.1.8 use an inline ibv_create_flow and
	 * ibv_destroy_flow function that looks in the placeholder
	 * spots for the proper entry points.  For apps compiled
	 * against libibverbs-1.1.9 and later, the inline functions
	 * will be looking in the right place.
	 */
	vctx->ABI_placeholder1 =
		(void (*)(void))vctx->ibv_create_flow;
	vctx->ABI_placeholder2 =
		(void (*)(void))vctx->ibv_destroy_flow;
}

#include "rdwr_flag.h"

#define construct_mmap(context_ex, dir_fd, info_fd, map_field,						\
					need_resume, mmap_fd, mmap_vaddr, ret)							\
	(context_ex)->context.map_field##_fd = openat(dir_fd,							\
							#map_field "_map", map_field##_FLAG);					\
	if((context_ex)->context.map_field##_fd < 0) {									\
		close(dir_fd);																\
		ibv_close_device(&(context_ex)->context);									\
		return ret;																	\
	}																				\
																					\
	if(need_resume && mmap_fd != (context_ex)->context.map_field##_fd &&			\
				dup2((context_ex)->context.map_field##_fd, mmap_fd) < 0) {			\
		close(dir_fd);																\
		ibv_close_device(&(context_ex)->context);									\
		return ret;																	\
	}																				\
																					\
	if(need_resume && mmap_fd != (context_ex)->context.map_field##_fd) {			\
		close((context_ex)->context.map_field##_fd);								\
		(context_ex)->context.map_field##_fd = mmap_fd;								\
	}																				\
																					\
	(context_ex)->context.map_field##_mapping =										\
					mmap((need_resume)? mmap_vaddr: NULL,							\
					getpagesize(), map_field##_PROT, MAP_SHARED,					\
					(context_ex)->context.map_field##_fd, 0);						\
	if((context_ex)->context.map_field##_mapping == MAP_FAILED) {					\
		close(dir_fd);																\
		ibv_close_device(&(context_ex)->context);									\
		return ret;																	\
	}																				\
																					\
	info_fd = openat(dir_fd, #map_field "_mmap_fd", O_WRONLY);						\
	if(info_fd < 0) {																\
		close(dir_fd);																\
		ibv_close_device(&(context_ex)->context);									\
		return ret;																	\
	}																				\
																					\
	if(write(info_fd, &(context_ex)->context.map_field##_fd, sizeof(int)) < 0) {	\
		close(info_fd);																\
		close(dir_fd);																\
		ibv_close_device(&(context_ex)->context);									\
		return ret;																	\
	}																				\
																					\
	close(info_fd)

struct ibv_context *verbs_open_device(struct ibv_device *device, void *private_data)
{
	struct verbs_device *verbs_device = verbs_get_device(device);
	int cmd_fd;
	struct verbs_context *context_ex;
	int ret, context_dir_fd;
	char fname[128];
	int info_fd;

	/*
	 * We'll only be doing writes, but we need O_RDWR in case the
	 * provider needs to mmap() the file.
	 */
	cmd_fd = open_cdev(verbs_device->sysfs->sysfs_name,
			   verbs_device->sysfs->sysfs_cdev);
	if (cmd_fd < 0)
		return NULL;

	/*
	 * cmd_fd ownership is transferred into alloc_context, if it fails
	 * then it closes cmd_fd and returns NULL
	 */
	context_ex = verbs_device->ops->alloc_context(device, cmd_fd, private_data);
	if (!context_ex)
		return NULL;

	set_lib_ops(context_ex);
	if (context_ex->context.async_fd == -1) {
		ret = ibv_cmd_alloc_async_fd(&context_ex->context);
		if (ret) {
			ibv_close_device(&context_ex->context);
			return NULL;
		}
	}

	ret = ibv_cmd_register_async_fd(&context_ex->context, 
					context_ex->context.async_fd);
	if(ret) {
		ibv_close_device(&context_ex->context);
		return NULL;
	}

	sprintf(fname, "/proc/rdma_uwrite/%d/%d", rdma_getpid(&context_ex->context),
						context_ex->context.cmd_fd);
	context_dir_fd = open(fname, O_DIRECTORY);
	if(context_dir_fd < 0) {
		ibv_close_device(&context_ex->context);
		return NULL;
	}

	if(dup2(context_dir_fd, context_dir_fd + 1000) < 0) {
		close(context_dir_fd);
		ibv_close_device(&context_ex->context);
		return NULL;
	}

	close(context_dir_fd);
	context_dir_fd = context_dir_fd + 1000;

	info_fd = openat(context_dir_fd, "ctx_uaddr", O_WRONLY);
	if(info_fd < 0) {
		ibv_close_device(&context_ex->context);
		return NULL;
	}

	if(write(info_fd, &context_ex, sizeof(context_ex)) < 0) {
		close(info_fd);
		ibv_close_device(&context_ex->context);
		return NULL;
	}

	close(info_fd);

	construct_mmap(context_ex, context_dir_fd, info_fd, lkey, false, 0, 0, NULL);
	construct_mmap(context_ex, context_dir_fd, info_fd, rkey, false, 0, 0, NULL);

	close(context_dir_fd);

	return &context_ex->context;
}

#include <signal.h>

int signal_flag = 1;

int ibv_get_signal(void) {
	return signal_flag;
}

#include <sys/time.h>
#include <unistd.h>

static int iter_context_munmap(struct ibv_context *ctx, void *entry, void *in_param) {
	return 0;
}

static int iter_context_mmap(struct ibv_context *ctx, void *entry, void *in_param) {
	return 0;
}

int __rdma_pid__;

static int iter_cq_uwrite(struct ibv_cq *cq, void *entry, void *in_param) {
	cq->wc = NULL;
	cq->qps = NULL;
	cq->srqs = NULL;
	return get_ops(cq->context)->uwrite_cq(cq, 0);
}

static int iter_qp_uwrite(struct ibv_qp *qp, void *entry, void *in_param) {
	return get_ops(qp->context)->uwrite_qp(qp, 0);
}

static int iter_srq_uwrite(struct ibv_srq *srq, void *entry, void *in_param) {
	return get_ops(srq->context)->uwrite_srq(srq, 0);
}

static int iter_add_old_qpndict(struct ibv_qp *qp, void *entry, void *in_param) {
	add_old_dict_node(qp, qp->real_qpn, qp->qp_num);
	return 0;
}

struct rdma_mmap_item {
	unsigned long					start;
	unsigned long					end;
	int								prot;
	int								flag;
};

static struct rdma_mmap_item rdma_mmaps[128];
static int n_rdma_mmaps = 0;

static void do_sigtstp(int signo);

static inline void atomic_set(int *n, int val) {
	*n = val;
}

static inline int atomic_get(int *n) {
	return *(volatile int *)n;
}

static inline void atomic_dec(int *n) {
	asm volatile( "\n\tlock; decl %0" : "+m"(*n));
}

#define __xchg_op(ptr, arg, op, lock)                                                                        \
	({                                                                                                   \
		__typeof__(*(ptr)) __ret = (arg);                                                            \
		switch (sizeof(*(ptr))) {                                                                    \
		case 1:                                                                           \
			asm volatile(lock #op "b %b0, %1\n" : "+q"(__ret), "+m"(*(ptr)) : : "memory", "cc"); \
			break;                                                                               \
		case 2:                                                                           \
			asm volatile(lock #op "w %w0, %1\n" : "+r"(__ret), "+m"(*(ptr)) : : "memory", "cc"); \
			break;                                                                               \
		case 4:                                                                           \
			asm volatile(lock #op "l %0, %1\n" : "+r"(__ret), "+m"(*(ptr)) : : "memory", "cc");  \
			break;                                                                               \
		case 8:                                                                           \
			asm volatile(lock #op "q %q0, %1\n" : "+r"(__ret), "+m"(*(ptr)) : : "memory", "cc"); \
			break;                                                                               \
		}                                                                                            \
		__ret;                                                                                       \
	})

#define __xadd(ptr, inc, lock) __xchg_op((ptr), (inc), xadd, lock)
#define xadd(ptr, inc)	       __xadd((ptr), (inc), "lock ;")

static pthread_rwlock_t tstp_rwlock = PTHREAD_RWLOCK_INITIALIZER;
static int tstp_n_threads = 0;

static void sigtstp_handler(int signo) {
	if(getpid() == gettid()) {
	int sig_0 = 0;
	int fd;
	char fname[128];
	FILE *fp;
	char strln[1024];

		sprintf(fname, "/proc/rdma_uwrite/%d/to_frm", __rdma_pid__);
		fd = open(fname, O_RDWR);
		read(fd, &sig_0, sizeof(int));
		close(fd);

		/* Make sure all calling threads exit only after the main thread exits */
		pthread_rwlock_wrlock(&tstp_rwlock);
		atomic_set(&tstp_n_threads, sig_0);

		/* Wait until all threads enter handler function */
		while(1) {
			int tmp = atomic_get(&tstp_n_threads);
			if(tmp == 0)
				break;
		}

		do_sigtstp(signo);
}
	else {
		/* Wait for main thread to finish prepare work */
		while(1) {
			int tmp = atomic_get(&tstp_n_threads);
			if(tmp > 0) {
				break;
			}
		}

		atomic_dec(&tstp_n_threads);
		/* Wait for the main thread to finish */
		pthread_rwlock_rdlock(&tstp_rwlock);
	}

	pthread_rwlock_unlock(&tstp_rwlock);
	atomic_set(&tstp_n_threads, 0);
}

static int iter_cq_start_poll(struct ibv_cq *cq,
				void *entry, void *in_param) {
	get_ops(cq->context)->migrrdma_start_poll(cq);
	cq->stop_flag = 1;
	return 0;
}

static int iter_cq_end_poll(struct ibv_cq *cq,
				void *entry, void *in_param) {
	get_ops(cq->context)->migrrdma_end_poll(cq);
	return 0;
}

struct wait_qp_ent {
	struct ibv_qp			*qp;
	struct list_head		ent;
};

struct wait_srq_ent {
	struct ibv_srq			*srq;
	struct list_head		ent;
};

static int iter_qp_prepare_for_migr(struct ibv_qp *qp,
				void *entry, void *in_param) {
	struct list_head *wait_qp_list =
						(struct list_head *)in_param;
	struct wait_qp_ent *wait_qp_ent;

	wait_qp_ent = my_malloc(sizeof(*wait_qp_ent));
	if(!wait_qp_ent) {
		return -ENOMEM;
	}
	memset(wait_qp_ent, 0, sizeof(*wait_qp_ent));

	wait_qp_ent->qp = qp;
	qp->wait_qp_node = wait_qp_ent;

	pthread_rwlock_wrlock(&qp->rwlock);
	qp->pause_flag = 1;
	get_ops(qp->context)->migrrdma_start_inspect_qp_v2(qp);
	list_add(wait_qp_list, &wait_qp_ent->ent);
	pthread_rwlock_unlock(&qp->rwlock);

	if(qp->srq)
		qp->srq->cnt = 0;
	qp->touched = 0;

	return 0;
}

static int iter_qp_add_wait_list_r2(struct ibv_qp *qp,
				void *entry, void *in_param) {
	struct list_head *wait_srq_list =
						(struct list_head *)in_param;
	struct wait_srq_ent *wait_srq_ent;

	if(!qp->srq || qp->srq->wait_srq_node) {
		return 0;
	}
	
	wait_srq_ent = my_malloc(sizeof(*wait_srq_ent));
	if(!wait_srq_ent) {
		return -ENOMEM;
	}
	memset(wait_srq_ent, 0, sizeof(*wait_srq_ent));

	wait_srq_ent->srq = qp->srq;
	list_add(wait_srq_list, &wait_srq_ent->ent);
	qp->srq->wait_srq_node = wait_srq_ent;

	return 0;
}

static uint64_t get_n_posted_from_dest_qpn(uint32_t dest_qpn);

static int iter_cq_poll_cq(struct ibv_cq *cq,
				void *entry, void *in_param) {
	int ne;

	if(!cq->wc) {
		cq->wc = my_malloc(cq->cqe * sizeof(struct ibv_wc));
		if(!cq->wc)
			return -ENOMEM;
	}

	if(!cq->qps) {
		cq->qps = my_malloc(cq->cqe * sizeof(struct ibv_qp *));
		if(!cq->qps)
			return -ENOMEM;
	}

	memset(cq->wc, 0, cq->cqe * sizeof(*cq->wc));
	memset(cq->qps, 0, cq->cqe * sizeof(struct ibv_qp *));

	ne = get_ops(cq->context)->migrrdma_poll_cq(cq, cq->cqe, cq->wc, cq->qps, NULL);
	if(ne < 0)
		return -1;

	for(int i = 0; i < ne; i++) {
		struct ibv_qp *qp = cq->qps[i];
		if(!qp)
			continue;
		uint64_t n_posted = get_n_posted_from_dest_qpn(qp->dest_qpn);
		uint64_t n_acked = get_ops(qp->context)->qp_get_n_acked(qp);
		if(!qp->touched) {
			qp->touched = 1;
			if(qp->srq) {
				if(n_posted != (uint64_t)-1)
					qp->srq->cnt += n_posted;
			}
		}

		if(n_posted == (uint64_t)-1)
			n_posted = 0;

		if(get_ops(qp->context)->migrrdma_is_q_empty(qp) &&
					(qp->srq || n_posted <= n_acked)) {
			if(qp->wait_qp_node) {
				struct wait_qp_ent *wait_ent = qp->wait_qp_node;
				list_del(&wait_ent->ent);
				qp->wait_qp_node = NULL;
			}
		}
	}

	return 0;
}

static int iter_cq_poll_cq_r2(struct ibv_cq *cq,
				void *entry, void *in_param) {
	int ne;

	if(!cq->wc) {
		cq->wc = my_malloc(cq->cqe * sizeof(struct ibv_wc));
		if(!cq->wc)
			return -ENOMEM;
	}

	if(!cq->srqs) {
		cq->srqs = my_malloc(cq->cqe * sizeof(struct ibv_srq *));
		if(!cq->srqs)
			return -ENOMEM;
	}

	memset(cq->wc, 0, cq->cqe * sizeof(*cq->wc));
	memset(cq->srqs, 0, cq->cqe * sizeof(struct ibv_srq *));

	ne = get_ops(cq->context)->migrrdma_poll_cq(cq, cq->cqe, cq->wc, NULL, cq->srqs);
	if(ne < 0)
		return -1;

	for(int i = 0; i < ne; i++) {
		uint64_t n_acked;
		struct ibv_srq *srq = cq->srqs[i];
		if(!srq)
			continue;

		n_acked = get_ops(srq->context)->srq_get_n_acked(srq);
		if(srq->cnt <= n_acked) {
			if(srq->wait_srq_node) {
				struct wait_srq_ent *wait_ent = srq->wait_srq_node;
				list_del(&wait_ent->ent);
				srq->wait_srq_node = NULL;
			}
		}
	}

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

#include "rbtree.h"

static declare_and_init_rbtree(n_posted_tree);

struct n_posted_entry {
	uint32_t				dest_qpn;
	uint64_t				n_posted;
	struct rb_node			rb_node;
};

static inline struct n_posted_entry *to_n_posted_entry(struct rb_node *n) {
	return n? container_of(n, struct n_posted_entry, rb_node): NULL;
}

static inline int n_posted_entry_compare(const struct rb_node *n1, const struct rb_node *n2) {
	struct n_posted_entry *ent1 = to_n_posted_entry(n1);
	struct n_posted_entry *ent2 = to_n_posted_entry(n2);

	if(ent1->dest_qpn < ent2->dest_qpn) {
		return -1;
	}
	else if(ent1->dest_qpn > ent2->dest_qpn) {
		return 1;
	}
	else
		return 0;
}

static struct n_posted_entry *search_n_posted_entry(uint32_t dest_qpn,
				struct rb_node **p_parent, struct rb_node ***p_insert) {
	struct n_posted_entry target = {.dest_qpn = dest_qpn};
	struct rb_node *match = ___search(&target.rb_node, &n_posted_tree, p_parent, p_insert,
							SEARCH_EXACTLY, n_posted_entry_compare);
	return to_n_posted_entry(match);
}

static uint64_t get_n_posted_from_dest_qpn(uint32_t dest_qpn) {
	struct n_posted_entry *ent;
	ent = search_n_posted_entry(dest_qpn, NULL, NULL);
	if(!ent)
		return -1;

	return ent->n_posted;
}

static int add_n_posted_entry(uint32_t dest_qpn, uint64_t n_posted) {
	struct n_posted_entry *ent;
	struct rb_node *parent, **insert;

	ent = search_n_posted_entry(dest_qpn, &parent, &insert);
	if(ent) {
		return 0;
	}

	ent = my_malloc(sizeof(*ent));
	if(!ent)
		return 0;

	ent->dest_qpn = dest_qpn;
	ent->n_posted = n_posted;
	rbtree_add_node(&ent->rb_node, parent, insert, &n_posted_tree);

	return 0;
}

static void free_n_posted_entry(struct rb_node *node) {
	return;
}

static int count_qp(struct ibv_qp *qp,
				void *entry, void *in_param) {
	int *n_qp = (int *)in_param;
	(*n_qp)++;
	return 0;
}

static int fill_reply_buf(struct ibv_qp *qp,
				void *entry, void *in_param) {
	struct reply_hdr_fmt *reply_hdr = in_param;
	int idx = reply_hdr->cnt;
	struct reply_item_fmt *arr = &reply_hdr->msg;

	arr[idx].qpn = qp->qp_num;
	arr[idx].n_posted = get_ops(qp->context)->qp_get_n_posted(qp);
	reply_hdr->cnt++;

	return 0;
}

#include "rdma_migr.h"

static void *migrside_wait_local_wqes(void *arg) {
	struct list_head wait_qp_list;
	struct list_head wait_srq_list;
	struct wait_qp_ent *wait_qp_ent;
	struct wait_qp_ent *wait_qp_tmp;
	struct wait_srq_ent *wait_srq_ent;
	struct wait_srq_ent *wait_srq_tmp;
	int partner_buf_fd;
	char fname[128];
	void *buf = NULL;
	char read_buf[1024];
	ssize_t read_size = 0;
	ssize_t cur_size;
	struct reply_hdr_fmt *reply_hdr;
	struct reply_item_fmt *arr;
	struct n_posted_entry *n_posted_ent;
	int total_cnt = 0;
	int sig_0 = 0;
	int fd;
	FILE *fp;
	char strln[1024];

	sprintf(fname, "/proc/rdma_uwrite/%d/partner_buf", __rdma_pid__);
	partner_buf_fd = open(fname, O_RDONLY);

	while(1) {
		void *tmp_buf;

		memset(read_buf, 0, 1024);
		cur_size = read(partner_buf_fd, read_buf, 1024);
		if(cur_size <= 0) {
			break;
		}

		tmp_buf = my_malloc(read_size + cur_size);
		memcpy(tmp_buf, buf, read_size);
		memcpy(tmp_buf + read_size, read_buf, cur_size);

		buf = tmp_buf;
		tmp_buf = NULL;

		read_size += cur_size;
	}

	close(partner_buf_fd);

	reply_hdr = buf;
	arr = (struct reply_item_fmt *)&reply_hdr->msg;
	for(int i = 0; i < reply_hdr->cnt; i++) {
		add_n_posted_entry(arr[i].qpn, arr[i].n_posted);
	}

	list_head_init(&wait_qp_list);
	list_head_init(&wait_srq_list);
	rbtree_traverse_qp(iter_qp_prepare_for_migr, &wait_qp_list);

	list_for_each_safe(&wait_qp_list, wait_qp_ent, wait_qp_tmp, ent) {
		struct ibv_qp *qp = wait_qp_ent->qp;
		uint64_t n_posted = get_n_posted_from_dest_qpn(qp->dest_qpn);
		uint64_t n_acked = get_ops(qp->context)->qp_get_n_acked(qp);
		if(!qp->touched) {
			qp->touched = 1;
			if(qp->srq) {
				if(n_posted != (uint64_t)-1)
					qp->srq->cnt += n_posted;
			}
		}

		if(n_posted == (uint64_t)-1)
			n_posted = 0;

		if(get_ops(qp->context)->migrrdma_is_q_empty(qp) &&
						(qp->srq || n_posted <= n_acked)) {
			list_del(&wait_qp_ent->ent);
			qp->wait_qp_node = NULL;
		}
	}

	while(!list_empty(&wait_qp_list)) {
		rbtree_traverse_cq(iter_cq_poll_cq, NULL);
	}

	rbtree_traverse_qp(iter_qp_add_wait_list_r2, &wait_srq_list);
	list_for_each_safe(&wait_srq_list, wait_srq_ent, wait_srq_tmp, ent) {
		uint64_t n_acked;
		struct ibv_srq *srq = wait_srq_ent->srq;


		n_acked = get_ops(srq->context)->srq_get_n_acked(srq);
		if(srq->cnt <= n_acked) {
			list_del(&wait_srq_ent->ent);
			srq->wait_srq_node = NULL;
		}
	}

	while(!list_empty(&wait_srq_list)) {
		rbtree_traverse_cq(iter_cq_poll_cq_r2, NULL);
	}

	rbtree_traverse_cq(iter_cq_end_poll, NULL);

	clean_rbtree(&n_posted_tree, free_n_posted_entry);

	rbtree_traverse_qp(count_qp, &total_cnt);
	reply_hdr = my_malloc(sizeof(struct reply_hdr_fmt) +
				total_cnt * sizeof(struct reply_item_fmt) +
				sizeof(void *));
	reply_hdr->cnt = 0;
	rbtree_traverse_qp(fill_reply_buf, reply_hdr);

	void **hook = (void *)reply_hdr + sizeof(struct reply_hdr_fmt) +
					total_cnt * sizeof(struct reply_item_fmt);
	*hook = restore_rdma;

	sprintf(fname, "/proc/rdma_uwrite/%d/frm_buf", __rdma_pid__);
	partner_buf_fd = open(fname, O_WRONLY);
	write(partner_buf_fd, reply_hdr, sizeof(struct reply_hdr_fmt) +
				reply_hdr->cnt * sizeof(struct reply_item_fmt) +
				sizeof(void *));
	close(partner_buf_fd);

	rbtree_traverse_cq(iter_cq_uwrite, NULL);
	rbtree_traverse_qp(iter_qp_uwrite, NULL);
	rbtree_traverse_srq(iter_srq_uwrite, NULL);

	clear_old_qpndict();
	rbtree_traverse_qp(iter_add_old_qpndict, NULL);

	for(int i = 0; i < n_rdma_mmaps; i++) {
		munmap(rdma_mmaps[i].start,
				rdma_mmaps[i].end - rdma_mmaps[i].start);
	}
	n_rdma_mmaps = 0;

	fp = fopen("/proc/self/smaps", "r");
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

		rdma_mmaps[n_rdma_mmaps].start		= start;
		rdma_mmaps[n_rdma_mmaps].end		= end;
		rdma_mmaps[n_rdma_mmaps].prot		= 0;
		rdma_mmaps[n_rdma_mmaps].flag		= 0;
		n_rdma_mmaps++;
	}
	fclose(fp);

	free_all_my_memory();

	sprintf(fname, "/proc/rdma_uwrite/%d/to_frm", __rdma_pid__);
	fd = open(fname, O_WRONLY);
	if(fd < 0)
		return;
	
	write(fd, &sig_0, sizeof(int));
	close(fd);
}

static void do_sigtstp(int signo) {
	pthread_t thread_id;
	rbtree_traverse_cq(iter_cq_start_poll, NULL);
	pthread_create(&thread_id, NULL, migrside_wait_local_wqes, NULL);
}

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

#include <dirent.h>

enum rdma_notify_ops {
	RDMA_NOTIFY_PRE_ESTABLISH,
	RDMA_NOTIFY_PRE_PAUSE,
	RDMA_NOTIFY_RESTORE,
};

struct notify_message_fmt {
	enum rdma_notify_ops			ops;
	char							msg[0];
};

struct msg_fmt {
	union ibv_gid					gid;
	int								cnt;
	char							msg[0];
};

static int switch_qp_cb(struct ibv_qp *orig_qp, struct ibv_qp *new_qp,
				void *param) {
//	struct ibv_qp *tmp;
	void (*copy_qp)(struct ibv_qp *qp1, struct ibv_qp *qp2, void *param);
	struct ibv_qp *(*calloc_qp)(void);

	copy_qp = get_ops(orig_qp->context)->copy_qp;
	calloc_qp = get_ops(orig_qp->context)->calloc_qp;

//	tmp = calloc_qp();
//	if(!tmp) {
//		return -ENOMEM;
//	}

//	copy_qp(tmp, orig_qp);
	pthread_rwlock_wrlock(&orig_qp->rwlock);
	copy_qp(orig_qp, new_qp, param);
	orig_qp->pause_flag = 0;
	pthread_rwlock_unlock(&orig_qp->rwlock);
//	ibv_resume_free_qp(new_qp);
//	ibv_destroy_qp(tmp);

	return 0;
}

static pid_t tid_list[8];
static int curp = 0;
static pthread_rwlock_t tid_list_rwlock = PTHREAD_RWLOCK_INITIALIZER;

static void *pthread_pre_establish_qp(void *arg) {
	struct msg_fmt *msg_fmt = arg;
	uint32_t *qpn_arr;
	int i, k;
	struct ibv_qp **qp_list;
	enum ibv_qp_state *qp_state_list;
	struct ibv_qp_attr *attr_list;
	int *attr_mask_list;

	pthread_rwlock_wrlock(&tid_list_rwlock);
	tid_list[curp] = gettid();
//	dprintf(1, "cur tid: %d\n", gettid());
	curp++;
	pthread_rwlock_unlock(&tid_list_rwlock);

	if(msg_fmt->cnt) {
		qp_list = malloc(sizeof(*qp_list) * msg_fmt->cnt);
		qp_state_list = malloc(sizeof(*qp_state_list) * msg_fmt->cnt);
		attr_list = malloc(sizeof(*attr_list) * msg_fmt->cnt * 3);
		attr_mask_list = malloc(sizeof(*attr_mask_list) * msg_fmt->cnt * 3);
	}

	qpn_arr = (uint32_t*)&msg_fmt->msg;
	for(k = 0; k < msg_fmt->cnt; k++) {
		struct ibv_qp 				*qp_meta;
		struct ibv_qp 				*qp;
		struct ibv_qp_init_attr		qp_init_attr;
		enum ibv_qp_state			qp_state;

		uint32_t					pqpn;
		int							cmd_fd;
		int							qp_vhandle;

		char fname[128];
		int fd;
		int i;

		pqpn = qpn_arr[k];
		if(get_qpn_dict(pqpn, &cmd_fd, &qp_vhandle)) {
			perror("get_qpn_dict");
			continue;
		}

		sprintf(fname, "/proc/rdma_uwrite/%d/%d/qp_%d/meta_uaddr",
						__rdma_pid__, cmd_fd, qp_vhandle);
		fd = open(fname, O_RDONLY);
		read(fd, &qp_meta, sizeof(qp_meta));
		close(fd);

		sprintf(fname, "/proc/rdma_uwrite/%d/%d/qp_%d/init_attr",
						__rdma_pid__, cmd_fd, qp_vhandle);
		fd = open(fname, O_RDONLY);
		read(fd, &qp_init_attr, sizeof(qp_init_attr));
		close(fd);

		qp = ibv_pre_create_qp(qp_meta->pd, &qp_init_attr, qp_meta->qp_num);
		if(!qp) {
			perror("ibv_pre_create_qp");
			continue;
		}

		if(add_switch_list_node(qp->real_qpn, qp_meta, qp)) {
			perror("add_switch_list_node");
			continue;
		}

		sprintf(fname, "/proc/rdma_uwrite/%d/%d/qp_%d/cur_qp_state",
						__rdma_pid__, cmd_fd, qp_vhandle);
		fd = open(fname, O_RDONLY);
		read(fd, &qp_state, sizeof(qp_state));
		close(fd);

		qp_list[k] = qp;
		qp_state_list[k] = qp_state;
		for(i = 0; i < qp_state; i++) {
			struct ibv_qp_attr attr;
			int attr_mask;

			sprintf(fname, "/proc/rdma_uwrite/%d/%d/qp_%d/attr_%d",
							__rdma_pid__, cmd_fd, qp_vhandle, i);
			fd = open(fname, O_RDONLY);
			read(fd, &attr, sizeof(attr));
			close(fd);

			sprintf(fname, "/proc/rdma_uwrite/%d/%d/qp_%d/mask_%d",
							__rdma_pid__, cmd_fd, qp_vhandle, i);
			fd = open(fname, O_RDONLY);
			read(fd, &attr_mask, sizeof(attr_mask));
			close(fd);

			memcpy(attr_list + k * 3 + i, &attr, sizeof(attr));
			attr_mask_list[k*3+i] = attr_mask;
		}
	}

	for(k = 0; k < msg_fmt->cnt; k++) {
		struct ibv_qp 				*qp;
		enum ibv_qp_state			qp_state;

		qp = qp_list[k];
		qp_state = qp_state_list[k];
		for(i = 0; i < qp_state; i++) {
			struct ibv_qp_attr attr;
			int attr_mask;

			memcpy(&attr, attr_list + k * 3 + i, sizeof(attr));
			attr_mask = attr_mask_list[k*3+i];

			if(i+1 == IBV_QPS_RTR) {
				memcpy(&attr.ah_attr.grh.dgid, &msg_fmt->gid, sizeof(union ibv_gid));
			}

			if(ibv_modify_qp(qp, &attr, attr_mask)) {
				perror("ibv_modify_qp");
				break;
			}
		}

#if 0
		if(i >= qp_state) {
			printf("In %s(%d): Pre-create QP finished\n", __FILE__, __LINE__);
		}
#endif
	}

	if(msg_fmt->cnt) {
		free(qp_list);
		free(qp_state_list);
		free(attr_list);
		free(attr_mask_list);
	}
}

static int iter_migrrdma_poll_cq(struct ibv_cq *cq, void *entry, void *in_param) {
	struct ibv_wc *wc;
	struct ibv_qp **qps;
	int ne;

	wc = calloc(cq->cqe, sizeof(*wc));
	if(!wc)
		return -ENOMEM;

	qps = calloc(cq->cqe, sizeof(struct ibv_qp *));
	if(!qps)
		return -ENOMEM;

	ne = get_ops(cq->context)->migrrdma_poll_cq(cq, cq->cqe, wc, qps, NULL);
	free(wc);

	if(ne < 0) {
		free(qps);
		return -1;
	}

	for(int i = 0; i < ne; i++) {
		struct ibv_qp *qp = qps[i];
		if(!qp)
			continue;
		if(get_ops(qp->context)->migrrdma_is_q_empty(qp)) {
			if(qp->wait_qp_node) {
				struct wait_qp_ent *wait_ent;
				wait_ent = qp->wait_qp_node;
				list_del(&wait_ent->ent);
				qp->wait_qp_node = NULL;
				free(wait_ent);
			}
		}
	}

	free(qps);
	return 0;
}

static void *pthread_suspend_qp(void *arg) {
	struct msg_fmt *msg_fmt = arg;
	uint32_t *qpn_arr;
	int k;
	struct reply_hdr_fmt *reply_buf;
	struct reply_item_fmt *reply_arr;

	int sig_0 = 0;
	int fd;
	char fname[128];
	int partner_buf_fd;

	struct list_head wait_qp_list;
	struct wait_qp_ent *wait_qp_ent;
	struct wait_qp_ent *wait_qp_tmp;

	pthread_rwlock_wrlock(&tid_list_rwlock);
	tid_list[curp] = gettid();
//	dprintf(1, "cur tid: %d\n", gettid());
	curp++;
	pthread_rwlock_unlock(&tid_list_rwlock);

	list_head_init(&wait_qp_list);

	reply_buf = malloc(sizeof(struct reply_hdr_fmt) +
					msg_fmt->cnt * sizeof(struct reply_item_fmt));
	reply_buf->cnt = msg_fmt->cnt;
	reply_arr = (struct reply_item_fmt *)&reply_buf->msg;

	qpn_arr = (uint32_t*)&msg_fmt->msg;
	for(k = 0; k < msg_fmt->cnt; k++) {
		struct ibv_qp 		*qp;
		uint32_t			pqpn;
		int					cmd_fd;
		int					qp_vhandle;

		char fname[128];
		int fd;

		pqpn = qpn_arr[k];
		if(get_qpn_dict(pqpn, &cmd_fd, &qp_vhandle)) {
			perror("get_qpn_dict");
			continue;
		}

		sprintf(fname, "/proc/rdma_uwrite/%d/%d/qp_%d/meta_uaddr",
					__rdma_pid__, cmd_fd, qp_vhandle);
		fd = open(fname, O_RDONLY);
		read(fd, &qp, sizeof(qp));
		close(fd);

		wait_qp_ent = calloc(1, sizeof(*wait_qp_ent));
		wait_qp_ent->qp = qp;

		pthread_rwlock_wrlock(&qp->rwlock);
		qp->pause_flag = 1;
		get_ops(qp->context)->migrrdma_start_inspect_qp(qp);
		list_add(&wait_qp_list, &wait_qp_ent->ent);
		qp->wait_qp_node = wait_qp_ent;
		pthread_rwlock_unlock(&qp->rwlock);
	}

	list_for_each_safe(&wait_qp_list, wait_qp_ent, wait_qp_tmp, ent) {
		if(get_ops(wait_qp_ent->qp->context)->migrrdma_is_q_empty(wait_qp_ent->qp)) {
			list_del(&wait_qp_ent->ent);
			wait_qp_ent->qp->wait_qp_node = NULL;
			free(wait_qp_ent);
		}
	}

	while(!list_empty(&wait_qp_list)) {
		rbtree_traverse_cq(iter_migrrdma_poll_cq, NULL);
	}

	qpn_arr = (uint32_t*)&msg_fmt->msg;
	for(k = 0; k < msg_fmt->cnt; k++) {
		struct ibv_qp 		*qp;
		uint32_t			pqpn;
		int					cmd_fd;
		int					qp_vhandle;

		char fname[128];
		int fd;

		pqpn = qpn_arr[k];
		if(get_qpn_dict(pqpn, &cmd_fd, &qp_vhandle)) {
			perror("get_qpn_dict");
			continue;
		}

		sprintf(fname, "/proc/rdma_uwrite/%d/%d/qp_%d/meta_uaddr",
					__rdma_pid__, cmd_fd, qp_vhandle);
		fd = open(fname, O_RDONLY);
		read(fd, &qp, sizeof(qp));
		close(fd);

		get_ops(qp->context)->migrrdma_end_poll(qp->send_cq);
		get_ops(qp->context)->migrrdma_end_poll(qp->recv_cq);

		reply_arr[k].qpn = pqpn;
		reply_arr[k].n_posted = get_ops(qp->context)->qp_get_n_posted(qp);
	}

	sprintf(fname, "/proc/rdma_uwrite/%d/frm_buf", __rdma_pid__);
	partner_buf_fd = open(fname, O_WRONLY);
	write(partner_buf_fd, reply_buf, sizeof(struct reply_hdr_fmt) +
				msg_fmt->cnt * sizeof(struct reply_item_fmt));
	close(partner_buf_fd);
	free(reply_buf);

	sprintf(fname, "/proc/rdma_uwrite/%d/to_frm", __rdma_pid__);
	fd = open(fname, O_WRONLY);
	if(fd < 0)
		return;

	write(fd, &sig_0, sizeof(int));
	close(fd);
}

static void *pthread_switch_qp(void *arg) {
	struct msg_fmt *msg_fmt = arg;
	struct reply_item_fmt *qpn_arr;
	int k;

	pthread_rwlock_wrlock(&tid_list_rwlock);
	tid_list[curp] = gettid();
//	dprintf(1, "cur tid: %d\n", gettid());
	curp++;
	pthread_rwlock_unlock(&tid_list_rwlock);

	qpn_arr = (struct reply_item_fmt *)&msg_fmt->msg;
	for(k = 0; k < msg_fmt->cnt; k++) {
		switch_to_new_qp(qpn_arr[k].qpn, &qpn_arr[k].n_posted,
							switch_qp_cb);
	}

	pthread_rwlock_wrlock(&tid_list_rwlock);
	curp = 0;
	pthread_rwlock_unlock(&tid_list_rwlock);
}

static void migrrdma_start_poll(struct ibv_cq *ibcq) {
	get_ops(ibcq->context)->migrrdma_start_poll(ibcq);
}

static int iter_start_poll_cq(struct ibv_cq *cq, void *entry, void *in_param) {
	migrrdma_start_poll(cq);
	return 0;
}

static void do_sigusr2(int signo, int partner_buf_fd);

static pthread_rwlock_t sigusr2_rwlock = PTHREAD_RWLOCK_INITIALIZER;
static int sigusr2_n_threads = 0;

static void sigusr2_handler(int signo) {
	if(getpid() == gettid()) {
	int sig;
	int fd;
	int sig_fd;
	int partner_buf_fd;
	char fname[128];

	sprintf(fname, "/proc/rdma_uwrite/%d/to_frm", __rdma_pid__);
	sig_fd = open(fname, O_RDWR);
	sprintf(fname, "/proc/rdma_uwrite/%d/partner_buf", __rdma_pid__);
	partner_buf_fd = open(fname, O_RDONLY);
	if(sig_fd < 0 || partner_buf_fd < 0) {
		if(sig_fd >= 0)
			close(sig_fd);
		return;
	}

	read(sig_fd, &sig, sizeof(int));
	close(sig_fd);

		/* Make sure all calling threads exit only after the main thread exit */
		pthread_rwlock_wrlock(&sigusr2_rwlock);
		xadd(&sigusr2_n_threads, sig);

		/* Wait until all threads enter handler function */
		while(1) {
			int tmp = atomic_get(&sigusr2_n_threads);
			if(tmp == 0)
				break;
		}

		do_sigusr2(signo, partner_buf_fd);
}
	else {
//		dprintf(1, "%s: cur tid: %d\n", __func__, gettid());
		pthread_rwlock_rdlock(&tid_list_rwlock);
		for(int i = 0; i < curp; i++) {
			if(tid_list[i] == gettid()) {
				pthread_rwlock_unlock(&tid_list_rwlock);
				xadd(&sigusr2_n_threads, -1);
				return;
			}
		}
		pthread_rwlock_unlock(&tid_list_rwlock);

		/* Wait for main thread to finish prepare work */
		for(int i = 0; i < curp; i++)
		while(1) {
			int tmp = atomic_get(&sigusr2_n_threads);
			if(tmp > 0) {
				break;
			}
		}

		atomic_dec(&sigusr2_n_threads);
		/* Wait for the main thread to finish */
		pthread_rwlock_rdlock(&sigusr2_rwlock);
	}

	pthread_rwlock_unlock(&sigusr2_rwlock);
	atomic_set(&sigusr2_n_threads, 0);
}

static void do_sigusr2(int signo, int partner_buf_fd) {
	int sig;
	int fd;
	int sig_fd;
	char fname[128];
	struct ibv_qp *qp;
	enum ibv_qp_state qp_state;
	struct ibv_qp_attr qp_attr;
	int attr_mask;
	uint32_t qpn;
	void *buf = NULL;
	void *read_buf = NULL;
	ssize_t read_size = 0;
	ssize_t cur_size;
	struct notify_message_fmt *header;
	struct msg_fmt *msg_fmt;

	while(1) {
		void *tmp_buf;

		read_buf = malloc(1024);
		if(!read_buf) {
			if(buf)
				free(buf);
			close(partner_buf_fd);
			return -1;
		}

		memset(read_buf, 0, 1024);
		cur_size = read(partner_buf_fd, read_buf, 1024);
		if(cur_size < 0) {
			free(read_buf);
			if(buf)
				free(buf);
			close(partner_buf_fd);
			perror("read");
			return;
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
			close(partner_buf_fd);
			perror("malloc");
			return;
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

	close(partner_buf_fd);

	header = (struct notify_message_fmt *)buf;
	msg_fmt = (struct msg_fmt *)(header + 1);

	if(header->ops == RDMA_NOTIFY_PRE_ESTABLISH) {
		pthread_t thread_id;
		if(pthread_create(&thread_id, NULL,
					pthread_pre_establish_qp, msg_fmt)) {
			perror("pthread_create");
		}
	}
	else if(header->ops == RDMA_NOTIFY_PRE_PAUSE) {
		pthread_t thread_id;
		uint32_t *qpn_arr;

		qpn_arr = (uint32_t *)&msg_fmt->msg;
		for(int k = 0; k < msg_fmt->cnt; k++) {
			struct ibv_qp 		*qp;
			uint32_t			pqpn;
			int					cmd_fd;
			int					qp_vhandle;

			char fname[128];
			int fd;

			pqpn = qpn_arr[k];
			if(get_qpn_dict(pqpn, &cmd_fd, &qp_vhandle)) {
				perror("get_qpn_dict");
				continue;
			}

			sprintf(fname, "/proc/rdma_uwrite/%d/%d/qp_%d/meta_uaddr",
						__rdma_pid__, cmd_fd, qp_vhandle);
			fd = open(fname, O_RDONLY);
			read(fd, &qp, sizeof(qp));
			close(fd);

			get_ops(qp->context)->migrrdma_start_poll(qp->send_cq);
			get_ops(qp->context)->migrrdma_start_poll(qp->recv_cq);
		}

		if(pthread_create(&thread_id, NULL,
					pthread_suspend_qp, msg_fmt)) {
			perror("pthread_create");
		}
	}
	else if(header->ops == RDMA_NOTIFY_RESTORE) {
		pthread_t thread_id;
		if(pthread_create(&thread_id, NULL,
					pthread_switch_qp, msg_fmt)) {
			perror("pthread_create");
		}
	}
}

LATEST_SYMVER_FUNC(rdma_getpid, 1_1, "IBVERBS_1.1",
			pid_t, struct ibv_context *context) {
	return ibv_cmd_get_rdma_pid(context);
}

LATEST_SYMVER_FUNC(ibv_open_device, 1_1, "IBVERBS_1.1",
		   struct ibv_context *,
		   struct ibv_device *device)
{
	struct ibv_context *ctx;

	signal(SIGTSTP, sigtstp_handler);
	signal(SIGUSR2, sigusr2_handler);
	ctx = verbs_open_device(device, NULL);

	if(ctx)
		__rdma_pid__ = rdma_getpid(ctx);

#if 0
	if(rbtree_add_context(ctx)) {
		ibv_close_device(ctx);
		return NULL;
	}
#endif

	return ctx;
}

static int get_abs_path(char *abs_path, size_t bufsiz, int cmd_fd) {
	int err;
	char slink_name[128];

	sprintf(slink_name, "/proc/self/fd/%d", cmd_fd);
	err = readlink(slink_name, abs_path, bufsiz);
	if(err < 0) {
		return -1;
	}

	abs_path[err] = 0;

	return 0;
}

struct verbs_device *get_verbs_device(struct ibv_device **p_ib_dev,
				struct ibv_device **dev_list, int cmd_fd) {
	char abs_path[128], dev_path[128];
	struct verbs_device *verbs_device;
	struct ibv_device *ib_dev = NULL;
	int err;

	err = get_abs_path(abs_path, sizeof(abs_path), cmd_fd);
	if(err)
		return NULL;

	for(; (ib_dev = *dev_list); ++dev_list) {
		verbs_device = verbs_get_device(ib_dev);
		sprintf(dev_path, "/dev/infiniband/%s",
					verbs_device->sysfs->sysfs_name);
		if(!strcmp(dev_path, abs_path)) {
			break;
		}
	}

	if(!ib_dev) {
		free(dev_list);
		return NULL;
	}

	if(p_ib_dev)
		*p_ib_dev = ib_dev;

	return verbs_device;
}

LATEST_SYMVER_FUNC(ibv_free_tmp_context, 1_1, "IBVERBS_1.1",
			void, struct ibv_context *context) {
	struct verbs_device *verbs_device;

	verbs_device = verbs_get_device(context->device);
	verbs_device->ops->free_tmp_context(context);
}

int ibv_post_resume_context(struct verbs_context *orig_ctx, struct ibv_context *new_ctx) {
	return get_ops(new_ctx)->copy_uar_list(orig_ctx, new_ctx);
}

LATEST_SYMVER_FUNC(ibv_pre_resume_context, 1_1, "IBVERBS_1.1",
			struct ibv_context *, struct ibv_device **dev_list,
			const struct ibv_resume_context_param *context_param) {
	int ctx_cmd_fd = -1;
	struct verbs_device *verbs_device;
	struct ibv_device *ib_dev = NULL;
	struct verbs_context *context_ex;
	int context_dir_fd;
	int info_fd;
	char fname[128];
	int ctx_async_fd = -1;
	int ret;

	signal_flag = 0;

	sprintf(fname, "/dev/infiniband/%s", context_param->cdev);
	ctx_cmd_fd = open(fname, O_RDWR | O_CLOEXEC);
	if(ctx_cmd_fd < 0) {
		return NULL;
	}

	if(ctx_cmd_fd != context_param->cmd_fd &&
					dup2(ctx_cmd_fd, context_param->cmd_fd) < 0) {
		close(ctx_cmd_fd);
		return NULL;
	}

	if(ctx_cmd_fd != context_param->cmd_fd) {
		close(ctx_cmd_fd);
	}

	verbs_device = get_verbs_device(&ib_dev, dev_list, context_param->cmd_fd);
	if(!verbs_device) {
		close(context_param->cmd_fd);
		return NULL;
	}

	context_ex = verbs_device->ops->pre_resume_context(ib_dev, context_param->cmd_fd);
	if(!context_ex) {
		return NULL;
	}

#if 0
	sprintf(fname, "/proc/rdma/%d/%d", rdma_getpid(&context_ex->context), context_ex->context.cmd_fd);
	context_dir_fd = open(fname, O_DIRECTORY);
	if(context_dir_fd < 0) {
		ibv_close_device(&context_ex->context);
		return -1;
	}

	if(dup2(context_dir_fd, context_dir_fd + 1000) < 0) {
		close(context_dir_fd);
		ibv_close_device(&context_ex->context);
		return -1;
	}

	close(context_dir_fd);
	context_dir_fd = context_dir_fd + 1000;
#endif

	return &context_ex->context;
}

LATEST_SYMVER_FUNC(ibv_resume_context, 1_1, "IBVERBS_1.1",
			struct ibv_context *, struct ibv_device **dev_list,
			const struct ibv_resume_context_param *context_param) {
	int ctx_cmd_fd = -1;
	struct verbs_device *verbs_device;
	struct ibv_device *ib_dev = NULL;
	struct verbs_context *context_ex;
	int context_dir_fd;
	int info_fd;
	char fname[128];
	int ctx_async_fd = -1;
	int ret;

	verbs_device = get_verbs_device(&ib_dev, dev_list, context_param->cmd_fd);
	if(!verbs_device) {
		close(context_param->cmd_fd);
		return NULL;
	}

	context_ex = verbs_device->ops->resume_context(ib_dev,
					context_param->cmd_fd, &ctx_async_fd,
					context_param->ctx_uaddr);

	if(ctx_async_fd < 0) {
		close(context_param->cmd_fd);
		return NULL;
	}

	set_lib_ops(context_ex);

	if(ctx_async_fd != context_param->async_fd &&
					dup2(ctx_async_fd, context_param->async_fd) < 0) {
		ibv_close_device(&context_ex->context);
		return NULL;
	}

	if(ctx_async_fd != context_param->async_fd)
		close(ctx_async_fd);

	context_ex->context.async_fd = context_param->async_fd;

	sprintf(fname, "/proc/rdma_uwrite/%d/%d/ctx_uaddr",
			rdma_getpid(&context_ex->context), context_ex->context.cmd_fd);
	info_fd = open(fname, O_WRONLY);
	if(info_fd < 0) {
		ibv_close_device(&context_ex->context);
		return NULL;
	}

	if(write(info_fd, &context_param->ctx_uaddr, sizeof(context_ex)) < 0) {
		close(info_fd);
		ibv_close_device(&context_ex->context);
		return NULL;
	}

	close(info_fd);
	return &context_ex->context;
}

struct ibv_context *ibv_import_device(int cmd_fd)
{
	struct verbs_device *verbs_device = NULL;
	struct verbs_context *context_ex;
	struct ibv_device **dev_list;
	struct ibv_context *ctx = NULL;
	struct stat st;
	int ret;
	int i;

	if (fstat(cmd_fd, &st) || !S_ISCHR(st.st_mode)) {
		errno = EINVAL;
		return NULL;
	}

	dev_list = ibv_get_device_list(NULL);
	if (!dev_list) {
		errno = ENODEV;
		return NULL;
	}

	for (i = 0; dev_list[i]; ++i) {
		if (verbs_get_device(dev_list[i])->sysfs->sysfs_cdev ==
					st.st_rdev) {
			verbs_device = verbs_get_device(dev_list[i]);
			break;
		}
	}

	if (!verbs_device) {
		errno = ENODEV;
		goto out;
	}

	if (!verbs_device->ops->import_context) {
		errno = EOPNOTSUPP;
		goto out;
	}

	/* In case the underlay cdev number was assigned in the meantime to
	 * other device as of some disassociate flow, the next call on the
	 * FD will end up with EIO (i.e. query_context command) and we should
	 * be safe from using the wrong device.
	 */
	context_ex = verbs_device->ops->import_context(&verbs_device->device, cmd_fd);
	if (!context_ex)
		goto out;

	set_lib_ops(context_ex);

	context_ex->priv->imported = true;
	ctx = &context_ex->context;
	ret = ibv_cmd_alloc_async_fd(ctx);
	if (ret) {
		ibv_close_device(ctx);
		ctx = NULL;
	}
out:
	ibv_free_device_list(dev_list);
	return ctx;
}

void verbs_uninit_context(struct verbs_context *context_ex)
{
	free(context_ex->priv);
	close(context_ex->context.cmd_fd);
	if (context_ex->context.async_fd != -1)
		close(context_ex->context.async_fd);
	ibverbs_device_put(context_ex->context.device);
}

LATEST_SYMVER_FUNC(ibv_close_device, 1_1, "IBVERBS_1.1",
		   int,
		   struct ibv_context *context)
{
	const struct verbs_context_ops *ops = get_ops(context);

	rbtree_del_context(context);

	ops->free_context(context);
	return 0;
}

LATEST_SYMVER_FUNC(ibv_get_async_event, 1_1, "IBVERBS_1.1",
		   int,
		   struct ibv_context *context,
		   struct ibv_async_event *event)
{
	struct ib_uverbs_async_event_desc ev;

	if (read(context->async_fd, &ev, sizeof ev) != sizeof ev)
		return -1;

	event->event_type = ev.event_type;

	switch (event->event_type) {
	case IBV_EVENT_CQ_ERR:
		event->element.cq = (void *) (uintptr_t) ev.element;
		break;

	case IBV_EVENT_QP_FATAL:
	case IBV_EVENT_QP_REQ_ERR:
	case IBV_EVENT_QP_ACCESS_ERR:
	case IBV_EVENT_COMM_EST:
	case IBV_EVENT_SQ_DRAINED:
	case IBV_EVENT_PATH_MIG:
	case IBV_EVENT_PATH_MIG_ERR:
	case IBV_EVENT_QP_LAST_WQE_REACHED:
		event->element.qp = (void *) (uintptr_t) ev.element;
		break;

	case IBV_EVENT_SRQ_ERR:
	case IBV_EVENT_SRQ_LIMIT_REACHED:
		event->element.srq = (void *) (uintptr_t) ev.element;
		break;

	case IBV_EVENT_WQ_FATAL:
		event->element.wq = (void *) (uintptr_t) ev.element;
		break;
	default:
		event->element.port_num = ev.element;
		break;
	}

	get_ops(context)->async_event(context, event);

	return 0;
}

LATEST_SYMVER_FUNC(ibv_ack_async_event, 1_1, "IBVERBS_1.1",
		   void,
		   struct ibv_async_event *event)
{
	switch (event->event_type) {
	case IBV_EVENT_CQ_ERR:
	{
		struct ibv_cq *cq = event->element.cq;

		pthread_mutex_lock(&cq->mutex);
		++cq->async_events_completed;
		pthread_cond_signal(&cq->cond);
		pthread_mutex_unlock(&cq->mutex);

		return;
	}

	case IBV_EVENT_QP_FATAL:
	case IBV_EVENT_QP_REQ_ERR:
	case IBV_EVENT_QP_ACCESS_ERR:
	case IBV_EVENT_COMM_EST:
	case IBV_EVENT_SQ_DRAINED:
	case IBV_EVENT_PATH_MIG:
	case IBV_EVENT_PATH_MIG_ERR:
	case IBV_EVENT_QP_LAST_WQE_REACHED:
	{
		struct ibv_qp *qp = event->element.qp;

		pthread_mutex_lock(&qp->mutex);
		++qp->events_completed;
		pthread_cond_signal(&qp->cond);
		pthread_mutex_unlock(&qp->mutex);

		return;
	}

	case IBV_EVENT_SRQ_ERR:
	case IBV_EVENT_SRQ_LIMIT_REACHED:
	{
		struct ibv_srq *srq = event->element.srq;

		pthread_mutex_lock(&srq->mutex);
		++srq->events_completed;
		pthread_cond_signal(&srq->cond);
		pthread_mutex_unlock(&srq->mutex);

		return;
	}

	case IBV_EVENT_WQ_FATAL:
	{
		struct ibv_wq *wq = event->element.wq;

		pthread_mutex_lock(&wq->mutex);
		++wq->events_completed;
		pthread_cond_signal(&wq->cond);
		pthread_mutex_unlock(&wq->mutex);

		return;
	}

	default:
		return;
	}
}
