/*
 * Copyright (c) 2005 Topspin Communications.  All rights reserved.
 * Copyright (c) 2006, 2007 Cisco Systems, Inc.  All rights reserved.
 * Copyright (c) 2020 Intel Corperation.  All rights reserved.
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
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <linux/ip.h>
#include <dirent.h>
#include <netinet/in.h>

#include <util/compiler.h>
#include <util/symver.h>
#include <infiniband/cmd_write.h>

#include "ibverbs.h"
#include <net/if.h>
#include <net/if_arp.h>
#include "neigh.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>

#undef ibv_query_port

int __attribute__((const)) ibv_rate_to_mult(enum ibv_rate rate)
{
	switch (rate) {
	case IBV_RATE_2_5_GBPS: return  1;
	case IBV_RATE_5_GBPS:   return  2;
	case IBV_RATE_10_GBPS:  return  4;
	case IBV_RATE_20_GBPS:  return  8;
	case IBV_RATE_30_GBPS:  return 12;
	case IBV_RATE_40_GBPS:  return 16;
	case IBV_RATE_60_GBPS:  return 24;
	case IBV_RATE_80_GBPS:  return 32;
	case IBV_RATE_120_GBPS: return 48;
	case IBV_RATE_28_GBPS:  return 11;
	case IBV_RATE_50_GBPS:  return 20;
	case IBV_RATE_400_GBPS: return 160;
	case IBV_RATE_600_GBPS: return 240;
	default:           return -1;
	}
}

enum ibv_rate __attribute__((const)) mult_to_ibv_rate(int mult)
{
	switch (mult) {
	case 1:  return IBV_RATE_2_5_GBPS;
	case 2:  return IBV_RATE_5_GBPS;
	case 4:  return IBV_RATE_10_GBPS;
	case 8:  return IBV_RATE_20_GBPS;
	case 12: return IBV_RATE_30_GBPS;
	case 16: return IBV_RATE_40_GBPS;
	case 24: return IBV_RATE_60_GBPS;
	case 32: return IBV_RATE_80_GBPS;
	case 48: return IBV_RATE_120_GBPS;
	case 11: return IBV_RATE_28_GBPS;
	case 20: return IBV_RATE_50_GBPS;
	case 160: return IBV_RATE_400_GBPS;
	case 240: return IBV_RATE_600_GBPS;
	default: return IBV_RATE_MAX;
	}
}

int  __attribute__((const)) ibv_rate_to_mbps(enum ibv_rate rate)
{
	switch (rate) {
	case IBV_RATE_2_5_GBPS: return 2500;
	case IBV_RATE_5_GBPS:   return 5000;
	case IBV_RATE_10_GBPS:  return 10000;
	case IBV_RATE_20_GBPS:  return 20000;
	case IBV_RATE_30_GBPS:  return 30000;
	case IBV_RATE_40_GBPS:  return 40000;
	case IBV_RATE_60_GBPS:  return 60000;
	case IBV_RATE_80_GBPS:  return 80000;
	case IBV_RATE_120_GBPS: return 120000;
	case IBV_RATE_14_GBPS:  return 14062;
	case IBV_RATE_56_GBPS:  return 56250;
	case IBV_RATE_112_GBPS: return 112500;
	case IBV_RATE_168_GBPS: return 168750;
	case IBV_RATE_25_GBPS:  return 25781;
	case IBV_RATE_100_GBPS: return 103125;
	case IBV_RATE_200_GBPS: return 206250;
	case IBV_RATE_300_GBPS: return 309375;
	case IBV_RATE_28_GBPS:  return 28125;
	case IBV_RATE_50_GBPS:  return 53125;
	case IBV_RATE_400_GBPS: return 425000;
	case IBV_RATE_600_GBPS: return 637500;
	default:               return -1;
	}
}

enum ibv_rate __attribute__((const)) mbps_to_ibv_rate(int mbps)
{
	switch (mbps) {
	case 2500:   return IBV_RATE_2_5_GBPS;
	case 5000:   return IBV_RATE_5_GBPS;
	case 10000:  return IBV_RATE_10_GBPS;
	case 20000:  return IBV_RATE_20_GBPS;
	case 30000:  return IBV_RATE_30_GBPS;
	case 40000:  return IBV_RATE_40_GBPS;
	case 60000:  return IBV_RATE_60_GBPS;
	case 80000:  return IBV_RATE_80_GBPS;
	case 120000: return IBV_RATE_120_GBPS;
	case 14062:  return IBV_RATE_14_GBPS;
	case 56250:  return IBV_RATE_56_GBPS;
	case 112500: return IBV_RATE_112_GBPS;
	case 168750: return IBV_RATE_168_GBPS;
	case 25781:  return IBV_RATE_25_GBPS;
	case 103125: return IBV_RATE_100_GBPS;
	case 206250: return IBV_RATE_200_GBPS;
	case 309375: return IBV_RATE_300_GBPS;
	case 28125:  return IBV_RATE_28_GBPS;
	case 53125:  return IBV_RATE_50_GBPS;
	case 425000: return IBV_RATE_400_GBPS;
	case 637500: return IBV_RATE_600_GBPS;
	default:     return IBV_RATE_MAX;
	}
}

LATEST_SYMVER_FUNC(ibv_query_device, 1_1, "IBVERBS_1.1",
		   int,
		   struct ibv_context *context,
		   struct ibv_device_attr *device_attr)
{
	return get_ops(context)->query_device_ex(
		context, NULL,
		container_of(device_attr, struct ibv_device_attr_ex, orig_attr),
		sizeof(*device_attr));
}

int __lib_query_port(struct ibv_context *context, uint8_t port_num,
		     struct ibv_port_attr *port_attr, size_t port_attr_len)
{
	/* Don't expose this mess to the provider, provide a large enough
	 * temporary buffer if the user buffer is too small.
	 */
	if (port_attr_len < sizeof(struct ibv_port_attr)) {
		struct ibv_port_attr tmp_attr = {};
		int rc;

		rc = get_ops(context)->query_port(context, port_num,
						    &tmp_attr);
		if (rc)
			return rc;

		memcpy(port_attr, &tmp_attr, port_attr_len);
		return 0;
	}

	memset(port_attr, 0, port_attr_len);
	return get_ops(context)->query_port(context, port_num, port_attr);
}

struct _compat_ibv_port_attr {
	enum ibv_port_state state;
	enum ibv_mtu max_mtu;
	enum ibv_mtu active_mtu;
	int gid_tbl_len;
	uint32_t port_cap_flags;
	uint32_t max_msg_sz;
	uint32_t bad_pkey_cntr;
	uint32_t qkey_viol_cntr;
	uint16_t pkey_tbl_len;
	uint16_t lid;
	uint16_t sm_lid;
	uint8_t lmc;
	uint8_t max_vl_num;
	uint8_t sm_sl;
	uint8_t subnet_timeout;
	uint8_t init_type_reply;
	uint8_t active_width;
	uint8_t active_speed;
	uint8_t phys_state;
	uint8_t link_layer;
	uint8_t flags;
};

LATEST_SYMVER_FUNC(ibv_query_port, 1_1, "IBVERBS_1.1",
		   int,
		   struct ibv_context *context, uint8_t port_num,
		   struct _compat_ibv_port_attr *port_attr)
{
	return __lib_query_port(context, port_num,
				(struct ibv_port_attr *)port_attr,
				sizeof(*port_attr));
}

static int read_gid_table_from_uwrite(struct ibv_context *context, int index,
									union ibv_gid *gid) {
	char fname[128];
	struct footprint_gid_entry entries[256];
	int fd;

	sprintf(fname, "/proc/rdma_uwrite/%d/%d/gid_table", rdma_getpid(context), context->cmd_fd);
	fd = open(fname, O_RDONLY);
	if(fd < 0) {
		return errno;
	}

	if(read(fd, entries, sizeof(entries)) < 0) {
		close(fd);
		return errno;
	}

	close(fd);
	memcpy(gid, &entries[index].gid, sizeof(*gid));

	return 0;
}

LATEST_SYMVER_FUNC(ibv_query_gid, 1_1, "IBVERBS_1.1",
		   int,
		   struct ibv_context *context, uint8_t port_num,
		   int index, union ibv_gid *gid)
{
	return read_gid_table_from_uwrite(context, index, gid);
#if 0
	struct ibv_gid_entry entry = {};
	int ret;

	ret = __ibv_query_gid_ex(context, port_num, index, &entry, 0,
				 sizeof(entry), VERBS_QUERY_GID_ATTR_GID);
	/* Preserve API behavior for empty GID */
	if (ret == ENODATA) {
		memset(gid, 0, sizeof(*gid));
		return 0;
	}
	if (ret)
		return -1;

	memcpy(gid, &entry.gid, sizeof(entry.gid));

	read_gid_table_from_uwrite(context);

	return 0;
#endif
}

LATEST_SYMVER_FUNC(ibv_query_pkey, 1_1, "IBVERBS_1.1",
		   int,
		   struct ibv_context *context, uint8_t port_num,
		   int index, __be16 *pkey)
{
	struct verbs_device *verbs_device = verbs_get_device(context->device);
	char attr[8];
	uint16_t val;

	if (ibv_read_ibdev_sysfs_file(attr, sizeof(attr), verbs_device->sysfs,
				      "ports/%d/pkeys/%d", port_num, index) < 0)
		return -1;

	if (sscanf(attr, "%hx", &val) != 1)
		return -1;

	*pkey = htobe16(val);
	return 0;
}

LATEST_SYMVER_FUNC(ibv_get_pkey_index, 1_5, "IBVERBS_1.5",
		   int,
		   struct ibv_context *context, uint8_t port_num, __be16 pkey)
{
	__be16 pkey_i;
	int i, ret;

	for (i = 0; ; i++) {
		ret = ibv_query_pkey(context, port_num, i, &pkey_i);
		if (ret < 0)
			return ret;
		if (pkey == pkey_i)
			return i;
	}
}

LATEST_SYMVER_FUNC(ibv_alloc_pd, 1_1, "IBVERBS_1.1",
		   struct ibv_pd *,
		   struct ibv_context *context)
{
	struct ibv_pd *pd;

	pd = get_ops(context)->alloc_pd(context);
	if (pd)
		pd->context = context;

	if(ibv_cmd_install_pd_handle_mapping(context, pd->handle, pd->handle)) {
		get_ops(pd->context)->dealloc_pd(pd);
		return NULL;
	}

	return pd;
}

LATEST_SYMVER_FUNC(ibv_resume_pd, 1_1, "IBVERBS_1.1",
			struct ibv_pd *, struct ibv_context *context, int vhandle) {
	struct ibv_pd *pd;

	pd = get_ops(context)->alloc_pd(context);
	if (pd)
		pd->context = context;
	
	if(ibv_cmd_install_pd_handle_mapping(context, vhandle, pd->handle)) {
		get_ops(pd->context)->dealloc_pd(pd);
		return NULL;
	}

	pd->handle = vhandle;
	return pd;
}

LATEST_SYMVER_FUNC(ibv_dealloc_pd, 1_1, "IBVERBS_1.1",
		   int,
		   struct ibv_pd *pd)
{
	return get_ops(pd->context)->dealloc_pd(pd);
}

static uint32_t get_first_empty_slot_for_lkey(struct ibv_context *context) {
	uint32_t *lkey_arr = context->lkey_mapping;
	uint32_t i;

	for(i = 0; i < getpagesize() / sizeof(uint32_t) && lkey_arr[i]; i++);

	if(i >= getpagesize() / sizeof(uint32_t))
		return -1;

	return i;
}

static uint32_t get_first_empty_slot_for_rkey(struct ibv_context *context) {
	uint32_t *rkey_arr = context->rkey_mapping;
	uint32_t i;

	for(i = 0; i < getpagesize() / sizeof(uint32_t) && rkey_arr[i]; i++);

	if(i >= getpagesize() / sizeof(uint32_t))
		return -1;

	return i;
}

struct ibv_mr *ibv_reg_mr_iova2(struct ibv_pd *pd, void *addr, size_t length,
				uint64_t iova, unsigned int access)
{
	struct verbs_device *device = verbs_get_device(pd->context->device);
	bool odp_mr = access & IBV_ACCESS_ON_DEMAND;
	struct ibv_mr *mr;
	char fname[128];
	int mr_dir_fd;
	int info_fd;
	uint32_t vlkey, vrkey;

	if (!(device->core_support & IB_UVERBS_CORE_SUPPORT_OPTIONAL_MR_ACCESS))
		access &= ~IBV_ACCESS_OPTIONAL_RANGE;

	if (!odp_mr && ibv_dontfork_range(addr, length))
		return NULL;

	mr = get_ops(pd->context)->reg_mr(pd, addr, length, iova, access);
	if (mr) {
		mr->context = pd->context;
		mr->pd      = pd;
		mr->addr    = addr;
		mr->length  = length;
	} else {
		if (!odp_mr)
			ibv_dofork_range(addr, length);
		return NULL;
	}

	if(ibv_cmd_install_mr_handle_mapping(pd->context, mr->handle, mr->handle)) {
		ibv_dereg_mr(mr);
		return NULL;
	}

	vlkey = get_first_empty_slot_for_lkey(pd->context);
	if(ibv_cmd_install_lkey_mapping(pd->context, vlkey, mr->lkey)) {
		ibv_dereg_mr(mr);
		return NULL;
	}

	mr->lkey = vlkey;

	vrkey = get_first_empty_slot_for_rkey(pd->context);
	if(ibv_cmd_install_local_rkey_mapping(pd->context, vrkey, mr->rkey)) {
		ibv_dereg_mr(mr);
		return NULL;
	}

	mr->rkey = vrkey;

	sprintf(fname, "/proc/rdma_uwrite/%d/%d/mr_%d/",
				rdma_getpid(pd->context), pd->context->cmd_fd, mr->handle);
	mr_dir_fd = open(fname, O_DIRECTORY);
	if(mr_dir_fd < 0) {
		ibv_dereg_mr(mr);
		return NULL;
	}

	info_fd = openat(mr_dir_fd, "vlkey", O_WRONLY);
	if(info_fd < 0) {
		close(mr_dir_fd);
		ibv_dereg_mr(mr);
		return NULL;
	}

	if(write(info_fd, &mr->lkey, sizeof(mr->lkey)) < 0) {
		close(info_fd);
		close(mr_dir_fd);
		ibv_dereg_mr(mr);
		return NULL;
	}

	close(info_fd);
	info_fd = openat(mr_dir_fd, "vrkey", O_WRONLY);
	if(info_fd < 0) {
		close(mr_dir_fd);
		ibv_dereg_mr(mr);
		return NULL;
	}

	if(write(info_fd, &mr->rkey, sizeof(mr->rkey)) < 0) {
		close(info_fd);
		close(mr_dir_fd);
		ibv_dereg_mr(mr);
		return NULL;
	}

	close(info_fd);
	close(mr_dir_fd);

	return mr;
}

#undef ibv_reg_mr
LATEST_SYMVER_FUNC(ibv_reg_mr, 1_1, "IBVERBS_1.1",
		   struct ibv_mr *,
		   struct ibv_pd *pd, void *addr,
		   size_t length, int access)
{
	return ibv_reg_mr_iova2(pd, addr, length, (uintptr_t)addr, access);
}

static struct ibv_mr *__ibv_reg_mr_iova2(struct ibv_pd *pd, void *addr, size_t length,
				uint64_t iova, unsigned int access, int mr_handle, uint32_t vlkey, uint32_t vrkey)
{
	struct verbs_device *device = verbs_get_device(pd->context->device);
	bool odp_mr = access & IBV_ACCESS_ON_DEMAND;
	struct ibv_mr *mr;

	if (!(device->core_support & IB_UVERBS_CORE_SUPPORT_OPTIONAL_MR_ACCESS))
		access &= ~IBV_ACCESS_OPTIONAL_RANGE;

	if (!odp_mr && ibv_dontfork_range(addr, length))
		return NULL;

	mr = get_ops(pd->context)->reg_mr(pd, addr, length, iova, access);
	if (mr) {
		mr->context = pd->context;
		mr->pd      = pd;
		mr->addr    = addr;
		mr->length  = length;
	} else {
		if (!odp_mr)
			ibv_dofork_range(addr, length);
	}

	if(ibv_cmd_install_mr_handle_mapping(pd->context, mr_handle, mr->handle)) {
		ibv_dereg_mr(mr);
		return NULL;
	}

	if(ibv_cmd_install_lkey_mapping(pd->context, vlkey, mr->lkey)) {
		ibv_dereg_mr(mr);
		return NULL;
	}

	if(ibv_cmd_install_local_rkey_mapping(pd->context, vrkey, mr->rkey)) {
		ibv_dereg_mr(mr);
		return NULL;
	}

	return mr;
}

LATEST_SYMVER_FUNC(ibv_resume_mr, 1_1, "IBVERBS_1.1",
			int, struct ibv_context *context, struct ibv_pd *pd,
					const struct ibv_resume_mr_param *mr_param) {
	struct ibv_mr *mr;
	char fname[128];
	int mr_dir_fd;
	int info_fd;

	pd->handle = mr_param->pd_vhandle;
	mr = __ibv_reg_mr_iova2(pd, mr_param->iova, mr_param->length,
							(uintptr_t)mr_param->iova,
							mr_param->access_flags, mr_param->mr_vhandle,
							mr_param->vlkey, mr_param->vrkey);
	if(!mr) {
		return -1;
	}

	mr->context			= context;
	mr->pd				= pd;
	mr->addr			= mr_param->iova;
	mr->length			= mr_param->length;
	mr->handle			= mr_param->mr_vhandle;
	mr->lkey			= mr_param->vlkey;
	mr->rkey			= mr_param->vrkey;

	sprintf(fname, "/proc/rdma_uwrite/%d/%d/mr_%d/",
				rdma_getpid(context), pd->context->cmd_fd, mr_param->mr_vhandle);
	mr_dir_fd = open(fname, O_DIRECTORY);
	if(mr_dir_fd < 0) {
		ibv_dereg_mr(mr);
		return -errno;
	}

	info_fd = openat(mr_dir_fd, "vlkey", O_WRONLY);
	if(info_fd < 0) {
		close(mr_dir_fd);
		ibv_dereg_mr(mr);
		return -1;
	}

	if(write(info_fd, &mr->lkey, sizeof(mr->lkey)) < 0) {
		close(info_fd);
		close(mr_dir_fd);
		ibv_dereg_mr(mr);
		return -1;
	}

	close(info_fd);

	info_fd = openat(mr_dir_fd, "vrkey", O_WRONLY);
	if(info_fd < 0) {
		close(mr_dir_fd);
		ibv_dereg_mr(mr);
		return -1;
	}

	if(write(info_fd, &mr->rkey, sizeof(mr->rkey)) < 0) {
		close(info_fd);
		close(mr_dir_fd);
		ibv_dereg_mr(mr);
		return -1;
	}

	close(info_fd);
	close(mr_dir_fd);
	return 0;
}

#undef ibv_reg_mr_iova
struct ibv_mr *ibv_reg_mr_iova(struct ibv_pd *pd, void *addr, size_t length,
			       uint64_t iova, int access)
{
	return ibv_reg_mr_iova2(pd, addr, length, iova, access);
}

struct ibv_pd *ibv_import_pd(struct ibv_context *context,
			     uint32_t pd_handle)
{
	return get_ops(context)->import_pd(context, pd_handle);
}


void ibv_unimport_pd(struct ibv_pd *pd)
{
	get_ops(pd->context)->unimport_pd(pd);
}


/**
 * ibv_import_mr - Import a memory region
 */
struct ibv_mr *ibv_import_mr(struct ibv_pd *pd, uint32_t mr_handle)
{
	return get_ops(pd->context)->import_mr(pd, mr_handle);
}

/**
 * ibv_unimport_mr - Unimport a memory region
 */
void ibv_unimport_mr(struct ibv_mr *mr)
{
	get_ops(mr->context)->unimport_mr(mr);
}

/**
 * ibv_import_dm - Import a device memory
 */
struct ibv_dm *ibv_import_dm(struct ibv_context *context, uint32_t dm_handle)
{
	return get_ops(context)->import_dm(context, dm_handle);
}

/**
 * ibv_unimport_dm - Unimport a device memory
 */
void ibv_unimport_dm(struct ibv_dm *dm)
{
	get_ops(dm->context)->unimport_dm(dm);
}

struct ibv_mr *ibv_reg_dmabuf_mr(struct ibv_pd *pd, uint64_t offset,
				 size_t length, uint64_t iova, int fd,
				 int access)
{
	struct ibv_mr *mr;

	mr = get_ops(pd->context)->reg_dmabuf_mr(pd, offset, length, iova,
						 fd, access);
	if (!mr)
		return NULL;

	mr->context = pd->context;
	mr->pd = pd;
	mr->addr = (void *)(uintptr_t)offset;
	mr->length = length;
	return mr;
}

LATEST_SYMVER_FUNC(ibv_rereg_mr, 1_1, "IBVERBS_1.1",
		   int,
		   struct ibv_mr *mr, int flags,
		   struct ibv_pd *pd, void *addr,
		   size_t length, int access)
{
	int dofork_onfail = 0;
	int err;
	void *old_addr;
	size_t old_len;

	if (verbs_get_mr(mr)->mr_type != IBV_MR_TYPE_MR) {
		errno = EINVAL;
		return IBV_REREG_MR_ERR_INPUT;
	}

	if (flags & ~IBV_REREG_MR_FLAGS_SUPPORTED) {
		errno = EINVAL;
		return IBV_REREG_MR_ERR_INPUT;
	}

	if ((flags & IBV_REREG_MR_CHANGE_TRANSLATION) &&
	    (!length || !addr)) {
		errno = EINVAL;
		return IBV_REREG_MR_ERR_INPUT;
	}

	if (access && !(flags & IBV_REREG_MR_CHANGE_ACCESS)) {
		errno = EINVAL;
		return IBV_REREG_MR_ERR_INPUT;
	}

	if (flags & IBV_REREG_MR_CHANGE_TRANSLATION) {
		err = ibv_dontfork_range(addr, length);
		if (err)
			return IBV_REREG_MR_ERR_DONT_FORK_NEW;
		dofork_onfail = 1;
	}

	old_addr = mr->addr;
	old_len = mr->length;
	err = get_ops(mr->context)->rereg_mr(verbs_get_mr(mr),
					     flags, pd, addr,
					     length, access);
	if (!err) {
		if (flags & IBV_REREG_MR_CHANGE_PD)
			mr->pd = pd;
		if (flags & IBV_REREG_MR_CHANGE_TRANSLATION) {
			mr->addr    = addr;
			mr->length  = length;
			err = ibv_dofork_range(old_addr, old_len);
			if (err)
				return IBV_REREG_MR_ERR_DO_FORK_OLD;
		}
	} else {
		err = IBV_REREG_MR_ERR_CMD;
		if (dofork_onfail) {
			if (ibv_dofork_range(addr, length))
				err = IBV_REREG_MR_ERR_CMD_AND_DO_FORK_NEW;
		}
	}

	return err;
}

LATEST_SYMVER_FUNC(ibv_dereg_mr, 1_1, "IBVERBS_1.1",
		   int,
		   struct ibv_mr *mr)
{
	int ret;
	void *addr		= mr->addr;
	size_t length		= mr->length;
	enum ibv_mr_type type	= verbs_get_mr(mr)->mr_type;
	int access = verbs_get_mr(mr)->access;

	ibv_cmd_delete_lkey_mapping(mr->context, mr->lkey);
	ibv_cmd_delete_local_rkey_mapping(mr->context, mr->rkey);

	ret = get_ops(mr->context)->dereg_mr(verbs_get_mr(mr));
	if (!ret && type == IBV_MR_TYPE_MR && !(access & IBV_ACCESS_ON_DEMAND))
		ibv_dofork_range(addr, length);

	return ret;
}

struct ibv_comp_channel *ibv_create_comp_channel(struct ibv_context *context)
{
	struct ibv_create_comp_channel req;
	struct ib_uverbs_create_comp_channel_resp resp;
	struct ibv_comp_channel            *channel;

	channel = malloc(sizeof *channel);
	if (!channel)
		return NULL;

	req.core_payload = (struct ib_uverbs_create_comp_channel){};
	if (execute_cmd_write(context, IB_USER_VERBS_CMD_CREATE_COMP_CHANNEL,
			      &req, sizeof(req), &resp, sizeof(resp))) {
		free(channel);
		return NULL;
	}

	channel->context = context;
	channel->fd      = resp.fd;
	channel->refcnt  = 0;

	return channel;
}

int ibv_resume_comp_channel(struct ibv_context *context, int comp_fd) {
	struct ibv_create_comp_channel req;
	struct ib_uverbs_create_comp_channel_resp resp;
	struct ibv_comp_channel            *channel;

	channel = malloc(sizeof *channel);
	if (!channel)
		return -1;

	req.core_payload = (struct ib_uverbs_create_comp_channel){};
	if (execute_cmd_write(context, IB_USER_VERBS_CMD_CREATE_COMP_CHANNEL,
			      &req, sizeof(req), &resp, sizeof(resp))) {
		free(channel);
		return -1;
	}

	if(resp.fd != comp_fd && dup2(resp.fd, comp_fd) < 0) {
		free(channel);
		return -1;
	}

	if(resp.fd != comp_fd) {
		close(resp.fd);
		resp.fd = comp_fd;
	}

	channel->context = context;
	channel->fd      = resp.fd;
	channel->refcnt  = 0;

	if(add_comp_channel(channel->fd, channel)) {
		free(channel);
		return -1;
	}

	if(ibv_cmd_update_comp_channel_fd(context, channel)) {
		free(channel);
		return -1;
	}

	return 0;
}

int ibv_destroy_comp_channel(struct ibv_comp_channel *channel)
{
	struct ibv_context *context;
	int ret;

	context = channel->context;
	pthread_mutex_lock(&context->mutex);

	if (channel->refcnt) {
		ret = EBUSY;
		goto out;
	}

	close(channel->fd);
	free(channel);
	ret = 0;

out:
	pthread_mutex_unlock(&context->mutex);

	return ret;
}

static int write_cq_meta_uaddr(struct ibv_context *context,
						struct ibv_cq *cq, void *cq_meta_addr) {
	char meta_uaddr_fname[128];
	int fd;
	ssize_t size;

	sprintf(meta_uaddr_fname, "/proc/rdma_uwrite/%d/%d/cq_%d/meta_uaddr",
					rdma_getpid(context), context->cmd_fd, cq->handle);
	
	fd = open(meta_uaddr_fname, O_WRONLY);
	if(fd < 0) {
		return -1;
	}

	size = write(fd, &cq_meta_addr, sizeof(cq_meta_addr));
	if(size < 0) {
		close(fd);
		return -1;
	}

	close(fd);
	return 0;
}

LATEST_SYMVER_FUNC(ibv_create_cq, 1_1, "IBVERBS_1.1",
		   struct ibv_cq *,
		   struct ibv_context *context, int cqe, void *cq_context,
		   struct ibv_comp_channel *channel, int comp_vector)
{
	struct ibv_cq *cq;

	cq = get_ops(context)->create_cq(context, cqe, channel, comp_vector);

	if (cq)
		verbs_init_cq(cq, context, channel, cq_context);
	
	if(!cq)
		return NULL;

	if(write_cq_meta_uaddr(context, cq, cq)) {
		ibv_destroy_cq(cq);
		return NULL;
	}

	if(rbtree_add_cq(cq)) {
		ibv_destroy_cq(cq);
		return NULL;
	}

	cq->arm_flag = 0;
	cq->wc = NULL;
	cq->qps = NULL;
	cq->srqs = NULL;
	cq->stop_flag = 0;

	return cq;
}

LATEST_SYMVER_FUNC(ibv_resume_cq, 1_1, "IBVERBS_1.1",
			struct ibv_cq *, struct ibv_context *context,
			const struct ibv_resume_cq_param *cq_param) {
	struct ibv_cq *cq;
	struct ibv_comp_channel *channel;
	struct ibv_cq *orig_cq = cq_param->meta_uaddr;

	channel = get_comp_channel_from_fd(cq_param->comp_fd);

#if 0
	if(get_ops(context)->uwrite_cq((struct ibv_cq *)cq_param->meta_uaddr, 0)) {
		return NULL;
	}
#endif

	cq = get_ops(context)->resume_cq(context, cq_param->meta_uaddr, cq_param->cq_size,
				channel, 0, cq_param->buf_addr, cq_param->db_addr, cq_param->cq_vhandle);
	if(!cq)
		return NULL;

	cq->context = context;
	cq->handle = cq_param->cq_vhandle;
	if(write_cq_meta_uaddr(context, cq, cq_param->meta_uaddr)) {
		ibv_destroy_cq(cq);
		return NULL;
	}

#if 0
	if(rbtree_add_cq(cq_param->meta_uaddr)) {
		ibv_destroy_cq(cq);
		return NULL;
	}
#endif

	cq->arm_flag = 0;
	orig_cq->stop_flag = 0;

	return cq;
}

LATEST_SYMVER_FUNC(ibv_resize_cq, 1_1, "IBVERBS_1.1",
		   int,
		   struct ibv_cq *cq, int cqe)
{
	return get_ops(cq->context)->resize_cq(cq, cqe);
}

LATEST_SYMVER_FUNC(ibv_destroy_cq, 1_1, "IBVERBS_1.1",
		   int,
		   struct ibv_cq *cq)
{
	struct ibv_comp_channel *channel = cq->channel;
	int ret;

	rbtree_del_cq(cq);

	ret = get_ops(cq->context)->destroy_cq(cq);

	if (channel) {
		if (!ret) {
			pthread_mutex_lock(&channel->context->mutex);
			--channel->refcnt;
			pthread_mutex_unlock(&channel->context->mutex);
		}
	}

	return ret;
}

LATEST_SYMVER_FUNC(ibv_get_cq_event, 1_1, "IBVERBS_1.1",
		   int,
		   struct ibv_comp_channel *channel,
		   struct ibv_cq **cq, void **cq_context)
{
	struct ib_uverbs_comp_event_desc ev;

	if (read(channel->fd, &ev, sizeof ev) != sizeof ev)
		return -1;

	*cq         = (struct ibv_cq *) (uintptr_t) ev.cq_handle;
	*cq_context = (*cq)->cq_context;

	(*cq)->arm_flag = 0;
	if(ev.flag)
		get_ops((*cq)->context)->cq_event(*cq);
	else {
		pthread_mutex_lock(&(*cq)->mutex);
		(*cq)->comp_events_completed--;
		pthread_mutex_unlock(&(*cq)->mutex);
	}

	return 0;
}

LATEST_SYMVER_FUNC(ibv_ack_cq_events, 1_1, "IBVERBS_1.1",
		   void,
		   struct ibv_cq *cq, unsigned int nevents)
{
	pthread_mutex_lock(&cq->mutex);
	cq->comp_events_completed += nevents;
	pthread_cond_signal(&cq->cond);
	pthread_mutex_unlock(&cq->mutex);
}

static int write_srq_umeta_addr(struct ibv_context *context, struct ibv_srq *srq,
				void *srq_meta_addr, struct ibv_srq_init_attr *srq_init_attr) {
	char srq_dir_name[128];
	int srq_dir_fd;
	int info_fd;

	sprintf(srq_dir_name, "/proc/rdma_uwrite/%d/%d/srq_%d/",
					rdma_getpid(context), context->cmd_fd, srq->handle);
	srq_dir_fd = open(srq_dir_name, O_DIRECTORY);
	if(srq_dir_fd < 0) {
		return -1;
	}

	info_fd = openat(srq_dir_fd, "meta_uaddr", O_WRONLY);
	if(info_fd < 0) {
		close(srq_dir_fd);
		return -1;
	}

	if(write(info_fd, &srq_meta_addr, sizeof(srq_meta_addr)) < 0) {
		close(info_fd);
		close(srq_dir_fd);
		return -1;
	}

	close(info_fd);

	info_fd = openat(srq_dir_fd, "srq_init_attr", O_WRONLY);
	if(info_fd < 0) {
		close(srq_dir_fd);
		return -1;
	}

	if(write(info_fd, srq_init_attr, sizeof(*srq_init_attr)) < 0) {
		close(info_fd);
		close(srq_dir_fd);
		return -1;
	}

	close(info_fd);
	close(srq_dir_fd);
	return 0;
}

LATEST_SYMVER_FUNC(ibv_create_srq, 1_1, "IBVERBS_1.1",
		   struct ibv_srq *,
		   struct ibv_pd *pd,
		   struct ibv_srq_init_attr *srq_init_attr)
{
	struct ibv_srq *srq;

	srq = get_ops(pd->context)->create_srq(pd, srq_init_attr);
	if (srq) {
		srq->context          = pd->context;
		srq->srq_context      = srq_init_attr->srq_context;
		srq->pd               = pd;
		srq->events_completed = 0;
		pthread_mutex_init(&srq->mutex, NULL);
		pthread_cond_init(&srq->cond, NULL);
	}

	srq->wait_srq_node = NULL;

	if(write_srq_umeta_addr(pd->context, srq, srq, srq_init_attr)) {
		ibv_destroy_srq(srq);
		return NULL;
	}

	if(rbtree_add_srq(srq)) {
		ibv_destroy_srq(srq);
		return NULL;
	}

	return srq;
}

LATEST_SYMVER_FUNC(ibv_resume_srq, 1_1, "IBVERBS_1.1",
		   struct ibv_srq *,
		   struct ibv_pd *pd,
		   struct ibv_resume_srq_param *srq_param) {
	struct ibv_srq *srq;

	if(get_ops(pd->context)->uwrite_srq(srq_param->meta_uaddr, 0)) {
		return NULL;
	}

	pd->handle = srq_param->pd_vhandle;
	srq = get_ops(pd->context)->resume_srq(pd, srq_param);
	if(!srq) {
		return NULL;
	}

	if (srq) {
		srq->context          = pd->context;
		srq->srq_context      = srq_param->init_attr.srq_context;
		srq->pd               = pd;
		srq->events_completed = 0;
		pthread_mutex_init(&srq->mutex, NULL);
		pthread_cond_init(&srq->cond, NULL);
	}

	if(write_srq_umeta_addr(pd->context, srq, srq_param->meta_uaddr,
						&srq_param->init_attr)) {
		ibv_destroy_srq(srq);
		return NULL;
	}

	if(add_srq_switch_node(srq, srq_param->meta_uaddr)) {
		perror("add_srq_switch_node");
		ibv_destroy_srq(srq);
		return NULL;
	}

	return srq;
}

LATEST_SYMVER_FUNC(ibv_modify_srq, 1_1, "IBVERBS_1.1",
		   int,
		   struct ibv_srq *srq,
		   struct ibv_srq_attr *srq_attr,
		   int srq_attr_mask)
{
	return get_ops(srq->context)->modify_srq(srq, srq_attr, srq_attr_mask);
}

LATEST_SYMVER_FUNC(ibv_query_srq, 1_1, "IBVERBS_1.1",
		   int,
		   struct ibv_srq *srq, struct ibv_srq_attr *srq_attr)
{
	return get_ops(srq->context)->query_srq(srq, srq_attr);
}

LATEST_SYMVER_FUNC(ibv_destroy_srq, 1_1, "IBVERBS_1.1",
		   int,
		   struct ibv_srq *srq)
{
	rbtree_del_srq(srq);
	return get_ops(srq->context)->destroy_srq(srq);
}

static int write_qp_umeta_addr(struct ibv_context *context, struct ibv_qp *qp,
					void *qp_meta_addr, struct ibv_qp_init_attr *qp_init_attr,
					uint32_t vqpn) {
	char qp_dir_fname[128];
	int qp_dir_fd;
	int info_fd;

	sprintf(qp_dir_fname, "/proc/rdma_uwrite/%d/%d/qp_%d/",
						rdma_getpid(context), context->cmd_fd, qp->handle);
	
	qp_dir_fd = open(qp_dir_fname, O_DIRECTORY);
	if(qp_dir_fd < 0) {
		return -1;
	}

	info_fd = openat(qp_dir_fd, "meta_uaddr", O_WRONLY);
	if(info_fd < 0) {
		close(qp_dir_fd);
		return -1;
	}

	if(write(info_fd, &qp_meta_addr, sizeof(qp_meta_addr)) < 0) {
		close(info_fd);
		close(qp_dir_fd);
		return -1;
	}

	close(info_fd);

	info_fd = openat(qp_dir_fd, "send_cq_handle", O_WRONLY);
	if(info_fd < 0) {
		close(qp_dir_fd);
		return -1;
	}

	if(write(info_fd, &qp->send_cq->handle, sizeof(qp->send_cq->handle)) < 0) {
		close(info_fd);
		close(qp_dir_fd);
		return -1;
	}

	close(info_fd);

	info_fd = openat(qp_dir_fd, "recv_cq_handle", O_WRONLY);
	if(info_fd < 0) {
		close(qp_dir_fd);
		return -1;
	}

	if(write(info_fd, &qp->recv_cq->handle, sizeof(qp->recv_cq->handle)) < 0) {
		close(info_fd);
		close(qp_dir_fd);
		return -1;
	}

	close(info_fd);

	info_fd = openat(qp_dir_fd, "init_attr", O_WRONLY);
	if(info_fd < 0) {
		close(qp_dir_fd);
		return -1;
	}

	if(write(info_fd, qp_init_attr, sizeof(*qp_init_attr)) < 0) {
		close(info_fd);
		close(qp_dir_fd);
		return -1;
	}

	close(info_fd);

	info_fd = openat(qp_dir_fd, "vqpn", O_WRONLY);
	if(info_fd < 0) {
		close(qp_dir_fd);
		return -1;
	}

	if(write(info_fd, &vqpn, sizeof(vqpn)) < 0) {
		close(info_fd);
		close(qp_dir_fd);
		return -1;
	}

	close(info_fd);
	close(qp_dir_fd);
	return 0;
}

static void pid_service(void *arg) {
	struct ibv_qp *qp = arg;
	struct sockaddr_in local_addr, remote_addr;
	socklen_t addrlen = sizeof(struct sockaddr_in);
	int sock;
	pid_t pid;
	ssize_t size;
	uint32_t qpn;
	int rcv_buf_sz = 4;
	int reuse = 1;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if(sock < 0) {
		return;
	}

	if(setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcv_buf_sz, sizeof(int))) {
		close(sock);
		exit(1);
	}

	if(setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(int))) {
		close(sock);
		exit(1);
	}

	local_addr.sin_family = AF_INET;
	local_addr.sin_port = htons(qp->qp_num % 65536 + 8000);
	local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	if(bind(sock, (struct sockaddr*)&local_addr, sizeof(local_addr))) {
		close(sock);
		exit(1);
	}

	size = recvfrom(sock, &pid, sizeof(pid), 0, &remote_addr, &addrlen);
	if(size != sizeof(pid)) {
		close(sock);
		exit(1);
	}

	pid = rdma_getpid(qp->context);
	size = sendto(sock, &pid, sizeof(pid), 0, &remote_addr, sizeof(remote_addr));
	if(size != sizeof(pid)) {
		close(sock);
		exit(1);
	}

	size = recvfrom(sock, &qpn, sizeof(qpn), 0, &remote_addr, &addrlen);
	if(size != sizeof(qpn)) {
		close(sock);
		exit(1);
	}

	qpn = qp->real_qpn;
	size = sendto(sock, &qpn, sizeof(qpn), 0, &remote_addr, sizeof(remote_addr));
	if(size != sizeof(qpn)) {
		close(sock);
		exit(1);
	}

	close(sock);
	return 0;
}

struct ibv_qp *ibv_pre_create_qp(struct ibv_pd *pd,
				struct ibv_qp_init_attr *qp_init_attr, uint32_t vqpn) {
	struct ibv_qp *qp = get_ops(pd->context)->create_qp(pd, qp_init_attr);
	int info_fd;
	char fname[128];
	pthread_t thread_id;

	if(!qp)
		return NULL;

	qp->real_qpn = qp->qp_num;

	if(write_qp_umeta_addr(pd->context, qp, qp, qp_init_attr, qp->qp_num)) {
		ibv_destroy_qp(qp);
		return NULL;
	}

	if(rbtree_add_qp(qp)) {
		ibv_destroy_qp(qp);
		return NULL;
	}

	if(add_qpn_dict_node(qp)) {
		ibv_destroy_qp(qp);
		return NULL;
	}

	qp->qp_num = vqpn;
	if(qp->qp_type != IBV_QPT_UD)
		pthread_create(&thread_id, NULL, pid_service, (void*)qp);

	pthread_rwlock_init(&qp->rwlock, NULL);

	if(ibv_cmd_install_qpndict(qp->context, qp->real_qpn,
				qp->qp_num)) {
		ibv_destroy_qp(qp);
		return NULL;
	}

	return qp;
}

LATEST_SYMVER_FUNC(ibv_create_qp, 1_1, "IBVERBS_1.1",
		   struct ibv_qp *,
		   struct ibv_pd *pd,
		   struct ibv_qp_init_attr *qp_init_attr)
{
	struct ibv_qp *qp = get_ops(pd->context)->create_qp(pd, qp_init_attr);
	int info_fd;
	char fname[128];
	pthread_t thread_id;

	if(!qp)
		return NULL;

	qp->real_qpn = qp->qp_num;
	qp->clear_qpndict_flag = 0;
	qp->wait_qp_node = NULL;

	if(write_qp_umeta_addr(pd->context, qp, qp, qp_init_attr, qp->qp_num)) {
		ibv_destroy_qp(qp);
		return NULL;
	}

	if(rbtree_add_qp(qp)) {
		ibv_destroy_qp(qp);
		return NULL;
	}

	if(add_qpn_dict_node(qp)) {
		ibv_destroy_qp(qp);
		return NULL;
	}

	if(ibv_cmd_install_qpndict(qp->context, qp->real_qpn,
				qp->qp_num)) {
		ibv_destroy_qp(qp);
		return NULL;
	}

	if(qp->qp_type != IBV_QPT_UD)
		pthread_create(&thread_id, NULL, pid_service, (void*)qp);

	pthread_rwlock_init(&qp->rwlock, NULL);
	return qp;
}

LATEST_SYMVER_FUNC(ibv_resume_create_qp, 1_1, "IBVERBS_1.1",
			struct ibv_qp *, struct ibv_context *context, struct ibv_pd *pd,
			struct ibv_cq *send_cq, struct ibv_cq *recv_cq, struct ibv_srq *srq,
			const struct ibv_resume_qp_param *qp_param, unsigned long long *bf_reg) {
	struct ibv_qp *qp_ptr = qp_param->meta_uaddr;
	struct ibv_qp *qp;
	struct ibv_qp_init_attr qp_init_attr;
	char fname[128];
	int info_fd;
	int err;
	pthread_t thread_id;

	if(get_ops(context)->uwrite_qp(qp_ptr, qp)) {
		return NULL;
	}

	memcpy(&qp_init_attr, &qp_param->init_attr, sizeof(qp_init_attr));

	send_cq->handle = qp_param->send_cq_handle;
	recv_cq->handle = qp_param->recv_cq_handle;
	qp_init_attr.send_cq = send_cq;
	qp_init_attr.recv_cq = recv_cq;
	qp_init_attr.srq = srq;
	
	qp = get_ops(context)->resume_qp(context, qp_param->pd_vhandle, qp_param->qp_vhandle,
					&qp_init_attr, qp_param->buf_addr, qp_param->db_addr,
					qp_param->usr_idx, qp_param->meta_uaddr, bf_reg);
	if(!qp) {
		return NULL;
	}

	qp->pd = pd;
	qp->send_cq = send_cq;
	qp->recv_cq = recv_cq;
	qp->real_qpn = qp->qp_num;
	
	qp->handle = qp_param->qp_vhandle;
	if(write_qp_umeta_addr(context, qp, qp_param->meta_uaddr,
						&qp_param->init_attr, qp_param->vqpn)) {
		ibv_destroy_qp(qp);
		return NULL;
	}

	qp->qp_num = qp_param->vqpn;

	qp_ptr->orig_real_qpn = qp_ptr->real_qpn;
	qp_ptr->real_qpn = qp->real_qpn;
	memcpy(&qp_ptr->local_gid, &qp->local_gid, sizeof(union ibv_gid));
	qp_ptr->pause_flag = 0;

	if(add_switch_list_node(qp->real_qpn, qp_ptr, qp)) {
		perror("add_switch_list_node");
		ibv_destroy_qp(qp);
		return NULL;
	}

	if(qp->qp_type != IBV_QPT_UD && qp_param->qp_state >= IBV_QPS_RTR)
		pthread_create(&thread_id, NULL, pid_service, (void*)qp);

	pthread_rwlock_init(&qp->rwlock, NULL);

	if(ibv_cmd_install_qpndict(qp->context, qp->real_qpn,
				qp->qp_num)) {
		ibv_destroy_qp(qp);
		return NULL;
	}

	return qp;
}

LATEST_SYMVER_FUNC(ibv_resume_free_qp, 1_1, "IBVERBS_1.1",
			void, struct ibv_qp *qp) {
	get_ops(qp->context)->free_qp(qp);
}

static int replay_recv_wr_cb(struct ibv_qp *orig_qp, struct ibv_qp *new_qp) {
	orig_qp->clear_qpndict_flag = 1;
	return get_ops(new_qp->context)->prepare_qp_recv_replay(orig_qp, new_qp);
}

static int replay_srq_recv_wr_cb(struct ibv_srq *orig_srq, struct ibv_qp *new_srq,
								int *head, int *tail) {
	return get_ops(new_srq->context)->prepare_srq_replay(orig_srq, new_srq, head, tail);
}

int iter_cq_insert_fake_comp_event(struct ibv_cq *cq,
					void *entry, void *in_param) {
	struct ib_uverbs_comp_event_desc desc;

	if(!cq->arm_flag)
		return 0;

	if(!cq->channel)
		return 0;

	desc.cq_handle = cq;
	if(write(cq->channel->fd, &desc, sizeof(desc)) < 0) {
		return -1;
	}

	return 0;
}

LATEST_SYMVER_FUNC(ibv_prepare_for_replay, 1_1, "IBVERBS_1.1",
			int, int (*qp_load_cb)(struct ibv_qp *orig_qp, void *replay_fn),
			int (*srq_load_cb)(struct ibv_srq *orig_srq, void *replay_fn, int head, int tail)) {
	return rbtree_traverse_cq(iter_cq_insert_fake_comp_event, NULL) ||
			switch_all_qps(replay_recv_wr_cb, qp_load_cb) ||
			switch_all_srqs(replay_srq_recv_wr_cb, srq_load_cb);
}

LATEST_SYMVER_FUNC(ibv_update_mem, 1_1, "IBVERBS_1.1",
			int,
			int (*update_mem_fn)(void *ptr, size_t size,
								void *content_p),
			int (*keep_mmap_fn)(unsigned long long start,
								unsigned long long end)) {
	int err;

	err = update_all_mem(update_mem_fn);
	if(err) {
		return err;
	}

	err = keep_all_mmap(keep_mmap_fn);
	return err;
}

struct ibv_qp_ex *ibv_qp_to_qp_ex(struct ibv_qp *qp)
{
	struct verbs_qp *vqp = (struct verbs_qp *)qp;

	if (vqp->comp_mask & VERBS_QP_EX)
		return &vqp->qp_ex;
	return NULL;
}

LATEST_SYMVER_FUNC(ibv_query_qp, 1_1, "IBVERBS_1.1",
		   int,
		   struct ibv_qp *qp, struct ibv_qp_attr *attr,
		   int attr_mask,
		   struct ibv_qp_init_attr *init_attr)
{
	int ret;

	ret = get_ops(qp->context)->query_qp(qp, attr, attr_mask, init_attr);
	if (ret)
		return ret;

	if (attr_mask & IBV_QP_STATE)
		qp->state = attr->qp_state;

	return 0;
}

int ibv_query_qp_data_in_order(struct ibv_qp *qp, enum ibv_wr_opcode op,
			       uint32_t flags)
{
#if !defined(__i386__) && !defined(__x86_64__)
	/* Currently this API is only supported for x86 architectures since most
	 * non-x86 platforms are known to be OOO and need to do a per-platform study.
	 */
	return 0;
#else
	return get_ops(qp->context)->query_qp_data_in_order(qp, op, flags);
#endif
}

static int write_modify_qp_attr(struct ibv_context *context, struct ibv_qp *qp,
			struct ibv_qp_attr *attr, int attr_mask) {
	char qp_dir_fname[128];
	char info_fname[32];
	int qp_dir_fd;
	int attr_fd = -1;
	int mask_fd = -1;

	sprintf(qp_dir_fname, "/proc/rdma_uwrite/%d/%d/qp_%d/",
					rdma_getpid(context), context->cmd_fd, qp->handle);
	
	qp_dir_fd = open(qp_dir_fname, O_DIRECTORY);
	if(qp_dir_fd < 0) {
		return -1;
	}

	if(attr->qp_state > IBV_QPS_RTS || attr->qp_state < IBV_QPS_INIT) {
		close(qp_dir_fd);
		return 0;
	}

	sprintf(info_fname, "attr_%d", attr->qp_state - 1);
	attr_fd = openat(qp_dir_fd, info_fname, O_WRONLY);
	sprintf(info_fname, "mask_%d", attr->qp_state - 1);
	mask_fd = openat(qp_dir_fd, info_fname, O_WRONLY);

	if(attr_fd < 0 || mask_fd < 0) {
		if(attr_fd >= 0)
			close(attr_fd);
		if(mask_fd >= 0)
			close(mask_fd);
		close(qp_dir_fd);
		return -1;
	}

	if(write(attr_fd, attr, sizeof(*attr)) < 0) {
		close(attr_fd);
		close(mask_fd);
		close(qp_dir_fd);
		return -1;
	}

	if(write(mask_fd, &attr_mask, sizeof(attr_mask)) < 0) {
		close(attr_fd);
		close(mask_fd);
		close(qp_dir_fd);
		return -1;
	}

	close(attr_fd);
	close(mask_fd);
	close(qp_dir_fd);
	return 0;
}

#include "rbtree.h"

static declare_and_init_rbtree(rendpoint_tree);

struct rendpoint_entry {
	union ibv_gid				rgid;
	pid_t						rpid;
	void						*rkey_arr;
	struct rb_node				node;
};

static inline struct rendpoint_entry *to_rendpoint_entry(struct rb_node *n) {
	return n? container_of(n, struct rendpoint_entry, node): NULL;
}

static void free_rendpoint_entry(struct rb_node *node) {
	struct rendpoint_entry *ent = to_rendpoint_entry(node);
	free(ent);
}

static inline int rendpoint_entry_compare(const struct rb_node *n1, const struct rb_node *n2) {
	struct rendpoint_entry *ent1 = to_rendpoint_entry(n1);
	struct rendpoint_entry *ent2 = to_rendpoint_entry(n2);
	int cmp;

	cmp = memcmp(&ent1->rgid, &ent2->rgid, sizeof(union ibv_gid));
	if(cmp < 0) {
		return -1;
	}
	else if(cmp > 0)
		return 1;
	else {
		if(ent1->rpid < ent2->rpid)
			return -1;
		else if(ent1->rpid > ent2->rpid)
			return 1;
		else
			return 0;
	}
}

static struct rendpoint_entry *search_rendpoint_entry(union ibv_gid *gid, pid_t pid,
					struct rb_node **p_parent, struct rb_node ***p_insert) {
	struct rendpoint_entry target;
	struct rb_node *match;

	memcpy(&target.rgid, gid, sizeof(union ibv_gid));
	target.rpid = pid;
	match = ___search(&target.node, &rendpoint_tree, p_parent, p_insert,
							SEARCH_EXACTLY, rendpoint_entry_compare);
	return to_rendpoint_entry(match);
}

static int add_rendpoint_entry(union ibv_gid *gid, pid_t pid, void *addr) {
	struct rendpoint_entry *ent;
	struct rb_node *parent, **insert;

	pthread_rwlock_wrlock(&rendpoint_tree.rwlock);
	ent = search_rendpoint_entry(gid, pid, &parent, &insert);
	if(ent) {
		pthread_rwlock_unlock(&rendpoint_tree.rwlock);
		return -EEXIST;
	}

	ent = malloc(sizeof(*ent));
	if(!ent) {
		pthread_rwlock_unlock(&rendpoint_tree.rwlock);
		return -ENOMEM;
	}

	memcpy(&ent->rgid, gid, sizeof(union ibv_gid));
	ent->rpid = pid;
	ent->rkey_arr = addr;
	rbtree_add_node(&ent->node, parent, insert, &rendpoint_tree);
	pthread_rwlock_unlock(&rendpoint_tree.rwlock);

	return 0;
}

static void *get_rkey_arr_from_rgid_and_rpid(union ibv_gid *gid, pid_t pid) {
	struct rendpoint_entry *ent;
	void *addr;

	pthread_rwlock_rdlock(&rendpoint_tree.rwlock);
	ent = search_rendpoint_entry(gid, pid, NULL, NULL);
	if(!ent) {
		pthread_rwlock_unlock(&rendpoint_tree.rwlock);
		return NULL;
	}

	addr = ent->rkey_arr;
	pthread_rwlock_unlock(&rendpoint_tree.rwlock);
	return addr;
}

void clear_rendpoint_tree(void) {
	clean_rbtree(&rendpoint_tree, free_rendpoint_entry);
}

LATEST_SYMVER_FUNC(ibv_modify_qp, 1_1, "IBVERBS_1.1",
		   int,
		   struct ibv_qp *qp, struct ibv_qp_attr *attr,
		   int attr_mask)
{
	int ret;
	struct ibv_qp_attr tmp_attr;

	memcpy(&tmp_attr, attr, sizeof(tmp_attr));

	if(attr->qp_state == IBV_QPS_RTR &&
					(attr_mask & (IBV_QP_STATE | IBV_QP_AV))) {
		struct sockaddr_in remote_addr;
		union ibv_gid local_gid;
		int sock;
		int err;
		char fname[1024];
		ssize_t size;
		int info_fd;
		int flags;

		sock = socket(AF_INET, SOCK_DGRAM, 0);
		if(sock < 0) {
			return -1;
		}

		flags = fcntl(sock, F_GETFL, 0);
		fcntl(sock, F_SETFL, flags | O_NONBLOCK);

		ibv_query_gid(qp->context, 1, attr->ah_attr.grh.sgid_index, &local_gid);
		memcpy(&qp->local_gid, &local_gid, sizeof(union ibv_gid));

		remote_addr.sin_family = AF_INET;
		remote_addr.sin_port = htons(attr->dest_qp_num % 65536 + 8000);
		memcpy(&remote_addr.sin_addr.s_addr, &tmp_attr.ah_attr.grh.dgid.raw[12],
						sizeof(uint32_t));

		while((size = recvfrom(sock, &qp->dest_pid, sizeof(pid_t), 0, NULL, NULL)) < 0 && errno == EAGAIN) {
			ssize_t this_size = sendto(sock, &qp->dest_pid, sizeof(pid_t), 0, &remote_addr, sizeof(remote_addr));
			if(this_size != sizeof(pid_t)) {
				close(sock);
				return -1;
			}
		}
		if(size != sizeof(pid_t)) {
			close(sock);
			return -1;
		}

//		printf("In %s(%d): this_pid: %d, dest_pid: %d\n", __FILE__, __LINE__, rdma_getpid(qp->context), qp->dest_pid);

		qp->dest_vqpn = attr->dest_qp_num;
		memcpy(&qp->rc_dest_gid, &tmp_attr.ah_attr.grh.dgid, sizeof(union ibv_gid));

		while((size = recvfrom(sock, &qp->dest_qpn, sizeof(uint32_t), 0, NULL, NULL)) < 0 && errno == EAGAIN) {
			ssize_t this_size = sendto(sock, &qp->dest_qpn, sizeof(uint32_t), 0, &remote_addr, sizeof(remote_addr));
			if(this_size != sizeof(uint32_t)) {
				close(sock);
				return -1;
			}
		}
		if(size != sizeof(uint32_t)) {
			close(sock);
			return -1;
		}

		close(sock);
//		printf("In %s(%d): this_real_qpn: %d, dest_real_qpn: %d\n", __FILE__, __LINE__, qp->real_qpn, qp->dest_qpn);

		sprintf(fname, "/proc/rdma_uwrite/%d/%d/qp_%d/rc_dest_pgid", rdma_getpid(qp->context),
									qp->context->cmd_fd, qp->handle);
		info_fd = open(fname, O_WRONLY);
		if(info_fd < 0) {
			return -1;
		}

		if(write(info_fd, &tmp_attr.ah_attr.grh.dgid, sizeof(union ibv_gid)) < 0) {
			close(info_fd);
			return -1;
		}

		close(info_fd);

		sprintf(fname, "/proc/rdma_uwrite/%d/%d/qp_%d/dest_pqpn", rdma_getpid(qp->context),
									qp->context->cmd_fd, qp->handle);
		info_fd = open(fname, O_WRONLY);
		if(info_fd < 0) {
			return -1;
		}

		if(write(info_fd, &qp->dest_qpn, sizeof(uint32_t)) < 0) {
			close(info_fd);
			return -1;
		}

		close(info_fd);
		tmp_attr.dest_qp_num = qp->dest_qpn;

		err = ibv_cmd_register_remote_gid_pid(qp->context,
								&tmp_attr.ah_attr.grh.dgid, qp->dest_pid);
		if(err) {
			return -1;
		}

		sprintf(fname, "/proc/rdma_uwrite/%d/%d/<%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x>_%d",
								rdma_getpid(qp->context), qp->context->cmd_fd,
								tmp_attr.ah_attr.grh.dgid.raw[0], tmp_attr.ah_attr.grh.dgid.raw[1], tmp_attr.ah_attr.grh.dgid.raw[2], tmp_attr.ah_attr.grh.dgid.raw[3],
								tmp_attr.ah_attr.grh.dgid.raw[4], tmp_attr.ah_attr.grh.dgid.raw[5], tmp_attr.ah_attr.grh.dgid.raw[6], tmp_attr.ah_attr.grh.dgid.raw[7],
								tmp_attr.ah_attr.grh.dgid.raw[8], tmp_attr.ah_attr.grh.dgid.raw[9], tmp_attr.ah_attr.grh.dgid.raw[10], tmp_attr.ah_attr.grh.dgid.raw[11],
								tmp_attr.ah_attr.grh.dgid.raw[12], tmp_attr.ah_attr.grh.dgid.raw[13], tmp_attr.ah_attr.grh.dgid.raw[14], tmp_attr.ah_attr.grh.dgid.raw[15],
								qp->dest_pid);
		qp->rkey_arr = get_rkey_arr_from_rgid_and_rpid(&tmp_attr.ah_attr.grh.dgid, qp->dest_pid);
		if(!qp->rkey_arr) {
			int fd = open(fname, O_RDWR);
			if(fd < 0) {
				return -1;
			}
			qp->rkey_arr = mmap(NULL, getpagesize(), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
			if(qp->rkey_arr == MAP_FAILED) {
				close(fd);
				return -1;
			}

			if(add_rendpoint_entry(&tmp_attr.ah_attr.grh.dgid, qp->dest_pid, qp->rkey_arr)) {
				close(fd);
				return -1;
			}

			close(fd);
		}
	}

	ret = get_ops(qp->context)->modify_qp(qp, &tmp_attr, attr_mask);
	if (ret)
		return ret;

	if (attr_mask & IBV_QP_STATE)
		qp->state = attr->qp_state;

	if(write_modify_qp_attr(qp->context, qp, attr, attr_mask))
		return -1;

	return 0;
}

LATEST_SYMVER_FUNC(ibv_destroy_qp, 1_1, "IBVERBS_1.1",
		   int,
		   struct ibv_qp *qp)
{
	del_qpn_dict_node(qp);
	rbtree_del_qp(qp);
	return get_ops(qp->context)->destroy_qp(qp);
}

LATEST_SYMVER_FUNC(ibv_create_ah, 1_1, "IBVERBS_1.1",
		   struct ibv_ah *,
		   struct ibv_pd *pd, struct ibv_ah_attr *attr)
{
	struct ibv_ah *ah = get_ops(pd->context)->create_ah(pd, attr);

	if (ah) {
		ah->context = pd->context;
		ah->pd      = pd;
	}

	return ah;
}

int ibv_query_gid_type(struct ibv_context *context, uint8_t port_num,
		       unsigned int index, enum ibv_gid_type_sysfs *type)
{
	struct ibv_gid_entry entry = {};
	int ret;

	ret = __ibv_query_gid_ex(context, port_num, index, &entry, 0,
				 sizeof(entry), VERBS_QUERY_GID_ATTR_TYPE);
	/* Preserve API behavior for empty GID */
	if (ret == ENODATA) {
		*type = IBV_GID_TYPE_SYSFS_IB_ROCE_V1;
		return 0;
	}
	if (ret)
		return -1;

	if (entry.gid_type == IBV_GID_TYPE_IB ||
	    entry.gid_type == IBV_GID_TYPE_ROCE_V1)
		*type = IBV_GID_TYPE_SYSFS_IB_ROCE_V1;
	else
		*type = IBV_GID_TYPE_SYSFS_ROCE_V2;

	return 0;
}

static int ibv_find_gid_index(struct ibv_context *context, uint8_t port_num,
			      union ibv_gid *gid,
			      enum ibv_gid_type_sysfs gid_type)
{
	enum ibv_gid_type_sysfs sgid_type = 0;
	union ibv_gid sgid;
	int i = 0, ret;

	do {
		ret = ibv_query_gid(context, port_num, i, &sgid);
		if (!ret) {
			ret = ibv_query_gid_type(context, port_num, i,
						 &sgid_type);
		}
		i++;
	} while (!ret && (memcmp(&sgid, gid, sizeof(*gid)) ||
		 (gid_type != sgid_type)));

	return ret ? ret : i - 1;
}

static inline void map_ipv4_addr_to_ipv6(__be32 ipv4, struct in6_addr *ipv6)
{
	ipv6->s6_addr32[0] = 0;
	ipv6->s6_addr32[1] = 0;
	ipv6->s6_addr32[2] = htobe32(0x0000FFFF);
	ipv6->s6_addr32[3] = ipv4;
}

static inline __sum16 ipv4_calc_hdr_csum(uint16_t *data, unsigned int num_hwords)
{
	unsigned int i = 0;
	uint32_t sum = 0;

	for (i = 0; i < num_hwords; i++)
		sum += *(data++);

	sum = (sum & 0xffff) + (sum >> 16);

	return (__force __sum16)~sum;
}

static inline int get_grh_header_version(struct ibv_grh *grh)
{
	int ip6h_version = (be32toh(grh->version_tclass_flow) >> 28) & 0xf;
	struct iphdr *ip4h = (struct iphdr *)((void *)grh + 20);
	struct iphdr ip4h_checked;

	if (ip6h_version != 6) {
		if (ip4h->version == 4)
			return 4;
		errno = EPROTONOSUPPORT;
		return -1;
	}
	/* version may be 6 or 4 */
	if (ip4h->ihl != 5) /* IPv4 header length must be 5 for RoCE v2. */
		return 6;
	/*
	* Verify checksum.
	* We can't write on scattered buffers so we have to copy to temp
	* buffer.
	*/
	memcpy(&ip4h_checked, ip4h, sizeof(ip4h_checked));
	/* Need to set the checksum field (check) to 0 before re-calculating
	 * the checksum.
	 */
	ip4h_checked.check = 0;
	ip4h_checked.check = ipv4_calc_hdr_csum((uint16_t *)&ip4h_checked, 10);
	/* if IPv4 header checksum is OK, believe it */
	if (ip4h->check == ip4h_checked.check)
		return 4;
	return 6;
}

static inline void set_ah_attr_generic_fields(struct ibv_ah_attr *ah_attr,
					      struct ibv_wc *wc,
					      struct ibv_grh *grh,
					      uint8_t port_num)
{
	uint32_t flow_class;

	flow_class = be32toh(grh->version_tclass_flow);
	ah_attr->grh.flow_label = flow_class & 0xFFFFF;
	ah_attr->dlid = wc->slid;
	ah_attr->sl = wc->sl;
	ah_attr->src_path_bits = wc->dlid_path_bits;
	ah_attr->port_num = port_num;
}

static inline int set_ah_attr_by_ipv4(struct ibv_context *context,
				      struct ibv_ah_attr *ah_attr,
				      struct iphdr *ip4h, uint8_t port_num)
{
	union ibv_gid sgid;
	int ret;

	/* No point searching multicast GIDs in GID table */
	if (IN_CLASSD(be32toh(ip4h->daddr))) {
		errno = EINVAL;
		return -1;
	}

	map_ipv4_addr_to_ipv6(ip4h->daddr, (struct in6_addr *)&sgid);
	ret = ibv_find_gid_index(context, port_num, &sgid,
				 IBV_GID_TYPE_SYSFS_ROCE_V2);
	if (ret < 0)
		return ret;

	map_ipv4_addr_to_ipv6(ip4h->saddr,
			      (struct in6_addr *)&ah_attr->grh.dgid);
	ah_attr->grh.sgid_index = (uint8_t) ret;
	ah_attr->grh.hop_limit = ip4h->ttl;
	ah_attr->grh.traffic_class = ip4h->tos;

	return 0;
}

#define IB_NEXT_HDR    0x1b
static inline int set_ah_attr_by_ipv6(struct ibv_context *context,
				  struct ibv_ah_attr *ah_attr,
				  struct ibv_grh *grh, uint8_t port_num)
{
	uint32_t flow_class;
	uint32_t sgid_type;
	int ret;

	/* No point searching multicast GIDs in GID table */
	if (grh->dgid.raw[0] == 0xFF) {
		errno = EINVAL;
		return -1;
	}

	ah_attr->grh.dgid = grh->sgid;
	if (grh->next_hdr == IPPROTO_UDP) {
		sgid_type = IBV_GID_TYPE_SYSFS_ROCE_V2;
	} else if (grh->next_hdr == IB_NEXT_HDR) {
		sgid_type = IBV_GID_TYPE_SYSFS_IB_ROCE_V1;
	} else {
		errno = EPROTONOSUPPORT;
		return -1;
	}

	ret = ibv_find_gid_index(context, port_num, &grh->dgid,
				 sgid_type);
	if (ret < 0)
		return ret;

	ah_attr->grh.sgid_index = (uint8_t) ret;
	flow_class = be32toh(grh->version_tclass_flow);
	ah_attr->grh.hop_limit = grh->hop_limit;
	ah_attr->grh.traffic_class = (flow_class >> 20) & 0xFF;

	return 0;
}

int ibv_init_ah_from_wc(struct ibv_context *context, uint8_t port_num,
			struct ibv_wc *wc, struct ibv_grh *grh,
			struct ibv_ah_attr *ah_attr)
{
	int version;
	int ret = 0;

	memset(ah_attr, 0, sizeof *ah_attr);
	set_ah_attr_generic_fields(ah_attr, wc, grh, port_num);

	if (wc->wc_flags & IBV_WC_GRH) {
		ah_attr->is_global = 1;
		version = get_grh_header_version(grh);

		if (version == 4)
			ret = set_ah_attr_by_ipv4(context, ah_attr,
						  (struct iphdr *)((void *)grh + 20),
						  port_num);
		else if (version == 6)
			ret = set_ah_attr_by_ipv6(context, ah_attr, grh,
						  port_num);
		else
			ret = -1;
	}

	return ret;
}

struct ibv_ah *ibv_create_ah_from_wc(struct ibv_pd *pd, struct ibv_wc *wc,
				     struct ibv_grh *grh, uint8_t port_num)
{
	struct ibv_ah_attr ah_attr;
	int ret;

	ret = ibv_init_ah_from_wc(pd->context, port_num, wc, grh, &ah_attr);
	if (ret)
		return NULL;

	return ibv_create_ah(pd, &ah_attr);
}

LATEST_SYMVER_FUNC(ibv_destroy_ah, 1_1, "IBVERBS_1.1",
		   int,
		   struct ibv_ah *ah)
{
	return get_ops(ah->context)->destroy_ah(ah);
}

LATEST_SYMVER_FUNC(ibv_attach_mcast, 1_1, "IBVERBS_1.1",
		   int,
		   struct ibv_qp *qp, const union ibv_gid *gid, uint16_t lid)
{
	return get_ops(qp->context)->attach_mcast(qp, gid, lid);
}

LATEST_SYMVER_FUNC(ibv_detach_mcast, 1_1, "IBVERBS_1.1",
		   int,
		   struct ibv_qp *qp, const union ibv_gid *gid, uint16_t lid)
{
	return get_ops(qp->context)->detach_mcast(qp, gid, lid);
}

static inline int ipv6_addr_v4mapped(const struct in6_addr *a)
{
	return IN6_IS_ADDR_V4MAPPED(&a->s6_addr32) ||
		/* IPv4 encoded multicast addresses */
		(a->s6_addr32[0]  == htobe32(0xff0e0000) &&
		((a->s6_addr32[1] |
		 (a->s6_addr32[2] ^ htobe32(0x0000ffff))) == 0UL));
}

struct peer_address {
	void *address;
	uint32_t size;
};

static inline int create_peer_from_gid(int family, void *raw_gid,
				       struct peer_address *peer_address)
{
	switch (family) {
	case AF_INET:
		peer_address->address = raw_gid + 12;
		peer_address->size = 4;
		break;
	case AF_INET6:
		peer_address->address = raw_gid;
		peer_address->size = 16;
		break;
	default:
		return -1;
	}

	return 0;
}

#define NEIGH_GET_DEFAULT_TIMEOUT_MS 3000
int ibv_resolve_eth_l2_from_gid(struct ibv_context *context,
				struct ibv_ah_attr *attr,
				uint8_t eth_mac[ETHERNET_LL_SIZE],
				uint16_t *vid)
{
	int dst_family;
	int src_family;
	int oif;
	struct get_neigh_handler neigh_handler;
	union ibv_gid sgid;
	int ether_len;
	struct peer_address src;
	struct peer_address dst;
	int ret = -EINVAL;
	int err;

	err = ibv_query_gid(context, attr->port_num,
			    attr->grh.sgid_index, &sgid);

	if (err)
		return err;

	err = neigh_init_resources(&neigh_handler,
				   NEIGH_GET_DEFAULT_TIMEOUT_MS);

	if (err)
		return err;

	dst_family = ipv6_addr_v4mapped((struct in6_addr *)attr->grh.dgid.raw) ?
			AF_INET : AF_INET6;
	src_family = ipv6_addr_v4mapped((struct in6_addr *)sgid.raw) ?
			AF_INET : AF_INET6;

	if (create_peer_from_gid(dst_family, attr->grh.dgid.raw, &dst))
		goto free_resources;

	if (create_peer_from_gid(src_family, &sgid.raw, &src))
		goto free_resources;

	if (neigh_set_dst(&neigh_handler, dst_family, dst.address,
			  dst.size))
		goto free_resources;

	if (neigh_set_src(&neigh_handler, src_family, src.address,
			  src.size))
		goto free_resources;

	oif = neigh_get_oif_from_src(&neigh_handler);

	if (oif > 0)
		neigh_set_oif(&neigh_handler, oif);
	else
		goto free_resources;

	ret = -EHOSTUNREACH;

	/* blocking call */
	if (process_get_neigh(&neigh_handler))
		goto free_resources;

	if (vid) {
		uint16_t ret_vid = neigh_get_vlan_id_from_dev(&neigh_handler);

		if (ret_vid <= 0xfff)
			neigh_set_vlan_id(&neigh_handler, ret_vid);
		*vid = ret_vid;
	}

	/* We are using only Ethernet here */
	ether_len = neigh_get_ll(&neigh_handler,
				 eth_mac,
				 sizeof(uint8_t) * ETHERNET_LL_SIZE);

	if (ether_len <= 0)
		goto free_resources;

	ret = 0;

free_resources:
	neigh_free_resources(&neigh_handler);

	return ret;
}

int ibv_set_ece(struct ibv_qp *qp, struct ibv_ece *ece)
{
	if (!ece->vendor_id) {
		errno = EOPNOTSUPP;
		return errno;
	}

	return get_ops(qp->context)->set_ece(qp, ece);
}

int ibv_query_ece(struct ibv_qp *qp, struct ibv_ece *ece)
{
	return get_ops(qp->context)->query_ece(qp, ece);
}
