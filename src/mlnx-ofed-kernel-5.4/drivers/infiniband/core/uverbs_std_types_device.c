// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2018, Mellanox Technologies inc.  All rights reserved.
 */

#include <linux/overflow.h>
#include <rdma/uverbs_std_types.h>
#include "rdma_core.h"
#include "uverbs.h"
#include <rdma/uverbs_ioctl.h>
#include <rdma/opa_addr.h>
#include <rdma/ib_cache.h>

/*
 * This ioctl method allows calling any defined write or write_ex
 * handler. This essentially replaces the hdr/ex_hdr system with the ioctl
 * marshalling, and brings the non-ex path into the same marshalling as the ex
 * path.
 */
static int UVERBS_HANDLER(UVERBS_METHOD_INVOKE_WRITE)(
	struct uverbs_attr_bundle *attrs)
{
	struct uverbs_api *uapi = attrs->ufile->device->uapi;
	const struct uverbs_api_write_method *method_elm;
	u32 cmd;
	int rc;

	rc = uverbs_get_const(&cmd, attrs, UVERBS_ATTR_WRITE_CMD);
	if (rc)
		return rc;

	method_elm = uapi_get_method(uapi, cmd);
	if (IS_ERR(method_elm))
		return PTR_ERR(method_elm);

	uverbs_fill_udata(attrs, &attrs->ucore, UVERBS_ATTR_CORE_IN,
			  UVERBS_ATTR_CORE_OUT);

	if (attrs->ucore.inlen < method_elm->req_size ||
	    attrs->ucore.outlen < method_elm->resp_size)
		return -ENOSPC;

	attrs->uobject = NULL;
	rc = method_elm->handler(attrs);
	if (attrs->uobject)
		uverbs_finalize_object(attrs->uobject, UVERBS_ACCESS_NEW, true,
				       !rc, attrs);
	return rc;
}

DECLARE_UVERBS_NAMED_METHOD(UVERBS_METHOD_INVOKE_WRITE,
			    UVERBS_ATTR_CONST_IN(UVERBS_ATTR_WRITE_CMD,
						 enum ib_uverbs_write_cmds,
						 UA_MANDATORY),
			    UVERBS_ATTR_PTR_IN(UVERBS_ATTR_CORE_IN,
					       UVERBS_ATTR_MIN_SIZE(sizeof(u32)),
					       UA_OPTIONAL),
			    UVERBS_ATTR_PTR_OUT(UVERBS_ATTR_CORE_OUT,
						UVERBS_ATTR_MIN_SIZE(0),
						UA_OPTIONAL),
			    UVERBS_ATTR_UHW());

static uint32_t *
gather_objects_handle(struct ib_uverbs_file *ufile,
		      const struct uverbs_api_object *uapi_object,
		      struct uverbs_attr_bundle *attrs,
		      ssize_t out_len,
		      u64 *total)
{
	u64 max_count = out_len / sizeof(u32);
	struct ib_uobject *obj;
	u64 count = 0;
	u32 *handles;

	/* Allocated memory that cannot page out where we gather
	 * all object ids under a spin_lock.
	 */
	handles = uverbs_zalloc(attrs, out_len);
	if (IS_ERR(handles))
		return handles;

	spin_lock_irq(&ufile->uobjects_lock);
	list_for_each_entry(obj, &ufile->uobjects, list) {
		u32 obj_id = obj->id;

		if (obj->uapi_object != uapi_object)
			continue;

		if (count >= max_count)
			break;

		handles[count] = obj_id;
		count++;
	}
	spin_unlock_irq(&ufile->uobjects_lock);

	*total = count;
	return handles;
}

static int UVERBS_HANDLER(UVERBS_METHOD_INFO_HANDLES)(
	struct uverbs_attr_bundle *attrs)
{
	const struct uverbs_api_object *uapi_object;
	ssize_t out_len;
	u64 total = 0;
	u16 object_id;
	u32 *handles;
	int ret;

	out_len = uverbs_attr_get_len(attrs, UVERBS_ATTR_INFO_HANDLES_LIST);
	if (out_len <= 0 || (out_len % sizeof(u32) != 0))
		return -EINVAL;

	ret = uverbs_get_const(&object_id, attrs, UVERBS_ATTR_INFO_OBJECT_ID);
	if (ret)
		return ret;

	uapi_object = uapi_get_object(attrs->ufile->device->uapi, object_id);
	if (!uapi_object)
		return -EINVAL;

	handles = gather_objects_handle(attrs->ufile, uapi_object, attrs,
					out_len, &total);
	if (IS_ERR(handles))
		return PTR_ERR(handles);

	ret = uverbs_copy_to(attrs, UVERBS_ATTR_INFO_HANDLES_LIST, handles,
			     sizeof(u32) * total);
	if (ret)
		goto err;

	ret = uverbs_copy_to(attrs, UVERBS_ATTR_INFO_TOTAL_HANDLES, &total,
			     sizeof(total));
err:
	return ret;
}

void copy_port_attr_to_resp(struct ib_port_attr *attr,
			    struct ib_uverbs_query_port_resp *resp,
			    struct ib_device *ib_dev, u8 port_num)
{
	resp->state = attr->state;
	resp->max_mtu = attr->max_mtu;
	resp->active_mtu = attr->active_mtu;
	resp->gid_tbl_len = attr->gid_tbl_len;
	resp->port_cap_flags = make_port_cap_flags(attr);
	resp->max_msg_sz = attr->max_msg_sz;
	resp->bad_pkey_cntr = attr->bad_pkey_cntr;
	resp->qkey_viol_cntr = attr->qkey_viol_cntr;
	resp->pkey_tbl_len = attr->pkey_tbl_len;

	if (rdma_is_grh_required(ib_dev, port_num))
		resp->flags |= IB_UVERBS_QPF_GRH_REQUIRED;

	if (rdma_cap_opa_ah(ib_dev, port_num)) {
		resp->lid = OPA_TO_IB_UCAST_LID(attr->lid);
		resp->sm_lid = OPA_TO_IB_UCAST_LID(attr->sm_lid);
	} else {
		resp->lid = ib_lid_cpu16(attr->lid);
		resp->sm_lid = ib_lid_cpu16(attr->sm_lid);
	}

	resp->lmc = attr->lmc;
	resp->max_vl_num = attr->max_vl_num;
	resp->sm_sl = attr->sm_sl;
	resp->subnet_timeout = attr->subnet_timeout;
	resp->init_type_reply = attr->init_type_reply;
	resp->active_width = attr->active_width;
	resp->active_speed = attr->active_speed;
	resp->phys_state = attr->phys_state;
	resp->link_layer = rdma_port_get_link_layer(ib_dev, port_num);
}

static int UVERBS_HANDLER(UVERBS_METHOD_QUERY_PORT)(
	struct uverbs_attr_bundle *attrs)
{
	struct ib_device *ib_dev;
	struct ib_port_attr attr = {};
	struct ib_uverbs_query_port_resp_ex resp = {};
	struct ib_ucontext *ucontext;
	int ret;
	u8 port_num;

	ucontext = ib_uverbs_get_ucontext(attrs);
	if (IS_ERR(ucontext))
		return PTR_ERR(ucontext);
	ib_dev = ucontext->device;

	/* FIXME: Extend the UAPI_DEF_OBJ_NEEDS_FN stuff.. */
	if (!ib_dev->ops.query_port)
		return -EOPNOTSUPP;

	ret = uverbs_get_const(&port_num, attrs,
			       UVERBS_ATTR_QUERY_PORT_PORT_NUM);
	if (ret)
		return ret;

	ret = ib_query_port(ib_dev, port_num, &attr);
	if (ret)
		return ret;

	copy_port_attr_to_resp(&attr, &resp.legacy_resp, ib_dev, port_num);
	resp.port_cap_flags2 = attr.port_cap_flags2;

	return uverbs_copy_to_struct_or_zero(attrs, UVERBS_ATTR_QUERY_PORT_RESP,
					     &resp, sizeof(resp));
}

#include "rdma_footprint.h"

static int UVERBS_HANDLER(UVERBS_METHOD_INSTALL_QPN_DICT)(
				struct uverbs_attr_bundle *attrs) {
	int real_qpn, vqpn;
	int ret;
	uint32_t *qpn_dict;

	ret = uverbs_copy_from(&real_qpn, attrs, 0);
	ret = uverbs_copy_from(&vqpn, attrs, 1);
	if(ret)
		return ret;

	qpn_dict = attrs->ufile->device->ib_dev->qpn_dict;
	qpn_dict[real_qpn] = vqpn;
	return 0;
}

static int UVERBS_HANDLER(UVERBS_METHOD_INSTALL_FOOTPRINT)(
				struct uverbs_attr_bundle *attrs) {
	int cmd_fd;
	int ret;

	ret = uverbs_copy_from(&cmd_fd, attrs, UVERBS_ATTR_FOOTPRINT_IN_FD);
	if(ret)
		return ret;
	
	ret = register_rdma_dev_fd_entry(cmd_fd, attrs->ufile);
	if(ret)
		return ret;

	return ufile_alloc_mapping(attrs->ufile);
}

static int UVERBS_HANDLER(UVERBS_METHOD_INSTALL_CTX_RESP)(
				struct uverbs_attr_bundle *attrs) {
	char __user *buf;
	size_t size;
	int ret;

	ret = uverbs_copy_from(&buf, attrs, UVERBS_ATTR_RESP_PTR);
	if(ret)
		return ret;
	
	ret = uverbs_copy_from(&size, attrs, UVERBS_ATTR_RESP_SZ);
	if(ret)
		return ret;

	return install_ctx_resp(attrs->ufile, buf, size);
}

static int UVERBS_HANDLER(UVERBS_METHOD_INSTALL_MR_HANDLE_MAPPING)(
				struct uverbs_attr_bundle *attrs) {
	struct ib_mr *mr;
	struct ib_uobject *uobj;
	int vhandle, handle;
	int ret;

	ret = uverbs_copy_from(&vhandle, attrs, UVERBS_ATTR_VHANDLE);
	ret = uverbs_copy_from(&handle, attrs, UVERBS_ATTR_HANDLE);
	if(ret)
		return ret;

	uobj = uobj_get_write(UVERBS_OBJECT_MR, handle, attrs);
	if(IS_ERR(uobj))
		return PTR_ERR(uobj);
	mr = uobj->object;

	ret = register_mr_to_footprint(mr, mr->pd, vhandle);
	if(ret) {
		uobj_put_write(uobj);
		return ret;
	}

	ret = register_mr_to_uwrite_footprint(mr, attrs->ufile, vhandle);
	if(ret) {
		uobj_put_write(uobj);
		return ret;
	}

	ret = register_mr_handle_mapping(attrs->ufile, mr, vhandle, handle);
	if(ret) {
		uobj_put_write(uobj);
		return ret;
	}

	uobj_put_write(uobj);
	return 0;
}

static int UVERBS_HANDLER(UVERBS_METHOD_INSTALL_SRQ_HANDLE_MAPPING)(
					struct uverbs_attr_bundle *attrs) {
	struct ib_srq *srq;
	int vhandle, handle;
	int ret;

	ret = uverbs_copy_from(&vhandle, attrs, UVERBS_ATTR_VHANDLE);
	ret = uverbs_copy_from(&handle, attrs, UVERBS_ATTR_HANDLE);
	if(ret)
		return ret;

	srq = uobj_get_obj_read(srq, UVERBS_OBJECT_SRQ, handle, attrs);
	if(!srq || srq->srq_type == IB_SRQT_XRC) {
		if(srq) {
			rdma_lookup_put_uobject(&srq->uobject->uevent.uobject,
									UVERBS_LOOKUP_READ);
		}
		return -EINVAL;
	}

	ret = register_srq_to_footprint(srq, srq->pd, vhandle);
	if(ret) {
		rdma_lookup_put_uobject(&srq->uobject->uevent.uobject,
									UVERBS_LOOKUP_READ);
		return ret;
	}

	ret = register_srq_handle_mapping(attrs->ufile, srq, vhandle, handle);
	if(ret) {
		rdma_lookup_put_uobject(&srq->uobject->uevent.uobject,
									UVERBS_LOOKUP_READ);
		return ret;
	}

	srq->vhandle = vhandle;

	ret = register_srq_to_uwrite_footprint(srq, attrs->ufile, vhandle);
	if(ret) {
		rdma_lookup_put_uobject(&srq->uobject->uevent.uobject,
									UVERBS_LOOKUP_READ);
		return ret;
	}

	rdma_lookup_put_uobject(&srq->uobject->uevent.uobject,
								UVERBS_LOOKUP_READ);
	return 0;
 }

static int UVERBS_HANDLER(UVERBS_METHOD_INSTALL_QP_HANDLE_MAPPING)(
					struct uverbs_attr_bundle *attrs) {
	struct ib_qp *qp;
	int vhandle, handle;
	int ret;

	ret = uverbs_copy_from(&vhandle, attrs, UVERBS_ATTR_VHANDLE);
	ret = uverbs_copy_from(&handle, attrs, UVERBS_ATTR_HANDLE);
	if(ret)
		return ret;
	
	qp = uobj_get_obj_read(qp, UVERBS_OBJECT_QP, handle, attrs);
	if(!qp)
		return -EINVAL;

	ret = register_qp_to_footprint(qp, qp->pd, vhandle);
	if(ret) {
		rdma_lookup_put_uobject(&qp->uobject->uevent.uobject,
								UVERBS_LOOKUP_READ);
		return ret;
	}

	qp->cmd_fd = attrs->ufile->cmd_fd;

	ret = register_qp_handle_mapping(attrs->ufile, qp, vhandle, handle);
	if(ret) {
		rdma_lookup_put_uobject(&qp->uobject->uevent.uobject,
								UVERBS_LOOKUP_READ);
		return ret;
	}

	qp->vhandle = vhandle;

	ret = register_qp_to_uwrite_footprint(qp, attrs->ufile, vhandle);
	if(ret) {
		rdma_lookup_put_uobject(&qp->uobject->uevent.uobject,
								UVERBS_LOOKUP_READ);
		return ret;
	}

	rdma_lookup_put_uobject(&qp->uobject->uevent.uobject,
						UVERBS_LOOKUP_READ);
	return 0;
}

static int UVERBS_HANDLER(UVERBS_METHOD_INSTALL_PD_HANDLE_MAPPING)(
				struct uverbs_attr_bundle *attrs) {
	struct ib_pd *pd;
	int vhandle, handle;
	int ret;

	ret = uverbs_copy_from(&vhandle, attrs, UVERBS_ATTR_VHANDLE);
	ret = uverbs_copy_from(&handle, attrs, UVERBS_ATTR_HANDLE);
	if(ret)
		return ret;
	
	pd = uobj_get_obj_read(pd, UVERBS_OBJECT_PD, handle, attrs);
	if(!pd) {
		return -EINVAL;
	}

	ret = register_pd_to_footprint(pd, attrs->ufile, vhandle);
	if(ret) {
		uobj_put_obj_read(pd);
		return ret;
	}

	ret = register_pd_handle_mapping(attrs->ufile, pd, vhandle, handle);
	if(ret) {
		uobj_put_obj_read(pd);
		return ret;
	}

	uobj_put_obj_read(pd);
	return 0;
}

static int UVERBS_HANDLER(UVERBS_METHOD_INSTALL_CQ_HANDLE_MAPPING)(
				struct uverbs_attr_bundle *attrs) {
	struct ib_cq *cq;
	int vhandle, handle;
	int ret;

	ret = uverbs_copy_from(&vhandle, attrs, UVERBS_ATTR_VHANDLE);
	ret = uverbs_copy_from(&handle, attrs, UVERBS_ATTR_HANDLE);
	if(ret)
		return ret;
	
	cq = uobj_get_obj_read(cq, UVERBS_OBJECT_CQ, handle, attrs);
	if(!cq) {
		return -EINVAL;
	}

	cq->comp_fd = cq->cq_context?
						container_of(cq->cq_context, struct ib_uverbs_completion_event_file,
								ev_queue)->comp_fd : -1;

	ret = register_cq_to_footprint(cq, attrs->ufile, vhandle);
	if(ret) {
		rdma_lookup_put_uobject(&cq->uobject->uevent.uobject,
						UVERBS_LOOKUP_READ);
		return ret;
	}

	ret = register_cq_to_uwrite_footprint(cq, attrs->ufile, vhandle);
	if(ret) {
		rdma_lookup_put_uobject(&cq->uobject->uevent.uobject,
						UVERBS_LOOKUP_READ);
		return ret;
	}

	ret = register_cq_handle_mapping(attrs->ufile, cq, vhandle, handle);
	if(ret) {
		rdma_lookup_put_uobject(&cq->uobject->uevent.uobject,
						UVERBS_LOOKUP_READ);
		return ret;
	}

	rdma_lookup_put_uobject(&cq->uobject->uevent.uobject,
						UVERBS_LOOKUP_READ);
	return 0;
}

static int UVERBS_HANDLER(UVERBS_METHOD_INSTALL_LQPN_MAPPING)(
				struct uverbs_attr_bundle *attrs) {
	uint32_t vqpn, qpn;
	int ret;

	ret = uverbs_copy_from(&vqpn, attrs, UVERBS_ATTR_VHANDLE);
	ret = uverbs_copy_from(&qpn, attrs, UVERBS_ATTR_HANDLE);
	if(ret)
		return ret;

#if 0
	if(update_lqpn_mapping(attrs->ufile, vqpn, qpn))
		return add_lqpn_mapping(attrs->ufile, vqpn, qpn);
	else
		return 0;
#endif
	return 0;
}

static int UVERBS_HANDLER(UVERBS_METHOD_INSTALL_LKEY_MAPPING)(
				struct uverbs_attr_bundle *attrs) {
	uint32_t vlkey, lkey;
	int ret;
	uint32_t *lkey_arr = attrs->ufile->lkey_mapping;

	ret = uverbs_copy_from(&vlkey, attrs, UVERBS_ATTR_VHANDLE);
	ret = uverbs_copy_from(&lkey, attrs, UVERBS_ATTR_HANDLE);
	if(ret)
		return ret;

	lkey_arr[vlkey] = lkey;
	return 0;
}

static int UVERBS_HANDLER(UVERBS_METHOD_INSTALL_LOCAL_RKEY_MAPPING)(
				struct uverbs_attr_bundle *attrs) {
	uint32_t vrkey, rkey;
	int ret;
	uint32_t *rkey_arr = attrs->ufile->rkey_mapping;

	ret = uverbs_copy_from(&vrkey, attrs, UVERBS_ATTR_VHANDLE);
	ret = uverbs_copy_from(&rkey, attrs, UVERBS_ATTR_HANDLE);
	if(ret)
		return ret;

	rkey_arr[vrkey] = rkey;
	return service_register_rkey_mapping(current->tgid, vrkey, rkey);
}

static int UVERBS_HANDLER(UVERBS_METHOD_DELETE_LOCAL_RKEY_MAPPING)(
				struct uverbs_attr_bundle *attrs) {
	uint32_t vrkey;
	int ret;
	uint32_t *rkey_arr = attrs->ufile->rkey_mapping;

	ret = uverbs_copy_from(&vrkey, attrs, UVERBS_ATTR_VHANDLE);
	if(ret)
		return ret;

	rkey_arr[vrkey] = 0;
	return service_delete_rkey_mapping(current->tgid, vrkey);
}

static int UVERBS_HANDLER(UVERBS_METHOD_DELETE_LQPN_MAPPING)(
				struct uverbs_attr_bundle *attrs) {
	uint32_t vqpn;
	int ret;

	ret = uverbs_copy_from(&vqpn, attrs, UVERBS_ATTR_VHANDLE);
	if(ret)
		return ret;
	
//	del_lqpn_mapping(attrs->ufile, vqpn);
	return 0;
}

static int UVERBS_HANDLER(UVERBS_METHOD_DELETE_LKEY_MAPPING)(
				struct uverbs_attr_bundle *attrs) {
	uint32_t vlkey;
	int ret;
	uint32_t *lkey_arr = attrs->ufile->lkey_mapping;

	ret = uverbs_copy_from(&vlkey, attrs, UVERBS_ATTR_VHANDLE);
	if(ret)
		return ret;

	lkey_arr[vlkey] = 0;
	return 0;
}

static int UVERBS_HANDLER(UVERBS_METHOD_REGISTER_REMOTE_GID_PID)(
				struct uverbs_attr_bundle *attrs) {
	union ib_gid gid;
	pid_t pid;
	int ret;

	ret = uverbs_copy_from(&gid, attrs, 0);
	ret = uverbs_copy_from(&pid, attrs, 1);
	if(ret)
		return ret;

	return register_remote_rkey_mapping(attrs->ufile, &gid, pid);
}

static int UVERBS_HANDLER(UVERBS_METHOD_GET_LOCAL_RDMA_PID)(
				struct uverbs_attr_bundle *attrs) {
	pid_t rdma_pid = current->tgid;
	return uverbs_copy_to(attrs, 0, &rdma_pid, sizeof(rdma_pid));
}

static int UVERBS_HANDLER(UVERBS_METHOD_UPDATE_COMP_CHANNEL_FD)(
				struct uverbs_attr_bundle *attrs) {
	struct ib_uobject *ev_file_uobj;
	struct ib_uverbs_completion_event_file *ev_file;

	ev_file_uobj = uverbs_attr_get_uobject(attrs, 0);
	if(IS_ERR(ev_file_uobj)) {
		return PTR_ERR(ev_file_uobj);
	}

	uverbs_uobject_get(ev_file_uobj);

	ev_file = container_of(ev_file_uobj,
					struct ib_uverbs_completion_event_file, uobj);
	if(ev_file->uobj.id != ev_file->comp_fd) {
		deregister_uverbs_completion_event_file_from_footprint(ev_file);
		ev_file->comp_fd = ev_file->uobj.id;
		register_uverbs_completion_event_file_to_footprint(ev_file, attrs->ufile, ev_file->comp_fd);
	}

	uverbs_uobject_put(ev_file_uobj);
	return 0;
}

static int UVERBS_HANDLER(UVERBS_METHOD_REGISTER_ASYNC_FD)(
				struct uverbs_attr_bundle *attrs) {
	int async_fd;
	int ret;

	ret = uverbs_copy_from(&async_fd, attrs, UVERBS_ATTR_FOOTPRINT_IN_FD);
	if(ret)
		return ret;
	
	return register_async_fd(attrs->ufile, async_fd);
}

static int UVERBS_HANDLER(UVERBS_METHOD_GET_CONTEXT)(
	struct uverbs_attr_bundle *attrs)
{
	u32 num_comp = attrs->ufile->device->num_comp_vectors;
	u64 core_support = IB_UVERBS_CORE_SUPPORT_OPTIONAL_MR_ACCESS;
	int ret;

	ret = uverbs_copy_to(attrs, UVERBS_ATTR_GET_CONTEXT_NUM_COMP_VECTORS,
			     &num_comp, sizeof(num_comp));
	if (IS_UVERBS_COPY_ERR(ret))
		return ret;

	ret = uverbs_copy_to(attrs, UVERBS_ATTR_GET_CONTEXT_CORE_SUPPORT,
			     &core_support, sizeof(core_support));
	if (IS_UVERBS_COPY_ERR(ret))
		return ret;

	ret = ib_alloc_ucontext(attrs);
	if (ret)
		return ret;
	ret = ib_init_ucontext(attrs);
	if (ret) {
		kfree(attrs->context);
		attrs->context = NULL;
		return ret;
	}
	return 0;
}

static int UVERBS_HANDLER(UVERBS_METHOD_QUERY_CONTEXT)(
	struct uverbs_attr_bundle *attrs)
{
	u64 core_support = IB_UVERBS_CORE_SUPPORT_OPTIONAL_MR_ACCESS;
	struct ib_ucontext *ucontext;
	struct ib_device *ib_dev;
	u32 num_comp;
	int ret;

	ucontext = ib_uverbs_get_ucontext(attrs);
	if (IS_ERR(ucontext))
		return PTR_ERR(ucontext);
	ib_dev = ucontext->device;

	if (!ib_dev->ops.query_ucontext)
		return -EOPNOTSUPP;

	num_comp = attrs->ufile->device->num_comp_vectors;
	ret = uverbs_copy_to(attrs, UVERBS_ATTR_QUERY_CONTEXT_NUM_COMP_VECTORS,
			     &num_comp, sizeof(num_comp));
	if (IS_UVERBS_COPY_ERR(ret))
		return ret;

	ret = uverbs_copy_to(attrs, UVERBS_ATTR_QUERY_CONTEXT_CORE_SUPPORT,
			     &core_support, sizeof(core_support));
	if (IS_UVERBS_COPY_ERR(ret))
		return ret;

	return ucontext->device->ops.query_ucontext(ucontext, attrs);
}

static int copy_gid_entries_to_user(struct uverbs_attr_bundle *attrs,
				    struct ib_uverbs_gid_entry *entries,
				    size_t num_entries, size_t user_entry_size)
{
	const struct uverbs_attr *attr;
	void __user *user_entries;
	size_t copy_len;
	int ret;
	int i;

	if (user_entry_size == sizeof(*entries)) {
		ret = uverbs_copy_to(attrs,
				     UVERBS_ATTR_QUERY_GID_TABLE_RESP_ENTRIES,
				     entries, sizeof(*entries) * num_entries);
		return ret;
	}

	copy_len = min_t(size_t, user_entry_size, sizeof(*entries));
	attr = uverbs_attr_get(attrs, UVERBS_ATTR_QUERY_GID_TABLE_RESP_ENTRIES);
	if (IS_ERR(attr))
		return PTR_ERR(attr);

	user_entries = u64_to_user_ptr(attr->ptr_attr.data);
	for (i = 0; i < num_entries; i++) {
		if (copy_to_user(user_entries, entries, copy_len))
			return -EFAULT;

		if (user_entry_size > sizeof(*entries)) {
			if (clear_user(user_entries + sizeof(*entries),
				       user_entry_size - sizeof(*entries)))
				return -EFAULT;
		}

		entries++;
		user_entries += user_entry_size;
	}

	return uverbs_output_written(attrs,
				     UVERBS_ATTR_QUERY_GID_TABLE_RESP_ENTRIES);
}

static int UVERBS_HANDLER(UVERBS_METHOD_QUERY_GID_TABLE)(
	struct uverbs_attr_bundle *attrs)
{
	struct ib_uverbs_gid_entry *entries;
	struct ib_ucontext *ucontext;
	struct ib_device *ib_dev;
	size_t user_entry_size;
	ssize_t num_entries;
	size_t max_entries;
	size_t num_bytes;
	u32 flags;
	int ret;

	ret = uverbs_get_flags32(&flags, attrs,
				 UVERBS_ATTR_QUERY_GID_TABLE_FLAGS, 0);
	if (ret)
		return ret;

	ret = uverbs_get_const(&user_entry_size, attrs,
			       UVERBS_ATTR_QUERY_GID_TABLE_ENTRY_SIZE);
	if (ret)
		return ret;

	max_entries = uverbs_attr_ptr_get_array_size(
		attrs, UVERBS_ATTR_QUERY_GID_TABLE_RESP_ENTRIES,
		user_entry_size);
	if (max_entries <= 0)
		return -EINVAL;

	ucontext = ib_uverbs_get_ucontext(attrs);
	if (IS_ERR(ucontext))
		return PTR_ERR(ucontext);
	ib_dev = ucontext->device;

	if (check_mul_overflow(max_entries, sizeof(*entries), &num_bytes))
		return -EINVAL;

	entries = uverbs_zalloc(attrs, num_bytes);
	if (!entries)
		return -ENOMEM;

	num_entries = rdma_query_gid_table(ib_dev, entries, max_entries);
	if (num_entries < 0)
		return -EINVAL;

	ret = copy_gid_entries_to_user(attrs, entries, num_entries,
				       user_entry_size);
	if (ret)
		return ret;

	ret = uverbs_copy_to(attrs,
			     UVERBS_ATTR_QUERY_GID_TABLE_RESP_NUM_ENTRIES,
			     &num_entries, sizeof(num_entries));
	return ret;
}

static int UVERBS_HANDLER(UVERBS_METHOD_QUERY_GID_ENTRY)(
	struct uverbs_attr_bundle *attrs)
{
	struct ib_uverbs_gid_entry entry = {};
	const struct ib_gid_attr *gid_attr;
	struct ib_ucontext *ucontext;
	struct ib_device *ib_dev;
	struct net_device *ndev;
	u32 gid_index;
	u32 port_num;
	u32 flags;
	int ret;

	ret = uverbs_get_flags32(&flags, attrs,
				 UVERBS_ATTR_QUERY_GID_ENTRY_FLAGS, 0);
	if (ret)
		return ret;

	ret = uverbs_get_const(&port_num, attrs,
			       UVERBS_ATTR_QUERY_GID_ENTRY_PORT);
	if (ret)
		return ret;

	ret = uverbs_get_const(&gid_index, attrs,
			       UVERBS_ATTR_QUERY_GID_ENTRY_GID_INDEX);
	if (ret)
		return ret;

	ucontext = ib_uverbs_get_ucontext(attrs);
	if (IS_ERR(ucontext))
		return PTR_ERR(ucontext);
	ib_dev = ucontext->device;

	if (!rdma_is_port_valid(ib_dev, port_num))
		return -EINVAL;

	gid_attr = rdma_get_gid_attr(ib_dev, port_num, gid_index);
	if (IS_ERR(gid_attr))
		return PTR_ERR(gid_attr);

	memcpy(&entry.gid, &gid_attr->gid, sizeof(gid_attr->gid));
	entry.gid_index = gid_attr->index;
	entry.port_num = gid_attr->port_num;
	entry.gid_type = gid_attr->gid_type;

	rcu_read_lock();
	ndev = rdma_read_gid_attr_ndev_rcu(gid_attr);
	if (IS_ERR(ndev)) {
		if (PTR_ERR(ndev) != -ENODEV) {
			ret = PTR_ERR(ndev);
			rcu_read_unlock();
			goto out;
		}
	} else {
		entry.netdev_ifindex = ndev->ifindex;
	}
	rcu_read_unlock();

	ret = uverbs_copy_to_struct_or_zero(
		attrs, UVERBS_ATTR_QUERY_GID_ENTRY_RESP_ENTRY, &entry,
		sizeof(entry));
out:
	rdma_put_gid_attr(gid_attr);
	return ret;
}

DECLARE_UVERBS_NAMED_METHOD(
	UVERBS_METHOD_INSTALL_FOOTPRINT,
	UVERBS_ATTR_PTR_IN(UVERBS_ATTR_FOOTPRINT_IN_FD,
				UVERBS_ATTR_TYPE(u32), UA_MANDATORY));

DECLARE_UVERBS_NAMED_METHOD(
	UVERBS_METHOD_INSTALL_QPN_DICT,
	UVERBS_ATTR_PTR_IN(0,
				UVERBS_ATTR_TYPE(u32), UA_MANDATORY),
	UVERBS_ATTR_PTR_IN(1,
				UVERBS_ATTR_TYPE(u32), UA_MANDATORY));

DECLARE_UVERBS_NAMED_METHOD(
	UVERBS_METHOD_INSTALL_CTX_RESP,
	UVERBS_ATTR_PTR_IN(UVERBS_ATTR_RESP_PTR,
				UVERBS_ATTR_TYPE(__aligned_u64), UA_MANDATORY),
	UVERBS_ATTR_PTR_IN(UVERBS_ATTR_RESP_SZ,
				UVERBS_ATTR_TYPE(u64), UA_MANDATORY));

DECLARE_UVERBS_NAMED_METHOD(
	UVERBS_METHOD_REGISTER_ASYNC_FD,
	UVERBS_ATTR_PTR_IN(UVERBS_ATTR_FOOTPRINT_IN_FD,
				UVERBS_ATTR_TYPE(u32), UA_MANDATORY));

DECLARE_UVERBS_NAMED_METHOD(
	UVERBS_METHOD_INSTALL_PD_HANDLE_MAPPING,
	UVERBS_ATTR_PTR_IN(UVERBS_ATTR_VHANDLE,
				UVERBS_ATTR_TYPE(u32), UA_MANDATORY),
	UVERBS_ATTR_PTR_IN(UVERBS_ATTR_HANDLE,
				UVERBS_ATTR_TYPE(u32), UA_MANDATORY));

DECLARE_UVERBS_NAMED_METHOD(
	UVERBS_METHOD_INSTALL_CQ_HANDLE_MAPPING,
	UVERBS_ATTR_PTR_IN(UVERBS_ATTR_VHANDLE,
				UVERBS_ATTR_TYPE(u32), UA_MANDATORY),
	UVERBS_ATTR_PTR_IN(UVERBS_ATTR_HANDLE,
				UVERBS_ATTR_TYPE(u32), UA_MANDATORY));

DECLARE_UVERBS_NAMED_METHOD(
	UVERBS_METHOD_INSTALL_MR_HANDLE_MAPPING,
	UVERBS_ATTR_PTR_IN(UVERBS_ATTR_VHANDLE,
				UVERBS_ATTR_TYPE(u32), UA_MANDATORY),
	UVERBS_ATTR_PTR_IN(UVERBS_ATTR_HANDLE,
				UVERBS_ATTR_TYPE(u32), UA_MANDATORY));

DECLARE_UVERBS_NAMED_METHOD(
	UVERBS_METHOD_INSTALL_QP_HANDLE_MAPPING,
	UVERBS_ATTR_PTR_IN(UVERBS_ATTR_VHANDLE,
				UVERBS_ATTR_TYPE(u32), UA_MANDATORY),
	UVERBS_ATTR_PTR_IN(UVERBS_ATTR_HANDLE,
				UVERBS_ATTR_TYPE(u32), UA_MANDATORY));

DECLARE_UVERBS_NAMED_METHOD(
	UVERBS_METHOD_INSTALL_SRQ_HANDLE_MAPPING,
	UVERBS_ATTR_PTR_IN(UVERBS_ATTR_VHANDLE,
				UVERBS_ATTR_TYPE(u32), UA_MANDATORY),
	UVERBS_ATTR_PTR_IN(UVERBS_ATTR_HANDLE,
				UVERBS_ATTR_TYPE(u32), UA_MANDATORY));

DECLARE_UVERBS_NAMED_METHOD(
	UVERBS_METHOD_INSTALL_LQPN_MAPPING,
	UVERBS_ATTR_PTR_IN(UVERBS_ATTR_VHANDLE,
				UVERBS_ATTR_TYPE(u32), UA_MANDATORY),
	UVERBS_ATTR_PTR_IN(UVERBS_ATTR_HANDLE,
				UVERBS_ATTR_TYPE(u32), UA_MANDATORY));

DECLARE_UVERBS_NAMED_METHOD(
	UVERBS_METHOD_INSTALL_LKEY_MAPPING,
	UVERBS_ATTR_PTR_IN(UVERBS_ATTR_VHANDLE,
				UVERBS_ATTR_TYPE(u32), UA_MANDATORY),
	UVERBS_ATTR_PTR_IN(UVERBS_ATTR_HANDLE,
				UVERBS_ATTR_TYPE(u32), UA_MANDATORY));

DECLARE_UVERBS_NAMED_METHOD(
	UVERBS_METHOD_INSTALL_LOCAL_RKEY_MAPPING,
	UVERBS_ATTR_PTR_IN(UVERBS_ATTR_VHANDLE,
				UVERBS_ATTR_TYPE(u32), UA_MANDATORY),
	UVERBS_ATTR_PTR_IN(UVERBS_ATTR_HANDLE,
				UVERBS_ATTR_TYPE(u32), UA_MANDATORY));

DECLARE_UVERBS_NAMED_METHOD(
	UVERBS_METHOD_DELETE_LOCAL_RKEY_MAPPING,
	UVERBS_ATTR_PTR_IN(UVERBS_ATTR_VHANDLE,
				UVERBS_ATTR_TYPE(u32), UA_MANDATORY));

DECLARE_UVERBS_NAMED_METHOD(
	UVERBS_METHOD_DELETE_LQPN_MAPPING,
	UVERBS_ATTR_PTR_IN(UVERBS_ATTR_VHANDLE,
				UVERBS_ATTR_TYPE(u32), UA_MANDATORY));

DECLARE_UVERBS_NAMED_METHOD(
	UVERBS_METHOD_DELETE_LKEY_MAPPING,
	UVERBS_ATTR_PTR_IN(UVERBS_ATTR_VHANDLE,
				UVERBS_ATTR_TYPE(u32), UA_MANDATORY));

DECLARE_UVERBS_NAMED_METHOD(
	UVERBS_METHOD_GET_LOCAL_RDMA_PID,
	UVERBS_ATTR_PTR_OUT(0,
				UVERBS_ATTR_TYPE(pid_t), UA_MANDATORY));

DECLARE_UVERBS_NAMED_METHOD(
	UVERBS_METHOD_UPDATE_COMP_CHANNEL_FD,
	UVERBS_ATTR_FD(0, UVERBS_OBJECT_COMP_CHANNEL,
			UVERBS_ACCESS_READ, UA_OPTIONAL));

DECLARE_UVERBS_NAMED_METHOD(
	UVERBS_METHOD_REGISTER_REMOTE_GID_PID,
	UVERBS_ATTR_PTR_IN(0,
				UVERBS_ATTR_TYPE(union ib_gid), UA_MANDATORY),
	UVERBS_ATTR_PTR_IN(1,
				UVERBS_ATTR_TYPE(u32), UA_MANDATORY));

DECLARE_UVERBS_NAMED_METHOD(
	UVERBS_METHOD_GET_CONTEXT,
	UVERBS_ATTR_PTR_OUT(UVERBS_ATTR_GET_CONTEXT_NUM_COMP_VECTORS,
			    UVERBS_ATTR_TYPE(u32), UA_OPTIONAL),
	UVERBS_ATTR_PTR_OUT(UVERBS_ATTR_GET_CONTEXT_CORE_SUPPORT,
			    UVERBS_ATTR_TYPE(u64), UA_OPTIONAL),
	UVERBS_ATTR_UHW());

DECLARE_UVERBS_NAMED_METHOD(
	UVERBS_METHOD_QUERY_CONTEXT,
	UVERBS_ATTR_PTR_OUT(UVERBS_ATTR_QUERY_CONTEXT_NUM_COMP_VECTORS,
			    UVERBS_ATTR_TYPE(u32), UA_OPTIONAL),
	UVERBS_ATTR_PTR_OUT(UVERBS_ATTR_QUERY_CONTEXT_CORE_SUPPORT,
			    UVERBS_ATTR_TYPE(u64), UA_OPTIONAL));

DECLARE_UVERBS_NAMED_METHOD(
	UVERBS_METHOD_INFO_HANDLES,
	/* Also includes any device specific object ids */
	UVERBS_ATTR_CONST_IN(UVERBS_ATTR_INFO_OBJECT_ID,
			     enum uverbs_default_objects, UA_MANDATORY),
	UVERBS_ATTR_PTR_OUT(UVERBS_ATTR_INFO_TOTAL_HANDLES,
			    UVERBS_ATTR_TYPE(u32), UA_OPTIONAL),
	UVERBS_ATTR_PTR_OUT(UVERBS_ATTR_INFO_HANDLES_LIST,
			    UVERBS_ATTR_MIN_SIZE(sizeof(u32)), UA_OPTIONAL));

DECLARE_UVERBS_NAMED_METHOD(
	UVERBS_METHOD_QUERY_PORT,
	UVERBS_ATTR_CONST_IN(UVERBS_ATTR_QUERY_PORT_PORT_NUM, u8, UA_MANDATORY),
	UVERBS_ATTR_PTR_OUT(
		UVERBS_ATTR_QUERY_PORT_RESP,
		UVERBS_ATTR_STRUCT(struct ib_uverbs_query_port_resp_ex,
				   reserved),
		UA_MANDATORY));

DECLARE_UVERBS_NAMED_METHOD(
	UVERBS_METHOD_QUERY_GID_TABLE,
	UVERBS_ATTR_CONST_IN(UVERBS_ATTR_QUERY_GID_TABLE_ENTRY_SIZE, u64,
			     UA_MANDATORY),
	UVERBS_ATTR_FLAGS_IN(UVERBS_ATTR_QUERY_GID_TABLE_FLAGS, u32,
			     UA_OPTIONAL),
	UVERBS_ATTR_PTR_OUT(UVERBS_ATTR_QUERY_GID_TABLE_RESP_ENTRIES,
			    UVERBS_ATTR_MIN_SIZE(0), UA_MANDATORY),
	UVERBS_ATTR_PTR_OUT(UVERBS_ATTR_QUERY_GID_TABLE_RESP_NUM_ENTRIES,
			    UVERBS_ATTR_TYPE(u64), UA_MANDATORY));

DECLARE_UVERBS_NAMED_METHOD(
	UVERBS_METHOD_QUERY_GID_ENTRY,
	UVERBS_ATTR_CONST_IN(UVERBS_ATTR_QUERY_GID_ENTRY_PORT, u32,
			     UA_MANDATORY),
	UVERBS_ATTR_CONST_IN(UVERBS_ATTR_QUERY_GID_ENTRY_GID_INDEX, u32,
			     UA_MANDATORY),
	UVERBS_ATTR_FLAGS_IN(UVERBS_ATTR_QUERY_GID_ENTRY_FLAGS, u32,
			     UA_MANDATORY),
	UVERBS_ATTR_PTR_OUT(UVERBS_ATTR_QUERY_GID_ENTRY_RESP_ENTRY,
			    UVERBS_ATTR_STRUCT(struct ib_uverbs_gid_entry,
					       netdev_ifindex),
			    UA_MANDATORY));

DECLARE_UVERBS_GLOBAL_METHODS(UVERBS_OBJECT_DEVICE,
			      &UVERBS_METHOD(UVERBS_METHOD_GET_CONTEXT),
			      &UVERBS_METHOD(UVERBS_METHOD_INVOKE_WRITE),
			      &UVERBS_METHOD(UVERBS_METHOD_INFO_HANDLES),
			      &UVERBS_METHOD(UVERBS_METHOD_QUERY_PORT),
			      &UVERBS_METHOD(UVERBS_METHOD_QUERY_CONTEXT),
			      &UVERBS_METHOD(UVERBS_METHOD_QUERY_GID_TABLE),
			      &UVERBS_METHOD(UVERBS_METHOD_QUERY_GID_ENTRY));

DECLARE_UVERBS_GLOBAL_METHODS(UVERBS_OBJECT_FOOTPRINT,
				&UVERBS_METHOD(UVERBS_METHOD_INSTALL_QPN_DICT),
				&UVERBS_METHOD(UVERBS_METHOD_INSTALL_FOOTPRINT),
				&UVERBS_METHOD(UVERBS_METHOD_INSTALL_CTX_RESP),
				&UVERBS_METHOD(UVERBS_METHOD_REGISTER_ASYNC_FD),
				&UVERBS_METHOD(UVERBS_METHOD_INSTALL_PD_HANDLE_MAPPING),
				&UVERBS_METHOD(UVERBS_METHOD_INSTALL_CQ_HANDLE_MAPPING),
				&UVERBS_METHOD(UVERBS_METHOD_INSTALL_MR_HANDLE_MAPPING),
				&UVERBS_METHOD(UVERBS_METHOD_INSTALL_QP_HANDLE_MAPPING),
				&UVERBS_METHOD(UVERBS_METHOD_INSTALL_SRQ_HANDLE_MAPPING),
				&UVERBS_METHOD(UVERBS_METHOD_INSTALL_LQPN_MAPPING),
				&UVERBS_METHOD(UVERBS_METHOD_INSTALL_LKEY_MAPPING),
				&UVERBS_METHOD(UVERBS_METHOD_INSTALL_LOCAL_RKEY_MAPPING),
				&UVERBS_METHOD(UVERBS_METHOD_DELETE_LOCAL_RKEY_MAPPING),
				&UVERBS_METHOD(UVERBS_METHOD_DELETE_LQPN_MAPPING),
				&UVERBS_METHOD(UVERBS_METHOD_DELETE_LKEY_MAPPING),
				&UVERBS_METHOD(UVERBS_METHOD_REGISTER_REMOTE_GID_PID),
				&UVERBS_METHOD(UVERBS_METHOD_GET_LOCAL_RDMA_PID),
				&UVERBS_METHOD(UVERBS_METHOD_UPDATE_COMP_CHANNEL_FD));

const struct uapi_definition uverbs_def_obj_device[] = {
	UAPI_DEF_CHAIN_OBJ_TREE_NAMED(UVERBS_OBJECT_DEVICE),
	{},
};

const struct uapi_definition uverbs_def_obj_footprint[] = {
	UAPI_DEF_CHAIN_OBJ_TREE_NAMED(UVERBS_OBJECT_FOOTPRINT),
	{},
};
