/*
 * Copyright (c) 2019, Mellanox Technologies. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *	Redistribution and use in source and binary forms, with or
 *	without modification, are permitted provided that the following
 *	conditions are met:
 *
 *	- Redistributions of source code must retain the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer.
 *
 *	- Redistributions in binary form must reproduce the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer in the documentation and/or other materials
 *	  provided with the distribution.
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

#include <unistd.h>
#include <stdlib.h>
#include "mlx5dv_dr.h"

enum {
	MLX5DV_DR_DOMAIN_SYNC_SUP_FLAGS =
		(MLX5DV_DR_DOMAIN_SYNC_FLAGS_SW |
		 MLX5DV_DR_DOMAIN_SYNC_FLAGS_HW |
		 MLX5DV_DR_DOMAIN_SYNC_FLAGS_MEM),
};

bool dr_domain_is_support_modify_hdr_cache(struct mlx5dv_dr_domain *dmn)
{
	return dmn->info.caps.support_modify_argument;
}

static int dr_domain_init_modify_header_resources(struct mlx5dv_dr_domain *dmn)
{
	if (!dr_domain_is_support_modify_hdr_cache(dmn))
		return 0;

	dmn->modify_header_ptrn_icm_pool =
		dr_icm_pool_create(dmn, DR_ICM_TYPE_MODIFY_HDR_PTRN);
	if (!dmn->modify_header_ptrn_icm_pool) {
		dr_dbg(dmn, "Couldn't get modify-header-pattern memory for %s\n",
		       ibv_get_device_name(dmn->ctx->device));
		return errno;
	}
	/* create argument pool */
	dmn->modify_header_arg_pool_mngr = dr_arg_pool_mngr_create(dmn);
	if (!dmn->modify_header_arg_pool_mngr)
		goto free_modify_header_pattern;

	return 0;

free_modify_header_pattern:
	dr_icm_pool_destroy(dmn->modify_header_ptrn_icm_pool);
	return errno;
}

static void dr_domain_destroy_modify_header_resources(struct mlx5dv_dr_domain *dmn)
{
	if (!dr_domain_is_support_modify_hdr_cache(dmn))
		return;

	dr_icm_pool_destroy(dmn->modify_header_ptrn_icm_pool);
	dr_arg_pool_mngr_destroy(dmn->modify_header_arg_pool_mngr);
}

static bool dr_domain_check_hw_basic_requirement_caps(struct mlx5dv_dr_domain *dmn)
{
	if (dmn->info.caps.sw_format_ver == MLX5_HW_CONNECTX_6DX &&
	    !dr_domain_is_support_modify_hdr_cache(dmn)) {
		return false;
	}

	return true;
}

static bool dr_domain_is_supp_sw_steering(struct mlx5dv_dr_domain *dmn)
{
	if (!dr_domain_check_hw_basic_requirement_caps(dmn))
		return false;

	switch (dmn->type) {
	case MLX5DV_DR_DOMAIN_TYPE_NIC_RX:
		if (!dmn->info.caps.rx_sw_owner && !dmn->info.caps.rx_sw_owner_v2)
			return false;
		break;
	case MLX5DV_DR_DOMAIN_TYPE_NIC_TX:
		if (!dmn->info.caps.tx_sw_owner && !dmn->info.caps.tx_sw_owner_v2)
			return false;
		break;
	case MLX5DV_DR_DOMAIN_TYPE_FDB:
		if (!dmn->info.caps.fdb_sw_owner && !dmn->info.caps.fdb_sw_owner_v2)
			return false;
		break;
	}
	return true;
}

static int dr_domain_init_resources(struct mlx5dv_dr_domain *dmn)
{
	int ret = -1;

	dmn->ste_ctx = dr_ste_get_ctx(dmn->info.caps.sw_format_ver);
	if (!dmn->ste_ctx) {
		dr_dbg(dmn, "Couldn't initialize STE context\n");
		return errno;
	}

	dmn->pd = ibv_alloc_pd(dmn->ctx);
	if (!dmn->pd) {
		dr_dbg(dmn, "Couldn't allocate PD\n");
		return ret;
	}

	dmn->uar = mlx5dv_devx_alloc_uar(dmn->ctx,
					 MLX5_IB_UAPI_UAR_ALLOC_TYPE_NC);

	if (!dmn->uar)
		dmn->uar = mlx5dv_devx_alloc_uar(dmn->ctx,
						 MLX5_IB_UAPI_UAR_ALLOC_TYPE_BF);

	if (!dmn->uar) {
		dr_dbg(dmn, "Can't allocate UAR\n");
		goto clean_pd;
	}

	dmn->ste_icm_pool = dr_icm_pool_create(dmn, DR_ICM_TYPE_STE);
	if (!dmn->ste_icm_pool) {
		dr_dbg(dmn, "Couldn't get icm memory for %s\n",
		       ibv_get_device_name(dmn->ctx->device));
		goto clean_uar;
	}

	dmn->action_icm_pool = dr_icm_pool_create(dmn, DR_ICM_TYPE_MODIFY_ACTION);
	if (!dmn->action_icm_pool) {
		dr_dbg(dmn, "Couldn't get action icm memory for %s\n",
		       ibv_get_device_name(dmn->ctx->device));
		goto free_ste_icm_pool;
	}

	ret = dr_send_ring_alloc(dmn);
	if (ret) {
		dr_dbg(dmn, "Couldn't create send-ring for %s\n",
		       ibv_get_device_name(dmn->ctx->device));
		goto free_action_icm_pool;
	}

	ret = dr_domain_init_modify_header_resources(dmn);
	if (ret) {
		dr_dbg(dmn, "Couldn't create modify-header-res for %s\n",
		       ibv_get_device_name(dmn->ctx->device));
		goto free_send_ring;
	}

	return 0;

free_send_ring:
	dr_send_ring_free(dmn);
free_action_icm_pool:
	dr_icm_pool_destroy(dmn->action_icm_pool);
free_ste_icm_pool:
	dr_icm_pool_destroy(dmn->ste_icm_pool);
clean_uar:
	mlx5dv_devx_free_uar(dmn->uar);
clean_pd:
	ibv_dealloc_pd(dmn->pd);

	return ret;
}

static void dr_free_resources(struct mlx5dv_dr_domain *dmn)
{
	dr_send_ring_free(dmn);
	dr_domain_destroy_modify_header_resources(dmn);
	dr_icm_pool_destroy(dmn->action_icm_pool);
	dr_icm_pool_destroy(dmn->ste_icm_pool);
	mlx5dv_devx_free_uar(dmn->uar);
	ibv_dealloc_pd(dmn->pd);
}

int dr_domain_query_and_set_vport(struct ibv_context *ctx,
				  struct dr_devx_vports *vports,
				  bool other_vport,
				  uint16_t vport_number)
{
	struct dr_devx_vport_cap *new_vport;
	int ret = 0;

	pthread_spin_lock(&vports->lock);

	/* Skip in case port already set */
	if (vports->vports[vport_number])
		goto unlock_ret;

	new_vport = calloc(1, sizeof(struct dr_devx_vport_cap));
	if (!new_vport) {
		errno = ENOMEM;
		ret = errno;
		goto unlock_ret;
	}

	ret = dr_devx_query_esw_vport_context(ctx, other_vport,
					      vport_number,
					      &new_vport->icm_address_rx,
					      &new_vport->icm_address_tx);
	if (ret)
		goto unlock_free;

	ret = dr_devx_query_gvmi(ctx, other_vport, vport_number, &new_vport->vport_gvmi);
	if (ret)
		goto unlock_free;

	new_vport->num = vport_number;
	new_vport->vhca_gvmi = vports->esw_mngr.vhca_gvmi;

	/* Set port only once all fields are set to avoid a race */
	vports->vports[vport_number] = new_vport;

	pthread_spin_unlock(&vports->lock);

	return 0;

unlock_free:
	free(new_vport);
unlock_ret:
	pthread_spin_unlock(&vports->lock);
	return ret;
}

static void dr_domain_vports_cleanup(struct dr_devx_vports *vports)
{
	int i;

	if (vports->ib_ports) {
		free(vports->ib_ports);
		vports->ib_ports = NULL;
	}

	for (i = 0; i < MAX_VPORT_NUM - 1; i++) {
		if (vports->vports[i]) {
			free(vports->vports[i]);
			vports->vports[i] = NULL;
		}

		if (vports->other_vports[i]) {
			free(vports->other_vports[i]);
			vports->other_vports[i] = NULL;
		}
	}
}

static int dr_domain_query_esw_mgr(struct mlx5dv_dr_domain *dmn,
				   struct dr_devx_vport_cap *esw_mngr)
{
	int ret;

	/* Query E-Switch manager PF/ECPF */
	ret = dr_devx_query_esw_vport_context(dmn->ctx, false, 0,
					      &esw_mngr->icm_address_rx,
					      &esw_mngr->icm_address_tx);
	if (ret)
		return ret;

	/* E-Switch manager gvmi and vhca id are the same */
	esw_mngr->vhca_gvmi = dmn->info.caps.gvmi;
	esw_mngr->vport_gvmi = dmn->info.caps.gvmi;

	return 0;
}

int dr_domain_query_and_set_ib_port(struct ibv_context *ctx,
				    struct dr_devx_vports *vports,
				    uint32_t port_num)
{
	struct mlx5dv_devx_port devx_port = {};
	struct dr_devx_vport_cap **vport_ptr;
	struct dr_devx_vport_cap *new_vport;
	uint64_t req_comp_mask;
	uint64_t wire_comp_mask;
	uint64_t comp_mask;
	int ret;

	wire_comp_mask = MLX5DV_DEVX_PORT_VPORT |
			 MLX5DV_DEVX_PORT_ESW_OWNER_VHCA_ID |
			 MLX5DV_DEVX_PORT_VPORT_ICM_TX;

	comp_mask = wire_comp_mask |
		    MLX5DV_DEVX_PORT_VPORT_VHCA_ID |
		    MLX5DV_DEVX_PORT_VPORT_ICM_RX;

	req_comp_mask = comp_mask |
			MLX5DV_DEVX_PORT_MATCH_REG_C_0;

	devx_port.comp_mask = req_comp_mask;

	ret = mlx5dv_query_devx_port(ctx, port_num, &devx_port);
	if (ret)
		return ret;

	if (!(devx_port.comp_mask & MLX5DV_DEVX_PORT_VPORT))
		return 0;

	/* Check if required fields were supplied */
	if (devx_port.vport_num == WIRE_PORT) {
		if ((devx_port.comp_mask & wire_comp_mask) != wire_comp_mask) {
			errno = EINVAL;
			return errno;
		}
	} else {
		if ((devx_port.comp_mask & comp_mask) != comp_mask)
			return 0;
	}

	pthread_spin_lock(&vports->lock);

	if (devx_port.esw_owner_vhca_id == vports->esw_mngr.vport_gvmi)
		vport_ptr = &vports->vports[devx_port.vport_num];
	else
		vport_ptr = &vports->other_vports[devx_port.vport_num];

	if (!*vport_ptr) {
		new_vport = calloc(1, sizeof(struct dr_devx_vport_cap));
		if (!new_vport) {
			errno = ENOMEM;
			ret = errno;
			goto unlock_ret;
		}
	} else {
		/* Continue in case the vport was not mapped to ib port */
		new_vport = *vport_ptr;
	}

	new_vport->num = devx_port.vport_num;
	new_vport->vport_gvmi = devx_port.vport_vhca_id;
	new_vport->vhca_gvmi = devx_port.esw_owner_vhca_id;
	new_vport->icm_address_rx = devx_port.icm_addr_rx;
	new_vport->icm_address_tx = devx_port.icm_addr_tx;

	if (devx_port.comp_mask & MLX5DV_DEVX_PORT_MATCH_REG_C_0) {
		new_vport->metadata_c = devx_port.reg_c_0.value;
		new_vport->metadata_c_mask = devx_port.reg_c_0.mask;
	}
	/* Set port only once all fields are set to avoid a race */
	*vport_ptr = new_vport;
	/* IB port idx <-> vport idx <-> GVMI/ICM is constant */
	vports->ib_ports[port_num - 1] = new_vport;

unlock_ret:
	pthread_spin_unlock(&vports->lock);
	return ret;
}

static int dr_domain_query_and_set_ib_ports(struct mlx5dv_dr_domain *dmn)
{
	struct dr_devx_vports *vports = &dmn->info.caps.vports;
	int ret;
	int i;

	vports->ib_ports = calloc(vports->num_ports, sizeof(struct dr_devx_vport_cap *));
	if (!vports->ib_ports) {
		errno = ENOMEM;
		return errno;
	}

	for (i = 1; i <= vports->num_ports; i++) {
		ret = dr_domain_query_and_set_ib_port(dmn->ctx, vports, i);
		if (ret)
			goto cleanup;
	}

	return 0;

cleanup:
	dr_domain_vports_cleanup(vports);
	return errno;
}

static void dr_domain_query_num_ib_ports(struct mlx5dv_dr_domain *dmn)
{
	int index = ibv_get_device_index(dmn->ctx->device);
	int ret;

	ret = dr_nl_get_number_of_ib_ports(index, &dmn->info.caps.num_vports);
	if (ret)
		dmn->info.caps.num_vports = dmn->info.attr.phys_port_cnt;
}

static int dr_domain_query_fdb_caps(struct ibv_context *ctx,
				    struct mlx5dv_dr_domain *dmn)
{
	struct dr_devx_vports *vports = &dmn->info.caps.vports;
	struct dr_esw_caps esw_caps = {};
	int ret;

	if (pthread_spin_init(&vports->lock, PTHREAD_PROCESS_PRIVATE))
		return ENOMEM;

	if (!dmn->info.caps.eswitch_manager)
		return 0;

	ret = dr_domain_query_esw_mgr(dmn, &vports->esw_mngr);
	if (ret)
		return ret;

	ret = dr_devx_query_esw_caps(ctx, &esw_caps);
	if (ret)
		return ret;

	dr_domain_query_num_ib_ports(dmn);
	vports->num_ports = dmn->info.caps.num_vports;

	/* Set uplink */
	vports->wire.icm_address_rx = esw_caps.uplink_icm_address_rx;
	vports->wire.icm_address_tx = esw_caps.uplink_icm_address_tx;
	vports->wire.vhca_gvmi = vports->esw_mngr.vhca_gvmi;
	vports->wire.num = WIRE_PORT;
	vports->vports[WIRE_PORT] = &vports->wire;

	/* Set FDB general caps */
	dmn->info.caps.fdb_sw_owner = esw_caps.sw_owner;
	dmn->info.caps.fdb_sw_owner_v2 = esw_caps.sw_owner_v2;
	dmn->info.caps.esw_rx_drop_address = esw_caps.drop_icm_address_rx;
	dmn->info.caps.esw_tx_drop_address = esw_caps.drop_icm_address_tx;

	ret = dr_domain_query_and_set_ib_ports(dmn);
	if (ret)
		dr_dbg(dmn, "Failed to query ib vports\n");

	return 0;
}

static int dr_domain_caps_init(struct ibv_context *ctx,
			       struct mlx5dv_dr_domain *dmn)
{
	struct ibv_port_attr port_attr = {};
	int ret;

	dmn->info.caps.ctx = ctx;

	ret = ibv_query_port(ctx, 1, &port_attr);
	if (ret) {
		dr_dbg(dmn, "Failed to query port\n");
		return ret;
	}

	if (port_attr.link_layer != IBV_LINK_LAYER_ETHERNET) {
		dr_dbg(dmn, "Failed to allocate domain, bad link type\n");
		errno = EOPNOTSUPP;
		return errno;
	}

	ret = ibv_query_device(ctx, &dmn->info.attr);
	if (ret)
		return ret;

	ret = dr_devx_query_device(ctx, &dmn->info.caps);
	if (ret)
		/* Ignore devx query failure to allow steering on root level
		 * tables in case devx is not supported over mlx5dv_dr API
		 */
		return 0;

	ret = dr_domain_query_fdb_caps(ctx, dmn);
	if (ret)
		return ret;

	if (!dr_domain_is_supp_sw_steering(dmn))
		return 0;

	switch (dmn->type) {
	case MLX5DV_DR_DOMAIN_TYPE_NIC_RX:
		dmn->info.supp_sw_steering = true;
		dmn->info.rx.type = DR_DOMAIN_NIC_TYPE_RX;
		dmn->info.rx.default_icm_addr = dmn->info.caps.nic_rx_drop_address;
		dmn->info.rx.drop_icm_addr = dmn->info.caps.nic_rx_drop_address;
		break;
	case MLX5DV_DR_DOMAIN_TYPE_NIC_TX:
		dmn->info.supp_sw_steering = true;
		dmn->info.tx.type = DR_DOMAIN_NIC_TYPE_TX;
		dmn->info.tx.default_icm_addr = dmn->info.caps.nic_tx_allow_address;
		dmn->info.tx.drop_icm_addr = dmn->info.caps.nic_tx_drop_address;
		break;
	case MLX5DV_DR_DOMAIN_TYPE_FDB:
		dmn->info.rx.type = DR_DOMAIN_NIC_TYPE_RX;
		dmn->info.tx.type = DR_DOMAIN_NIC_TYPE_TX;

		dmn->info.supp_sw_steering = true;
		dmn->info.tx.default_icm_addr = dmn->info.caps.vports.esw_mngr.icm_address_tx;
		dmn->info.rx.default_icm_addr = dmn->info.caps.vports.esw_mngr.icm_address_rx;
		dmn->info.rx.drop_icm_addr = dmn->info.caps.esw_rx_drop_address;
		dmn->info.tx.drop_icm_addr = dmn->info.caps.esw_tx_drop_address;
		break;
	default:
		dr_dbg(dmn, "Invalid domain\n");
		ret = EINVAL;
		break;
	}

	return ret;
}

static void dr_domain_caps_uninit(struct mlx5dv_dr_domain *dmn)
{
	dr_domain_vports_cleanup(&dmn->info.caps.vports);
}

static int dr_domain_check_icm_memory_caps(struct mlx5dv_dr_domain *dmn)
{
	char *str_req_icm_sz;
	uint32_t req_icm_sz;

	if (dmn->info.caps.log_modify_hdr_icm_size < DR_CHUNK_SIZE_4K +
	    DR_MODIFY_ACTION_LOG_SIZE) {
		errno = ENOMEM;
		return errno;
	}

	dmn->info.max_log_action_icm_sz = min_t(uint32_t,
						DR_CHUNK_SIZE_1024K,
						dmn->info.caps.log_modify_hdr_icm_size
						- DR_MODIFY_ACTION_LOG_SIZE);

	/* Allows user to set max hash table size */
	str_req_icm_sz = getenv("TEMP_TESTING_MAX_TABLE_LOG_SIZE");
	if (str_req_icm_sz && dmn->info.caps.sw_format_ver == MLX5_HW_CONNECTX_6DX)
		req_icm_sz = strtol(str_req_icm_sz, NULL, 0);
	else
		req_icm_sz = DR_CHUNK_SIZE_1024K;

	if (dmn->info.caps.log_icm_size < req_icm_sz + DR_STE_LOG_SIZE) {
		errno = ENOMEM;
		return errno;
	}

	dmn->info.max_log_sw_icm_sz = req_icm_sz;

	if (dmn->info.caps.sw_format_ver == 1) {
		if (dmn->info.caps.log_modify_pattern_icm_size < DR_CHUNK_SIZE_4K +
		    DR_MODIFY_ACTION_LOG_SIZE) {
			errno = ENOMEM;
			return errno;
		}
		dmn->info.max_log_modify_hdr_pattern_icm_sz = DR_CHUNK_SIZE_4K;
	}

	return 0;
}

struct mlx5dv_dr_domain *
mlx5dv_dr_domain_create(struct ibv_context *ctx,
			enum mlx5dv_dr_domain_type type)
{
	struct mlx5dv_dr_domain *dmn;
	int ret;

	if (type > MLX5DV_DR_DOMAIN_TYPE_FDB) {
		errno = EINVAL;
		return NULL;
	}

	dmn = calloc(1, sizeof(*dmn));
	if (!dmn) {
		errno = ENOMEM;
		return NULL;
	}

	dmn->ctx = ctx;
	dmn->type = type;

	atomic_init(&dmn->refcount, 1);
	list_head_init(&dmn->tbl_list);
	list_head_init(&dmn->modify_hdr_list);
	ret = pthread_spin_init(&dmn->debug_lock, PTHREAD_PROCESS_PRIVATE);
	if (ret) {
		errno = ret;
		goto free_domain;
	}

	if (dr_domain_nic_init(&dmn->info.rx) ||
	    dr_domain_nic_init(&dmn->info.tx) ||
	    pthread_spin_init(&dmn->modify_hdr_lock, PTHREAD_PROCESS_PRIVATE)) {
		errno = ENOMEM;
		goto free_domain;
	}

	if (dr_domain_caps_init(ctx, dmn)) {
		dr_dbg(dmn, "Failed init domain, no caps\n");
		goto free_domain;
	}

	/* Allocate resources */
	if (dmn->info.supp_sw_steering) {

		if (dr_domain_check_icm_memory_caps(dmn))
			goto uninit_caps;

		ret = dr_domain_init_resources(dmn);
		if (ret) {
			dr_dbg(dmn, "Failed init domain resources for %s\n",
			       ibv_get_device_name(ctx->device));
			goto uninit_caps;
		}
		/* Init CRC table for htbl CRC calculation */
		dr_crc32_init_table();
	}

	pthread_mutex_init(&dmn->cross_mutex, NULL);

	return dmn;

uninit_caps:
	dr_domain_caps_uninit(dmn);
free_domain:
	free(dmn);
	return NULL;
}

/*
 * Assure synchronization of the device steering tables with updates made by SW
 * insertion.
 */
int mlx5dv_dr_domain_sync(struct mlx5dv_dr_domain *dmn, uint32_t flags)
{
	int ret = 0;

	if (!dmn->info.supp_sw_steering ||
	    !check_comp_mask(flags, MLX5DV_DR_DOMAIN_SYNC_SUP_FLAGS)) {
		errno = EOPNOTSUPP;
		return errno;
	}

	if (flags & MLX5DV_DR_DOMAIN_SYNC_FLAGS_SW) {
		ret = dr_send_ring_force_drain(dmn);
		if (ret)
			return ret;
	}

	if (flags & MLX5DV_DR_DOMAIN_SYNC_FLAGS_HW) {
		ret = dr_devx_sync_steering(dmn->ctx);
		if (ret)
			return ret;
	}

	if (flags & MLX5DV_DR_DOMAIN_SYNC_FLAGS_MEM) {
		if (dmn->ste_icm_pool) {
			ret = dr_icm_pool_sync_pool(dmn->ste_icm_pool);
			if (ret)
				return ret;
		}

		if (dmn->action_icm_pool) {
			ret = dr_icm_pool_sync_pool(dmn->action_icm_pool);
			if (ret)
				return ret;
		}

		if (dmn->modify_header_ptrn_icm_pool)
			ret = dr_icm_pool_sync_pool(dmn->modify_header_ptrn_icm_pool);
	}

	return ret;
}

void mlx5dv_dr_domain_set_reclaim_device_memory(struct mlx5dv_dr_domain *dmn,
						bool enable)
{
	dr_domain_lock(dmn);
	if (enable)
		dmn->flags |= DR_DOMAIN_FLAG_MEMORY_RECLAIM;
	else
		dmn->flags &= ~DR_DOMAIN_FLAG_MEMORY_RECLAIM;
	dr_domain_unlock(dmn);
}

void mlx5dv_dr_domain_allow_duplicate_rules(struct mlx5dv_dr_domain *dmn,
					    bool allow)
{
	dr_domain_lock(dmn);
	if (allow)
		dmn->flags &= ~DR_DOMAIN_FLAG_DISABLE_DUPLICATE_RULES;
	else
		dmn->flags |= DR_DOMAIN_FLAG_DISABLE_DUPLICATE_RULES;
	dr_domain_unlock(dmn);
}

int mlx5dv_dr_domain_destroy(struct mlx5dv_dr_domain *dmn)
{
	if (atomic_load(&dmn->refcount) > 1)
		return EBUSY;

	if (dmn->info.supp_sw_steering) {
		/* make sure resources are not used by the hardware */
		dr_devx_sync_steering(dmn->ctx);
		dr_free_resources(dmn);
	}

	dr_domain_caps_uninit(dmn);

	pthread_mutex_destroy(&dmn->cross_mutex);

	free(dmn);
	return 0;
}
