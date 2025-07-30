// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2021 Nvidia Corporation. All rights reserved. See COPYING file
 */

#include <util/rdma_nl.h>
#include "mlx5dv_dr.h"

static int find_num_ports_nl_cb(struct nl_msg *msg, void *data)
{
	struct nlattr *tb[RDMA_NLDEV_ATTR_MAX];
	uint32_t *num_ports = data;
	int ret;

	ret = nlmsg_parse(nlmsg_hdr(msg), 0, tb, RDMA_NLDEV_ATTR_MAX - 1,
			  rdmanl_policy);
	if (ret < 0)
		return ret;

	if (!tb[RDMA_NLDEV_ATTR_PORT_INDEX])
		return NLE_PARSE_ERR;

	*num_ports = nla_get_u32(tb[RDMA_NLDEV_ATTR_PORT_INDEX]);

	return 0;
}

int dr_nl_get_number_of_ib_ports(int ibidx, uint32_t *num_ports)
{
	struct nl_sock *nl;
	int ret;

	nl = rdmanl_socket_alloc();
	if (!nl)
		return -EOPNOTSUPP;

	ret = rdmanl_get_device(nl, ibidx, find_num_ports_nl_cb, num_ports);
	nl_socket_free(nl);

	return ret;
}
