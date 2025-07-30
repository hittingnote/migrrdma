#ifndef _MLNX_COMPAT_LINUX_NETLINK_H
#define _MLNX_COMPAT_LINUX_NETLINK_H 1

#include_next <linux/netlink.h>

#ifndef NETLINK_RDMA
#define NETLINK_RDMA           20
#endif

#endif /* _MLNX_COMPAT_LINUX_NETLINK_H */
