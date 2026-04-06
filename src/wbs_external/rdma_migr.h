#ifndef __RDMA_MIGR_H__
#define __RDMA_MIGR_H__

#include <sys/types.h>
#include <unistd.h>
#include <arpa/inet.h>

int notify_partners_suspend(pid_t pid);
int dump_rdma_mmap(pid_t pid, char *img_path);

#endif
