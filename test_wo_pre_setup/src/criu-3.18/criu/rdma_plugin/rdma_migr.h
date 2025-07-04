#ifndef __RDMA_MIGR_H__
#define __RDMA_MIGR_H__

#include <sys/types.h>
#include <unistd.h>
#include <arpa/inet.h>

int dump_rdma(pid_t pid, char *img_dir_path, struct sockaddr_in *migr_dest_addr);
int notify_partners_suspend(pid_t pid);
int dump_smap_with_rdma(pid_t pid, int pid_fd);
int add_rdma_vma(unsigned long long start, unsigned long long end, char *type_str);
int dump_rdma_mmap(pid_t pid, char *img_path);

#endif
