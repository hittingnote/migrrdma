#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include "rdma_migr.h"

struct rdma_mmap_item {
	unsigned long					start;
	unsigned long					end;
	int								prot;
	int								flag;
};

int dump_rdma_mmap(pid_t pid, char *img_path) {
	char fname[128];
	FILE *fp;
	int fd_out;
	int info_fd;
	int virt_pid;
	char strln[1024];
	struct rdma_mmap_item item;

	sprintf(fname, "/proc/rdma/%d/user_pid", pid);
	info_fd = open(fname, O_RDONLY);
	read(info_fd, &virt_pid, sizeof(virt_pid));
	close(info_fd);

	sprintf(fname, "%s/rdma_mmap_%d.raw", img_path, virt_pid);
	fd_out = open(fname, O_RDWR | O_CREAT | O_TRUNC, 00666);

	sprintf(fname, "/proc/%d/smaps", pid);
	fp = fopen(fname, "r");
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

		item.start = start;
		item.end = end;
		item.prot = 0;
		item.flag = 0;

		if(prots_and_flags[0] == 'r') {
			item.prot |= PROT_READ;
		}
		if(prots_and_flags[1] == 'w') {
			item.prot |= PROT_WRITE;
		}
		if(prots_and_flags[2] == 'x') {
			item.prot |= PROT_EXEC;
		}
		if(prots_and_flags[3] == 'p') {
			item.flag = MAP_PRIVATE;
		}
		else {
			item.flag = MAP_SHARED;
		}

		write(fd_out, &item, sizeof(item));
	}

	fclose(fp);
	close(fd_out);
	return 0;
}
