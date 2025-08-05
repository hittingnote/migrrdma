#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <signal.h>
#include "rdma_migr.h"
#include "debug.h"

static pid_t *pid_get_child(pid_t ppid, int *size) {
	char fname[1024];
	int task_fd;
	DIR *task_DIR;
	struct dirent *task_dirent;
	int cnt = 0;
	int curp = 0;
	pid_t *pid_list = NULL;

	*size = -1;

	sprintf(fname, "/proc/%d/task", ppid);
	task_fd = open(fname, O_DIRECTORY);
	if(task_fd < 0) {
		return NULL;
	}

	task_DIR = fdopendir(task_fd);
	while((task_dirent = readdir(task_DIR)) != NULL) {
		int child_fd;
		FILE *child_fp;
		pid_t child_pid;

		if(!strncmp(task_dirent->d_name, ".", strlen(".")))
			continue;
		
		sprintf(fname, "%s/children", task_dirent->d_name);
		child_fd = openat(task_fd, fname, O_RDONLY);
		if(child_fd < 0) {
			close(task_fd);
			return NULL;
		}

		child_fp = fdopen(child_fd, "r");
		while(fscanf(child_fp, "%d", &child_pid) != EOF) {
			char cmdline[2048];
			int cmd_fd;

			sprintf(fname, "/proc/%d/cmdline", child_pid);
			cmd_fd = open(fname, O_RDONLY);
			memset(cmdline, 0, sizeof(cmdline));
			if(read(cmd_fd, cmdline, 2048) < 0) {
				close(child_fd);
				close(task_fd);
				return NULL;
			}
			close(cmd_fd);

			cnt++;
		}

		close(child_fd);
	}

	if(cnt == 0) {
		close(task_fd);
		*size = 0;
		return NULL;
	}

	lseek(task_fd, 0, SEEK_SET);
	pid_list = calloc(cnt, sizeof(pid_t));
	if(!pid_list) {
		close(task_fd);
		return NULL;
	}

	while((task_dirent = readdir(task_DIR)) != NULL) {
		int child_fd;
		FILE *child_fp;
		pid_t child_pid;

		if(!strncmp(task_dirent->d_name, ".", strlen(".")))
			continue;
		
		sprintf(fname, "%s/children", task_dirent->d_name);
		child_fd = openat(task_fd, fname, O_RDONLY);
		if(child_fd < 0) {
			free(pid_list);
			close(task_fd);
			return NULL;
		}

		child_fp = fdopen(child_fd, "r");
		while(fscanf(child_fp, "%d", &child_pid) != EOF) {
			char cmdline[2048];
			int cmd_fd;

			sprintf(fname, "/proc/%d/cmdline", child_pid);
			cmd_fd = open(fname, O_RDONLY);
			memset(cmdline, 0, sizeof(cmdline));
			if(read(cmd_fd, cmdline, 2048) < 0) {
				free(pid_list);
				close(child_fd);
				close(task_fd);
				return NULL;
			}
			close(cmd_fd);

			pid_list[curp++] = child_pid;
		}

		close(child_fd);
	}

	close(task_fd);
	*size = cnt;
	return pid_list;
}

static int wait_for_proc_complete(pid_t pid, char *img_path) {
	char fname[128];
	int channel_fd;
	int sig;
	int partner_buf_fd;
	void *buf = NULL;
	void *read_buf = NULL;
	ssize_t read_size = 0;
	ssize_t cur_size;
	int info_fd;
	pid_t virt_pid;

	sprintf(fname, "/proc/rdma/%d/to_proc", pid);
	channel_fd = open(fname, O_RDONLY);
	if(channel_fd < 0) {
		if(errno == ENOENT)
			return 0;

		return -1;
	}

	if(read(channel_fd, &sig, sizeof(int)) < 0) {
		close(channel_fd);
		return -1;
	}

	close(channel_fd);

	sprintf(fname, "/proc/rdma/%d/frm_buf", pid);
	partner_buf_fd = open(fname, O_RDONLY);
	if(partner_buf_fd < 0) {
		err_info("Failed to open %s\n", fname);
		return -1;
	}

	while(1) {
		void *tmp_buf;

		read_buf = malloc(1024);
		if(!read_buf) {
			if(buf)
				free(buf);
			perror("malloc");
			close(partner_buf_fd);
			return -1;
		}

		memset(read_buf, 0, 1024);
		cur_size = read(partner_buf_fd, read_buf, 1024);
		if(cur_size < 0) {
			perror("read");
			free(read_buf);
			if(buf)
				free(buf);
			perror("malloc");
			close(partner_buf_fd);
			return -1;
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
			perror("malloc");
			close(partner_buf_fd);
			return -1;
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

	sprintf(fname, "/proc/rdma/%d/user_pid", pid);
	info_fd = open(fname, O_RDONLY);
	if(info_fd < 0) {
		err_info("Failed to open %s\n", fname);
		free(buf);
		return -1;
	}

	if(read(info_fd, &virt_pid, sizeof(pid)) < 0) {
		close(info_fd);
		free(buf);
		perror("read");
		return -1;
	}

	close(info_fd);

	sprintf(fname, "%s/qp_n_posted_%d.raw", img_path, virt_pid);
	partner_buf_fd = open(fname, O_WRONLY | O_CREAT | O_TRUNC, 00666);
	if(partner_buf_fd < 0) {
		free(buf);
		err_info("Failed to open %s\n", fname);
		return -1;
	}

	write(partner_buf_fd, buf, read_size);
	close(partner_buf_fd);
	free(buf);
	return 0;
}

static int get_all_thread_ids(pid_t pid, pid_t **tids,
					int *n_tids) {
	char fname[128];
	int fd_dir;
	DIR *dir;
	struct dirent *ent;
	int ret_n_tids = 0;
	pid_t *tids_arr;
	int curp = 0;

	sprintf(fname, "/proc/%d/task", pid);
	fd_dir = open(fname, O_DIRECTORY);
	dir = fdopendir(fd_dir);

	for(int i = 0; i < 2; i++) {
		if(i == 1) {
			tids_arr = malloc(sizeof(pid_t) * ret_n_tids);
		}

		lseek(fd_dir, 0, SEEK_SET);
		while((ent = readdir(dir)) != NULL) {
			pid_t this_tid;

			if(ent->d_name[0] == '.')
				continue;

			if(sscanf(ent->d_name, "%d", &this_tid) < 1)
				continue;

			if(i == 0) {
				ret_n_tids++;
			}
			else {
				tids_arr[curp++] = this_tid;
			}
		}
	}

	close(fd_dir);

	if(tids)
		*tids = tids_arr;

	if(n_tids)
		*n_tids = ret_n_tids;

	return 0;
}

int main(int argc, char *argv[]) {
	pid_t *pid_list;
	int num_child, i;
	int err;
	struct sockaddr_in migr_dest_addr;
	int n_child = 0;
	pid_t child_pid;

	if(argc != 3) {
		return -EINVAL;
	}

	child_pid = fork();
	if(child_pid < 0) {
		err_info("Failed to fork waiting process\n");
		return -1;
	}
	else if(child_pid == 0) {
		char fname[128];
		int fd_to_proc;

		notify_partners_suspend(atoi(argv[1]));

		sprintf(fname, "/proc/rdma/%d/to_proc", atoi(argv[1]));
		fd_to_proc = open(fname, O_RDWR);
		if(fd_to_proc >= 0) {
			int n_tids;
			pid_t *tids;

			if(get_all_thread_ids(atoi(argv[1]), &tids, &n_tids)) {
				exit(-1);
			}

			n_tids--;
			write(fd_to_proc, &n_tids, sizeof(int));
			close(fd_to_proc);
			for(int i = 0; i < n_tids + 1; i++) {
				dprintf(1, "tids[i]: %d\n", tids[i]);
				usleep(1);
				kill(tids[i], SIGTSTP);
			}
			wait_for_proc_complete(atoi(argv[1]), argv[2]);
			dump_rdma_mmap(atoi(argv[1]), argv[2]);
		}

		exit(0);
	}
	else {
		n_child++;
	}

	pid_list = pid_get_child(atoi(argv[1]), &num_child);
	if(num_child < 0) {
		err_info("Failed to notify local RDMA-based process\n");
		return num_child;
	}

	for(i = 0; i < num_child; i++) {
		child_pid = fork();
		if(child_pid < 0) {
			err_info("Failed to fork waiting process\n");
			return -1;
		}
		else if(child_pid == 0) {
			char fname[128];
			int fd_to_proc;

			notify_partners_suspend(pid_list[i]);

			sprintf(fname, "/proc/rdma/%d/to_proc", pid_list[i]);
			fd_to_proc = open(fname, O_RDWR);
			if(fd_to_proc >= 0) {
				int n_tids;
				pid_t *tids;

				if(get_all_thread_ids(pid_list[i], &tids, &n_tids)) {
					exit(-1);
				}

				n_tids--;
				write(fd_to_proc, &n_tids, sizeof(int));
				close(fd_to_proc);
				for(int j = 0; j < n_tids + 1; j++) {
					dprintf(1, "tids[j]: %d\n", tids[j]);
					usleep(1);
					kill(tids[j], SIGTSTP);
				}
				wait_for_proc_complete(pid_list[i], argv[2]);
				dump_rdma_mmap(pid_list[i], argv[2]);
			}

			exit(0);
		}
		else {
			n_child++;
		}
	}

	while(n_child) {
		wait(NULL);
		n_child--;
	}

	return 0;
}
