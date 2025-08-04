#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <linux/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <signal.h>
#include <sys/socket.h>

static int get_num_process(int argc, char *argv[]) {
	int i;
	char image_dir[256];
	int image_dir_fd;
	DIR *image_DIR;
	struct dirent *image_dirent;
	int ret = 0;

	for(i = 0; i < argc; i++) {
		if(!strcmp(argv[i], "--image-path")) {
			i++;
			break;
		}
	}

	strcpy(image_dir, argv[i]);
	image_dir_fd = open(image_dir, O_DIRECTORY);
	if(image_dir_fd < 0) {
		perror("open");
		return -1;
	}

	image_DIR = fdopendir(image_dir_fd);
	while((image_dirent = readdir(image_DIR)) != NULL) {
		struct stat statbuf;
		pid_t pid;
		char pid_str[64];

		if(!strncmp(image_dirent->d_name, ".", strlen("."))) {
			continue;
		}

		if(fstatat(image_dir_fd, image_dirent->d_name, &statbuf, 0)) {
			close(image_dir_fd);
			perror("fstatat");
			return -1;
		}

		if(!S_ISDIR(statbuf.st_mode)) {
			continue;
		}

		sscanf(image_dirent->d_name, "%d", &pid);
		sprintf(pid_str, "%d", pid);
		if(strcmp(pid_str, image_dirent->d_name)) {
			continue;
		}

		ret++;
	}

	return ret+1;
}

int main(int argc, char *argv[]) {
	pid_t pid;
	int sock;
	struct sockaddr_un sock_un;
	char sockname[1024];
	int total_wait = 0;
	char buf[32];
	int err;
	int n_process;

	n_process = get_num_process(argc, argv);

	pid = fork();
	if(pid < 0) {
		perror("fork");
		return -1;
	}
	else if(pid == 0) {
		execvp("runc", argv);
		return -1;
	}

#if 0
	sock = socket(AF_UNIX, SOCK_DGRAM, 0);
	if(sock < 0) {
		perror("socket");
		kill(pid, SIGKILL);
		return -1;
	}

	memset(&sock_un, 0, sizeof(sock_un));
	sock_un.sun_family = AF_UNIX;
	sprintf(sockname, "/dev/shm/prerestore_%d.sock", pid);
	strcpy(sock_un.sun_path, sockname);
	unlink(sockname);
	err = bind(sock, (struct sockaddr *)&sock_un, sizeof(sock_un));
	if(err) {
		perror("bind");
		close(sock);
		kill(pid, SIGKILL);
		return -1;
	}

	while(1) {
		char buf[32];
		if(recvfrom(sock, buf, 32, 0, NULL, NULL) < 0) {
			perror("recvfrom");
			close(sock);
			kill(pid, SIGKILL);
			return -1;
		}

		if(!strcmp(buf, "FINISH")) {
			total_wait--;
			if(!total_wait && !n_process)
				break;
		}
		else {
			int n_wait = *((int*)buf);
			total_wait += n_wait;
			n_process--;
		}
	}

	close(sock);
	unlink(sockname);
#endif

	return 0;
}
