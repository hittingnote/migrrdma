#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>

static inline double get_timestamp(char *strln) {
	double ret;
	sscanf(strln, "(%lf)", &ret);
	ret = ret * 1000.0;
	return ret;
}

int main(int argc, char *argv[]) {
	int fd_dir;
	DIR *fd_DIR;
	int fd;
	FILE *fp;
	struct dirent *dirent;
	char dump_log[256];
	char restore_log[256];
	char strln[32768];
	double checkpoint_time;
	double start, end, restore_total;

	fd_dir = open("/dev/shm/", O_DIRECTORY);
	if(fd_dir < 0) {
		fprintf(stderr, "Failed to open /dev/shm/\n");
		exit(-1);
	}

	fd_DIR = fdopendir(fd_dir);
	while((dirent = readdir(fd_DIR)) != NULL) {
		unsigned long long id;
		if(!strncmp(dirent->d_name, ".", 1))
			continue;

		if(sscanf(dirent->d_name, "dump_%lld.log", &id) >= 1) {
			sprintf(dump_log, "%s", dirent->d_name);
		}

		if(sscanf(dirent->d_name, "restore_%lld.log", &id) >= 1) {
			sprintf(restore_log, "%s", dirent->d_name);
		}
	}

	fd = openat(fd_dir, dump_log, O_RDONLY);
	if(fd < 0) {
		fprintf(stderr, "Failed to open /dev/shm/%s\n", dump_log);
		exit(-1);
	}

	fp = fdopen(fd, "r");
	while(fgets(strln, 32768, fp) != NULL);

	checkpoint_time = get_timestamp(strln);
	printf("Checkpoint time: %lf ms\n", checkpoint_time);

	close(fd);

	fd = openat(fd_dir, restore_log, O_RDONLY);
	if(fd < 0) {
		fprintf(stderr, "Failed to open /dev/shm/%s\n", restore_log);
		exit(-1);
	}

	fp = fdopen(fd, "r");
	while(fgets(strln, 32768, fp) != NULL) {
		if(strstr(strln, "Full restore")) {
			start = get_timestamp(strln);
			break;
		}
	}

	while(fgets(strln, 32768, fp) != NULL);

	end = get_timestamp(strln);
	restore_total = end - start;

	return 0;
}

