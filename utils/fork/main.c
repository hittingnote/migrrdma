#define _GNU_SOURCE
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
	pid_t child_pid;
	unsigned short port_num;
	int n_partners;
	int cur_opt;
	char *arg_raw;
	char **my_argv;
	void *start;
	void *end;
	off_t off = 0;
	char *fname = NULL;

	while((cur_opt = getopt(argc, argv, "n:p:o:")) != -1) {
		switch(cur_opt) {
		case 'n':
			n_partners = atoi(optarg);
			break;
		case 'p':
			port_num = atoi(optarg);
			break;
		case 'o':
			asprintf(&fname, "%s", optarg);
			break;
		default:
			break;
		}
	}

	if(optind >= argc) {
		fprintf(stderr, "Nothing to do, exiting...\n");
		exit(-1);
	}

	start = argv[optind];
	end = argv[argc-1] + strlen(argv[argc-1]) + 1;
	arg_raw = malloc(end - start + 256);
	if(!arg_raw) {
		fprintf(stderr, "Failed to malloc\n");
		exit(-1);
	}

	memcpy(arg_raw, start, end - start);
	off += sprintf(arg_raw + (end - start) + off, "-p") + 1;
	off += sprintf(arg_raw + (end - start) + off, "%d", port_num) + 1;

	my_argv = malloc(sizeof(char *) * (argc - optind + 1 + 2));
	if(!my_argv) {
		fprintf(stderr, "Failed to malloc\n");
		exit(-1);
	}

	for(int i = 0, off = 0; i < argc - optind + 2; i++) {
		my_argv[i] = arg_raw + off;
		off += strlen(my_argv[i]) + 1;
	}
	my_argv[argc - optind + 2] = NULL;

	for(int i = 0; i < n_partners; i++) {
		sprintf(my_argv[argc-optind+1], "%d", port_num+i);

		child_pid = fork();
		if(child_pid < 0) {
			fprintf(stderr, "Failed to fork\n");
			exit(-1);
		}

		if(child_pid == 0) {
			char *c_fname;
			int fd;

			if(fname) {
				asprintf(&c_fname, "%s_%d.txt", fname, getpid());
				fd = open(c_fname, O_RDWR | O_CREAT, 00666);
				dup2(fd, STDOUT_FILENO);
				close(fd);
			}
			execvp(my_argv[0], &my_argv[0]);
			return -1;
		}
	}

	return 0;
}

