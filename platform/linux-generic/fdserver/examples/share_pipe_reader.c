/* Copyright (c) 2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <sys/prctl.h>
#include <signal.h>

#include <fdserver.h>

#include "share_pipe_common.h"

static void run_writer(fdserver_context_t *context)
{
	int fd;

	sleep(2); /* give time to register, etc */

	fd = fdserver_lookup_fd(context, SHARE_PIPE_KEY_WRITER);
	if (fd == -1) {
		fprintf(stderr, "Could not retrive fd\n");
		exit(EXIT_FAILURE);
	}

	printf("Writer: got file descriptor %d, sending\n", fd);
	write(fd, &fd, sizeof(int));
	printf("Writer:  done\n");
	close(fd);

	exit(EXIT_SUCCESS);
}

int main(int argc, char *argv[])
{
	int fd[2];
	int ret;
	int data;
	fdserver_context_t *context;
	pid_t pid;

	ret = fdserver_new_context(&context);
	if (ret == -1) {
		fprintf(stderr, "Could not create a new context\n");
		exit(EXIT_FAILURE);
	}

	pid = fork();
	if (pid == -1) {
		fdserver_del_context(&context);
		exit(EXIT_FAILURE);
	}
	if (pid == 0) {
		/* die if parent dies too */
		prctl(PR_SET_PDEATHSIG, SIGTERM);
		run_writer(context);
	}

	/* parent */
	ret = pipe(fd);
	if (ret == -1) {
		fdserver_del_context(&context);
		perror("pipe");
		exit(EXIT_FAILURE);
	}

	ret = fdserver_register_fd(context,
				   SHARE_PIPE_KEY_WRITER,
				   fd[1]);
	if (ret == -1) {
		fdserver_del_context(&context);
		fprintf(stderr, "failed to register fd\n");
		exit(EXIT_FAILURE);
	}

	close(fd[1]);

	/* wait for the other end to write an integer */
	while (read(fd[0], &data, sizeof(int)) == -1) {
		if (errno == EAGAIN || errno == EINTR) {
			printf("again\n");
			continue;
		}
		perror("read");
		fdserver_del_context(&context);
		exit(EXIT_FAILURE);
	}

	printf("Reader: Received: %d\n", data);

	close(fd[0]);

	fdserver_del_context(&context);

	exit(EXIT_SUCCESS);
}

