/* Copyright (c) 2016-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "config.h"

/*
 * This file implements a file descriptor sharing server enabling
 * sharing of file descriptors between processes, regardless of fork time.
 *
 * File descriptors are process scoped, but they can be "sent and converted
 * on the fly" between processes using special unix domain socket ancillary
 * data.
 * The receiving process gets a file descriptor "pointing" to the same thing
 * as the one sent (but the value of the file descriptor itself may be different
 * from the one sent).
 * Because ODP applications are responsible for creating ODP threads (i.e.
 * pthreads or linux processes), ODP has no control on the order things happen:
 * Nothing prevent a thread A to fork B and C, and then C creating a pktio
 * which will be used by A and B to send/receive packets.
 * Assuming this pktio uses a file descriptor, the latter will need to be
 * shared between the processes, despite the "non convenient" fork time.
 * The shared memory allocator is likely to use this as well to be able to
 * share memory regardless of fork() time.
 * This server handles a table of {(context,key)<-> fd} pair, and is
 * interfaced by the following functions:
 *
 * _odp_fdserver_register_fd(context, key, fd_to_send);
 * _odp_fdserver_deregister_fd(context, key);
 * _odp_fdserver_lookup_fd(context, key);
 *
 * which are used to register/deregister or querry for file descriptor based
 * on a context and key value couple, which has to be unique.
 *
 * Note again that the file descriptors stored here are local to this server
 * process and get converted both when registered or looked up.
 */

#include <odp_posix_extensions.h>
#include <odp_global_data.h>
#include <odp_init_internal.h>
#include <odp_debug_internal.h>
#include <sys/prctl.h>
#include <signal.h>

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <fdserver.h>
#include <odp_libconfig_internal.h>

#define FDSERVER_SOCKPATH_MAXLEN 255
#define FDSERVER_SOCK_FORMAT "%s/%s/odp-%d-fdserver"
#define FDSERVER_SOCKDIR_FORMAT "%s/%s"
#define FDSERVER_DEFAULT_DIR "/dev/shm"
#define FDSERVER_BACKLOG 5
static char fdserver_sockpath[FDSERVER_SOCKPATH_MAXLEN] = {'\0'};

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif

static pid_t fdserver_pid = (pid_t)-1;

static pid_t start_fdserver_process(const char *sockpath)
{
	/* FIXME */
	const char *binary =
		"/tmp/build-odp/platform/linux-generic/fdserver/src/fdserver";
	pid_t pid;

	pid = fork();
	if (pid == -1)
		return -1;
	if (pid == 0) {
		execlp(binary, binary, "-H", "-p", sockpath, NULL);
		ODP_PRINT("Failed to start fdserver\n");
		exit(EXIT_FAILURE);
	}

	return pid;
}

static int socket_exists(const char *path)
{
	struct stat statbuf;

	if (stat(path, &statbuf) != 0)
		return 0;

	if (S_ISSOCK(statbuf.st_mode)) {
		ODP_DBG("fdserver: Socket exists at %s\n", path);
		return 1;
	}

	ODP_DBG("fdserver: File %s exists but is not a socket\n", path);

	/* if it exists but it is not a socket, delete. What, too drastic? */
	unlink(path);

	return 0;
}

/*
 * Spawn the fdserver daemon
 */
int _odp_fdserver_init_global(void)
{
	const char *path = NULL;

	_odp_libconfig_lookup_ext_str("fdserver", "", "socket_path", &path);

	if (path == NULL) {
		snprintf(fdserver_sockpath, sizeof(fdserver_sockpath),
			 "/tmp/odp-%d-fdserver",
			 odp_global_data.main_pid);
	} else {
		if (strlen(path) < sizeof(fdserver_sockpath))
			strncpy(fdserver_sockpath, path,
				sizeof(fdserver_sockpath));
		else
			return 1;
	}

	/* start server if socket does not exist */
	if (!socket_exists(fdserver_sockpath)) {
		ODP_PRINT("Starting fdserver socket at: %s\n", fdserver_sockpath);
		fdserver_pid = start_fdserver_process(fdserver_sockpath);
		if (fdserver_pid == (pid_t)-1) {
			ODP_ERR("Could not start fdserver\n");
			return -1;
		}
		sleep(1); /* FIXME: give time the server to start */
	}

	if (fdserver_init(fdserver_sockpath) != 0) {
		ODP_ERR("Could not initialize fdserver\n");
		return -1;
	}

	/* parent */
	return 0;
}

/*
 * Terminate the server
 */
int _odp_fdserver_term_global(void)
{
	if (fdserver_pid != -1)
		kill(fdserver_pid, SIGHUP);

	return 0;
}
