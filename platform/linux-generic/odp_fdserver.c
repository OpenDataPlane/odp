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

#define FDSERVER_SOCKPATH_MAXLEN 255
#define FDSERVER_SOCK_FORMAT "%s/%s/odp-%d-fdserver"
#define FDSERVER_SOCKDIR_FORMAT "%s/%s"
#define FDSERVER_DEFAULT_DIR "/dev/shm"
#define FDSERVER_BACKLOG 5

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif

#define FD_ODP_DEBUG_PRINT 0

#define FD_ODP_DBG(fmt, ...) \
	do { \
		if (FD_ODP_DEBUG_PRINT == 1) \
			ODP_DBG(fmt, ##__VA_ARGS__);\
	} while (0)

/*
 * Spawn the fdserver daemon
 */
int _odp_fdserver_init_global(void)
{
	char sockpath[FDSERVER_SOCKPATH_MAXLEN];

	snprintf(sockpath, FDSERVER_SOCKPATH_MAXLEN, FDSERVER_SOCKDIR_FORMAT,
		 odp_global_data.shm_dir,
		 odp_global_data.uid);

	mkdir(sockpath, 0744);

	/* construct the server named socket path: */
	snprintf(sockpath, FDSERVER_SOCKPATH_MAXLEN, FDSERVER_SOCK_FORMAT,
		 odp_global_data.shm_dir,
		 odp_global_data.uid,
		 odp_global_data.main_pid);

	ODP_PRINT("Socket path: %s\n", sockpath);

	/* TODO: fork a server process: */

	/* parent */
	return 0;
}

/*
 * Terminate the server
 */
int _odp_fdserver_term_global(void)
{
	char sockpath[FDSERVER_SOCKPATH_MAXLEN];

	/* construct the server named socket path: */
	snprintf(sockpath, FDSERVER_SOCKPATH_MAXLEN, FDSERVER_SOCK_FORMAT,
		 odp_global_data.shm_dir,
		 odp_global_data.uid,
		 odp_global_data.main_pid);

	/* delete the UNIX domain socket: */
	unlink(sockpath);

	/* delete shm files directory */
	snprintf(sockpath, FDSERVER_SOCKPATH_MAXLEN, FDSERVER_SOCKDIR_FORMAT,
		 odp_global_data.shm_dir,
		 odp_global_data.uid);
	rmdir(sockpath);

	return 0;
}
