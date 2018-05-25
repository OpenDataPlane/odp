/* Copyright (c) 2016-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

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
 * fdserver_register_fd(context, key, fd_to_send);
 * fdserver_deregister_fd(context, key);
 * fdserver_lookup_fd(context, key);
 *
 * which are used to register/deregister or querry for file descriptor based
 * on a context and key value couple, which has to be unique.
 *
 * Note again that the file descriptors stored here are local to this server
 * process and get converted both when registered or looked up.
 */


#include <unistd.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include <fdserver.h>
#include <fdserver_internal.h>
#include <fdserver_common.h>

struct sockaddr_un fdserver_socket = {
	.sun_family = SOCK_STREAM,
	.sun_path = FDSERVER_SOCKET_PATH
};

/* opens and returns a connected socket to the server */
static int get_socket(void)
{
	int s_sock; /* server socket */
	struct sockaddr_un remote;
	int len;

	s_sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (s_sock == -1) {
		ODP_ERR("Cannot create socket: %s\n", strerror(errno));
		return -1;
	}

	memcpy(&remote, &fdserver_socket, sizeof(struct sockaddr_un));
	len = strlen(remote.sun_path) + sizeof(remote.sun_family);
	while (connect(s_sock, (struct sockaddr *)&remote, len) == -1) {
		if (errno == EINTR)
			continue;
		ODP_ERR("cannot connect to server: %s\n", strerror(errno));
		close(s_sock);
		return -1;
	}

	return s_sock;
}

static int send_command(int command, fdserver_context_t *context,
			uint64_t *key, int *fd)
{
	int s_sock;
	int res;
	int retval = -1;

	if (context == NULL)
		return -1;

	s_sock = get_socket();
	if (s_sock < 0)
		return -1;

	res = fdserver_internal_send_msg(s_sock, command, context,
					 *key, *fd);
	if (res < 0) {
		ODP_ERR("Failed to send message to fdserver\n");
		close(s_sock);
		return -1;
	}

	res = fdserver_internal_recv_msg(s_sock, &retval, context,
					 key, fd);
	close(s_sock);
	if ((res < 0) || (retval != FD_RETVAL_SUCCESS)) {
		ODP_ERR("Error receiving message from fdserver\n");
		return retval;
	}

	return 0;
}

/*
 * Client function:
 * Register a file descriptor to the server. Return -1 on error.
 */
int fdserver_register_fd(fdserver_context_t *context, uint64_t key,
			 int fd_to_send)
{
	int res;

	FD_ODP_DBG("FD client register: pid=%d key=%" PRIu64 ", fd=%d\n",
		   getpid(), key, fd_to_send);

	res = send_command(FD_REGISTER_REQ, context, &key, &fd_to_send);
	if (res != 0)
		ODP_ERR("fd registration failure\n");

	return res;
}

/*
 * Client function:
 * Deregister a file descriptor from the server. Return -1 on error.
 */
int fdserver_deregister_fd(fdserver_context_t *context, uint64_t key)
{
	int res;
	int fd = -1;

	FD_ODP_DBG("FD client deregister: pid=%d key=%" PRIu64 "\n",
		   getpid(), key);

	res = send_command(FD_DEREGISTER_REQ, context, &key, &fd);
	if (res != 0)
		ODP_ERR("fd de-registration failure\n");

	return res;
}

/*
 * client function:
 * lookup a file descriptor from the server. return -1 on error,
 * or the file descriptor on success (>=0).
 */
int fdserver_lookup_fd(fdserver_context_t *context, uint64_t key)
{
	int res;
	int fd = -1;

	FD_ODP_DBG("FD client lookup: pid=%d, key=%" PRIu64 ", fd=%d\n",
		   getpid(), key, fd);

	res = send_command(FD_LOOKUP_REQ, context, &key, &fd);
	if (res != 0) {
		ODP_ERR("fd lookup failure\n");
		return -1;
	}

	return fd;
}

int fdserver_new_context(fdserver_context_t **ctx)
{
	int res;
	struct fdserver_context *context;
	uint64_t key = 0;
	int fd = -1;

	FD_ODP_DBG("FD New context pid=%d\n", getpid());

	if (ctx == NULL)
		return -1;

	context = malloc(sizeof(fdserver_context_t));
	if (context == NULL)
		return -1;

	context->index = 0;
	context->token = 0;
	res = send_command(FD_NEW_CONTEXT, context, &key, &fd);
	if (res != 0) {
		ODP_ERR("FD Failed to create context\n");
		free(context);
		return -1;
	}

	*ctx = context;

	return 0;
}

int fdserver_del_context(fdserver_context_t **ctx)
{
	int res;
	uint64_t key = 0;
	int retval = -1;

	FD_ODP_DBG("FD Delete context pid=%d\n", getpid());

	if (ctx == NULL || *ctx == NULL)
		return -1;

	res = send_command(FD_DEL_CONTEXT, *ctx, &key, &retval);
	if (res != 0) {
		ODP_ERR("FD Failed to remove context\n");
		return -1;
	}

	free(*ctx);
	*ctx = NULL;

	return 0;
}

int fdserver_init(const char *path)
{
	if (path != NULL) {
		if (strlen(path) >= sizeof(fdserver_socket.sun_path))
			return -1;
		strcpy(fdserver_socket.sun_path, path);
	}

	return 0;
}
