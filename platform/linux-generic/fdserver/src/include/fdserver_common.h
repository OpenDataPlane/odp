/* Copyright (c) 2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
#ifndef FDSERVER_COMMON_H
#define FDSERVER_COMMON_H
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#define FDSERVER_SOCKET_PATH "/tmp/fdserver_socket"

/*
 * Client and server function:
 * Send a fdserver_msg, possibly including a file descriptor, on the socket
 * This function is used both by:
 * -the client (sending a FD_REGISTER_REQ with a file descriptor to be shared,
 *  or FD_LOOKUP_REQ/FD_DEREGISTER_REQ without a file descriptor)
 * -the server to send the reply to the request with a return value, currently
 *  either FD_RETVAL_SUCCESS or FD_RETVAL_FAILURE
 * This function make use of the ancillary data (control data) to pass and
 * convert file descriptors over UNIX sockets
 * Return -1 on error, 0 on success.
 */
static int fdserver_internal_send_msg(int sock, int command,
				      struct fdserver_context *context,
				      uint64_t key, int fd_to_send)
{
	struct msghdr socket_message;
	struct iovec io_vector[1]; /* one msg frgmt only */
	struct cmsghdr *control_message = NULL;
	int *fd_location;
	fdserver_msg_t msg;
	int res;

	char ancillary_data[CMSG_SPACE(sizeof(int))];

	/* prepare the register request body (single framgent): */
	msg.command = command;
	msg.index = context->index;
	msg.token = context->token;
	msg.key = key;
	io_vector[0].iov_base = &msg;
	io_vector[0].iov_len = sizeof(fdserver_msg_t);

	/* initialize socket message */
	memset(&socket_message, 0, sizeof(struct msghdr));
	socket_message.msg_iov = io_vector;
	socket_message.msg_iovlen = 1;

	if (fd_to_send >= 0) {
		/* provide space for the ancillary data */
		memset(ancillary_data, 0, CMSG_SPACE(sizeof(int)));
		socket_message.msg_control = ancillary_data;
		socket_message.msg_controllen = CMSG_SPACE(sizeof(int));

		/* initialize a single ancillary data element for fd passing */
		control_message = CMSG_FIRSTHDR(&socket_message);
		control_message->cmsg_level = SOL_SOCKET;
		control_message->cmsg_type = SCM_RIGHTS;
		control_message->cmsg_len = CMSG_LEN(sizeof(int));
		fd_location = (int *)(void *)CMSG_DATA(control_message);
		*fd_location = fd_to_send;
	}
	res = sendmsg(sock, &socket_message, 0);
	if (res < 0)
		return -1;

	return 0;
}

/*
 * Client and server function
 * Receive a fdserver_msg, possibly including a file descriptor, on the
 * given socket.
 * This function is used both by:
 * -the server (receiving a FD_REGISTER_REQ with a file descriptor to be shared,
 *  or FD_LOOKUP_REQ, FD_DEREGISTER_REQ without a file descriptor)
 * -the client (receiving the reply of a request)
 * This function makes use of the ancillary data (control data) to pass and
 * convert file descriptors over UNIX sockets.
 * Return -1 on error, 0 on success.
 */
static int fdserver_internal_recv_msg(int sock, int *command,
				      struct fdserver_context *context,
				      uint64_t *key, int *recvd_fd)
{
	struct msghdr socket_message;
	struct iovec io_vector[1]; /* one msg frgmt only */
	struct cmsghdr *control_message = NULL;
	int *fd_location;
	fdserver_msg_t msg;
	char ancillary_data[CMSG_SPACE(sizeof(int))];

	memset(&socket_message, 0, sizeof(struct msghdr));
	memset(ancillary_data, 0, CMSG_SPACE(sizeof(int)));

	/* setup a place to fill in message contents */
	io_vector[0].iov_base = &msg;
	io_vector[0].iov_len = sizeof(fdserver_msg_t);
	socket_message.msg_iov = io_vector;
	socket_message.msg_iovlen = 1;

	/* provide space for the ancillary data */
	socket_message.msg_control = ancillary_data;
	socket_message.msg_controllen = CMSG_SPACE(sizeof(int));

	/* receive the message */
	if (recvmsg(sock, &socket_message, MSG_CMSG_CLOEXEC) < 0)
		return -1;

	*command = msg.command;
	context->index = msg.index;
	context->token = msg.token;
	*key = msg.key;

	/* grab the converted file descriptor (if any) */
	*recvd_fd = -1;

	/* FIXME: we need to tread this properly, if the other end is the
	 * client, it could wait forever for our reply... */
	if ((socket_message.msg_flags & MSG_CTRUNC) == MSG_CTRUNC)
		return 0;

	/* iterate ancillary elements to find the file descriptor: */
	for (control_message = CMSG_FIRSTHDR(&socket_message);
	     control_message != NULL;
	     control_message = CMSG_NXTHDR(&socket_message, control_message)) {
		if ((control_message->cmsg_level == SOL_SOCKET) &&
		    (control_message->cmsg_type == SCM_RIGHTS)) {
			fd_location = (int *)(void *)CMSG_DATA(control_message);
			*recvd_fd = *fd_location;
			break;
		}
	}

	return 0;
}
#endif
