/*
 * Copyright (c) 2014, Linaro Limited
 * Copyright (c) 2014, Texas Instruments Incorporated
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 *
 * Based on TI McSDK NETAPI library
 */

#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <malloc.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>

#include "sockutils.h"
#include "odp_debug_internal.h"

typedef struct sock_data {
	struct sockaddr_un addr;
	fd_set  readfds;
	int fd;
} sock_data_t;

static int check_and_create_path(char *path)
{
	char *d = path;
	if (!d)
		return -1;

	while ((d = strchr(d + 1, '/'))) {
		*d = 0;
		if (mkdir(path, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) < 0) {
			if (errno != EEXIST) {
				*d = '/';
				odp_pr_err("can't create path %s (error: %s)",
					   path, strerror(errno));
				return -1;
			}
		}
		*d = '/';
	}
	return 0;
}

sock_h sock_open(sock_name_t *sock_name)
{
	sock_data_t *sd = 0;
	int retval = 0;

	if (!sock_name)
		return 0;

	sd = calloc(1, sizeof(sock_data_t));

	if (sock_name->type == sock_addr_e) {
		memcpy(&sd->addr, sock_name->s.addr,
		       sizeof(struct sockaddr_un));
	} else {
		if (check_and_create_path(sock_name->s.name) < 0)
			goto check_n_return;
		sd->addr.sun_family = AF_UNIX;
		strncpy(sd->addr.sun_path, sock_name->s.name, UNIX_PATH_MAX);
	}

	sd->fd =  socket(AF_UNIX, SOCK_DGRAM, 0);
	if (sd->fd < 0) {
		odp_pr_err("can't open socket %s (error: %s)",
			   sd->addr.sun_path, strerror(errno));
		goto check_n_return;
	}

	unlink(sd->addr.sun_path);
	if (bind(sd->fd, (struct sockaddr *)&sd->addr,
		 sizeof(struct sockaddr_un)) < 0) {
		odp_pr_err("can't bind socket %s (error: %s)",
			   sd->addr.sun_path, strerror(errno));
		goto check_n_return;
	}

	FD_ZERO(&sd->readfds);
	FD_SET(sd->fd, &sd->readfds);

	retval = (int) sd;

check_n_return:
	if (!retval)
		sock_close((sock_h)sd);

	return (sock_h)retval;
}

int sock_close(sock_h handle)
{
	sock_data_t *sd = (sock_data_t *)handle;

	if (!sd)
		return -1;

	if (sd->fd)
		close(sd->fd);
	free(sd);

	return 0;
}

int sock_send(sock_h handle, const char *data, int length,
			sock_name_t *to)
{
	int fd;
	sock_data_t *sd = (sock_data_t *)handle;
	struct sockaddr_un to_addr;

	if (!to)
		return -1;

	if (to->type == sock_addr_e) {
		memcpy(&to_addr, to->s.addr, sizeof(struct sockaddr_un));
	} else {
		to_addr.sun_family = AF_UNIX;
		strncpy(to_addr.sun_path, to->s.name, UNIX_PATH_MAX);
	}

	if (sd) {
		fd = sd->fd;
	} else {
		fd =  socket(AF_UNIX, SOCK_DGRAM, 0);
		if (fd < 0) {
			odp_pr_err("can't open socket %s (error: %s)",
				   to_addr.sun_path, strerror(errno));
			return -1;
		}
	}

	if (sendto(fd, data, length, 0, (struct sockaddr *)&to_addr,
		   sizeof(struct sockaddr_un)) < 0) {
		odp_pr_err("can't send data to %s (error: %s)",
			   to_addr.sun_path, strerror(errno));
		return -1;
	}

	return 0;
}

int sock_wait(sock_h handle, int *size, struct timeval *timeout, int extern_fd)
{
	sock_data_t *sd = (sock_data_t *)handle;
	int retval;
	fd_set fds;

	if (!sd) {
		odp_pr_err("invalid hanlde");
		return -1;
	}

	fds = sd->readfds;

	if (extern_fd != -1)
		FD_SET(extern_fd, &fds);

	retval = select(FD_SETSIZE, &fds, NULL, NULL, timeout);
	if (retval == -1) {
		odp_pr_err("select failed for %s (error: %s)",
			   sd->addr.sun_path, strerror(errno));
		return -1;
	}

	if ((extern_fd != -1) && (FD_ISSET(extern_fd, &fds)))
		return 1;

	if (!FD_ISSET(sd->fd, &fds))
		return -2; /* Wait timedout */

	if (!retval)
		return 0;

	if (size != 0) {
		retval = ioctl(sd->fd, FIONREAD, size);
		if (retval == -1) {
			odp_pr_err("can't read datagram size for %s (error: %s)",
				   sd->addr.sun_path, strerror(errno));
			return -1;
		}
	}

	return 0;
}

int sock_recv(sock_h handle, char *data, int length, sock_name_t *from)
{
	int size;
	sock_data_t *sd = (sock_data_t *)handle;
	socklen_t from_length = 0;
	struct sockaddr *sock_addr;

	if (!sd) {
		odp_pr_err("invalid handle");
		return -1;
	}

	if (from) {
		from->type = sock_addr_e;
		if (from->type && from->s.addr) {
			from_length = sizeof(struct sockaddr_un);
		} else {
			odp_pr_err("invalid from parameter");
			return -1;
		}
	}

	sock_addr = (struct sockaddr *)((from_length) ? from->s.addr : NULL);
	size = recvfrom(sd->fd, data, length, 0, sock_addr, &from_length);
	if (size < 1) {
		odp_pr_err("can't read datagram from socket for %s (error: %s), size %d",
			   sd->addr.sun_path, strerror(errno), size);
		return -1;
	}

	return size;
}
