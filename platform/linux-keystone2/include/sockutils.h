/*
 * Copyright (c) 2014, Linaro Limited
 * Copyright (c) 2014, Texas Instruments Incorporated
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef __SOCKUTILS_H__
#define __SOCKUTILS_H__

#include <sys/socket.h>
#include <sys/un.h>

#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX 108
#endif


typedef enum {
	sock_name_e,
	sock_addr_e
} sock_name_type;

typedef struct {
	sock_name_type type;
	union sock {
		char *name;
		struct sockaddr_un *addr;
	} s;
} sock_name_t;

#define sock_h void *

sock_h sock_open(sock_name_t *sock_name);

int sock_close(sock_h handle);

int sock_send(sock_h handle, const char *data, int length,
	      sock_name_t *to);

int sock_wait(sock_h handle, int *size, struct timeval *timeout, int extern_fd);

int sock_recv(sock_h handle, char *data, int length, sock_name_t *from);

#endif
