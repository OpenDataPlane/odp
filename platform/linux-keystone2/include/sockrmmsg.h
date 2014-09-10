/*
 * Copyright (c) 2014, Linaro Limited
 * Copyright (c) 2014, Texas Instruments Incorporated
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef __SOCKRMMSG_H__
#define __SOCKRMMSG_H__

#include <stdint.h>

#define RM_SERVER_SOCKET_NAME "/tmp/var/run/rm/rm_server"

#define msg_alloc(p) \
	do { \
		p = calloc(1, sizeof(*p)); \
		if (p) { \
			p->length = sizeof(*p); \
		} \
	} while (0)

#define msg_length(x) ((x) ? (sizeof(*x) + x->length) : 0)
#define msg_data(x)   ((x->length) ? ((char *)x + sizeof(*x)) : NULL)

#endif /* __SOCKRMMSG_H__ */
