/* Copyright (c) 2016-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef _FD_SERVER_INTERNAL_H
#define _FD_SERVER_INTERNAL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

typedef struct fdserver_context fdserver_context_t;

int fdserver_init(const char *path);
int fdserver_new_context(fdserver_context_t **context);
int fdserver_del_context(fdserver_context_t **context);
int fdserver_register_fd(fdserver_context_t *context, uint64_t key, int fd);
int fdserver_deregister_fd(fdserver_context_t *context, uint64_t key);
int fdserver_lookup_fd(fdserver_context_t *context, uint64_t key);

#ifdef __cplusplus
}
#endif

#endif
