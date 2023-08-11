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

/*
 * the following enum defines the different contexts by which the
 * FD server may be used: In the FD server, the keys used to store/retrieve
 * a file descriptor are actually context based:
 * Both the context and the key are stored at fd registration time,
 * and both the context and the key are used to retrieve a fd.
 * In other words a context identifies a FD server usage, so that different
 * unrelated fd server users do not have to guarantee key unicity between
 * them.
 */
typedef enum fd_server_context {
	FD_SRV_CTX_NA,  /* Not Applicable   */
	FD_SRV_CTX_ISHM,
	FD_SRV_CTX_END, /* upper enum limit */
} fd_server_context_e;

int _odp_fdserver_register_fd(fd_server_context_e context, uint64_t key,
			      int fd);
int _odp_fdserver_deregister_fd(fd_server_context_e context, uint64_t key);
int _odp_fdserver_lookup_fd(fd_server_context_e context, uint64_t key);

#ifdef __cplusplus
}
#endif

#endif
