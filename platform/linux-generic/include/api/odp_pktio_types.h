/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_PKTIO_TYPES_H
#define ODP_PKTIO_TYPES_H

#ifdef __cplusplus
extern "C" {
#endif

/* We should ensure that future enum values will never overlap, otherwise
 * applications that want netmap suport might get in trouble if the odp lib
 * was not built with netmap support and there are more types define below
 */

typedef enum {
	ODP_PKTIO_TYPE_SOCKET_BASIC = 0x1,
	ODP_PKTIO_TYPE_SOCKET_MMSG,
	ODP_PKTIO_TYPE_SOCKET_MMAP,
	ODP_PKTIO_TYPE_NETMAP,
} odp_pktio_type_t;

#include <odp_pktio_socket.h>
#ifdef ODP_HAVE_NETMAP
#include <odp_pktio_netmap.h>
#endif

typedef union odp_pktio_params_t {
	odp_pktio_type_t type;
	socket_params_t sock_params;
#ifdef ODP_HAVE_NETMAP
	netmap_params_t nm_params;
#endif
} odp_pktio_params_t;

#ifdef __cplusplus
}
#endif

#endif
