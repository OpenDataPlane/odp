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

typedef enum {
	ODP_PKTIO_TYPE_SOCKET = 0x01,
} odp_pktio_type_t;

#include <odp_pktio_socket.h>

typedef union odp_pktio_params_t {
	odp_pktio_type_t type;
	socket_params_t sock_params;
} odp_pktio_params_t;

#ifdef __cplusplus
}
#endif

#endif
