/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP packet input/output socket
 */

#ifndef ODP_PKTIO_SOCKET_H
#define ODP_PKTIO_SOCKET_H

#ifdef __cplusplus
extern "C" {
#endif

#include <odp_pktio_types.h>

/**
 * Socket Parameters
 */
typedef struct {
	odp_pktio_type_t type;	/**< Packet IO type */
	int fanout;		/**< Fantout */
} socket_params_t;

#ifdef __cplusplus
}
#endif

#endif
