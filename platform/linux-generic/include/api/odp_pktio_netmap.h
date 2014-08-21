
/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP packet input/output netmap
 */

#ifndef ODP_PKTIO_NETMAP_H
#define ODP_PKTIO_NETMAP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <odp_pktio_types.h>

#define ODP_NETMAP_MODE_HW	0 /**< Netmap mode in hardware */
#define ODP_NETMAP_MODE_SW	1 /**< Netmap mode in software */

/**
 * Netmap parameters
 */
typedef struct {
	odp_pktio_type_t type;	/**< Packet IO type */
	int netmap_mode;	/**< Netmap Mode */
	uint16_t ringid;	/**< Ring identifiers */
} netmap_params_t;

#ifdef __cplusplus
}
#endif

#endif
