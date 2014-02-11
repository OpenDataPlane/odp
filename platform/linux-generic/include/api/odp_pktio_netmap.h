
/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_PKTIO_NETMAP_H
#define ODP_PKTIO_NETMAP_H

#include <odp_pktio_types.h>

#define ODP_NETMAP_MODE_HW	0
#define ODP_NETMAP_MODE_SW	1

typedef struct {
	odp_pktio_type_t type;
	int netmap_mode;
	uint16_t ringid;
} netmap_params_t;

#endif
