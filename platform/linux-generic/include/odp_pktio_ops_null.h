/* Copyright (c) 2018, ARM Limited. All rights reserved.
 *
 * Copyright (c) 2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef ODP_PKTIO_OPS_NULL_H_
#define ODP_PKTIO_OPS_NULL_H_

#include <odp/api/pool.h>

typedef struct {
	int promisc; /**< whether promiscuous mode is on */
} pktio_ops_null_data_t;

#endif
