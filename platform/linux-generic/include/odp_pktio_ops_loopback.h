/* Copyright (c) 2017, ARM Limited. All rights reserved.
 *
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef ODP_PKTIO_OPS_LOOPBACK_H_
#define ODP_PKTIO_OPS_LOOPBACK_H_

typedef struct {
	odp_queue_t loopq;  /**< loopback queue for "loop" device */
	odp_bool_t promisc; /**< promiscuous mode state */
	uint8_t idx;	    /**< index of "loop" device */
} pktio_ops_loopback_data_t;

#endif
