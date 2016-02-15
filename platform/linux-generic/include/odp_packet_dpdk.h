/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_PACKET_DPDK_H
#define ODP_PACKET_DPDK_H

#include <odp/api/packet_io.h>
#include <odp/api/pool.h>

/** Packet IO using DPDK interface */
typedef struct {
	odp_pool_t pool;		  /**< pool to alloc packets from */
	odp_pktio_capability_t	capa;	  /**< interface capabilities */
} pkt_dpdk_t;

#endif
