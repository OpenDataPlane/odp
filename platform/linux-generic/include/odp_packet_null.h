/* Copyright (c) 2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_PACKET_NULL_H_
#define ODP_PACKET_NULL_H_

#include <odp/api/pool.h>

typedef struct {
	int promisc;			/**< whether promiscuous mode is on */
} pkt_null_t;

#endif
