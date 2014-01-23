/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP UDP header
 */

#ifndef ODP_UDP_H_
#define ODP_UDP_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp_align.h>
#include <odp_debug.h>
#include <odp_byteorder.h>

#define ODP_UDPHDR_LEN 8

typedef struct ODP_PACKED {
	uint16be_t src_port; /**< Source port number */
	uint16be_t dst_port; /**< Destination port number */
	uint16be_t length;   /**< UDP datagram length in bytes (header+data) */
	uint16be_t chksum;   /**< UDP header and data checksum (0 if not used)*/
} odp_udphdr_t;

ODP_ASSERT(sizeof(odp_udphdr_t) == ODP_UDPHDR_LEN, ODP_UDPHDR_T__SIZE_ERROR);

#ifdef __cplusplus
}
#endif

#endif
