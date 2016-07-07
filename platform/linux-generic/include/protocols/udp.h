/* Copyright (c) 2016, Linaro Limited
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

#include <odp_api.h>

/** @addtogroup odp_header ODP HEADER
 *  @{
 */

/** UDP header length */
#define _ODP_UDPHDR_LEN 8

/** UDP header */
typedef struct ODP_PACKED {
	odp_u16be_t src_port; /**< Source port */
	odp_u16be_t dst_port; /**< Destination port */
	odp_u16be_t length;   /**< UDP datagram length in bytes (header+data) */
	odp_u16be_t chksum;   /**< UDP header and data checksum (0 if not used)*/
} _odp_udphdr_t;

/** @internal Compile time assert */
ODP_STATIC_ASSERT(sizeof(_odp_udphdr_t) == _ODP_UDPHDR_LEN,
		  "_ODP_UDPHDR_T__SIZE_ERROR");

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
