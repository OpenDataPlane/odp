/* Copyright (c) 2020, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP GTPU header
 */
#ifndef _ODPH_GTP_H_
#define _ODPH_GTP_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp_api.h>

/**
 * Simplified GTP protocol header.
 * Contains 8-bit gtp_hdr_info, 8-bit msg_type,
 * 16-bit plen, 32-bit teid.
 * No optional fields and next extension header.
 */
typedef struct ODP_PACKED {
	uint8_t gtp_hdr_info; /**< GTP header info */
	uint8_t msg_type;     /**< GTP message type */
	odp_u16be_t plen;     /**< Total payload length */
	odp_u32be_t teid;     /**< Tunnel endpoint ID */
} odph_gtpuhdr_t;

/** GTP header length */
#define ODP_GTPU_HLEN sizeof(odph_gtpuhdr_t)

/** GTP UDP port number */
#define ODP_GTPU_UDP_PORT 2152

#ifdef __cplusplus
}
#endif

#endif /* ODP_GTP_H_ */
