/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Marvell
 */

/**
 * @file
 *
 * ODP GTP header
 */
#ifndef _ODPH_GTP_H_
#define _ODPH_GTP_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp_api.h>

/**
 * @addtogroup odph_protocols
 * @{
 */

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
} odph_gtphdr_t;

/** GTP header length */
#define ODPH_GTP_HLEN sizeof(odph_gtphdr_t)

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif /* ODP_GTP_H_ */
