/* Copyright (c) 2014-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP SCTP header
 */

#ifndef ODPH_SCTP_H_
#define ODPH_SCTP_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp_api.h>

/**
 * @addtogroup odph_protocols
 * @{
 */

/** SCTP header length */
#define ODPH_SCTPHDR_LEN 12

/** SCTP header */
typedef struct ODP_PACKED {
	odp_u16be_t src_port; /**< Source port */
	odp_u16be_t dst_port; /**< Destination port */
	odp_u32be_t tag;      /**< Verification tag */
	odp_u32be_t chksum;   /**< SCTP header and data checksum */
} odph_sctphdr_t;

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */
ODP_STATIC_ASSERT(sizeof(odph_sctphdr_t) == ODPH_SCTPHDR_LEN,
		  "ODPH_SCTPHDR_T__SIZE_ERROR");
/** @endcond */

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
