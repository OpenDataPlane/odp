/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2018 Linaro Limited
 */

/**
 * @file
 *
 * ODP SCTP header
 */

#ifndef ODP_SCTP_H_
#define ODP_SCTP_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/align.h>
#include <odp/api/byteorder.h>
#include <odp/api/debug.h>

/** @addtogroup odp_header ODP HEADER
 *  @{
 */

/** SCTP header length */
#define _ODP_SCTPHDR_LEN 12

/** SCTP header */
typedef struct ODP_PACKED {
	odp_u16be_t src_port; /**< Source port */
	odp_u16be_t dst_port; /**< Destination port */
	odp_u32be_t tag;      /**< Verification tag */
	odp_u32be_t chksum;   /**< SCTP header and data checksum */
} _odp_sctphdr_t;

/** @internal Compile time assert */
ODP_STATIC_ASSERT(sizeof(_odp_sctphdr_t) == _ODP_SCTPHDR_LEN,
		  "_ODP_SCTPHDR_T__SIZE_ERROR");

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
