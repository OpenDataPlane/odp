/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP Packet IO
 */

#ifndef ODP_API_ABI_PACKET_IO_H_
#define ODP_API_ABI_PACKET_IO_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/std_types.h>
#include <odp/api/plat/strong_types.h>

/** @addtogroup odp_packet_io
 *  Operations on a packet.
 *  @{
 */

typedef ODP_HANDLE_T(odp_pktio_t);

/** @internal */
typedef struct odp_pktin_queue_t {
	odp_pktio_t pktio; /**< @internal pktio handle */
	int index;         /**< @internal pktio queue index */
} odp_pktin_queue_t;

/** @internal */
typedef struct odp_pktout_queue_t {
	odp_pktio_t pktio; /**< @internal pktio handle */
	int index;         /**< @internal pktio queue index */
} odp_pktout_queue_t;

#define ODP_PKTIO_INVALID _odp_cast_scalar(odp_pktio_t, 0)

#define ODP_PKTIO_MACADDR_MAXSIZE 16

#define ODP_PKTIN_NO_WAIT 0
#define ODP_PKTIN_WAIT    UINT64_MAX

/**
 * @}
 */

#define _ODP_INLINE static inline
#include <odp/api/plat/pktio_inlines.h>
#include <odp/api/plat/pktio_inlines_api.h>

#ifdef __cplusplus
}
#endif

#endif
