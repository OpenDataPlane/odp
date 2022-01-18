/* Copyright (c) 2015-2018, Linaro Limited
 * Copyright (c) 2020-2022, Nokia
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
typedef ODP_HANDLE_T(odp_lso_profile_t);

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
#define ODP_LSO_PROFILE_INVALID _odp_cast_scalar(odp_lso_profile_t, 0)

#define ODP_PKTIO_MACADDR_MAXSIZE 16

#define ODP_PKTIN_NO_WAIT 0

#define ODP_PKTIO_STATS_EXTRA_NAME_LEN 64

/**
 * @}
 */

#include <odp/api/plat/pktio_inlines.h>

#ifdef __cplusplus
}
#endif

#endif
