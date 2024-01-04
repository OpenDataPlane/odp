/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2015-2018 Linaro Limited
 * Copyright (c) 2020-2023 Nokia
 */

/**
 * @file
 *
 * ODP Packet IO
 */

#ifndef ODP_ABI_PACKET_IO_TYPES_H_
#define ODP_ABI_PACKET_IO_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/std_types.h>

/** @internal Dummy type for strong typing */
typedef struct { char dummy; /**< @internal Dummy */ } _odp_abi_pktio_t;

/** @internal Dummy type for strong typing */
typedef struct { char dummy; /**< @internal Dummy */ } _odp_abi_lso_profile_t;

/** @addtogroup odp_packet_io
 *  @{
 */

typedef _odp_abi_pktio_t *odp_pktio_t;
typedef _odp_abi_lso_profile_t *odp_lso_profile_t;

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

#define ODP_PKTIO_INVALID ((odp_pktio_t)0)
#define ODP_LSO_PROFILE_INVALID ((odp_lso_profile_t)0)

#define ODP_PKTIO_MAX_INDEX 63

#define ODP_PKTIO_MACADDR_MAXSIZE 16

#define ODP_PKTIN_NO_WAIT 0

#define ODP_PKTIN_MAX_QUEUES 64

#define ODP_PKTOUT_MAX_QUEUES 64

#define ODP_PKTIO_STATS_EXTRA_NAME_LEN 64

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
