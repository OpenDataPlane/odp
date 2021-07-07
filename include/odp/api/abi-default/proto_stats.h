/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

/**
 * @file
 *
 * ODP Proto Stats
 */

#ifndef ODP_ABI_PROTO_STATS_H_
#define ODP_ABI_PROTO_STATS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/std_types.h>

/** @internal Dummy type for strong typing */
typedef struct { char dummy; /**< @internal Dummy */ } _odp_abi_proto_stats_t;

/** @ingroup odp_proto_stats
 *  Operations on a proto stats object.
 *  @{
 */

typedef _odp_abi_proto_stats_t *odp_proto_stats_t;

#define ODP_PROTO_STATS_INVALID ((odp_proto_stats_t)0)

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
