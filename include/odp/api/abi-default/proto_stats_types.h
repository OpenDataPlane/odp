/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 Marvell
 * Copyright (c) 2021 Nokia
 */

#ifndef ODP_ABI_PROTO_STATS_TYPES_H_
#define ODP_ABI_PROTO_STATS_TYPES_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @internal Dummy type for strong typing */
typedef struct { char dummy; /**< @internal Dummy */ } _odp_abi_proto_stats_t;

/** @addtogroup odp_proto_stats
 *  @{
 */

typedef _odp_abi_proto_stats_t *odp_proto_stats_t;

#define ODP_PROTO_STATS_INVALID ((odp_proto_stats_t)0)

#define ODP_PROTO_STATS_NAME_LEN 64

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
