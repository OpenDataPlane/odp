/* Copyright (c) 2021, Marvell
 * Copyright (c) 2021, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/**
 * @file
 *
 * ODP proto stats types
 */

#ifndef ODP_API_ABI_PROTO_STATS_TYPES_H_
#define ODP_API_ABI_PROTO_STATS_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/std_types.h>
#include <odp/api/plat/strong_types.h>

/** @addtogroup odp_proto_stats
 *  @{
 */

typedef ODP_HANDLE_T(odp_proto_stats_t);

#define ODP_PROTO_STATS_INVALID _odp_cast_scalar(odp_proto_stats_t, 0)

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
