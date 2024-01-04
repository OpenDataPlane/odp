/* Copyright (c) 2022, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP pool
 */

#ifndef ODP_API_ABI_POOL_TYPES_H_
#define ODP_API_ABI_POOL_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/plat/strong_types.h>

/** @addtogroup odp_pool
 *  @{
 */

typedef ODP_HANDLE_T(odp_pool_t);

#define ODP_POOL_INVALID _odp_cast_scalar(odp_pool_t, 0)

#define ODP_POOL_NAME_LEN  32

#define ODP_POOL_MAX_THREAD_STATS  128

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
