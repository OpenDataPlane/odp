/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2017-2018 Linaro Limited
 * Copyright (c) 2022 Nokia
 */

#ifndef ODP_ABI_POOL_TYPES_H_
#define ODP_ABI_POOL_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

/** @internal Dummy type for strong typing */
typedef struct { char dummy; /**< @internal Dummy */ } _odp_abi_pool_t;

/** @addtogroup odp_pool
 *  @{
 */

typedef _odp_abi_pool_t *odp_pool_t;

#define ODP_POOL_INVALID   ((odp_pool_t)0)

#define ODP_POOL_NAME_LEN  32

#define ODP_POOL_MAX_THREAD_STATS  128

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
