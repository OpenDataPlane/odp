/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2013-2018 Linaro Limited
 */

/**
 * @file
 *
 * ODP timer service
 */

#ifndef ODP_ABI_TIMER_TYPES_H_
#define ODP_ABI_TIMER_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

/** @internal Dummy type for strong typing */
typedef struct { char dummy; /**< @internal Dummy */ } _odp_abi_timer_t;

/** @internal Dummy type for strong typing */
typedef struct { char dummy; /**< @internal Dummy */ } _odp_abi_timeout_t;

/** @internal Dummy type for strong typing */
typedef struct { char dummy; /**< @internal Dummy */ } _odp_abi_timer_pool_t;

/** @addtogroup odp_timer
 *  @{
 **/

typedef _odp_abi_timer_pool_t *odp_timer_pool_t;

#define ODP_TIMER_POOL_INVALID  ((odp_timer_pool_t)0)

#define ODP_TIMER_POOL_NAME_LEN  32

typedef _odp_abi_timer_t *odp_timer_t;

#define ODP_TIMER_INVALID ((odp_timer_t)0)

typedef _odp_abi_timeout_t *odp_timeout_t;

#define ODP_TIMEOUT_INVALID  ((odp_timeout_t)0)

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
