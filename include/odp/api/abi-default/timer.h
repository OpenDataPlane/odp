/* Copyright (c) 2013-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP timer service
 */

#ifndef ODP_ABI_TIMER_H_
#define ODP_ABI_TIMER_H_

#ifdef __cplusplus
extern "C" {
#endif

/** @internal Dummy type for strong typing */
typedef struct { char dummy; /**< @internal Dummy */ } _odp_abi_timer_t;

/** @internal Dummy type for strong typing */
typedef struct { char dummy; /**< @internal Dummy */ } _odp_abi_timeout_t;

/** @addtogroup odp_timer
 *  @{
 **/

struct timer_pool_s; /**< Forward declaration */

typedef struct timer_pool_s *odp_timer_pool_t;

#define ODP_TIMER_POOL_INVALID NULL

#define ODP_TIMER_POOL_NAME_LEN  32

typedef _odp_abi_timer_t *odp_timer_t;

#define ODP_TIMER_INVALID ((odp_timer_t)0xffffffff)

typedef _odp_abi_timeout_t *odp_timeout_t;

#define ODP_TIMEOUT_INVALID  ((odp_timeout_t)NULL)

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
