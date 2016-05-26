/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP timer service
 */

#ifndef ODP_TIMER_TYPES_H_
#define ODP_TIMER_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/plat/strong_types.h>

/** @addtogroup odp_timer
 *  @{
 **/

struct odp_timer_pool_s; /**< Forward declaration */

typedef struct odp_timer_pool_s *odp_timer_pool_t;

#define ODP_TIMER_POOL_INVALID NULL

typedef ODP_HANDLE_T(odp_timer_t);

#define ODP_TIMER_INVALID _odp_cast_scalar(odp_timer_t, 0xffffffff)

typedef ODP_HANDLE_T(odp_timeout_t);

#define ODP_TIMEOUT_INVALID  _odp_cast_scalar(odp_timeout_t, 0)

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
