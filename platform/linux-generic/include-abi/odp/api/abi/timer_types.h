/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2013-2018 Linaro Limited
 */


/**
 * @file
 *
 * ODP timer service
 */

#ifndef ODP_API_ABI_TIMER_TYPES_H_
#define ODP_API_ABI_TIMER_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/plat/strong_types.h>

/** @addtogroup odp_timer
 *  @{
 **/

typedef ODP_HANDLE_T(odp_timer_pool_t);

#define ODP_TIMER_POOL_INVALID _odp_cast_scalar(odp_timer_pool_t, 0)

#define ODP_TIMER_POOL_NAME_LEN  32

typedef ODP_HANDLE_T(odp_timer_t);

#define ODP_TIMER_INVALID _odp_cast_scalar(odp_timer_t, 0)

typedef ODP_HANDLE_T(odp_timeout_t);

#define ODP_TIMEOUT_INVALID  _odp_cast_scalar(odp_timeout_t, 0)

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
