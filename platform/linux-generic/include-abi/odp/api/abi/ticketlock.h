/* Copyright (c) 2015-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP ticketlock
 */

#ifndef ODP_API_ABI_TICKETLOCK_H_
#define ODP_API_ABI_TICKETLOCK_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/atomic.h>

/** @ingroup odp_locks
 *  @{
 */

/** @internal */
typedef struct odp_ticketlock_s {
	odp_atomic_u32_t  next_ticket; /**< Next ticket */
	odp_atomic_u32_t  cur_ticket;  /**< Current ticket */
} odp_ticketlock_t;

/* Include inlined versions of API functions */
#define _ODP_INLINE static inline
#include <odp/api/plat/ticketlock_inlines.h>
#include <odp/api/plat/ticketlock_inlines_api.h>

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
