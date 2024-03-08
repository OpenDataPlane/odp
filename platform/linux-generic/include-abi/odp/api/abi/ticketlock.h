/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2015-2018 Linaro Limited
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

/** @addtogroup odp_locks
 *  @{
 */

/** @internal */
typedef struct odp_ticketlock_s {
	odp_atomic_u32_t  next_ticket; /**< Next ticket */
	odp_atomic_u32_t  cur_ticket;  /**< Current ticket */
} odp_ticketlock_t;

/* Include inlined versions of API functions */
#include <odp/api/plat/ticketlock_inlines.h>

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
