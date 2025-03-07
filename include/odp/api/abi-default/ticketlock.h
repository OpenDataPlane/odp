/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2015-2018 Linaro Limited
 */

/**
 * @file
 *
 * ODP ticketlock
 */

#ifndef ODP_ABI_TICKETLOCK_H_
#define ODP_ABI_TICKETLOCK_H_

#include <odp/api/atomic.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @internal */
typedef struct odp_ticketlock_s {
	odp_atomic_u32_t  next_ticket; /**< Next ticket */
	odp_atomic_u32_t  cur_ticket;  /**< Current ticket */
} odp_ticketlock_t;

#ifdef __cplusplus
}
#endif

#endif
