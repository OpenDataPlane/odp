/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2015-2018 Linaro Limited
 */

/**
 * @file
 *
 * ODP barrier
 */

#ifndef ODP_ABI_BARRIER_H_
#define ODP_ABI_BARRIER_H_

#include <odp/api/std_types.h>
#include <odp/api/atomic.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @internal
 * ODP thread synchronization barrier
 */
struct odp_barrier_s {
	uint32_t         count;  /**< Thread count */
	odp_atomic_u32_t bar;    /**< Barrier counter */
};

/** @addtogroup odp_barrier
 *  @{
 */

typedef struct odp_barrier_s odp_barrier_t;

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
