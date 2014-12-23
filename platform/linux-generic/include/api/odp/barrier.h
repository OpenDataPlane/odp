/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP execution barriers
 */

#ifndef ODP_BARRIER_H_
#define ODP_BARRIER_H_

#ifdef __cplusplus
extern "C" {
#endif


#include <odp/std_types.h>
#include <odp/atomic.h>

/** @addtogroup odp_synchronizers
 *  Synchronize threads.
 *  @{
 */

/**
 * ODP thread synchronization barrier
 */
typedef struct odp_barrier_t {
	uint32_t         count;  /**< @private Thread count */
	odp_atomic_u32_t bar;    /**< @private Barrier counter */
} odp_barrier_t;


/**
 * Initialize barrier with thread count.
 *
 * @param barr Pointer to a barrier variable
 * @param count Thread count
 */
void odp_barrier_init(odp_barrier_t *barr, int count);


/**
 * Synchronize thread execution on barrier.
 * Wait for all threads to arrive at the barrier until they are let loose again.
 * Threads will block (spin) until the last thread has arrived at the barrier.
 * All memory operations before the odp_barrier_wait() call will be visible
 * to all threads when they leave the barrier.
 *
 * @param barr Pointer to a barrier variable
 */
void odp_barrier_wait(odp_barrier_t *barr);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
