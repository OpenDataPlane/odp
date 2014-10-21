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


#include <odp_std_types.h>
#include <odp_atomic.h>

/** @addtogroup odp_synchronizers
 *  Barrier between threads.
 *  @{
 */

/**
 * ODP execution barrier
 */
typedef struct odp_barrier_t {
	int              count;  /**< @private Thread count */
	odp_atomic_int_t bar;    /**< @private Barrier counter */
} odp_barrier_t;


/**
 * Init barrier with thread count
 *
 * @param barrier    Barrier
 * @param count      Thread count
 */
void odp_barrier_init_count(odp_barrier_t *barrier, int count);


/**
 * Synchronise thread execution on barrier
 *
 * @param barrier    Barrier
 */
void odp_barrier_sync(odp_barrier_t *barrier);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
