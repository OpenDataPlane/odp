/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2013-2018 Linaro Limited
 * Copyright (c) 2025 Nokia
 */

/**
 * @file
 *
 * ODP execution barriers
 */

#ifndef ODP_API_SPEC_BARRIER_H_
#define ODP_API_SPEC_BARRIER_H_
#include <odp/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup odp_barrier ODP BARRIER
 * Thread execution and memory ordering barriers.
 *
 * @details
 * <b> Thread execution barrier (odp_barrier_t) </b>
 *
 * Thread execution barrier synchronizes a group of threads to wait on the
 * barrier until the entire group has reached the barrier.
 *  @{
 */

/**
 * @typedef odp_barrier_t
 * ODP thread synchronization barrier
 */

/**
 * Initialize barrier with thread count.
 *
 * This function must not be called by multiple threads simultaneously for
 * the same barrier nor at the same time when any other thread is calling
 * odp_barrier_wait() for the same barrier.
 *
 * @param barr Pointer to a barrier variable
 * @param count Thread count
 */
void odp_barrier_init(odp_barrier_t *barr, int count);

/**
 * Synchronize thread execution on barrier.
 *
 * Wait for a number of threads to arrive at the barrier until they are
 * let loose again.
 *
 * Threads will block (spin) until the last thread has arrived at the barrier.
 * All memory operations before the odp_barrier_wait() call will be visible
 * to all threads when they leave the barrier.
 *
 * A barrier must be initialized using odp_barrier_init() before first use.
 *
 * A barrier can be reused without reinitializing it again. It is ok to call
 * odp_barrier_wait() for the same barrier again immediately after returning
 * from the previous odp_barrier_wait() even if other threads that were waiting
 * for the barrier have not yet returned from odp_barrier_wait().
 *
 * If a barrier is used by more threads than the thread count the barrier was
 * initialized with, the number of threads that have called odp_barrier_wait()
 * but not yet returned from it must never exceed the thread count the barrier
 * was initialized with.
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

#include <odp/visibility_end.h>
#endif
