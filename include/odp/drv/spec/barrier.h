/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODPDRV execution barriers
 */

#ifndef ODPDRV_API_BARRIER_H_
#define ODPDRV_API_BARRIER_H_
#include <odp/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup odpdrv_barrier ODPDRV BARRIER
 * Thread execution and memory ordering barriers.
 *
 * @details
 * <b> Thread execution barrier (odpdrv_barrier_t) </b>
 *
 * Thread execution barrier synchronizes a group of threads to wait on the
 * barrier until the entire group has reached the barrier.
 *  @{
 */

/**
 * @typedef odpdrv_barrier_t
 * ODPDRV thread synchronization barrier
 */

/**
 * Initialize barrier with thread count.
 *
 * @param barr Pointer to a barrier variable
 * @param count Thread count
 */
void odpdrv_barrier_init(odpdrv_barrier_t *barr, int count);

/**
 * Synchronize thread execution on barrier.
 * Wait for all threads to arrive at the barrier until they are let loose again.
 * Threads will block (spin) until the last thread has arrived at the barrier.
 * All memory operations before the odpdrv_barrier_wait() call will be visible
 * to all threads when they leave the barrier.
 *
 * @param barr Pointer to a barrier variable
 */
void odpdrv_barrier_wait(odpdrv_barrier_t *barr);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
