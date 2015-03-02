/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP thread API
 */

#ifndef ODP_API_THREAD_H_
#define ODP_API_THREAD_H_

#ifdef __cplusplus
extern "C" {
#endif

/** @defgroup odp_thread ODP THREAD
 *  @{
 */

/**
 * Get thread identifier
 *
 * Returns the thread identifier of the current thread. Thread ids range from 0
 * to ODP_CONFIG_MAX_THREADS-1. The ODP thread id is assinged by
 * odp_init_local() and freed by odp_term_local(). Thread id is unique within
 * the ODP instance.
 *
 * @return Thread identifier of the current thread
 */
int odp_thread_id(void);

/**
 * Thread count
 *
 * Returns the current ODP thread count. This is the number of active threads
 * running the ODP instance. Each odp_init_local() call increments and each
 * odp_term_local() call decrements the count. The count is always between 1 and
 * ODP_CONFIG_MAX_THREADS.
 *
 * @return Current thread count
 */
int odp_thread_count(void);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
