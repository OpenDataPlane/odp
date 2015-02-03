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

#ifndef ODP_THREAD_H_
#define ODP_THREAD_H_

#ifdef __cplusplus
extern "C" {
#endif

/** @defgroup odp_thread ODP THREAD
 *  @{
 */

/**
 * Get thread identifier
 *
 * @return Thread identifier of the current thread
 */
int odp_thread_id(void);


/**
 * Get CPU number
 *
 * @return CPU number where the thread is currently running
 */
int odp_thread_cpu(void);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
