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
 * Get thread id
 *
 * @return Thread id of the current thread
 */
int odp_thread_id(void);


/**
 * Get core id
 *
 * @return Core id where the thread is running currently
 */
int odp_thread_core(void);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
