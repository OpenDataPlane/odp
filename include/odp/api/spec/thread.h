/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2013-2018 Linaro Limited
 * Copyright (c) 2022-2023 Nokia
 */

/**
 * @file
 *
 * ODP thread API
 */

#ifndef ODP_API_SPEC_THREAD_H_
#define ODP_API_SPEC_THREAD_H_
#include <odp/visibility_begin.h>

#include <odp/api/thread_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup odp_thread
 *  Thread types, masks and IDs.
 *  @{
 */

/**
 * Get thread identifier
 *
 * Returns the ODP thread identifier of current thread. Thread IDs range from 0
 * to odp_thread_count_max() - 1 and are unique within an ODP instance.
 *
 * Thread IDs are assigned by odp_init_local() and freed by odp_term_local().
 * IDs are assigned sequentially starting from 0 in the same order threads call
 * odp_init_local(). Thread IDs freed by odp_term_local() may be reused by
 * following odp_init_local() calls.
 *
 * @return Thread identifier of the current thread
 */
int odp_thread_id(void);

/**
 * Thread count
 *
 * Returns the current ODP thread count. This is the number of active threads
 * of any type running in the ODP instance. Each odp_init_local() call
 * increments and each odp_term_local() call decrements the count. The count is
 * always between 1 and odp_thread_count_max().
 *
 * @return Current thread count
 */
int odp_thread_count(void);

/**
 * Control thread count
 *
 * Otherwise like odp_thread_count(), but returns the number of active threads
 * of type #ODP_THREAD_CONTROL. The count is always between 0 and
 * odp_thread_control_count_max().
 *
 * @return Current control thread count
 */
int odp_thread_control_count(void);

/**
 * Worker thread count
 *
 * Otherwise like odp_thread_count(), but returns the number of active threads
 * of type #ODP_THREAD_WORKER. The count is always between 0 and
 * odp_thread_worker_count_max().
 *
 * @return Current worker thread count
 */
int odp_thread_worker_count(void);

/**
 * Maximum thread count
 *
 * Returns the maximum number of threads of any type. This is a constant value
 * and set in ODP initialization phase. The value may be lower than
 * #ODP_THREAD_COUNT_MAX.
 *
 * @return Maximum thread count
 */
int odp_thread_count_max(void);

/**
 * Maximum control thread count
 *
 * Otherwise like odp_thread_count_max(), but returns the maximum number of
 * control threads (#ODP_THREAD_CONTROL). The returned value is always <=
 * odp_thread_count_max().
 *
 * @return Maximum control thread count
 */
int odp_thread_control_count_max(void);

/**
 * Maximum worker thread count
 *
 * Otherwise like odp_thread_count_max(), but returns the maximum number of
 * worker threads (#ODP_THREAD_WORKER). The returned value is always <=
 * odp_thread_count_max().
 *
 * @return Maximum worker thread count
 */
int odp_thread_worker_count_max(void);

/**
 * Thread type
 *
 * Returns the thread type of the current thread.
 *
 * @return Thread type
 */
odp_thread_type_t odp_thread_type(void);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
