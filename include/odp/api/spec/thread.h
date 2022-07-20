/* Copyright (c) 2013-2018, Linaro Limited
 * Copyright (c) 2022, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP thread API
 */

#ifndef ODP_API_SPEC_THREAD_H_
#define ODP_API_SPEC_THREAD_H_
#include <odp/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @defgroup odp_thread ODP THREAD
 *  Thread types, masks and IDs.
 *  @{
 */

/**
 * @def ODP_THREAD_COUNT_MAX
 * Maximum number of threads supported in build time. Use
 * odp_thread_count_max() for maximum number of threads supported in run time,
 * which depend on system configuration and may be lower than this number.
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
 * running the ODP instance. Each odp_init_local() call increments and each
 * odp_term_local() call decrements the count. The count is always between 1 and
 * odp_thread_count_max().
 *
 * @return Current thread count
 */
int odp_thread_count(void);

/**
 * Maximum thread count
 *
 * Returns the maximum thread count, which is a constant value and set in
 * ODP initialization phase. This may be lower than ODP_THREAD_COUNT_MAX.
 *
 * @return Maximum thread count
 */
int odp_thread_count_max(void);

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
