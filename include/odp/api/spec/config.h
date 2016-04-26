/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP configuration
 */

#ifndef ODP_API_CONFIG_H_
#define ODP_API_CONFIG_H_
#include <odp/api/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @defgroup odp_config ODP CONFIG
 *  Platform-specific configuration limits.
 *
 * @note The API calls defined for ODP configuration limits are the
 * normative means of accessing platform-specific configuration limits.
 * Platforms MAY in addition include \#defines for these limits for
 * internal use in dimensioning arrays, however there is no guarantee
 * that applications using such \#defines will be portable across all
 * ODP implementations. Applications SHOULD expect that over time such
 * \#defines will be deprecated and removed.
 *  @{
 */

/**
 * Maximum number of queues
 * @return The maximum number of queues supported by this platform
 */
int odp_config_queues(void);

/**
 * Maximum number of ordered locks per queue
 * @return The maximum number of ordered locks per queue supported by
 * this platform.
 */
int odp_config_max_ordered_locks_per_queue(void);

/**
 * Number of scheduling priorities
 * @return The number of scheduling priorities supported by this platform
 */
int odp_config_sched_prios(void);

/**
 * Number of scheduling groups
 * @return Number of scheduling groups supported by this platofmr
 */
int odp_config_sched_grps(void);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/api/visibility_end.h>
#endif
