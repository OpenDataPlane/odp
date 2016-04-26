/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP configuration
 */

#ifndef ODP_PLAT_CONFIG_H_
#define ODP_PLAT_CONFIG_H_

#ifdef __cplusplus
extern "C" {
#endif

/** @ingroup odp_config ODP CONFIG
 * Platform-specific configuration limits
 * @{
 */

/**
 * Maximum number of queues
 */
#define ODP_CONFIG_QUEUES 1024
static inline int odp_config_queues(void)
{
	return ODP_CONFIG_QUEUES;
}

/**
 * Number of ordered locks per queue
 */
#define ODP_CONFIG_MAX_ORDERED_LOCKS_PER_QUEUE 2
static inline int odp_config_max_ordered_locks_per_queue(void)
{
	return ODP_CONFIG_MAX_ORDERED_LOCKS_PER_QUEUE;
}

/**
 * Number of scheduling priorities
 */
#define ODP_CONFIG_SCHED_PRIOS 8
static inline int odp_config_sched_prios(void)
{
	return ODP_CONFIG_SCHED_PRIOS;
}

/**
 * Number of scheduling groups
 */
#define ODP_CONFIG_SCHED_GRPS 256
static inline int odp_config_sched_grps(void)
{
	return ODP_CONFIG_SCHED_GRPS;
}

#include <odp/api/spec/config.h>

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
