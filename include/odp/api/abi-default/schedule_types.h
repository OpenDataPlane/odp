/* Copyright (c) 2015-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP schedule
 */

#ifndef ODP_ABI_SCHEDULE_TYPES_H_
#define ODP_ABI_SCHEDULE_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/deprecated.h>
#include <odp/api/std_types.h>

/** @addtogroup odp_scheduler
 *  @{
 */

#define ODP_SCHED_WAIT     UINT64_MAX
#define ODP_SCHED_NO_WAIT  0

#define ODP_SCHED_GROUP_NAME_LEN 32

#if ODP_DEPRECATED_API
#define ODP_SCHED_PRIO_HIGHEST  (odp_schedule_max_prio())

#define ODP_SCHED_PRIO_NORMAL   (odp_schedule_default_prio())

#define ODP_SCHED_PRIO_LOWEST   (odp_schedule_min_prio())

#define ODP_SCHED_PRIO_DEFAULT  (odp_schedule_default_prio())
#else
/* Required to prevent Doxygen warning */
#define ODP_SCHED_PRIO_HIGHEST
#define ODP_SCHED_PRIO_NORMAL
#define ODP_SCHED_PRIO_LOWEST
#define ODP_SCHED_PRIO_DEFAULT
#undef ODP_SCHED_PRIO_HIGHEST
#undef ODP_SCHED_PRIO_NORMAL
#undef ODP_SCHED_PRIO_LOWEST
#undef ODP_SCHED_PRIO_DEFAULT
#endif

typedef int odp_schedule_sync_t;

#define ODP_SCHED_SYNC_PARALLEL 0
#define ODP_SCHED_SYNC_ATOMIC   1
#define ODP_SCHED_SYNC_ORDERED  2

typedef int odp_schedule_group_t;

/* These must be kept in sync with thread_globals_t in odp_thread.c */
#define ODP_SCHED_GROUP_INVALID ((odp_schedule_group_t)-1)
#define ODP_SCHED_GROUP_ALL     0
#define ODP_SCHED_GROUP_WORKER  1
#define ODP_SCHED_GROUP_CONTROL 2

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
