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

/** @addtogroup odp_scheduler
 *  @{
 */

typedef int odp_schedule_prio_t;

#define ODP_SCHED_PRIO_HIGHEST  0

#define ODP_SCHED_PRIO_NORMAL   4

#define ODP_SCHED_PRIO_LOWEST   7

#define ODP_SCHED_PRIO_DEFAULT  ODP_SCHED_PRIO_NORMAL

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
