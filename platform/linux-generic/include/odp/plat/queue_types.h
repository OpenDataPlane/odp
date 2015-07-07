/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP queue
 */

#ifndef ODP_QUEUE_TYPES_H_
#define ODP_QUEUE_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/std_types.h>
#include <odp/plat/strong_types.h>

/** @addtogroup odp_queue ODP QUEUE
 *  Macros and operation on a queue.
 *  @{
 */

typedef ODP_HANDLE_T(odp_queue_t);

typedef ODP_HANDLE_T(odp_queue_group_t);

#define ODP_QUEUE_INVALID  _odp_cast_scalar(odp_queue_t, 0)

#define ODP_QUEUE_NAME_LEN 32


typedef int odp_queue_type_t;

#define ODP_QUEUE_TYPE_SCHED  0
#define ODP_QUEUE_TYPE_POLL   1
#define ODP_QUEUE_TYPE_PKTIN  2
#define ODP_QUEUE_TYPE_PKTOUT 3

typedef int odp_schedule_prio_t;

#define ODP_SCHED_PRIO_HIGHEST  0

#define ODP_SCHED_PRIO_NORMAL   (ODP_CONFIG_SCHED_PRIOS / 2)

#define ODP_SCHED_PRIO_LOWEST   (ODP_CONFIG_SCHED_PRIOS - 1)

#define ODP_SCHED_PRIO_DEFAULT  ODP_SCHED_PRIO_NORMAL


typedef int odp_schedule_sync_t;

#define ODP_SCHED_SYNC_NONE     0
#define ODP_SCHED_SYNC_ATOMIC   1
#define ODP_SCHED_SYNC_ORDERED  2

typedef int odp_schedule_group_t;

#define ODP_SCHED_GROUP_ALL     0

/** Get printable format of odp_queue_t */
static inline uint64_t odp_queue_to_u64(odp_queue_t hdl)
{
	return _odp_pri(hdl);
}

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
