/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP schedule types
 */

#ifndef ODP_API_SCHEDULE_TYPES_H_
#define ODP_API_SCHEDULE_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup odp_scheduler
 *  @{
 */

/**
 * @typedef odp_schedule_prio_t
 * Scheduler priority level
 */

/**
 * @def ODP_SCHED_PRIO_HIGHEST
 * Highest scheduling priority
 */

/**
 * @def ODP_SCHED_PRIO_NORMAL
 * Normal scheduling priority
 */

/**
 * @def ODP_SCHED_PRIO_LOWEST
 * Lowest scheduling priority
 */

/**
 * @def ODP_SCHED_PRIO_DEFAULT
 * Default scheduling priority. User does not care about the selected priority
 * level - throughput, load balacing and synchronization features are more
 * important than priority scheduling.
 */

/**
 * @typedef odp_schedule_sync_t
 * Scheduler synchronization method
 */

/**
 * @def ODP_SCHED_SYNC_NONE
 * Queue not synchronised
 *
 * The scheduler does not provide event synchronization or ordering, only load
 * balancing. Events can be scheduled freely to multiple threads for concurrent
 * processing.
 */

/**
 * @def ODP_SCHED_SYNC_ATOMIC
 * Atomic queue synchronization
 *
 * Events from an atomic queue can be scheduled only to a single thread at a
 * time. The thread is guaranteed to have exclusive (atomic) access to the
 * associated queue context and event ordering is maintained. This enables the
 * user to avoid SW synchronization for those two.
 *
 * The atomic queue is dedicated to the thread until it requests another event
 * from the scheduler (which implicitly releases the queue) or calls
 * odp_schedule_release_atomic(), which allows the scheduler to release the
 * queue immediately.
 */

/**
 * @def ODP_SCHED_SYNC_ORDERED
 * Ordered queue synchronization
 *
 * Events from an ordered queue can be scheduled to multiple threads for
 * concurrent processing. The source queue (dequeue) ordering is maintained when
 * events are enqueued to their destination queue(s) before another schedule
 * call. Events from the same (source) queue appear in their original order
 * when dequeued from a destination queue. The destination queue can have any
 * queue type and synchronization method.
 */

/**
 * @typedef odp_schedule_group_t
 * Scheduler thread group
 */

/**
 * @def ODP_SCHED_GROUP_ALL
 * Group of all threads. All active worker and control threads belong to this
 * group. The group is automatically updated when new threads enter or old
 * threads exit ODP.
 */

/**
 * @def ODP_SCHED_GROUP_WORKER
 * Group of all worker threads. All active worker threads belong to this
 * group. The group is automatically updated when new worker threads enter or
 * old threads exit ODP.
 */

/** Scheduler parameters */
typedef	struct odp_schedule_param_t {
	/** Priority level */
	odp_schedule_prio_t  prio;
	/** Synchronization method */
	odp_schedule_sync_t  sync;
	/** Thread group */
	odp_schedule_group_t group;
} odp_schedule_param_t;

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
