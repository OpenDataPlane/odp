/* Copyright (c) 2015-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP schedule types
 */

#ifndef ODP_API_SPEC_SCHEDULE_TYPES_H_
#define ODP_API_SPEC_SCHEDULE_TYPES_H_
#include <odp/visibility_begin.h>

#include <odp/api/support.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup odp_scheduler
 *  @{
 */

/**
 * @def ODP_SCHED_PRIO_HIGHEST
 * This macro is equivalent of calling odp_schedule_max_prio() and will be
 * deprecated. Use direct function call instead.
 */

/**
 * @def ODP_SCHED_PRIO_NORMAL
 * This macro is equivalent of calling odp_schedule_default_prio() and will be
 * deprecated. Use direct function call instead.
 */

/**
 * @def ODP_SCHED_PRIO_LOWEST
 * This macro is equivalent of calling odp_schedule_min_prio() and will be
 * deprecated. Use direct function call instead.
 */

/**
 * @def ODP_SCHED_PRIO_DEFAULT
 * This macro is equivalent of calling odp_schedule_default_prio() and will be
 * deprecated. Use direct function call instead.
 */

/**
 * @typedef odp_schedule_sync_t
 * Scheduler synchronization method
 */

/**
 * @def ODP_SCHED_SYNC_PARALLEL
 * Parallel scheduled queues
 *
 * The scheduler performs priority scheduling, load balancing, prefetching, etc
 * functions but does not provide additional event synchronization or ordering.
 * It's free to schedule events from single parallel queue to multiple threads
 * for concurrent processing. Application is responsible for queue context
 * synchronization and event ordering (SW synchronization).
 */

/**
 * @def ODP_SCHED_SYNC_ATOMIC
 * Atomic queue synchronization
 *
 * Events from an atomic queue can be scheduled only to a single thread at a
 * time. The thread is guaranteed to have exclusive (atomic) access to the
 * associated queue context, which enables the user to avoid SW synchronization.
 * Atomic queue also helps to maintain event ordering since only one thread at
 * a time is able to process events from a queue.
 *
 * The atomic queue synchronization context is dedicated to the thread until it
 * requests another event from the scheduler, which implicitly releases the
 * context. User may allow the scheduler to release the context earlier than
 * that by calling odp_schedule_release_atomic(). However, this call is just
 * a hint to the implementation and the context may be held until the next
 * schedule call.
 *
 * When scheduler is enabled as flow-aware, the event flow id value affects
 * scheduling of the event and synchronization is maintained per flow within
 * each queue.
 */

/**
 * @def ODP_SCHED_SYNC_ORDERED
 * Ordered queue synchronization
 *
 * Events from an ordered queue can be scheduled to multiple threads for
 * concurrent processing but still maintain the original event order. This
 * enables the user to achieve high single flow throughput by avoiding
 * SW synchronization for ordering between threads.
 *
 * The source queue (dequeue) ordering is maintained when
 * events are enqueued to their destination queue(s) within the same ordered
 * queue synchronization context. A thread holds the context until it
 * requests another event from the scheduler, which implicitly releases the
 * context. User may allow the scheduler to release the context earlier than
 * that by calling odp_schedule_release_ordered(). However, this call is just
 * a hint to the implementation and the context may be held until the next
 * schedule call.
 *
 * Events from the same (source) queue appear in their original order
 * when dequeued from a destination queue. The destination queue can have any
 * queue type and synchronization method. Event ordering is based on the
 * received event(s), but also other (newly allocated or stored) events are
 * ordered when enqueued within the same ordered context. Events not enqueued
 * (e.g. freed or stored) within the context are considered missing from
 * reordering and are skipped at this time (but can be ordered again within
 * another context).
 *
 * Unnecessary event re-ordering may be avoided for those destination queues
 * that do not need to maintain the original event order by setting 'order'
 * queue parameter to ODP_QUEUE_ORDER_IGNORE.
 *
 * When scheduler is enabled as flow-aware, the event flow id value affects
 * scheduling of the event and synchronization is maintained per flow within
 * each queue.
 */

/**
 * @typedef odp_schedule_group_t
 * Scheduler thread group
 */

/**
 * @def ODP_SCHED_GROUP_INVALID
 * Invalid scheduler group
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

/**
 * @def ODP_SCHED_GROUP_CONTROL
 * Predefined scheduler group of all control threads
 */

/**
 * Scheduling priority level
 *
 * Priority level is an integer value between odp_schedule_min_prio() and
 * odp_schedule_max_prio(). Queues with a higher priority value are served with
 * higher priority than queues with a lower priority value.
 */
typedef int odp_schedule_prio_t;

/** Scheduler parameters */
typedef	struct odp_schedule_param_t {
	/** Priority level
	  *
	  * Default value is returned by odp_schedule_default_prio(). */
	odp_schedule_prio_t  prio;

	/** Synchronization method
	  *
	  * Default value is ODP_SCHED_SYNC_PARALLEL. */
	odp_schedule_sync_t  sync;

	/** Thread group
	  *
	  * Default value is ODP_SCHED_GROUP_ALL. */
	odp_schedule_group_t group;

	/** Ordered lock count for this queue
	  *
	  * Default value is 0. */
	uint32_t lock_count;
} odp_schedule_param_t;

/**
 * Scheduler capabilities
 */
typedef struct odp_schedule_capability_t {
	/** Maximum number of ordered locks per queue */
	uint32_t max_ordered_locks;

	/** Maximum number of scheduling groups */
	uint32_t max_groups;

	/** Number of scheduling priorities */
	uint32_t max_prios;

	/** Maximum number of scheduled (ODP_BLOCKING) queues of the default
	 * size. */
	uint32_t max_queues;

	/** Maximum number of events a scheduled (ODP_BLOCKING) queue can store
	 * simultaneously. The value of zero means that scheduled queues do not
	 * have a size limit, but a single queue can store all available
	 * events. */
	uint32_t max_queue_size;

	/** Maximum flow ID per queue
	 *
	 *  Valid flow ID range in flow aware mode of scheduling is from 0 to
	 *  this maximum value. So, maximum number of flows per queue is this
	 *  value plus one. A value of 0 indicates that flow aware mode is not
	 *  supported. */
	uint32_t max_flow_id;

	/** Lock-free (ODP_NONBLOCKING_LF) queues support.
	 * The specification is the same as for the blocking implementation. */
	odp_support_t lockfree_queues;

	/** Wait-free (ODP_NONBLOCKING_WF) queues support.
	 * The specification is the same as for the blocking implementation. */
	odp_support_t waitfree_queues;

} odp_schedule_capability_t;

/**
 * Schedule configuration
 */
typedef struct odp_schedule_config_t {
	/** Maximum number of scheduled queues to be supported.
	 *
	 * @see odp_schedule_capability_t
	 */
	uint32_t num_queues;

	/** Maximum number of events required to be stored simultaneously in
	 * scheduled queue. This number must not exceed 'max_queue_size'
	 * capability.  A value of 0 configures default queue size supported by
	 * the implementation.
	 */
	uint32_t queue_size;

	/** Maximum flow ID per queue
	 *
	 *  This value must not exceed 'max_flow_id' capability. Flow aware
	 *  mode of scheduling is enabled when the value is greater than 0.
	 *  The default value is 0.
	 *
	 *  Application can assign events to specific flows by calling
	 *  odp_event_flow_id_set() before enqueuing events into a scheduled
	 *  queue. When in flow aware mode, the event flow id value affects
	 *  scheduling of the event and synchronization is maintained per flow
	 *  within each queue.
	 *
	 *  Depeding on implementation, there may be much more flows supported
	 *  than queues, as flows are lightweight entities.
	 *
	 *  @see odp_schedule_capability_t, odp_event_flow_id()
	 */
	uint32_t max_flow_id;

} odp_schedule_config_t;

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
