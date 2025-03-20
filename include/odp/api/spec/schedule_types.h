/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2015-2018 Linaro Limited
 * Copyright (c) 2023-2025 Nokia
 */

/**
 * @file
 *
 * ODP schedule types
 */

#ifndef ODP_API_SPEC_SCHEDULE_TYPES_H_
#define ODP_API_SPEC_SCHEDULE_TYPES_H_
#include <odp/visibility_begin.h>

#include <odp/api/event_vector_types.h>
#include <odp/api/std_types.h>
#include <odp/api/thrmask.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @defgroup odp_scheduler ODP SCHEDULER
 *  @{
 */

/**
 * @def ODP_SCHED_WAIT
 * Wait infinitely
 */

/**
 * @def ODP_SCHED_NO_WAIT
 * Do not wait
 */

/**
 * @def ODP_SCHED_GROUP_NAME_LEN
 * Maximum schedule group name length, including the null character
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
 * When odp_schedule() returns an event, the calling thread is associated
 * with an ordered scheduling synchronization context. The contexts arising
 * from the same ordered queue have the same mutual ordering as the
 * corresponding events had in the queue.
 *
 * When odp_schedule_multi() returns more than one event from an ordered
 * queue, the events returned were consecutive in the queue and the calling
 * thread is associated with single ordered scheduling synchronization
 * context that is ordered with respect to other contexts as if just the
 * first event was returned.
 *
 * When threads holding ordered scheduling synchronization contexts, which
 * arise from the same ordered queue, enqueue events to destination queues,
 * the order of events in each destination queue will be as follows:
 *
 * - Events enqueued by one thread have the order in which the enqueue
 *   calls were made.
 *
 * - Two events enqueued by different threads have the same mutual order
 *   as the scheduling synchronization contexts of the enqueuing threads.
 *
 * The ordering rules above apply to all events, not just those that were
 * scheduled from the ordered queue. For instance, newly allocated events
 * and previously stored events are ordered in the destination queue based
 * on the scheduling synchronization context. The ordering rules apply
 * regarless of the type (scheduled or plain) or schedule type (atomic,
 * ordered, or parallel) of the destination queue. If the order type of
 * the destination queue is ODP_QUEUE_ORDER_IGNORE, then the order between
 * events enqueued by different threads is not guaranteed.
 *
 * An ordered scheduling synchronization context is implicitly released when
 * the thread holding the context requests a new event from the scheduler.
 * User may allow the scheduler to release the context earlier than that by
 * calling odp_schedule_release_ordered(). However, this call is just a hint
 * to the implementation and the context may be held until the next schedule
 * call.
 *
 * Enqueue calls by different threads may return in a different order than
 * the final order of the enqueued events in the destination queue.
 *
 * Unnecessary event re-ordering may be avoided for those destination queues
 * that do not need to maintain the specified event order by setting 'order'
 * queue parameter to ODP_QUEUE_ORDER_IGNORE.
 *
 * When scheduler is enabled as flow-aware, the event flow id value affects
 * scheduling of the event and synchronization is maintained and order is
 * defined per flow within each queue.
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
 * Priority level is a non-negative integer value between
 * odp_schedule_min_prio() and odp_schedule_max_prio(). Queues with a higher
 * priority value are served with higher priority than queues with a lower
 * priority value.
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

	/** Maximum number of scheduling groups. The value includes the enabled
	 *  predefined scheduling groups (ODP_SCHED_GROUP_ALL,
	 *  ODP_SCHED_GROUP_WORKER, and ODP_SCHED_GROUP_CONTROL). By default, an
	 *  application can create 'max_groups' - 3 groups. */
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

	/** Order wait support. If not supported, odp_schedule_order_wait()
	 *  does nothing. */
	odp_support_t order_wait;

	/** Event aggregator capabilities for scheduled queues */
	odp_event_aggr_capability_t aggr;

} odp_schedule_capability_t;

/**
 * Region specific cache stashing configuration
 *
 * Region specific cache stashing configuration for different cache levels.
 * Application can, for example, configure caching of certain portions of a
 * region to L2 while configuring another portion to be cached to L3 or
 * alternatively caching to both levels by configuring overlapping offsets and
 * byte counts.
 */
typedef struct odp_cache_stash_region_t {
	/** L2 cache stashing */
	struct {
		/** Byte offset into a region to start caching from
		 *
		 *  Depending on the implementation, this might be rounded down
		 *  to a more suitable boundary.
		 */
		uint32_t offset;

		/** Length in bytes to cache
		 *
		 *  Depending on the implementation, this might be rounded up
		 *  to a more suitable boundary.
		 */
		uint32_t len;

	} l2;

	/** L3 cache stashing */
	struct {
		/** Byte offset into a region to start caching from
		 *
		 *  Depending on the implementation, this might be rounded down
		 *  to a more suitable boundary.
		 */
		uint32_t offset;

		/** Length in bytes to cache
		 *
		 *  Depending on the implementation, this might be rounded up
		 *  to a more suitable boundary.
		 */
		uint32_t len;

	} l3;

} odp_cache_stash_region_t;

/**
 * Cache stashing configuration
 *
 * Cache stashing configuration for different data regions.
 */
typedef struct odp_cache_stash_config_t {
	/** Region specific configuration toggle */
	union {
		/** Region bit fields */
		struct {
			/** Enable/disable event_metadata L2 cache stashing */
			uint32_t event_metadata_l2  : 1;

			/** Enable/disable event_metadata L3 cache stashing */
			uint32_t event_metadata_l3  : 1;

			/** Enable/disable event_data L2 cache stashing */
			uint32_t event_data_l2      : 1;

			/** Enable/disable event_data L3 cache stashing */
			uint32_t event_data_l3      : 1;

			/** Enable/disable event_user_area L2 cache stashing */
			uint32_t event_user_area_l2 : 1;

			/** Enable/disable event_user_area L3 cache stashing */
			uint32_t event_user_area_l3 : 1;

			/** Enable/disable queue_context L2 cache stashing */
			uint32_t queue_context_l2   : 1;

			/** Enable/disable queue_context L3 cache stashing */
			uint32_t queue_context_l3   : 1;

		};

		/** All bits of the bit field structure
		 *
		 *  This field can be used to set/clear all bits, or bitwise
		 *  operations over the entire structure.
		 */
		uint32_t all;

	} regions;

	/** Cache stashing for event metadata */
	odp_cache_stash_region_t event_metadata;

	/** Cache stashing for event data */
	odp_cache_stash_region_t event_data;

	/** Cache stashing for event user area */
	odp_cache_stash_region_t event_user_area;

	/** Cache stashing for queue context region */
	odp_cache_stash_region_t queue_context;

} odp_cache_stash_config_t;

/**
 * Priority specific cache stashing configuration
 */
typedef struct odp_cache_stash_prio_config_t {
	/** Priority level for applying this cache stashing configuration to */
	odp_schedule_prio_t  prio;

	/** Cache stashing configuration */
	odp_cache_stash_config_t config;

} odp_cache_stash_prio_config_t;

/**
 * Schedule group parameters
 */
typedef struct odp_schedule_group_param_t {
	/** Group specific cache stashing hints
	 *
	 *  Depending on the implementation, configuring these may improve
	 *  performance. Cache stashing hints can be configured with a
	 *  group-wide configuration using 'common' and with optional priority
	 *  specific exceptions using 'prio' and 'num'. For example:
	 *
	 * @code{.unparsed}
	 *    ...
	 *    odp_schedule_group_param_t param;
	 *    odp_cache_stash_prio_config_t prio;
	 *
	 *    odp_schedule_group_param_init(&param);
	 *    prio.prio = 3;
	 *    prio.config.regions.event_user_area_l2 = 1;
	 *    prio.config.event_user_area.l2.offset = 0;
	 *    prio.config.event_user_area.l2.len = 64;
	 *    param.cache_stash_hints.prio = &prio;
	 *    param.cache_stash_hints.num = 1;
	 *    ...
	 * @endcode
	 *
	 *  would disable cache stashing entirely for the group except
	 *  priority 3 would have event user area L2 cache stashing
	 *  enabled.
	 *
	 * @code{.unparsed}
	 *    ...
	 *    odp_schedule_group_param_t param;
	 *    odp_cache_stash_prio_config_t prio;
	 *
	 *    odp_schedule_group_param_init(&param);
	 *    param.cache_stash_hints.common.regions.event_data_l2 = 1;
	 *    param.cache_stash_hints.common.event_data.l2.offset = 0;
	 *    param.cache_stash_hints.common.event_data.l2.len = 128;
	 *    prio.prio = 3;
	 *    prio.config.regions.all = 0;
	 *    param.cache_stash_hints.prio = &prio;
	 *    param.cache_stash_hints.num = 1;
	 *    ...
	 * @endcode
	 *
	 *  would enable event data L2 cache stashing entirely for the
	 *  group except disable cache stashing for priority 3.
	 *
	 * @code{.unparsed}
	 *    ...
	 *    odp_schedule_group_param_t param;
	 *    odp_cache_stash_prio_config_t prio[2];
	 *
	 *    odp_schedule_group_param_init(&param);
	 *    param.cache_stash_hints.common.regions.event_data_l2 = 1;
	 *    param.cache_stash_hints.common.event_data.l2.offset = 0;
	 *    param.cache_stash_hints.common.event_data.l2.len = 128;
	 *    prio[0].prio = 3;
	 *    prio[0].config.regions.event_data_l2 = 1;
	 *    prio[0].config.event_data.l2.offset = 64;
	 *    prio[0].config.event_data.l2.len = 128;
	 *    prio[1].prio = 4;
	 *    prio[1].config.regions.event_data_l2 = 1;
	 *    prio[1].config.event_data.l2.offset = 64;
	 *    prio[1].config.event_data.l2.len = 128;
	 *    param.cache_stash_hints.prio = prio;
	 *    param.cache_stash_hints.num = 2;
	 *    ...
	 * @endcode
	 *
	 *  would enable event data L2 cache stashing entirely for the
	 *  group but priorities 3 and 4 would have event data cache
	 *  stashing beginning from offset 64 instead of 0.
	 */
	struct {
		/** Common group specific cache stashing hints
		 *
		 *  Configures cache stashing for each priority under the
		 *  group. By default, all regions are disabled (see
		 *  odp_cache_stash_config_t::regions).
		 */
		odp_cache_stash_config_t common;

		/** Priority specific cache stashing hints
		 *
		 *  Configures priority specific cache stashing. Overrides
		 *  completely the 'common' stashing configuration for the
		 *  given priority.
		 */
		struct {
			/** Pointer to 'num' entries of priority specific
			 *  configuration
			 *
			 *  The field is ignored if 'num' is 0.
			 */
			const odp_cache_stash_prio_config_t *prio;

			/** Number of entries in 'prio' array
			 *
			 *  0 by default.
			 */
			uint32_t num;

		};

	} cache_stash_hints;

} odp_schedule_group_param_t;

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
	 *  Depending on the implementation, there may be much more flows
	 *  supported than queues, as flows are lightweight entities.
	 *
	 *  @see odp_schedule_capability_t, odp_event_flow_id()
	 */
	uint32_t max_flow_id;

	/** Enable/disable predefined scheduling groups
	 *
	 *  Application can additionally provide parameters for the
	 *  to-be-enabled predefined schedule groups.
	 */
	struct {
		/** ODP_SCHED_GROUP_ALL
		 *
		 *  0: Disable group
		 *  1: Enable group (default)
		 */
		odp_bool_t all;

		/** ODP_SCHED_GROUP_CONTROL
		 *
		 *  0: Disable group
		 *  1: Enable group (default)
		 */
		odp_bool_t control;

		/** ODP_SCHED_GROUP_WORKER
		 *
		 *  0: Disable group
		 *  1: Enable group (default)
		 */
		odp_bool_t worker;

		/** Parameters for ODP_SCHED_GROUP_ALL schedule group */
		odp_schedule_group_param_t all_param;

		/** Parameters for ODP_SCHED_GROUP_CONTROL schedule group */
		odp_schedule_group_param_t control_param;

		/** Parameters for ODP_SCHED_GROUP_WORKER schedule group */
		odp_schedule_group_param_t worker_param;

	} sched_group;

} odp_schedule_config_t;

/**
 * Schedule group information
 */
typedef struct odp_schedule_group_info_t {
	const char    *name;   /**< Schedule group name */
	odp_thrmask_t thrmask; /**< Thread mask of the schedule group */
} odp_schedule_group_info_t;

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
