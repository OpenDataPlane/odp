/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2018 Linaro Limited
 * Copyright (c) 2024-2025 Nokia
 */

/**
 * @file
 *
 * ODP queue types
 */

#ifndef ODP_API_SPEC_QUEUE_TYPES_H_
#define ODP_API_SPEC_QUEUE_TYPES_H_
#include <odp/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/event_vector_types.h>
#include <odp/api/schedule_types.h>

/** @defgroup odp_queue ODP QUEUE
 *  @{
 */

/**
 * @typedef odp_queue_t
 * ODP queue
 */

/**
 * @def ODP_QUEUE_INVALID
 * Invalid queue
 */

/**
 * @def ODP_QUEUE_NAME_LEN
 * Maximum queue name length, including the null character
 */

/**
 * Queue type
 */
typedef enum odp_queue_type_t {
	/** Plain queue
	  *
	  * Plain queues offer simple FIFO storage of events. Application may
	  * dequeue directly from these queues. */
	ODP_QUEUE_TYPE_PLAIN = 0,

	/** Scheduled queue
	  *
	  * Scheduled queues are connected to the scheduler. Application must
	  * not dequeue events directly from these queues but use the scheduler
	  * instead. */
	ODP_QUEUE_TYPE_SCHED,

	/** Aggregator queue
	  *
	  * Aggregator queues are connected to an underlying plain or scheduled
	  * queue. They cannot be created directly but through the creation
	  * of the underlying queue. Application must not dequeue events
	  * directly from these queues.
	  */
	ODP_QUEUE_TYPE_AGGR,

} odp_queue_type_t;

/**
 * Queue operation mode
 */
typedef enum odp_queue_op_mode_t {
	/** Multithread safe operation
	  *
	  * Queue operation (enqueue or dequeue) is multithread safe. Any
	  * number of application threads may perform the operation
	  * concurrently. */
	ODP_QUEUE_OP_MT = 0,

	/** Not multithread safe operation
	  *
	  * Queue operation (enqueue or dequeue) may not be multithread safe.
	  * Application ensures synchronization between threads so that
	  * simultaneously only single thread attempts the operation on
	  * the same queue. */
	ODP_QUEUE_OP_MT_UNSAFE,

	/** Disabled
	  *
	  * Direct enqueue or dequeue operation from application is disabled.
	  * An attempt to enqueue/dequeue directly will result undefined
	  * behaviour. Various ODP functions (e.g. packet input, timer,
	  * crypto, scheduler, etc) are able to perform enqueue or
	  * dequeue operations normally on the queue.
	  * */
	ODP_QUEUE_OP_DISABLED

} odp_queue_op_mode_t;

/**
 * Non-blocking level
 *
 * A non-blocking level defines implementation guarantees for application
 * progress when multiple threads operate on the same resource (e.g. a queue)
 * simultaneously. The first level (ODP_BLOCKING) does not have any block
 * freedom guarantees, but a suspending thread may block the other threads for
 * the entire time it remains suspended (infinitely if crashed).
 * On the contrary, actual non-blocking levels provide guarantees of progress:
 *
 * ODP_NONBLOCKING_LF:  A non-blocking and lock-free implementation guarantees
 *                      that at least one of the threads successfully completes
 *                      its operations, regardless of what other threads do.
 *                      Application progress is guaranteed, but individual
 *                      threads may starve while trying to execute their
 *                      operations on the shared resource.
 *
 * ODP_NONBLOCKING_WF:  A non-blocking and wait-free implementation guarantees
 *                      application progress with starvation freedom. All
 *                      threads are guaranteed to complete their operations in
 *                      a bounded number of steps, regardless of what other
 *                      threads do.
 *
 * Non-blocking levels are listed from the weakest to the strongest guarantee of
 * block freedom. Performance of a non-blocking implementation may be lower than
 * the blocking one. Non-blocking guarantees are important e.g. for real-time
 * applications when real-time and non real-time threads share a resource.
 */
typedef enum odp_nonblocking_t {
	/** Blocking implementation. A suspeding thread may block all other
	 *  threads, i.e. no block freedom guarantees. This is the lowest level.
	 */
	ODP_BLOCKING = 0,

	/** Non-blocking and lock-free implementation. Other threads can make
	 *  progress while a thread is suspended. Starvation freedom is not
	 *  guaranteed.
	 */
	ODP_NONBLOCKING_LF,

	/** Non-blocking and wait-free implementation. Other threads can make
	 *  progress while a thread is suspended. Starvation freedom is
	 *  guaranteed.
	 */
	ODP_NONBLOCKING_WF

} odp_nonblocking_t;

/**
 * Original event order maintenance options
 *
 * Options to keep or ignore the original event order of a source queue. This
 * option is relevant for (plain or parallel scheduled) queues that are
 * destinations for events enqueued while holding an ordered queue
 * synchronization context. By default, an ordered context maintains original
 * event order regardless of the destination queue type. Event re-ordering may
 * cause extra synchronization effort for implementation and a long delay before
 * application can receive a re-ordered event from the destination queue. This
 * is wasteful and in some cases the extra delay is not acceptable for those
 * destination queues that do not need to maintain the original event order.
 * Application can use ODP_QUEUE_ORDER_IGNORE option to prevent implementation
 * from performing unnecessary event re-ordering and negative side-effects of
 * that.
 */
typedef enum odp_queue_order_t {
	/** Keep original event order. Events enqueued into this queue while
	 *  holding an ordered queue synchronization context maintain the
	 *  original event order of the source queue.
	 */
	ODP_QUEUE_ORDER_KEEP = 0,

	/** Ignore original event order. Events enqueued into this queue do not
	 *  need to maintain the original event order of the source queue.
	 *  Implementation must avoid significant event re-ordering delays.
	 */
	ODP_QUEUE_ORDER_IGNORE

} odp_queue_order_t;

/**
 * Queue capabilities
 */
typedef struct odp_queue_capability_t {
	/** Maximum number of event queues of any type (default size). Use
	  * this in addition to queue type specific 'max_num', if both queue
	  * types are used simultaneously. */
	uint32_t max_queues;

	/** Plain queue capabilities */
	struct {
		/** Maximum number of plain (ODP_BLOCKING) queues of the
		  * default size. */
		uint32_t max_num;

		/** Maximum number of events a plain (ODP_BLOCKING) queue can
		  * store simultaneously. The value of zero means that plain
		  * queues do not have a size limit, but a single queue can
		  * store all available events. */
		uint32_t max_size;

		/** Lock-free (ODP_NONBLOCKING_LF) implementation capabilities.
		  * The specification is the same as for the blocking
		  * implementation. */
		struct {
			/** Maximum number of queues. Lock-free queues are not
			  * supported when zero. */
			uint32_t max_num;

			/** Maximum queue size. The value of zero means that
			 *  there is no size limit. */
			uint32_t max_size;

		} lockfree;

		/** Wait-free (ODP_NONBLOCKING_WF) implementation capabilities.
		  * The specification is the same as for the blocking
		  * implementation. */
		struct {
			/** Maximum number of queues. Wait-free queues are not
			  * supported when zero. */
			uint32_t max_num;

			/** Maximum queue size. The value of zero means that
			 *  there is no size limit. */
			uint32_t max_size;

		} waitfree;

		/** Event vector generation capabilities */
		odp_event_aggr_capability_t aggr;

	} plain;

} odp_queue_capability_t;

/**
 * ODP Queue parameters
 */
typedef struct odp_queue_param_t {
	/** Queue type
	  *
	  * Valid values for other parameters in this structure depend on
	  * the queue type. The default value is ODP_QUEUE_TYPE_PLAIN. */
	odp_queue_type_t type;

	/** Enqueue mode
	  *
	  * Default value for both queue types is ODP_QUEUE_OP_MT. Application
	  * may enable performance optimizations by defining MT_UNSAFE or
	  * DISABLED modes when applicable. */
	odp_queue_op_mode_t enq_mode;

	/** Dequeue mode
	  *
	  * For PLAIN queues, the default value is ODP_QUEUE_OP_MT. Application
	  * may enable performance optimizations by defining MT_UNSAFE or
	  * DISABLED modes when applicable. However, when a plain queue is input
	  * to the implementation (e.g. a queue for packet output), the
	  * parameter is ignored in queue creation and the value is
	  * ODP_QUEUE_OP_DISABLED.
	  *
	  * For SCHED queues, the parameter is ignored in queue creation and
	  * the value is ODP_QUEUE_OP_DISABLED. */
	odp_queue_op_mode_t deq_mode;

	/** Scheduler parameters
	  *
	  * These parameters are considered only when queue type is
	  * ODP_QUEUE_TYPE_SCHED. */
	odp_schedule_param_t sched;

	/** Original event order maintenance
	  *
	  * Keep or ignore the original event order of a source queue.
	  * The default value is ODP_QUEUE_ORDER_KEEP. */
	odp_queue_order_t order;

	/** Non-blocking level
	  *
	  * Queue implementation must guarantee at least this level of block
	  * freedom for queue enqueue and dequeue/schedule operations.
	  * The default value is ODP_BLOCKING. */
	odp_nonblocking_t nonblocking;

	/** Queue context pointer
	  *
	  * User defined context pointer associated with the queue. The same
	  * pointer can be accessed with odp_queue_context() and
	  * odp_queue_context_set() calls. The implementation may read the
	  * pointer for prefetching the context data. Default value of the
	  * pointer is NULL. */
	void *context;

	/** Queue context data length
	  *
	  * User defined context data length in bytes for prefetching.
	  * The implementation may use this value as a hint for the number of
	  * context data bytes to prefetch. Default value is zero (no hint). */
	uint32_t context_len;

	/** Queue size
	  *
	  * The queue must be able to store at minimum this many events
	  * simultaneously. The value must not exceed 'max_size' queue
	  * capability. The value of zero means implementation specific
	  * default size. The default value is 0. */
	uint32_t size;

	/** Number of event aggregators
	  *
	  * Event aggregators are queues which try to aggregate multiple
	  * events into vector events before enqueuing the events or vector
	  * events to this queue. When at least one event aggregator is
	  * configured, an event can be enqueued directly using the queue
	  * handle of this queue or indirectly through an event aggregator
	  * using the queue handle of the event aggregator (see
	  * odp_queue_aggr()).
	  *
	  * Two events enqueued through different aggregators (or one through
	  * an aggregator and the other directly through this queue) may
	  * appear in any order when dequeued.
	  *
	  * When >= 1, configuration must be provided for each aggregator
	  * through the 'aggr' array.
	  *
	  * The default value is zero.
	  */
	uint32_t num_aggr;

	/** Event aggregator configuration parameters
	  *
	  * When 'num_aggr' is non-zero, 'aggr' must point to an array
	  * of size 'num_aggr'.
	  *
	  * The default value is null.
	  */
	const odp_event_aggr_config_t *aggr;

} odp_queue_param_t;

/**
 * Queue information
 * Retrieve information about a queue with odp_queue_info()
 */
typedef struct odp_queue_info_t {
	const char *name;         /**< queue name */
	odp_queue_param_t param;  /**< queue parameters */
} odp_queue_info_t;

/**
 * Event aggregator enqueuing parameters
 */
typedef struct odp_aggr_enq_param_t {
	/** The event being enqueued is the first event of related events.
	  *
	  * Give a hint to an event aggregator to make room for new events
	  * in the aggregation queue by generating an event vector of the
	  * events already in the aggregation queue. This makes it more
	  * likely that this event and the related events end up in the
	  * same event vector.
	  *
	  * This flag has an effect only when an event is enqueued to an
	  * event aggregation queue.
	  *
	  * Default value is zero.
	  */
	uint8_t start_of_vector :1;

	/** The event being enqueued is the last event of related events.
	  *
	  * Give a hint to an event aggregator to stop aggregating more
	  * events before generating an event vector. This reduces the
	  * delay experienced by the events being aggregated.
	  *
	  * This flag has an effect only when an event is enqueued to an
	  * event aggregation queue.
	  *
	  * Default value is zero.
	  */
	uint8_t end_of_vector :1;

} odp_aggr_enq_param_t;

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
