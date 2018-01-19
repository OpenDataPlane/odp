/* Copyright (c) 2013-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP queue
 */

#ifndef ODP_API_SPEC_QUEUE_H_
#define ODP_API_SPEC_QUEUE_H_
#include <odp/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/schedule_types.h>
#include <odp/api/event.h>

/** @defgroup odp_queue ODP QUEUE
 *  Macros and operation on a queue.
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
 * Maximum queue name length in chars including null char
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
	ODP_QUEUE_TYPE_SCHED
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
 * Queue capabilities
 */
typedef struct odp_queue_capability_t {
	/** Maximum number of event queues of any type (default size). Use
	  * this in addition to queue type specific 'max_num', if both queue
	  * types are used simultaneously. */
	uint32_t max_queues;

	/** Maximum number of ordered locks per queue */
	uint32_t max_ordered_locks;

	/** Maximum number of scheduling groups */
	unsigned max_sched_groups;

	/** Number of scheduling priorities */
	unsigned sched_prios;

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

			/** Maximum queue size */
			uint32_t max_size;

		} lockfree;

		/** Wait-free (ODP_NONBLOCKING_WF) implementation capabilities.
		  * The specification is the same as for the blocking
		  * implementation. */
		struct {
			/** Maximum number of queues. Wait-free queues are not
			  * supported when zero. */
			uint32_t max_num;

			/** Maximum queue size */
			uint32_t max_size;

		} waitfree;

	} plain;

	/** Scheduled queue capabilities */
	struct {
		/** Maximum number of scheduled (ODP_BLOCKING) queues of the
		  * default size. */
		uint32_t max_num;

		/** Maximum number of events a scheduled (ODP_BLOCKING) queue
		  * can store simultaneously. The value of zero means that
		  * scheduled queues do not have a size limit, but a single
		  * queue can store all available events. */
		uint32_t max_size;

		/** Lock-free (ODP_NONBLOCKING_LF) implementation capabilities.
		  * The specification is the same as for the blocking
		  * implementation. */
		struct {
			/** Maximum number of queues. Lock-free queues are not
			  * supported when zero. */
			uint32_t max_num;

			/** Maximum queue size */
			uint32_t max_size;

		} lockfree;

		/** Wait-free (ODP_NONBLOCKING_WF) implementation capabilities.
		  * The specification is the same as for the blocking
		  * implementation. */
		struct {
			/** Maximum number of queues. Wait-free queues are not
			  * supported when zero. */
			uint32_t max_num;

			/** Maximum queue size */
			uint32_t max_size;

		} waitfree;

	} sched;

} odp_queue_capability_t;

/**
 * ODP Queue parameters
 */
typedef struct odp_queue_param_t {
	/** Queue type
	  *
	  * Valid values for other parameters in this structure depend on
	  * the queue type. */
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
	  * default size. */
	uint32_t size;

} odp_queue_param_t;

/**
 * Queue create
 *
 * Create a queue according to the queue parameters. Queue type is specified by
 * queue parameter 'type'. Use odp_queue_param_init() to initialize parameters
 * into their default values. Default values are also used when 'param' pointer
 * is NULL. The default queue type is ODP_QUEUE_TYPE_PLAIN. The use of queue
 * name is optional. Unique names are not required. However, odp_queue_lookup()
 * returns only a single matching queue.
 *
 * @param name    Name of the queue or NULL. Maximum string length is
 *                ODP_QUEUE_NAME_LEN.
 * @param param   Queue parameters. Uses defaults if NULL.
 *
 * @return Queue handle
 * @retval ODP_QUEUE_INVALID on failure
 */
odp_queue_t odp_queue_create(const char *name, const odp_queue_param_t *param);

/**
 * Destroy ODP queue
 *
 * Destroys ODP queue. The queue must be empty and detached from other
 * ODP API (crypto, pktio, etc). Application must ensure that no other
 * operations on this queue are invoked in parallel. Otherwise behavior
 * is undefined.
 *
 * @param queue    Queue handle
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int odp_queue_destroy(odp_queue_t queue);

/**
 * Find a queue by name
 *
 * @param name    Queue name
 *
 * @return Handle of the first matching queue
 * @retval ODP_QUEUE_INVALID on failure
 */
odp_queue_t odp_queue_lookup(const char *name);

/**
 * Query queue capabilities
 *
 * Outputs queue capabilities on success.
 *
 * @param[out] capa   Pointer to capability structure for output
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int odp_queue_capability(odp_queue_capability_t *capa);

/**
 * Set queue context
 *
 * It is the responsibility of the user to ensure that the queue context
 * is stored in a location accessible by all threads that attempt to
 * access it.
 *
 * @param queue    Queue handle
 * @param context  Address to the queue context
 * @param len      Queue context data length in bytes
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int odp_queue_context_set(odp_queue_t queue, void *context, uint32_t len);

/**
 * Get queue context
 *
 * @param queue    Queue handle
 *
 * @return pointer to the queue context
 * @retval NULL on failure
 */
void *odp_queue_context(odp_queue_t queue);

/**
 * Queue enqueue
 *
 * Enqueue the 'ev' on 'queue'. On failure the event is not consumed, the caller
 * has to take care of it.
 *
 * @param queue   Queue handle
 * @param ev      Event handle
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int odp_queue_enq(odp_queue_t queue, odp_event_t ev);

/**
 * Enqueue multiple events to a queue
 *
 * Enqueue the events from 'events[]' on 'queue'. A successful call returns the
 * actual number of events enqueued. If return value is less than 'num', the
 * remaining events at the end of events[] are not consumed, and the caller
 * has to take care of them.
 *
 * @param queue   Queue handle
 * @param events  Array of event handles
 * @param num     Number of event handles to enqueue
 *
 * @return Number of events actually enqueued (0 ... num)
 * @retval <0 on failure
 */
int odp_queue_enq_multi(odp_queue_t queue, const odp_event_t events[], int num);

/**
 * Queue dequeue
 *
 * Dequeues next event from head of the queue. Cannot be used for
 * ODP_QUEUE_TYPE_SCHED type queues (use odp_schedule() instead).
 *
 * @param queue   Queue handle
 *
 * @return Event handle
 * @retval ODP_EVENT_INVALID on failure (e.g. queue empty)
 */
odp_event_t odp_queue_deq(odp_queue_t queue);

/**
 * Dequeue multiple events from a queue
 *
 * Dequeues multiple events from head of the queue. Cannot be used for
 * ODP_QUEUE_TYPE_SCHED type queues (use odp_schedule() instead).
 *
 * @param queue   Queue handle
 * @param[out] events  Array of event handles for output
 * @param num     Maximum number of events to dequeue

 * @return Number of events actually dequeued (0 ... num)
 * @retval <0 on failure
 */
int odp_queue_deq_multi(odp_queue_t queue, odp_event_t events[], int num);

/**
 * Queue type
 *
 * @param queue   Queue handle
 *
 * @return Queue type
 */
odp_queue_type_t odp_queue_type(odp_queue_t queue);

/**
 * Queue schedule type
 *
 * @param queue   Queue handle
 *
 * @return Queue schedule synchronization type
 */
odp_schedule_sync_t odp_queue_sched_type(odp_queue_t queue);

/**
 * Queue priority
 *
 * @note Passing an invalid queue_handle will result in UNDEFINED behavior
 *
 * @param queue   Queue handle
 *
 * @return Queue schedule priority
 */
odp_schedule_prio_t odp_queue_sched_prio(odp_queue_t queue);

/**
 * Queue group
 *
 * @note Passing an invalid queue_handle will result in UNDEFINED behavior
 *
 * @param queue   Queue handle
 *
 * @return Queue schedule group
 */
odp_schedule_group_t odp_queue_sched_group(odp_queue_t queue);

/**
 * Queue lock count
 *
 * Return number of ordered locks associated with this ordered queue.
 * Lock count is defined in odp_schedule_param_t.
 *
 * @param queue   Queue handle
 *
 * @return	Number of ordered locks associated with this ordered queue
 * @retval 0	Specified queue is not ordered or no ordered lock associated
 *		with the ordered queue.
 */
uint32_t odp_queue_lock_count(odp_queue_t queue);

/**
 * Get printable value for an odp_queue_t
 *
 * @param hdl  odp_queue_t handle to be printed
 * @return     uint64_t value that can be used to print/display this
 *             handle
 *
 * @note This routine is intended to be used for diagnostic purposes
 * to enable applications to generate a printable value that represents
 * an odp_queue_t handle.
 */
uint64_t odp_queue_to_u64(odp_queue_t hdl);

/**
 * Initialize queue params
 *
 * Initialize an odp_queue_param_t to its default values for all fields.
 * Also the schedule parameters are set to defaults, although the default queue
 * type is ODP_QUEUE_TYPE_PLAIN.
 *
 * @param param   Address of the odp_queue_param_t to be initialized
 */
void odp_queue_param_init(odp_queue_param_t *param);

/**
 * Queue information
 * Retrieve information about a queue with odp_queue_info()
 */
typedef struct odp_queue_info_t {
	const char *name;         /**< queue name */
	odp_queue_param_t param;  /**< queue parameters */
} odp_queue_info_t;

/**
 * Retrieve information about a queue
 *
 * Invalid queue handles or handles to free/destroyed queues leads to
 * undefined behaviour. Not intended for fast path use.
 *
 * @param      queue   Queue handle
 * @param[out] info    Queue info pointer for output
 *
 * @retval 0 Success
 * @retval <0 Failure.  Info could not be retrieved.
 */
int odp_queue_info(odp_queue_t queue, odp_queue_info_t *info);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
