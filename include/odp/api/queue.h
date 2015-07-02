/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP queue
 */

#ifndef ODP_API_QUEUE_H_
#define ODP_API_QUEUE_H_

#ifdef __cplusplus
extern "C" {
#endif


/** @defgroup odp_queue ODP QUEUE
 *  Macros and operation on a queue.
 *  @{
 */

/**
 * @typedef odp_queue_t
 * ODP queue
 */

/**
 * @typedef odp_queue_group_t
 * Queue group instance type
 */

/**
 * @def ODP_QUEUE_INVALID
 * Invalid queue
 */

/**
 * @def ODP_QUEUE_NAME_LEN
 * Maximum queue name length in chars
 */


/**
 * @typedef odp_queue_type_t
 * ODP queue type
 */

/**
 * @def ODP_QUEUE_TYPE_SCHED
 * Scheduled queue
 */

/**
 * @def ODP_QUEUE_TYPE_POLL
 * Not scheduled queue
 */

/**
 * @def ODP_QUEUE_TYPE_PKTIN
 * Packet input queue
 */

/**
 * @def ODP_QUEUE_TYPE_PKTOUT
 * Packet output queue
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
 * ODP Queue parameters
 */
typedef struct odp_queue_param_t {
	/** Scheduler parameters */
	odp_schedule_param_t sched;
	/** Queue context */
	void *context;
} odp_queue_param_t;


/**
 * Queue create
 *
 * @param name    Queue name
 * @param type    Queue type
 * @param param   Queue parameters. Uses defaults if NULL.
 *
 * @return Queue handle
 * @retval ODP_QUEUE_INVALID on failure
 */
odp_queue_t odp_queue_create(const char *name, odp_queue_type_t type,
			     odp_queue_param_t *param);

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
 * @return Queue handle
 * @retval ODP_QUEUE_INVALID on failure
 */
odp_queue_t odp_queue_lookup(const char *name);

/**
 * Set queue context
 *
 * It is the responsibility of the interface user to make sure
 * queue context allocation is done in an area reachable for
 * all EOs accessing the context
 *
 * @param queue    Queue handle
 * @param context  Address to the queue context
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int odp_queue_set_context(odp_queue_t queue, void *context);

/**
 * Get queue context
 *
 * @param queue    Queue handle
 *
 * @return pointer to the queue context
 * @retval NULL on failure
 */
void *odp_queue_get_context(odp_queue_t queue);

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
 * @param[in] events Array of event handles
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
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
