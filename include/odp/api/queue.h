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

#ifndef ODP_QUEUE_H_
#define ODP_QUEUE_H_

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
 * Maximum queue name lenght in chars
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
 * ODP schedule priority
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
 * Default scheduling priority
 */


/**
 * @typedef odp_schedule_sync_t
 * ODP schedule synchronisation
 */

/**
 * @def ODP_SCHED_SYNC_NONE
 * Queue not synchronised
 */

/**
 * @def ODP_SCHED_SYNC_ATOMIC
 * Atomic queue
 */

/**
 * @def ODP_SCHED_SYNC_ORDERED
 * Ordered queue
 */

/**
 * @def ODP_SCHED_SYNC_DEFAULT
 * Default queue synchronisation
 */

/**
 * @typedef odp_schedule_group_t
 * ODP schedule core group
 */

/**
 * @def ODP_SCHED_GROUP_ALL
 * Group of all cores
 */

/**
 * @def ODP_SCHED_GROUP_DEFAULT
 * Default core group
 */

/**
 * ODP Queue parameters
 */
typedef struct odp_queue_param_t {
	/** Scheduler parameters */
	struct {
		odp_schedule_prio_t  prio;
		odp_schedule_sync_t  sync;
		odp_schedule_group_t group;
	} sched;
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
 * @return Queue handle or ODP_QUEUE_INVALID
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
 * @return 0 if successful
 */
int odp_queue_destroy(odp_queue_t queue);

/**
 * Find a queue by name
 *
 * @param name    Queue name
 *
 * @return Queue handle or ODP_QUEUE_INVALID
 */
odp_queue_t odp_queue_lookup(const char *name);

/**
 * Set queue context
 *
 * Its the responsability of the interface user to make sure
 * queue context allocation is done in an area reachable for
 * all EOs accessing the context
 *
 * @param queue    Queue handle
 * @param context  Address to the queue context
 *
 * @return 0 if successful
 */
int odp_queue_set_context(odp_queue_t queue, void *context);

/**
 * Get queue context
 *
 * @param queue    Queue handle
 *
 * @return If successful, a pointer to the queue context,
 *         NULL for failure.
 */
void *odp_queue_get_context(odp_queue_t queue);

/**
 * Queue enqueue
 *
 * @param queue   Queue handle
 * @param ev      Event handle
 *
 * @return 0 if succesful
 */
int odp_queue_enq(odp_queue_t queue, odp_event_t ev);

/**
 * Enqueue multiple events to a queue
 *
 * @param queue   Queue handle
 * @param ev      Event handles
 * @param num     Number of event handles
 *
 * @return 0 if succesful
 */
int odp_queue_enq_multi(odp_queue_t queue, odp_event_t ev[], int num);

/**
 * Queue dequeue
 *
 * Dequeues next event from head of the queue. Cannot be used for
 * ODP_QUEUE_TYPE_SCHED type queues (use odp_schedule() instead).
 *
 * @param queue   Queue handle
 *
 * @return Event handle, or ODP_EVENT_INVALID
 */
odp_event_t odp_queue_deq(odp_queue_t queue);

/**
 * Dequeue multiple events from a queue
 *
 * Dequeues multiple events from head of the queue. Cannot be used for
 * ODP_QUEUE_TYPE_SCHED type queues (use odp_schedule() instead).
 *
 * @param queue   Queue handle
 * @param events  Event handle array for output
 * @param num     Maximum number of event handles

 * @return Number of events written (0 ... num)
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
 * @return Queue schedule synchronisation type
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
