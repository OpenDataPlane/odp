/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2013-2018 Linaro Limited
 * Copyright (c) 2023-2025 Nokia
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

#include <odp/api/event_types.h>
#include <odp/api/queue_types.h>
#include <odp/api/std_types.h>

/** @addtogroup odp_queue
 *  Queues for event passing and scheduling.
 *  @{
 */

/**
 * Queue create
 *
 * Create a queue according to the queue parameters. The use of queue name is
 * optional. Unique names are not required. However, odp_queue_lookup() returns
 * only a single matching queue. Use odp_queue_param_init() to initialize
 * parameters into their default values. Default values are also used when
 * 'param' pointer is NULL.
 *
 * @param name    Name of the queue or NULL. Maximum string length is
 *                ODP_QUEUE_NAME_LEN, including the null character.
 * @param param   Queue parameters. Uses defaults if NULL.
 *
 * @return Queue handle
 * @retval ODP_QUEUE_INVALID on failure
 */
odp_queue_t odp_queue_create(const char *name, const odp_queue_param_t *param);

/**
 * Create multiple queues
 *
 * Otherwise like odp_queue_create(), but creates multiple queues with a single
 * call. The output queue handles are written in the same order as input
 * parameters. A single odp_queue_create_multi() call is equivalent to calling
 * odp_queue_create() 'num' times in row.
 *
 * If 'share_param' value is false, 'param' array must contain 'num' elements.
 * If the value is true, only a single element is required and it's used as
 * queue parameters for all created queues. If 'name' array is not NULL, the
 * array must contain 'num' elements.
 *
 * @param      name         Array of queue name pointers or NULL. NULL is also
 *                          valid queue name pointer value.
 * @param      param        Array of queue parameters
 * @param      share_param  If true, use same parameters ('param[0]') for all
 *                          queues.
 * @param[out] queue        Array of queue handles for output
 * @param      num          Number of queues to create
 *
 * @return Number of queues actually created (0 ... num)
 * @retval <0 on failure
 */
int odp_queue_create_multi(const char *name[], const odp_queue_param_t param[],
			   odp_bool_t share_param, odp_queue_t queue[],
			   int num);

/**
 * Destroy ODP queue
 *
 * Destroys ODP queue. The queue must be empty and detached from other
 * ODP API (crypto, pktio, classifier, timer, etc). Application must ensure
 * that no other operations on this queue are invoked in parallel. Otherwise
 * behavior is undefined.
 *
 * @param queue    Queue handle
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int odp_queue_destroy(odp_queue_t queue);

/**
 * Destroy multiple queues
 *
 * Otherwise like odp_queue_destroy(), but destroys multiple queues with a
 * single call.
 *
 * @param queue    Array of queue handles
 * @param num      Number of queues to destroy
 *
 * @retval Number of queues actually destroyed (1 ... num)
 * @retval <0 on failure
 */
int odp_queue_destroy_multi(odp_queue_t queue[], int num);

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
 * Returns previously stored queue context pointer. The context pointer may
 * be set with odp_queue_context_set() or during queue creation
 * (see odp_queue_param_t). The pointer value is set to NULL by default.
 *
 * @param queue    Queue handle
 *
 * @return pointer to the queue context
 * @retval NULL on failure
 *
 * @see odp_queue_context_set(), odp_queue_create()
 */
void *odp_queue_context(odp_queue_t queue);

/**
 * Get a queue handle of an event aggregator associated with a queue
 *
 * Returns a queue handle that can be used to refer to an event aggregator
 * associated with this queue. Unless otherwise noted, the returned queue
 * handle can be used in all contexts where queue handles are used.
 * In particular, the queue handle can be used in odp_queue_enq() to
 * enqueue events through an event aggregator to the underlying queue.
 * Similarly, the queue handle can be given as a destination queue or a
 * completion queues to various ODP APIs (such as packet I/O, classifier,
 * crypto, IPsec) to have the generated events enqueued by ODP through
 * the event aggregator. If event aggregation is not supported by a
 * particular event source, passing an aggregator queue handle has the same
 * effect as passing the handle of the underlying queue, i.e. aggregation
 * does not occur.
 *
 * This function does not create a new queue but merely returns a reference
 * to an aggregator queue which has the same lifetime as the underlying
 * queue. The underlying queue must not be destroyed as long as any of its
 * aggregators is in use. The aggregator queue gets destroyed when the
 * underlying queue gets destroyed. An aggregator queue handle must not
 * be passed to odp_queue_destroy().
 *
 * An aggregator queue has the same enq_mode as the underlying queue.
 *
 * The returned queue handle cannot be used for dequeuing events. It must
 * not be passed to odp_queue_deq() or similar. When an event that has
 * passed through an aggregator is dequeued by the scheduler, the indicated
 * source queue is the underlying queue, not the aggregator queue.
 *
 * Aggregator queues do not have queue contexts. An application must not
 * call odp_queue_context_set() or odp_queue_context().
 *
 * 'aggr_index' refers to the aggregator configured with the same index
 * in odp_queue_param_t::aggr.
 *
 * If 'aggr_index' is greater than odp_queue_param_t::num_aggr,
 * ODP_QUEUE_INVALID is returned.
 *
 * @param queue       Queue handle
 * @param aggr_index  Index of the event aggregator
 *
 * @return event aggregator queue handle
 * @retval ODP_QUEUE_INVALID on failure
 *
 * @see odp_queue_create()
 */
odp_queue_t odp_queue_aggr(odp_queue_t queue, uint32_t aggr_index);

/**
 * Enqueue an event to a queue
 *
 * Enqueues the event into the queue. The caller loses ownership of the event on
 * a successful call. The event is not enqueued on failure, and the caller
 * maintains ownership of it.
 *
 * When successful, this function acts as a release memory barrier between
 * the sender (the calling thread) and the receiver of the event. The receiver
 * sees correctly the memory stores done by the sender before it enqueued
 * the event.
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
 * Like odp_queue_enq(), but enqueues multiple events into the queue. Events are
 * stored into the queue in the order they are in the array. A successful
 * call returns the actual number of events enqueued. If return value is less
 * than 'num', the remaining events at the end of events[] are not enqueued,
 * and the caller maintains ownership of those.
 *
 * @param queue   Queue handle
 * @param events  Array of event handles
 * @param num     Number of events to enqueue
 *
 * @return Number of events actually enqueued (0 ... num)
 * @retval <0 on failure
 */
int odp_queue_enq_multi(odp_queue_t queue, const odp_event_t events[], int num);

/**
 * Dequeue an event from a queue
 *
 * Returns the next event from head of the queue, or ODP_EVENT_INVALID when the
 * queue is empty. Cannot be used for ODP_QUEUE_TYPE_SCHED type queues
 * (use odp_schedule() instead).
 *
 * When successful, this function acts as an acquire memory barrier between
 * the sender and the receiver (the calling thread) of the event. The receiver
 * sees correctly the memory stores done by the sender before it enqueued
 * the event.
 *
 * @param queue   Queue handle
 *
 * @return Event handle
 * @retval ODP_EVENT_INVALID on failure, or when the queue is empty
 */
odp_event_t odp_queue_deq(odp_queue_t queue);

/**
 * Dequeue multiple events from a queue
 *
 * Like odp_queue_deq(), but dequeues multiple events from head of the queue.
 * Cannot be used for ODP_QUEUE_TYPE_SCHED type queues (use odp_schedule_multi()
 * instead). A successful call returns the actual number of events dequeued.
 *
 * @param queue        Queue handle
 * @param[out] events  Array of event handles for output
 * @param num          Maximum number of events to dequeue

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
 * @note The queue must be of type #ODP_QUEUE_TYPE_SCHED
 *
 * @param queue   Queue handle
 *
 * @return Queue schedule synchronization type
 */
odp_schedule_sync_t odp_queue_sched_type(odp_queue_t queue);

/**
 * Queue priority
 *
 * @note The queue must be of type #ODP_QUEUE_TYPE_SCHED
 *
 * @param queue   Queue handle
 *
 * @return Queue schedule priority
 */
odp_schedule_prio_t odp_queue_sched_prio(odp_queue_t queue);

/**
 * Queue group
 *
 * @note The queue must be of type #ODP_QUEUE_TYPE_SCHED
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
 * @note The queue must be of type #ODP_QUEUE_TYPE_SCHED
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
 * Print queue info
 *
 * Print implementation defined information about the specified queue to the ODP
 * log. The information is intended to be used for debugging.
 *
 * @param      queue   Queue handle
 */
void odp_queue_print(odp_queue_t queue);

/**
 * Print debug info about all queues
 *
 * Print implementation defined information about all created queues to the ODP
 * log. The information is intended to be used for debugging.
 */
void odp_queue_print_all(void);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
