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

#include <odp/api/event.h>
#include <odp/api/spec/queue_types.h>

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
