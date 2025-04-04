/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2013-2018 Linaro Limited
 * Copyright (c) 2024-2025 Nokia
 */

/**
 * @file
 *
 * ODP schedule
 */

#ifndef ODP_API_SPEC_SCHEDULE_H_
#define ODP_API_SPEC_SCHEDULE_H_
#include <odp/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/std_types.h>
#include <odp/api/event_types.h>
#include <odp/api/queue_types.h>
#include <odp/api/schedule_types.h>
#include <odp/api/thrmask.h>

/** @addtogroup odp_scheduler
 *  Event scheduler for work load balancing and prioritization.
 *  @{
 */

/**
 * Schedule wait time
 *
 * Converts nanoseconds to wait values for other schedule functions.
 *
 * @param ns Nanoseconds
 *
 * @return Value for the wait parameter in schedule functions
 */
uint64_t odp_schedule_wait_time(uint64_t ns);

/**
 * Schedule an event
 *
 * Run event scheduler to find the next highest priority event which is
 * available for the calling thread. Only queues that have been created with
 * ODP_QUEUE_TYPE_SCHED type are connected to the scheduler. Optionally,
 * outputs the source queue of the event. If there's no event available, waits
 * for an event according to the wait parameter setting. Returns
 * ODP_EVENT_INVALID if reaches end of the wait period.
 *
 * When returns an event, the thread holds the queue synchronization context
 * (atomic or ordered) until the next schedule call (e.g. odp_schedule() or
 * odp_schedule_multi()). The next call implicitly releases the current context
 * and potentially returns with a new context. User can allow early context
 * release (e.g., see odp_schedule_release_atomic() and
 * odp_schedule_release_ordered()) for performance optimization.
 *
 * When successful, this function acts as an acquire memory barrier between
 * the sender and the receiver (the calling thread) of the event. The receiver
 * sees correctly the memory stores done by the sender before it enqueued
 * the event.
 *
 * When the event was scheduled from an atomic queue, this function acts as
 * an acquire memory barrier between the previous holder of the same atomic
 * synchronization context and the calling thread. When the context is released,
 * a release memory barrier is performed towards the next holder of the context.
 * This ensures that memory stores done when holding an atomic context are
 * correctly visible to other threads that will subsequently hold the same
 * atomic context.
 *
 * @param from    Output parameter for the source queue (where the event was
 *                dequeued from). Ignored if NULL.
 * @param wait    Minimum time to wait for an event. Waits indefinitely if set
 *                to ODP_SCHED_WAIT. Does not wait if set to ODP_SCHED_NO_WAIT.
 *                Use odp_schedule_wait_time() to convert time to other wait
 *                values.
 *
 * @return Next highest priority event
 * @retval ODP_EVENT_INVALID on timeout and no events available
 *
 * @see odp_schedule_multi(), odp_schedule_release_atomic(),
 * odp_schedule_release_ordered()
 */
odp_event_t odp_schedule(odp_queue_t *from, uint64_t wait);

/**
 * Schedule multiple events
 *
 * Like odp_schedule(), but returns multiple events from a queue. The caller
 * specifies the maximum number of events it is willing to accept. The
 * scheduler is under no obligation to return more than a single event but
 * will never return more than the number specified by the caller. The return
 * code specifies the number of events returned and all of these events always
 * originate from the same source queue and share the same scheduler
 * synchronization context.
 *
 * @param from    Output parameter for the source queue (where the event was
 *                dequeued from). Ignored if NULL.
 * @param wait    Minimum time to wait for an event. Waits infinitely, if set to
 *                ODP_SCHED_WAIT. Does not wait, if set to ODP_SCHED_NO_WAIT.
 *                Use odp_schedule_wait_time() to convert time to other wait
 *                values.
 * @param events  Event array for output
 * @param num     Maximum number of events to output
 *
 * @return Number of events outputted (0 ... num)
 */
int odp_schedule_multi(odp_queue_t *from, uint64_t wait, odp_event_t events[],
		       int num);

/**
 * Schedule, wait for events
 *
 * Like odp_schedule_multi(), but waits infinitely for events.
 *
 * @param[out] from    Output parameter for the source queue (where the event
 *                     was dequeued from). Ignored if NULL.
 * @param[out] events  Event array for output
 * @param      num     Maximum number of events to output
 *
 * @return Number of events outputted (1 ... num)
 */
int odp_schedule_multi_wait(odp_queue_t *from, odp_event_t events[], int num);

/**
 * Schedule, do not wait for events
 *
 * Like odp_schedule_multi(), but does not wait for events.
 *
 * @param[out] from    Output parameter for the source queue (where the event
 *                     was dequeued from). Ignored if NULL.
 * @param[out] events  Event array for output
 * @param      num     Maximum number of events to output
 *
 * @return Number of events outputted (0 ... num)
 */
int odp_schedule_multi_no_wait(odp_queue_t *from, odp_event_t events[],
			       int num);

/**
 * Pause scheduling
 *
 * Pause global scheduling for this thread. After this call, only
 * ODP_SCHED_NO_WAIT schedule calls are allowed and these calls will return only
 * locally pre-scheduled events (if any). User can exit the schedule loop only
 * after the schedule function indicates that there's no more (pre-scheduled)
 * events.
 *
 * Example call pattern:
 *
 * while (!stop) {
 *     odp_event_t ev = odp_schedule(NULL, ODP_SCHED_WAIT);
 *     // Process event
 * }
 *
 * odp_schedule_pause();
 *
 * while (1) {
 *     odp_event_t ev = odp_schedule(NULL, ODP_SCHED_NO_WAIT);
 *     if (ev == ODP_EVENT_INVALID)
 *         break;
 *     odp_event_free(ev);
 * }
 */
void odp_schedule_pause(void);

/**
 * Resume scheduling
 *
 * Resume global scheduling for this thread. After this call, all schedule calls
 * will schedule normally (perform global scheduling).
 */
void odp_schedule_resume(void);

/**
 * Release the current atomic context
 *
 * This call is valid only for source queues with atomic synchronization. It
 * hints the scheduler that the user has completed critical section processing
 * in the current atomic context. The scheduler is now allowed to schedule
 * events from the same queue to another thread. However, the context may be
 * still held until the next odp_schedule() or odp_schedule_multi() call - this
 * call allows but does not force the scheduler to release the context early.
 *
 * Early atomic context release may increase parallelism and thus system
 * performance, but user needs to design carefully the split into critical vs.
 * non-critical sections.
 */
void odp_schedule_release_atomic(void);

/**
 * Release the current ordered context
 *
 * This call is valid only for source queues with ordered synchronization. It
 * hints the scheduler that the user has done all enqueues that need to maintain
 * event order in the current ordered context. The scheduler is allowed to
 * release the ordered context of this thread and avoid reordering any following
 * enqueues. However, the context may be still held until the next
 * odp_schedule() or odp_schedule_multi() call - this call allows but does not
 * force the scheduler to release the context early.
 *
 * Early ordered context release may increase parallelism and thus system
 * performance, since scheduler may start reordering events sooner than the next
 * schedule call.
 */
void odp_schedule_release_ordered(void);

/**
 * Prefetch events for next schedule call
 *
 * Hint the scheduler that application is about to finish processing the current
 * event(s) and will soon request more events. The scheduling context status is
 * not affect. The call does not guarantee that the next schedule call will
 * return any number of events. It may improve system performance, since the
 * scheduler may prefetch the next (batch of) event(s) in parallel to
 * application processing the current event(s).
 *
 * @param num     Number of events to prefetch
 */
void odp_schedule_prefetch(int num);

/**
 * Maximum scheduling priority level
 *
 * This is the global maximum value that can be set to 'prio' field in
 * odp_schedule_param_t (e.g. odp_queue_create()). Configured based on
 * odp_schedule_config_t::prio. Queues with a higher priority value are
 * served with higher priority than queues with a lower priority value.
 *
 * Schedule group specific maximum priority (see
 * odp_schedule_group_param_t::prio) can be queried with
 * odp_schedule_group_max_prio().
 *
 * @return Maximum scheduling priority level
 */
int odp_schedule_max_prio(void);

/**
 * Minimum scheduling priority level
 *
 * This is the global minimum value that can be set to 'prio' field in
 * odp_schedule_param_t (e.g. odp_queue_create()). Configured based on
 * odp_schedule_config_t::prio. Queues with a higher priority value are
 * served with higher priority than queues with a lower priority value.
 *
 * Schedule group specific minimum priority (see
 * odp_schedule_group_param_t::prio) can be queried with
 * odp_schedule_group_min_prio().
 *
 * @return Minimum scheduling priority level
 */
int odp_schedule_min_prio(void);

/**
 * Default scheduling priority level
 *
 * This is the global default value of 'prio' field in odp_schedule_param_t
 * (e.g. odp_queue_param_init()). Configured based on
 * odp_schedule_config_t::prio. The default value should be suitable for
 * an application that uses single priority level for all its queues (uses
 * scheduler only for load balancing and synchronization). Typically,
 * the default value is between minimum and maximum values, but with a few
 * priority levels it may be close or equal to those.
 *
 * Schedule group specific default priority (see
 * odp_schedule_group_param_t::prio) can be queried with
 * odp_schedule_group_default_prio().
 *
 * @return Default scheduling priority level
 */
int odp_schedule_default_prio(void);

/**
 * Number of scheduling priorities
 *
 * The number of global priority levels support by the scheduler. It equals to
 * odp_schedule_max_prio() - odp_schedule_min_prio() + 1. Configured based on
 * odp_schedule_config_t::prio.
 *
 * Schedule group specific priority count (see
 * odp_schedule_group_param_t::prio) can be queried with
 * odp_schedule_group_num_prio().
 *
 * @return Number of scheduling priorities
 */
int odp_schedule_num_prio(void);

/**
 * Maximum schedule group specific priority level
 *
 * Similar to odp_schedule_max_prio(), but returns group specific maximum
 * priority level.
 *
 * @param group  Schedule group handle
 *
 * @return Maximum schedule group specific priority level
 * @retval <0 on failure
 */
int odp_schedule_group_max_prio(odp_schedule_group_t group);

/**
 * Minimum schedule group specific priority level
 *
 * Similar to odp_schedule_min_prio(), but returns group specific minimum
 * priority level.
 *
 * @param group  Schedule group handle
 *
 * @return Minimum schedule group specific priority level
 * @retval <0 on failure
 */
int odp_schedule_group_min_prio(odp_schedule_group_t group);

/**
 * Default schedule group specific priority level
 *
 * Similar to odp_schedule_default_prio(), but returns group specific default
 * priority level.
 *
 * @param group  Schedule group handle
 *
 * @return Default schedule group specific priority level
 * @retval <0 on failure
 */
int odp_schedule_group_default_prio(odp_schedule_group_t group);

/**
 * Number of schedule group specific priorities
 *
 * Similar to odp_schedule_num_prio(), but returns group specific number of
 * priority levels.
 *
 * @param group  Schedule group handle
 *
 * @return Number of schedule group specific priorities
 * @retval <0 on failure
 */
int odp_schedule_group_num_prio(odp_schedule_group_t group);

/**
 * Initialize schedule configuration options
 *
 * Initialize an odp_schedule_config_t to its default values.
 *
 * @param[out] config  Pointer to schedule configuration structure
 */
void odp_schedule_config_init(odp_schedule_config_t *config);

/**
 * Global schedule configuration
 *
 * Initialize and configure scheduler with global configuration options
 * to schedule events across different scheduled queues.
 * This function must be called only once and before scheduler is used
 * (any other scheduler function is called except odp_schedule_capability() and
 * odp_schedule_config_init()) or any queues are created (by application itself
 * or by other ODP modules).
 * An application can pass NULL value to use default configuration. It will
 * have the same result as filling the structure with
 * odp_schedule_config_init() and then passing it to odp_schedule_config().
 *
 * The initialization sequence should be:
 *   * odp_schedule_capability()
 *   * odp_schedule_config_init()
 *   * odp_schedule_config()
 *   * odp_schedule()
 *
 * @param config   Pointer to scheduler configuration structure or NULL for the
 *                 default configuration
 *
 * @retval 0 on success
 * @retval <0 on failure
 *
 * @see odp_schedule_capability(), odp_schedule_config_init()
 */
int odp_schedule_config(const odp_schedule_config_t *config);

/**
 * Query scheduler capabilities
 *
 * Outputs schedule capabilities on success.
 *
 * @param[out] capa   Pointer to capability structure for output
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int odp_schedule_capability(odp_schedule_capability_t *capa);

/**
 * Schedule group create
 *
 * Creates a schedule group with the thread mask. Only threads in the
 * mask will receive events from a queue that belongs to the schedule group.
 * Thread masks of various schedule groups may overlap. There are predefined
 * groups, such as ODP_SCHED_GROUP_ALL and ODP_SCHED_GROUP_WORKER, which are
 * present by default and are automatically updated. The use of group name is
 * optional. Unique names are not required. However, odp_schedule_group_lookup()
 * returns only a single matching group.
 *
 * @param name    Name of the schedule group or NULL. Maximum string length is
 *                ODP_SCHED_GROUP_NAME_LEN, including the null character.
 * @param mask    Thread mask
 *
 * @return Schedule group handle
 * @retval ODP_SCHED_GROUP_INVALID on failure
 *
 * @see ODP_SCHED_GROUP_ALL, ODP_SCHED_GROUP_WORKER
 */
odp_schedule_group_t odp_schedule_group_create(const char *name,
					       const odp_thrmask_t *mask);
/**
 * Initialize schedule group parameters
 *
 * Initialize an odp_schedule_group_param_t to its default values.
 *
 * @param[out] param  Pointer to parameter structure
 */
void odp_schedule_group_param_init(odp_schedule_group_param_t *param);

/**
 * Schedule group create with parameters
 *
 * Otherwise like odp_schedule_group_create() but additionally accepts a set of
 * parameters.
 *
 * @param name    Name of the schedule group or NULL. Maximum string length is
 *                ODP_SCHED_GROUP_NAME_LEN, including the null character.
 * @param mask    Thread mask
 * @param param   Schedule group parameters
 *
 * @return Schedule group handle
 * @retval ODP_SCHED_GROUP_INVALID on failure
 *
 * @see odp_schedule_group_create()
 */
odp_schedule_group_t odp_schedule_group_create_2(const char *name,
						 const odp_thrmask_t *mask,
						 const odp_schedule_group_param_t *param);

/**
 * Schedule group destroy
 *
 * Destroys a schedule group. All queues belonging to the schedule group must
 * be destroyed before destroying the group. Other operations on this group
 * must not be invoked in parallel.
 *
 * @param group   Schedule group handle
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int odp_schedule_group_destroy(odp_schedule_group_t group);

/**
 * Look up a schedule group by name
 *
 * @param name   Name of schedule group
 *
 * @return Handle of the first matching schedule group
 * @retval ODP_SCHED_GROUP_INVALID No matching schedule group found
 */
odp_schedule_group_t odp_schedule_group_lookup(const char *name);

/**
 * Join a schedule group
 *
 * Join a threadmask to an existing schedule group
 *
 * @param group  Schedule group handle
 * @param mask   Thread mask
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int odp_schedule_group_join(odp_schedule_group_t group,
			    const odp_thrmask_t *mask);

/**
 * Leave a schedule group
 *
 * Remove a threadmask from an existing schedule group
 *
 * @param group  Schedule group handle
 * @param mask   Thread mask
 *
 * @retval 0 on success
 * @retval <0 on failure
 *
 * @note Leaving a schedule group means threads in the specified mask will no
 * longer receive events from queues belonging to the specified schedule
 * group. This effect is not instantaneous, however, and events that have been
 * prestaged may still be presented to the masked threads.
 */
int odp_schedule_group_leave(odp_schedule_group_t group,
			     const odp_thrmask_t *mask);

/**
 * Get a schedule group's thrmask
 *
 * @param      group   Schedule group handle
 * @param[out] thrmask The current thrmask used for this schedule group
 *
 * @retval 0  On success
 * @retval <0 Invalid group specified
 */
int odp_schedule_group_thrmask(odp_schedule_group_t group,
			       odp_thrmask_t *thrmask);

/**
 * Retrieve information about a schedule group
 *
 * Fills in schedule group information structure with current values.
 * The call is not synchronized with calls modifying the schedule group. So,
 * the application should ensure that it does not simultaneously modify and
 * retrieve information about the same group with this call. The call is not
 * intended for fast path use. The info structure is written only on success.
 *
 * @param      group   Schedule group handle
 * @param[out] info    Pointer to schedule group info struct for output
 *
 * @retval  0 On success
 * @retval <0 On failure
 */
int odp_schedule_group_info(odp_schedule_group_t group,
			    odp_schedule_group_info_t *info);

/**
 * Get printable value for schedule group handle
 *
 * @param group        Handle to be converted for debugging
 *
 * @return uint64_t value that can be used to print/display this handle
 */
uint64_t odp_schedule_group_to_u64(odp_schedule_group_t group);

/**
 * Acquire ordered context lock
 *
 * This call is valid only when holding an ordered synchronization context.
 * Ordered locks are used to protect critical sections that are executed
 * within an ordered context. Threads enter the critical section in the order
 * determined by the context (source queue). Lock ordering is automatically
 * skipped for threads that release the context instead of using the lock.
 *
 * The number of ordered locks available is set by the lock_count parameter of
 * the schedule parameters passed to odp_queue_create(), which must be less
 * than or equal to queue capability 'max_ordered_locks'. If this routine is
 * called outside of an ordered context or with a lock_index that exceeds the
 * number of available ordered locks in this context results are undefined.
 * The number of ordered locks associated with a given ordered queue may be
 * queried by the odp_queue_lock_count() API.
 *
 * Each ordered lock may be used only once per ordered context. If events
 * are to be processed with multiple ordered critical sections, each should
 * be protected by its own ordered lock. This promotes maximum parallelism by
 * allowing order to maintained on a more granular basis. If an ordered lock
 * is used multiple times in the same ordered context results are undefined.
 * Only one ordered lock can be active in an ordered context at any given time.
 * Results are undefined when multiple ordered locks are acquired in nested
 * fashion within the same ordered context.
 *
 * @param lock_index Index of the ordered lock in the current context to be
 *                   acquired. Must be in the range 0..odp_queue_lock_count()
 *                   - 1
 */
void odp_schedule_order_lock(uint32_t lock_index);

/**
 * Release ordered context lock
 *
 * This call is valid only when holding an ordered synchronization context.
 * Release a previously locked ordered context lock.
 *
 * @param lock_index Index of the ordered lock in the current context to be
 *                   released. Results are undefined if the caller does not
 *                   hold this lock. Must be in the range
 *                   0..odp_queue_lock_count() - 1
 */
void odp_schedule_order_unlock(uint32_t lock_index);

/**
 * Release existing ordered context lock and acquire a new lock
 *
 * This call is valid only when holding an ordered synchronization context.
 * Release a previously locked ordered context lock and acquire a new ordered
 * context lock. The operation is equivalent to application calling first
 * odp_schedule_order_unlock(unlock_index) and then
 * odp_schedule_order_lock(lock_index). The same constraints apply with this
 * call as with those two.
 *
 * @param unlock_index	Index of the acquired ordered lock in the current
 *			context to be released.
 * @param lock_index	Index of the ordered lock in the current context to be
 *			acquired. Must be in the range
 *			0...odp_queue_lock_count() - 1.
 *
 * @see odp_schedule_order_lock(), odp_schedule_order_unlock()
 *
 */
void odp_schedule_order_unlock_lock(uint32_t unlock_index, uint32_t lock_index);

/** Asynchronous ordered context lock
 * Request an ordered context lock to be acquired. Starts an ordered context
 * lock acquire operation, but does not wait until the lock has been acquired.
 * Application can use this call to potentially interleave some processing
 * within waiting for this lock. Each start lock call must be paired with a wait
 * call that blocks until the lock has been acquired. Locks cannot be acquired
 * in nested fashion i.e each start call must follow a paring wait and unlock
 * calls, before using another lock.
 * The same constraints apply as with odp_schedule_order_lock()
 *
 * @param lock_index	Index of the ordered lock in the current context to
 *			start acquire operation.
 *			Must be in the range 0..odp_queue_lock_count() - 1.
 *
 */
void odp_schedule_order_lock_start(uint32_t lock_index);

/** Asynchronous ordered context lock wait
 * Wait for a previously started lock acquire operation to finish.
 * Lock index must match with the previous start call. Ordered lock acquisition
 * will be completed during this call.
 *
 * @param lock_index	Index of the ordered lock in the current context to
 *			complete acquire operation.
 *			Must be in the range 0..odp_queue_lock_count() - 1.
 */
void odp_schedule_order_lock_wait(uint32_t lock_index);

/**
 * Wait until the currently held scheduling context is the first in order
 *
 * Wait until there are no other scheduling contexts that precede the
 * scheduling context of the calling thread in the source queue order.
 * The context remains the first in order until the thread releases it.
 *
 * This function must not be called if the current thread is not holding
 * an ordered scheduling context or if an ordered lock is being held.
 *
 * This functions does nothing if ordered wait is not supported.
 *
 * @see odp_schedule_capability()
 */
void odp_schedule_order_wait(void);

/**
 * Print debug info about scheduler
 *
 * Print implementation defined information about scheduler to the ODP log.
 * The information is intended to be used for debugging.
 */
void odp_schedule_print(void);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
