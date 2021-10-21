/* Copyright (c) 2013-2018, Linaro Limited
 * Copyright (c) 2019-2021, Nokia
 *
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP timer service
 */

#ifndef ODP_API_SPEC_TIMER_H_
#define ODP_API_SPEC_TIMER_H_
#include <odp/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/timer_types.h>
#include <odp/api/event.h>
#include <odp/api/queue_types.h>
#include <odp/api/pool.h>

/** @addtogroup odp_timer
 *  @{
 */

/**
 * Query timer capabilities per clock source
 *
 * Outputs timer capabilities on success. Returns -1 if the clock source
 * is not supported.
 *
 * @param      clk_src  Clock source for timers
 * @param[out] capa     Pointer to capability structure for output
 *
 * @retval   0 on success
 * @retval  -1 when the clock source is not supported
 * @retval <-1 on other failures
 */
int odp_timer_capability(odp_timer_clk_src_t clk_src, odp_timer_capability_t *capa);

/**
 * Timer resolution capability
 *
 * This function fills in capability limits for timer pool resolution and
 * min/max timeout values, based on either resolution or maximum timeout.
 * Set the required value to a resolution field (res_ns or res_hz) or to the
 * maximum timeout field (max_tmo), and set other fields to zero. A successful
 * call fills in the other fields. The call returns a failure, if the user
 * defined value exceeds capability limits. Outputted values are minimums for
 * 'res_ns' and 'min_tmo', and maximums for 'res_hz' and 'max_tmo'.
 *
 * @param         clk_src  Clock source for timers
 * @param[in,out] res_capa Resolution capability pointer for input/output.
 *                         Set either a resolution or max timeout field,
 *                         a successful call fills in other fields.
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int odp_timer_res_capability(odp_timer_clk_src_t clk_src,
			     odp_timer_res_capability_t *res_capa);

/**
 * Create a timer pool
 *
 * The use of pool name is optional. Unique names are not required.
 *
 * @param name       Name of the timer pool or NULL. Maximum string length is
 *                   ODP_TIMER_POOL_NAME_LEN.
 * @param params     Timer pool parameters. The content will be copied.
 *
 * @return Timer pool handle on success
 * @retval ODP_TIMER_POOL_INVALID on failure and errno set
 */
odp_timer_pool_t odp_timer_pool_create(const char *name,
				       const odp_timer_pool_param_t *params);

/**
 * Start a timer pool
 *
 * Start all created timer pools, enabling the allocation of timers.
 * The purpose of this call is to coordinate the creation of multiple timer
 * pools that may use the same underlying HW resources.
 * This function may be called multiple times.
 */
void odp_timer_pool_start(void);

/**
 * Destroy a timer pool
 *
 * Destroy a timer pool, freeing all resources.
 * All timers must have been freed.
 *
 * @param timer_pool  Timer pool
 */
void odp_timer_pool_destroy(odp_timer_pool_t timer_pool);

/**
 * Convert timer ticks to nanoseconds
 *
 * @param timer_pool  Timer pool
 * @param ticks       Timer ticks
 *
 * @return Nanoseconds
 */
uint64_t odp_timer_tick_to_ns(odp_timer_pool_t timer_pool, uint64_t ticks);

/**
 * Convert nanoseconds to timer ticks
 *
 * @param timer_pool  Timer pool
 * @param ns          Nanoseconds
 *
 * @return Timer ticks
 */
uint64_t odp_timer_ns_to_tick(odp_timer_pool_t timer_pool, uint64_t ns);

/**
 * Current tick value
 *
 * @param timer_pool  Timer pool
 *
 * @return Current time in timer ticks
 */
uint64_t odp_timer_current_tick(odp_timer_pool_t timer_pool);

/**
 * Query timer pool configuration and current state
 *
 * @param      timer_pool  Timer pool
 * @param[out] info        Pointer to information buffer
 *
 * @retval 0 on success
 * @retval <0 on failure. Info could not be retrieved.
 */
int odp_timer_pool_info(odp_timer_pool_t timer_pool,
			odp_timer_pool_info_t *info);

/**
 * Allocate a timer
 *
 * Create a timer (allocating all necessary resources e.g. timeout event) from
 * the timer pool. The user_ptr is copied to timeouts and can be retrieved
 * using the odp_timeout_user_ptr() call.
 *
 * @param timer_pool  Timer pool
 * @param queue       Destination queue for timeout notifications
 * @param user_ptr    User defined pointer or NULL to be copied to timeouts
 *
 * @return Timer handle on success
 * @retval ODP_TIMER_INVALID on failure and errno set.
 */
odp_timer_t odp_timer_alloc(odp_timer_pool_t timer_pool, odp_queue_t queue, const void *user_ptr);

/**
 * Free a timer
 *
 * Free (destroy) a timer, reclaiming associated resources.
 * The timeout event for an active timer will be returned.
 * The timeout event for an expired timer will not be returned. It is the
 * responsibility of the application to handle this timeout when it is received.
 *
 * @param timer      Timer
 *
 * @return Event handle of timeout event
 * @retval ODP_EVENT_INVALID on failure
 */
odp_event_t odp_timer_free(odp_timer_t timer);

/**
 * Set (or reset) a timer with absolute expiration time
 *
 * This function sets a timer to expire at a specific time. If the timer is
 * already running (set and not yet expired), the function updates (resets) it
 * with a new expiration time and optionally with a new event. A successful
 * reset operation with a new event outputs the old event. A failed reset
 * operation does not modify the timer.
 *
 * The user provided event can be of any event type, but only ODP_EVENT_TIMEOUT
 * type events (odp_timeout_t) carry timeout specific metadata. Furthermore,
 * timer performance may have been optimized for that event type. When the timer
 * expires, the event is enqueued to the destination queue of the timer.
 *
 * @param         timer    Timer
 * @param         abs_tick Absolute expiration time in timer ticks
 * @param[in,out] tmo_ev   Pointer to an event handle. The event is enqueued
 *                         when the timer expires. Use NULL when resetting the
 *                         timer without changing the event. When resetting the
 *                         timer with a new event, a successful operation
 *                         outputs the old event here.
 *
 * @retval ODP_TIMER_SUCCESS  Success
 * @retval ODP_TIMER_TOO_NEAR Failure. Expiration time is too near to
 *                            the current time.
 * @retval ODP_TIMER_TOO_FAR  Failure. Expiration time is too far from
 *                            the current time.
 * @retval ODP_TIMER_FAIL     Failure. Set operation: No event provided.
 *                            Reset operation: Too late to reset the timer.
 *
 * @see odp_timer_set_rel(), odp_timer_alloc(), odp_timer_cancel()
 */
int odp_timer_set_abs(odp_timer_t timer, uint64_t abs_tick,
		      odp_event_t *tmo_ev);

/**
 * Set (or reset) a timer with relative expiration time
 *
 * Like odp_timer_set_abs(), but the expiration time is relative to the current
 * time: expiration tick = odp_timer_current_tick() + 'rel_tick'.
 *
 * @param         timer    Timer
 * @param         rel_tick Expiration time relative to current time of
 *                         the timer pool in timer ticks
 * @param[in,out] tmo_ev   Pointer to an event handle. The event is enqueued
 *                         when the timer expires. Use NULL when resetting the
 *                         timer without changing the event. When resetting the
 *                         timer with a new event, a successful operation
 *                         outputs the old event here.
 *
 * @retval ODP_TIMER_SUCCESS  Success
 * @retval ODP_TIMER_TOO_NEAR Failure. Expiration time is too near to
 *                            the current time.
 * @retval ODP_TIMER_TOO_FAR  Failure. Expiration time is too far from
 *                            the current time.
 * @retval ODP_TIMER_FAIL     Failure. Set operation: No event provided.
 *                            Reset operation: Too late to reset the timer.
 *
 * @see odp_timer_set_abs(), odp_timer_alloc(), odp_timer_cancel()
 */
int odp_timer_set_rel(odp_timer_t timer, uint64_t rel_tick,
		      odp_event_t *tmo_ev);

/**
 * Cancel a timer
 *
 * Cancel a timer, preventing future expiration and event delivery. Return any
 * present event.
 *
 * A timer that has already expired may be impossible to cancel and the timeout
 * will instead be delivered to the destination queue.
 *
 * @param      timer  Timer
 * @param[out] tmo_ev Pointer to an event handle for output
 *
 * @retval 0  Success. Active timer cancelled, timeout returned in 'tmo_ev'
 * @retval <0 Failure. Timer inactive or already expired.
 */
int odp_timer_cancel(odp_timer_t timer, odp_event_t *tmo_ev);

/**
 * Get timeout handle from a ODP_EVENT_TIMEOUT type event
 *
 * @param ev An event of type ODP_EVENT_TIMEOUT
 *
 * @return timeout handle
 */
odp_timeout_t odp_timeout_from_event(odp_event_t ev);

/**
 * Convert timeout handle to event handle
 *
 * @param tmo Timeout handle
 *
 * @return Event handle
 */
odp_event_t odp_timeout_to_event(odp_timeout_t tmo);

/**
 * Check for fresh timeout
 *
 * If the corresponding timer has been reset or cancelled since this timeout
 * was enqueued, the timeout is stale (not fresh).
 *
 * @param tmo Timeout handle
 * @retval 1 Timeout is fresh
 * @retval 0 Timeout is stale
 */
int odp_timeout_fresh(odp_timeout_t tmo);

/**
 * Return timer handle for the timeout
 *
 * @param tmo Timeout handle
 *
 * @return Timer handle
 */
odp_timer_t odp_timeout_timer(odp_timeout_t tmo);

/**
 * Timeout expiration tick
 *
 * Returns the absolute expiration time (in timer ticks) that was used to set
 * (or reset) the timer. For timers set with absolute expiration time this
 * equals the provided tick value.
 *
 * @param tmo Timeout handle
 *
 * @return Expiration tick
 */
uint64_t odp_timeout_tick(odp_timeout_t tmo);

/**
 * Return user pointer for the timeout
 *
 * The user pointer was specified when the timer was allocated.
 *
 * @param tmo Timeout handle
 *
 * @return User pointer
 */
void *odp_timeout_user_ptr(odp_timeout_t tmo);

/**
 * Timeout alloc
 *
 * Allocates timeout from pool. Pool must be created with ODP_POOL_TIMEOUT type.
 *
 * @param pool Pool handle
 *
 * @return Timeout handle
 * @retval ODP_TIMEOUT_INVALID  Timeout could not be allocated
 */
odp_timeout_t odp_timeout_alloc(odp_pool_t pool);

/**
 * Timeout free
 *
 * Frees the timeout back to the pool it was allocated from.
 *
 * @param tmo Timeout handle
 */
void odp_timeout_free(odp_timeout_t tmo);

/**
 * Print timer pool debug information
 *
 * Prints implementation specific debug information about
 * the timer pool to the ODP log.
 *
 * @param timer_pool  Timer pool handle
 */
void odp_timer_pool_print(odp_timer_pool_t timer_pool);

/**
 * Print timer debug information
 *
 * Prints implementation specific debug information about
 * the timer to the ODP log.
 *
 * @param timer       Timer handle
 */
void odp_timer_print(odp_timer_t timer);

/**
 * Print timeout debug information
 *
 * Prints implementation specific debug information about
 * the timeout to the ODP log.
 *
 * @param tmo         Timeout handle
 */
void odp_timeout_print(odp_timeout_t tmo);

/**
 * Get printable value for an odp_timer_pool_t
 *
 * @param timer_pool  odp_timer_pool_t handle to be printed
 *
 * @return uint64_t value that can be used to print/display this handle
 *
 * @note This routine is intended to be used for diagnostic purposes
 * to enable applications to generate a printable value that represents
 * an odp_timer_pool_t handle.
 */
uint64_t odp_timer_pool_to_u64(odp_timer_pool_t timer_pool);

/**
 * Get printable value for an odp_timer_t
 *
 * @param timer  odp_timer_t handle to be printed
 *
 * @return uint64_t value that can be used to print/display this handle
 *
 * @note This routine is intended to be used for diagnostic purposes
 * to enable applications to generate a printable value that represents
 * an odp_timer_t handle.
 */
uint64_t odp_timer_to_u64(odp_timer_t timer);

/**
 * Get printable value for an odp_timeout_t
 *
 * @param tmo  odp_timeout_t handle to be printed
 *
 * @return uint64_t value that can be used to print/display this handle
 *
 * @note This routine is intended to be used for diagnostic purposes
 * to enable applications to generate a printable value that represents
 * an odp_timeout_t handle.
 */
uint64_t odp_timeout_to_u64(odp_timeout_t tmo);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
