/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2013-2018 Linaro Limited
 * Copyright (c) 2019-2026 Nokia
 */

/**
 * @file
 *
 * ODP timer service
 */

#ifndef ODP_API_SPEC_TIMER_H_
#define ODP_API_SPEC_TIMER_H_
#include <odp/visibility_begin.h>

#include <odp/api/timer_types.h>
#include <odp/api/event_types.h>
#include <odp/api/pool_types.h>
#include <odp/api/queue_types.h>

#ifdef __cplusplus
extern "C" {
#endif

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
 * Periodic timer capability
 *
 * Checks periodic timer capability to support the requested base frequency and other parameters.
 * Application sets 'capa' with the requested timer pool base frequency, the maximum
 * frequency multiplier and the minimum timeout resolution. If there is no requirement for timeout
 * resolution, it is set to zero.
 *
 * When the call returns success, 'capa' fields are overwritten in following ways. On return value
 * of 1, timer supports the requested base frequency exactly, and meets or exceeds other requested
 * values. The base frequency value is not modified, but other 'capa' fields are updated with
 * resulting maximum capabilities.
 *
 * When the call returns 0, the requested base frequency is not supported exactly, but timer
 * capabilities meet or exceed all other requested values. In this case, the call overwrites
 * 'base_freq_hz' with the closest supported frequency and updates other 'capa' fields accordingly.
 *
 * Failure is returned when the requirements are not supported or the call fails otherwise.
 *
 * @param         clk_src    Clock source for timer pool
 * @param[in,out] capa       Pointer to periodic timer capability for input/output.
 *
 * @retval 1   Success. Capability matches base frequency, and meets or exceeds other requested
 *             values.
 * @retval 0   Success. Capability does not match base frequency exactly, but meets or exceeds
 *             other requested values.
 * @retval <0  Failure
 */
int odp_timer_periodic_capability(odp_timer_clk_src_t clk_src,
				  odp_timer_periodic_capability_t *capa);

/**
 * Initialize timer pool parameters
 *
 * Initialize an odp_timer_pool_param_t to its default values for all fields.
 *
 * @param[out] param  Pointer to the odp_timer_pool_param_t structure to be initialized
 */
void odp_timer_pool_param_init(odp_timer_pool_param_t *param);

/**
 * Create a timer pool
 *
 * Creates a timer pool according to the parameters. Use 'timer_type' parameter to select if timers
 * are single shot or periodic. All timers in the pool are of the same type. The selected timer
 * type defines which other parameters are used or ignored.
 *
 * The use of pool name is optional. Unique names are not required. Use odp_timer_pool_param_init()
 * to initialize timer pool parameters into their default values.
 *
 * After creation a timer pool can be either started (see odp_timer_pool_start_multi()) or
 * destroyed. The returned pool handle cannot be used with any other APIs, except
 * odp_timer_pool_to_u64(), before the pool is successfully started.
 *
 * Periodic timer expiration frequency is a multiple of the timer pool base frequency
 * (odp_timer_pool_param_t::periodic::base_freq_hz). Depending on implementation, the base
 * frequency may need to be selected carefully with respect to the timer pool source clock
 * frequency. Use odp_timer_periodic_capability() to check which base frequencies and multipliers
 * are supported. Additionally with periodic timers, an ODP_EVENT_TIMEOUT pool is created as part
 * of timer pool creation from which events for periodic timeouts are allocated from. The
 * to-be-created timeout pool may decrease the number of event pools that can be subsequently
 * created by application. Application can configure user area size for the event pool with
 * odp_timer_pool_param_t::periodic::uarea_size and later initialize user areas of timeout events
 * associated with a specific timer during timer allocation with
 * odp_timer_periodic_param_t::uarea_init::init_fn.
 *
 * The call returns failure when requested parameter values are not supported.
 *
 * @param name       Name of the timer pool or NULL. Maximum string length is
 *                   ODP_TIMER_POOL_NAME_LEN, including the null character.
 * @param params     Timer pool parameters. The content will be copied.
 *
 * @return Timer pool handle on success
 * @retval ODP_TIMER_POOL_INVALID on failure
 */
odp_timer_pool_t odp_timer_pool_create(const char *name, const odp_timer_pool_param_t *params);

/**
 * Start timer pools
 *
 * Start given timer pools. After a pool has been successfully started the pool handle can be used
 * with other APIs. Each timer pool can be started only once.
 *
 * Returns 'num' when all given timer pools have been successfully started. If the return value
 * N < 'num', only the first N pools started successfully and at least some of the remaining ones
 * failed to start. In case of a negative return value, none of the pools were started. The
 * unstarted timer pools cannot be used anymore (can only be destroyed).
 *
 * @param timer_pool  Array of timer pool handles
 * @param num         Number of pools to start
 *
 * @retval  num on success
 * @retval <num on failure
 */
int odp_timer_pool_start_multi(odp_timer_pool_t timer_pool[], int num);

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
 * Returns the current tick value of the timer pool. Timer tick is an implementation defined unit
 * of time. Ticks and related nanosecond values are timer pool specific. Those may not start from
 * zero, but are guaranteed not to wrap around in at least 10 years from the ODP instance startup.
 *
 * Timer tick value increments with a constant, timer pool specific frequency. Tick frequency may
 * be equal or higher than the requested timer pool resolution. The frequency can be checked with
 * odp_timer_pool_info(). Tick value increments with implementation specific step sizes.
 *
 * Use odp_timer_sample_ticks() to determine offset between tick values of two or more timer pools.
 *
 * @param timer_pool  Timer pool
 *
 * @return Current time in timer ticks
 *
 * @see odp_timer_tick_info_t
 */
uint64_t odp_timer_current_tick(odp_timer_pool_t timer_pool);

/**
 * Sample tick values of timer pools
 *
 * Reads timer pool tick values simultaneously (or closely back-to-back) from all requested timer
 * pools, and outputs those on success. Optionally, outputs corresponding source clock (HW) counter
 * values, which are implementation specific and may be used for debugging. When a timer pool does
 * not support reading of the source clock value, zero is written instead. Values are written into
 * the output arrays in the same order which timer pools were defined. Nothing is written on
 * failure.
 *
 * @param      timer_pool  Timer pools to sample
 * @param[out] tick        Tick value array for output (one element per timer pool)
 * @param[out] clk_count   Source clock counter value array for output (one element per
 *                         timer pool), or NULL when counter values are not requested.
 * @param      num         Number of timer pools to sample
 *
 * @retval  0 All requested timer pools sampled successfully
 * @retval -1 Failure
 */
int odp_timer_sample_ticks(odp_timer_pool_t timer_pool[], uint64_t tick[], uint64_t clk_count[],
			   int num);

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
 * Allocate a single shot timer
 *
 * Allocates a single shot timer from the timer pool. The pool must have been created with
 * ODP_TIMER_TYPE_SINGLE type. The allocated timer is started with odp_timer_start() call. A timer
 * may be reused multiple times before freeing it back into the timer pool.
 *
 * When timer expires, a timeout event, configured with odp_timer_start_t::tmo_ev, is sent into the
 * provided destination queue.
 *
 * The provided user pointer value is copied into timeout events when the event type is
 * ODP_EVENT_TIMEOUT. The value can be retrieved from an event with odp_timeout_user_ptr() call.
 *
 * @param timer_pool  Timer pool
 * @param queue       Destination queue for timeout events
 * @param user_ptr    User defined pointer value or NULL
 *
 * @return Timer handle on success
 * @retval ODP_TIMER_INVALID on failure
 */
odp_timer_t odp_timer_alloc(odp_timer_pool_t timer_pool, odp_queue_t queue, const void *user_ptr);

/**
 * Free a timer
 *
 * Frees a previously allocated timer. The timer must be inactive when calling this function.
 * In other words, the application must cancel an active single shot timer (odp_timer_cancel())
 * successfully or wait it to expire before freeing it. Similarly for an active periodic timer, the
 * application must cancel it (odp_timer_periodic_cancel()) and acknowledge all events delivered by
 * the timer (odp_timer_periodic_ack()) before freeing it.
 *
 * The call returns failure only on non-recoverable errors. Application must not use the timer
 * handle anymore after the call, regardless of the return value.
 *
 * @param timer       Timer
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int odp_timer_free(odp_timer_t timer);

/**
 * Start a single shot timer
 *
 * Starts a single shot timer with an expiration time and a timeout event. The timer must not be
 * active when calling this function. After a successful call, the timer remains active until it
 * expires or is cancelled successfully. An active timer can be restarted with odp_timer_restart().
 *
 * The timeout event is sent to the destination queue when the timer expires. The expiration time
 * may be passed as absolute timer ticks or ticks relative to the current time. Use 'tick_type'
 * parameter to select between the tick types. Current time of the timer pool can be read with
 * odp_timer_current_tick().
 *
 * The timer is not started when a failure is returned.
 *
 * @param timer               Timer to be started
 * @param start_param         Timer start parameters
 *
 * @retval ODP_TIMER_SUCCESS  Success
 * @retval ODP_TIMER_TOO_NEAR Failure. The expiration time passed already, or is too near to
 *                            the current time.
 * @retval ODP_TIMER_TOO_FAR  Failure. The expiration time is too far from the current time.
 * @retval ODP_TIMER_FAIL     Other failure.
 */
int odp_timer_start(odp_timer_t timer, const odp_timer_start_t *start_param);

/**
 * Restart a single shot timer
 *
 * A successful restart call updates the expiration time of an active single shot timer. The
 * timeout event is not changed.
 *
 * The timer is not modified when a failure is returned. The call returns #ODP_TIMER_FAIL if
 * the timer has expired already, or is so close to expire that it cannot be restarted anymore.
 * A failure is returned also when the new expiration time is too near to the current time
 * (#ODP_TIMER_TOO_NEAR) or too far from the current time (#ODP_TIMER_TOO_FAR).
 *
 * The new expiration time is passed the same way as with odp_timer_start() call.
 *
 * @param timer               Timer to be restarted
 * @param start_param         Timer start parameters. Value of 'tmo_ev' parameter is ignored.
 *
 * @retval ODP_TIMER_SUCCESS  Success
 * @retval ODP_TIMER_TOO_NEAR Failure. The new expiration time passed already, or is too near to
 *                            the current time.
 * @retval ODP_TIMER_TOO_FAR  Failure. The new expiration time is too far from the current time.
 * @retval ODP_TIMER_FAIL     Failure. The timer expired already, or other failure.
 */
int odp_timer_restart(odp_timer_t timer, const odp_timer_start_t *start_param);

/**
 * Initialize periodic timer parameters
 *
 * Initialize an odp_timer_periodic_param_t to its default values for all fields.
 *
 * @param[out] param  Pointer to the odp_timer_periodic_param_t structure to be initialized
 */
void odp_timer_periodic_param_init(odp_timer_periodic_param_t *param);

/**
 * Allocate a periodic timer
 *
 * Allocates a periodic timer from the timer pool according to the parameters. The pool must have
 * been created with ODP_TIMER_TYPE_PERIODIC type. The allocated timer is started with
 * odp_timer_periodic_start() call. A timer may be reused multiple times before freeing it back
 * into the timer pool.
 *
 * @param timer_pool Timer pool
 * @param params     Timer parameters
 *
 * @return Timer handle on success
 * @retval ODP_TIMER_INVALID on failure
 */
odp_timer_t odp_timer_periodic_alloc(odp_timer_pool_t timer_pool,
				     const odp_timer_periodic_param_t *params);

/**
 * Start a periodic timer
 *
 * Starts a periodic timer. Timeout events are delivered periodically to the destination queue
 * starting from the first expiration time provided. The timeout events are from the timeout pool
 * created during periodic timer pool creation. Depending on the implementation, each delivered
 * event may be a unique event or a single event delivered multiple times (meaning the same event
 * may appear in a destination queue multiple times if application falls behind) or something in
 * between. The timer must not be active when calling this function. After a successful call, the
 * timer remains active until it is cancelled and all its timeout events have been acknowledged.
 *
 * Timer period cannot be changed after timer allocation. If period requires a change, the current
 * timer is cancelled (and freed), and a new timer is allocated and started with new parameters.
 *
 * Received events must not be freed by the application and each received event must be
 * acknowledged with odp_timer_periodic_ack(). Attached data (e.g. odp_timeout_user_ptr() and
 * odp_timeout_user_area()) may be accessed once received until event acknowledgment. Ensuring
 * thread-safe modifications of the data is up to the application.
 *
 * The timer is not started when a failure is returned.
 *
 * @param timer               Periodic timer to be started
 * @param start_param         Periodic timer start parameters
 *
 * @retval ODP_TIMER_SUCCESS  Success
 * @retval ODP_TIMER_TOO_NEAR Failure. The first expiration time passed already, or is too near to
 *                            the current time.
 * @retval ODP_TIMER_TOO_FAR  Failure. The first expiration time is too far from the current time.
 * @retval ODP_TIMER_FAIL     Other failure.
 *
 * @see odp_timer_periodic_cancel()
 */
int odp_timer_periodic_start(odp_timer_t timer, const odp_timer_periodic_start_t *start_param);

/**
 * Acknowledge timeout from a periodic timer
 *
 * This call is valid only for periodic timers. Each time a periodic timeout is received, it must
 * be acknowledged with this call. Acknowledgment should be done as soon as possible after
 * receiving the event. A late call may affect accuracy of the following period(s). However, a
 * missing acknowledgment may not stop timeout event delivery to the destination queue, potentially
 * filling it up if application falls behind. The events may be acknowledged in any order or in
 * parallel by multiple threads. Attached data (e.g. odp_timeout_user_ptr() and
 * odp_timeout_user_area()) of received timeout events is accessible until acknowledgment. Once
 * acknowledged, a timeout event must not be used or its data accessed by application.
 *
 * Normally, the acknowledgment call returns zero on success. After cancellation, the timer
 * delivers any remaining event(s) (always at least one, may not arrive at the requested interval)
 * to the destination queue. Acknowledgment call continues to return zero on success until last
 * event delivered by the timer, return value of 1 marks the last delivered event. After
 * application has acknowledged it and all other events from the timer, it can free or start the
 * timer again.
 *
 * Note that when a multi-threaded application uses a plain or scheduled parallel/ordered queue as
 * a timer destination queue, one of the threads may receive the last timeout event before the
 * other threads receive preceding timeout events from the timer. Also in this case, the
 * application must ensure that it acknowledges all the events before freeing or starting the
 * timer.
 *
 * Timeout events associated with a periodic timer can be distinguished with
 * odp_timeout_is_periodic().
 *
 * @param timer    Periodic timer
 * @param tmo_ev   Timeout event that was received from the periodic timer
 *
 * @retval 1  Success, the last event delivered by a cancelled timer.
 * @retval 0  Success.
 * @retval <0 Failure.
 */
int odp_timer_periodic_ack(odp_timer_t timer, odp_event_t tmo_ev);

/**
 * Cancel a periodic timer
 *
 * Cancel a previously started periodic timer. A successful operation stops timer expiration.
 * The timer delivers remaining timeout event(s) into the destination queue. Note that there is
 * always at least one event delivered and that the event(s) may not arrive at the requested
 * interval. Return value of odp_timer_periodic_ack() call will indicate the last timeout event
 * delivered by the timer.
 *
 * @param      timer  Timer
 *
 * @retval 0  Periodic timer expiration stopped. Remaining timeout events will be received through
 *            the destination queue.
 * @retval <0 Timer cancel failed.
 */
int odp_timer_periodic_cancel(odp_timer_t timer);

/**
 * Cancel a single shot timer
 *
 * Cancels a previously started single shot timer. A successful operation (#ODP_TIMER_SUCCESS)
 * prevents timer expiration and returns the timeout event back to application. Application may
 * use or free the event normally.
 *
 * When the timer is close to expire or has expired already, the call may not be able cancel it
 * anymore. In this case, the call returns #ODP_TIMER_TOO_NEAR and the timeout is delivered to
 * the destination queue.
 *
 * @param      timer  Timer
 * @param[out] tmo_ev Pointer to an event handle for output. Event handle is written only
 *                    on success.
 *
 * @retval ODP_TIMER_SUCCESS  Timer was cancelled successfully. Timeout event returned in 'tmo_ev'.
 * @retval ODP_TIMER_TOO_NEAR Timer cannot be cancelled. Timer has expired already, or cannot be
 *                            cancelled due to close expiration time.
 * @retval ODP_TIMER_FAIL     Other failure.
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
 * Convert multiple timeout events to timeout handles
 *
 * All events must be of type ODP_EVENT_TIMEOUT.
 *
 * @param[out] tmo  Timeout handle array for output
 * @param      ev   Array of event handles to convert
 * @param      num  Number of timeouts and events
 */
void odp_timeout_from_event_multi(odp_timeout_t tmo[], const odp_event_t ev[], int num);

/**
 * Convert timeout handle to event handle
 *
 * @param tmo Timeout handle
 *
 * @return Event handle
 */
odp_event_t odp_timeout_to_event(odp_timeout_t tmo);

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
 * For periodic timers, returns the expiration time of the period, or zero.
 * When periodic timer implementation cannot return expiration time, it returns zero
 * for all timeouts from the timer pool.
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
 * Timeout user area
 *
 * Returns pointer to the user area associated with the timeout. Size of the area is fixed
 * and defined in timeout pool parameters.
 *
 * @param tmo    Timeout handle
 *
 * @return       Pointer to the user area of the timeout
 * @retval NULL  The timeout does not have user area
 */
void *odp_timeout_user_area(odp_timeout_t tmo);

/**
 * Check if timeout is from a periodic timer.
 *
 * @param tmo Timeout handle
 *
 * @retval non-zero Timeout is from a periodic timer
 * @retval 0        Timeout is not from a periodic timer
 */
int odp_timeout_is_periodic(odp_timeout_t tmo);

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
 * Allocate multiple timeouts
 *
 * Otherwise like odp_timeout_alloc(), but allocates multiple timeouts from a pool.
 *
 * @param      pool   Pool handle
 * @param[out] tmo    Array of timeout handles for output
 * @param      num    Number of timeouts to allocate
 *
 * @return Number of timeouts actually allocated (0 ... num)
 * @retval <0 on failure
 */
int odp_timeout_alloc_multi(odp_pool_t pool, odp_timeout_t tmo[], int num);

/**
 * Timeout free
 *
 * Frees the timeout back to the pool it was allocated from.
 *
 * @param tmo Timeout handle
 */
void odp_timeout_free(odp_timeout_t tmo);

/**
 * Free multiple timeouts
 *
 * Otherwise like odp_timeout_free(), but frees multiple timeouts to their originating pools.
 *
 * @param tmo         Array of timeout handles
 * @param num         Number of timeouts to free
 */
void odp_timeout_free_multi(odp_timeout_t tmo[], int num);

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
