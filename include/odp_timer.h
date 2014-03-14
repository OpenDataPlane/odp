/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP timer
 */

#ifndef ODP_TIMER_H_
#define ODP_TIMER_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp_std_types.h>
#include <odp_buffer.h>
#include <odp_buffer_pool.h>
#include <odp_queue.h>


/**
* ODP timer handle
*/
typedef uint32_t odp_timer_t;

#define ODP_TIMER_INVALID 0


/**
* ODP timeout handle
*/
typedef odp_buffer_t odp_timer_tmo_t;

#define ODP_TIMER_TMO_INVALID 0


/**
 * Create a timer
 *
 * Creates a new timer with requested properties.
 *
 * @param name       Name
 * @param pool       Buffer pool for allocating timeout notifications
 * @param resolution Timeout resolution in nanoseconds
 * @param min_tmo    Minimum timeout duration in nanoseconds
 * @param max_tmo    Maximum timeout duration in nanoseconds
 *
 * @return Timer handle if successful, otherwise ODP_TIMER_INVALID
 */
odp_timer_t odp_timer_create(const char *name, odp_buffer_pool_t pool,
			     uint64_t resolution, uint64_t min_tmo,
			     uint64_t max_tmo);

/**
 * Convert timer ticks to nanoseconds
 *
 * @param timer Timer
 * @param ticks Timer ticks
 *
 * @return Nanoseconds
 */
uint64_t odp_timer_tick_to_ns(odp_timer_t timer, uint64_t ticks);

/**
 * Convert nanoseconds to timer ticks
 *
 * @param timer Timer
 * @param ns    Nanoseconds
 *
 * @return Timer ticks
 */
uint64_t odp_timer_ns_to_tick(odp_timer_t timer, uint64_t ns);

/**
 * Timer resolution in nanoseconds
 *
 * @param timer Timer
 *
 * @return Resolution in nanoseconds
 */
uint64_t odp_timer_resolution(odp_timer_t timer);

/**
 * Maximum timeout in timer ticks
 *
 * @param timer Timer
 *
 * @return Maximum timeout in timer ticks
 */
uint64_t odp_timer_maximum_tmo(odp_timer_t timer);

/**
 * Current timer tick
 *
 * @param timer Timer
 *
 * @return Current time in timer ticks
 */
uint64_t odp_timer_current_tick(odp_timer_t timer);

/**
 * Request timeout with an absolute timer tick
 *
 * When tick reaches tmo_tick, the timer enqueues the timeout notification into
 * the destination queue.
 *
 * @param timer    Timer
 * @param tmo_tick Absolute timer tick value which triggers the timeout
 * @param queue    Destination queue for the timeout notification
 * @param buf      User defined timeout notification buffer. When
 *                 ODP_BUFFER_INVALID, default timeout notification is used.
 *
 * @return Timeout handle if successful, otherwise ODP_TIMER_TMO_INVALID
 */
odp_timer_tmo_t odp_timer_absolute_tmo(odp_timer_t timer, uint64_t tmo_tick,
				       odp_queue_t queue, odp_buffer_t buf);

/**
 * Cancel a timeout
 *
 * @param timer Timer
 * @param tmo   Timeout to cancel
 *
 * @return 0 if successful
 */
int odp_timer_cancel_tmo(odp_timer_t timer, odp_timer_tmo_t tmo);


#ifdef __cplusplus
}
#endif

#endif
