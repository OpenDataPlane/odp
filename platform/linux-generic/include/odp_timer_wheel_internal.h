/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2015 EZchip Semiconductor Ltd.
 * Copyright (c) 2015-2018 Linaro Limited
 */

#ifndef _ODP_INT_TIMER_WHEEL_H_
#define _ODP_INT_TIMER_WHEEL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

typedef uint64_t _odp_timer_wheel_t;

#define _ODP_INT_TIMER_WHEEL_INVALID  0

_odp_timer_wheel_t _odp_timer_wheel_create(uint32_t max_concurrent_timers,
					   void    *tm_system);

void _odp_timer_wheel_start(_odp_timer_wheel_t timer_wheel,
			    uint64_t           current_time);

/* _odp_int_timer_wheel_curr_time_update should be called before the first
 * call to _odp_int_timer_wheel_insert, _odp_int_timer_wheel_next, etc..
 * It returns > 0 if there are timers expired.
 */
uint32_t _odp_timer_wheel_curr_time_update(_odp_timer_wheel_t timer_wheel,
					   uint64_t           current_time);

/* Maximum wakeup_time is 100 seconds in the future (though a wakeup time
 * greater than a dozen seconds or so is of questionable value), and in
 * addition the wakeup_time MUST represent a time in the future.  Note that
 * the user_ptr cannot be NULL and must be aligned to an 4-byte boundary
 * (i.e. the bottom 2 bits of this ptr must be 0).  AGAIN THIS MUST BE
 * STRESSED - user_ptr is not an arbitrary 64-bit pointer, BUT MUST be
 * non-zero and have its bottom two bits being 0!
 */
int _odp_timer_wheel_insert(_odp_timer_wheel_t timer_wheel,
			    uint64_t           wakeup_time,
			    uint64_t           user_context);

/* Returns the exact same user_ptr value as was passed to
 * _odp_int_timer_wheel_insert().
 */
uint64_t _odp_timer_wheel_next_expired(_odp_timer_wheel_t timer_wheel);

/* Returns the number of timers that have been inserted but not yet passed
 * back to the user.  This number includes the number of timers that have
 * internally expired and are in the expired list, but have not yet been
 * retrieved via an odp_timer_wheel_next_expired call.
 */
uint32_t _odp_timer_wheel_count(_odp_timer_wheel_t timer_wheel);

void _odp_timer_wheel_stats_print(_odp_timer_wheel_t timer_wheel);

void _odp_timer_wheel_destroy(_odp_timer_wheel_t timer_wheel);

#ifdef __cplusplus
}
#endif

#endif
