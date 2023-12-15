/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2013-2018 Linaro Limited
 * Copyright (c) 2019-2023 Nokia
 */

/**
 * @file
 *
 * ODP timer API type definitions
 */

#ifndef ODP_API_SPEC_TIMER_TYPES_H_
#define ODP_API_SPEC_TIMER_TYPES_H_
#include <odp/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/deprecated.h>
#include <odp/api/event_types.h>
#include <odp/api/std_types.h>

/** @defgroup odp_timer ODP TIMER
 *  Timer generating timeout events.
 *  @{
 */

/**
 * @typedef odp_timer_pool_t
 * ODP timer pool handle
 */

/**
 * @def ODP_TIMER_POOL_INVALID
 * Invalid timer pool handle
 */

/**
 * @typedef odp_timer_t
 * ODP timer handle
 */

/**
 * @def ODP_TIMER_INVALID
 * Invalid timer handle
 */

/**
 * @typedef odp_timeout_t
 * ODP timeout handle
 */

/**
 * @def ODP_TIMEOUT_INVALID
 * Invalid timeout handle
 */

/**
 * @def ODP_TIMER_POOL_NAME_LEN
 * Maximum timer pool name length in chars including null char
 */

/**
 * Timer type
 *
 * There are two types of timers. A single shot timer (ODP_TIMER_TYPE_SINGLE) is started with
 * an expiration time for each timeout. A periodic timer (ODP_TIMER_TYPE_PERIODIC) keeps expiring
 * and sending timeout events with the given period until it is cancelled.
 */
typedef enum {
	/** Single shot timer */
	ODP_TIMER_TYPE_SINGLE = 0,

	/** Periodic timer */
	ODP_TIMER_TYPE_PERIODIC

} odp_timer_type_t;

/**
 * Timer resolution capability
 */
typedef struct {
	/** Timeout resolution in nanoseconds */
	uint64_t res_ns;

	/** Timeout resolution in hertz */
	uint64_t res_hz;

	/** Minimum relative timeout in nanoseconds */
	uint64_t min_tmo;

	/** Maximum relative timeout in nanoseconds */
	uint64_t max_tmo;

} odp_timer_res_capability_t;

/**
 * Periodic timer capability
 */
typedef struct {
	/**
	 * Periodic timer pool base frequency in hertz
	 *
	 * Base frequency is represented as a fractional number where the fraction part is always
	 * less than one. In other words, the integer part specifies whole hertz whereas
	 * the fraction part specifies parts of a hertz (if any). The fraction part does not
	 * need to be reduced to its lowest terms - e.g. 100.5 Hz may be represented as 100 1/2 Hz,
	 * 100 5/10 Hz, or 100 Hz with some other equivalent fraction part.
	 */
	odp_fract_u64_t base_freq_hz;

	/** Maximum base frequency multiplier */
	uint64_t max_multiplier;

	/** Timeout resolution in nanoseconds */
	uint64_t res_ns;

} odp_timer_periodic_capability_t;

/**
 * Timer capability
 */
typedef struct {
	/** Maximum number of timer pools
	 *
	 * The total number of timer pools that can be created combining both types and
	 * different clock sources.
	 */
	uint32_t max_pools_combined;

	/** Maximum number of timer pools for single shot timers (per clock source) */
	uint32_t max_pools;

	/** Maximum number of single shot timers in a pool
	 *
	 * The value of zero means that limited only by the available
	 * memory size for the pool. */
	uint32_t max_timers;

	/** Highest timer resolution in nanoseconds.
	 *
	 *  This defines the highest resolution supported by a timer.
	 *  It's the minimum valid value for 'res_ns' timer pool
	 *  parameter.
	 *
	 *  This value is equal to 'max_res.res_ns' capability.
	 */
	uint64_t highest_res_ns;

	/**
	 * Maximum resolution
	 *
	 * This defines the highest resolution supported by a timer, with
	 * limits to min/max timeout values. The highest resolution for a timer
	 * pool is defined by 'max_res.res_ns' in nanoseconds and
	 * 'max_res.res_hz' in hertz.
	 * When this resolution is used:
	 * - 'min_tmo' parameter value must be in minimum 'max_res.min_tmo'
	 * - 'max_tmo' parameter value must be in maximum 'max_res.max_tmo'
	 */
	odp_timer_res_capability_t max_res;

	/**
	 * Maximum timeout length
	 *
	 * This defines the maximum relative timeout value supported by a timer,
	 * with limits to min timeout and max resolution values. The maximum
	 * value for 'max_tmo' timer pool parameter is defined by
	 * 'max_tmo.max_tmo'. When this max timeout value is used:
	 * - 'min_tmo' parameter value must be in minimum 'max_tmo.min_tmo'
	 * - 'res_ns'  parameter value must be in minimum 'max_tmo.res_ns' or
	 * - 'res_hz'  parameter value must be in maximum 'max_tmo.res_hz'
	 */
	odp_timer_res_capability_t max_tmo;

	/**
	 * Scheduled queue destination support
	 *
	 * This defines whether schedule queues are supported as timeout
	 * destination queues.
	 * 0: Scheduled queues are not supported as timeout destination queues
	 * 1: Scheduled queues are supported as timeout destination queues
	 * @see odp_timer_alloc()
	 */
	odp_bool_t queue_type_sched;

	/**
	 * Plain queue destination support
	 *
	 * This defines whether plain queues are supported as timeout
	 * destination queues.
	 * 0: Plain queues are not supported as timeout destination queues
	 * 1: Plain queues are supported as timeout destination queues
	 * @see odp_timer_alloc()
	 */
	odp_bool_t queue_type_plain;

	/** Periodic timer capabilities */
	struct {
		/** Maximum number of timer pools for periodic timers
		 *
		 *  When zero, periodic timers (#ODP_TIMER_TYPE_PERIODIC) are not supported.
		 */
		uint32_t max_pools;

		/** Maximum number of periodic timers in a pool */
		uint32_t max_timers;

		/** Minimum supported base frequency value */
		odp_fract_u64_t min_base_freq_hz;

		/** Maximum supported base frequency value */
		odp_fract_u64_t max_base_freq_hz;

		/** Maximum number of timeout events that may be needed
		 *
		 *  The number of timeout events per timer, as returned by
		 *  odp_timer_periodic_events(), is less than or equal to this value.
		 */
		uint32_t max_tmo_events;

	} periodic;

} odp_timer_capability_t;

/**
 * Clock sources for timer pools
 *
 * ODP_CLOCK_DEFAULT is the default clock source and it is supported always. It is implementation
 * defined which other clock sources are supported. See from implementation documentation how the
 * supported clock sources are mapped into these enumerations.
 */
typedef enum {
	/** Clock source number 0 */
	ODP_CLOCK_SRC_0,

	/** Clock source number 1 */
	ODP_CLOCK_SRC_1,

	/** Clock source number 2 */
	ODP_CLOCK_SRC_2,

	/** Clock source number 3  */
	ODP_CLOCK_SRC_3,

	/** Clock source number 4  */
	ODP_CLOCK_SRC_4,

	/** Clock source number 5  */
	ODP_CLOCK_SRC_5,

	/** Number of clock source enumerations */
	ODP_CLOCK_NUM_SRC

} odp_timer_clk_src_t;

/** The default clock source */
#define ODP_CLOCK_DEFAULT ODP_CLOCK_SRC_0

#if ODP_DEPRECATED_API
/**
 * For backwards compatibility, ODP_CLOCK_CPU is synonym of ODP_CLOCK_DEFAULT.
 *
 * @deprecated Use #ODP_CLOCK_DEFAULT instead.
 */
#define ODP_CLOCK_CPU ODP_CLOCK_DEFAULT

/**
 * For backwards compatibility, ODP_CLOCK_EXT is synonym of ODP_CLOCK_SRC_1.
 *
 * @deprecated Use #ODP_CLOCK_SRC_1 instead.
 */
#define ODP_CLOCK_EXT ODP_CLOCK_SRC_1
#endif

/**
 * Timer expiration mode
 *
 * Expiration mode selects how timer expiration tick is interpreted. In ODP_TIMER_EXP_RELAXED mode,
 * timer implementation may round the requested time up or down within resolution limits, and
 * therefore application may receive timeouts slightly before or after the requested time.
 * In ODP_TIMER_EXP_AFTER mode, timers are limited to expire exactly on the requested time or
 * after it, but never before the time.
 */
typedef enum {
	/**
	 * Expiration after the target time
	 *
	 * Timers expire on the specified time or after it, but never before it. */
	ODP_TIMER_EXP_AFTER = 0,

	/**
	 * Expiration relaxed
	 *
	 * Timers may expire before or after the specified time (within resolution limits).
	 * Depending on implementation, this may improve expiration accuracy compared to
	 * ODP_TIMER_EXP_AFTER.
	 */
	ODP_TIMER_EXP_RELAXED

} odp_timer_exp_mode_t;

/**
 * Timer pool parameters
 */
typedef struct {
	/** Timer type
	 *
	 *  Select whether the pool is created for single shot (#ODP_TIMER_TYPE_SINGLE) or
	 *  periodic (#ODP_TIMER_TYPE_PERIODIC) timers. All timers in a pool are of the same type.
	 *  Timer capabilities specify how many pools of each type are supported.
	 *
	 *  The default value is ODP_TIMER_TYPE_SINGLE.
	 */
	odp_timer_type_t timer_type;

	/** Clock source for timers
	 *
	 *  The default value is ODP_CLOCK_DEFAULT. */
	odp_timer_clk_src_t clk_src;

	/** Timer expiration mode
	 *
	 *  The default value is ODP_TIMER_EXP_AFTER. */
	odp_timer_exp_mode_t exp_mode;

	/** Timeout resolution in nanoseconds. Timer pool must serve timeouts
	 *  with this or higher resolution. The minimum valid value (highest
	 *  resolution) is defined by timer resolution capability. When this
	 *  parameter is used, set 'res_hz' to zero. The default value is zero. */
	uint64_t res_ns;

	/** Timeout resolution in hertz. This may be used to specify the highest
	 *  required resolution in hertz instead of nanoseconds. When this
	 *  parameter is used, set 'res_ns' to zero. The default value is zero. */
	uint64_t res_hz;

	/** Minimum relative timeout in nanoseconds
	 *
	 *  All requested timeouts will be at least this many nanoseconds after the current
	 *  time of the timer pool. Timer set functions return an error, if too short timeout
	 *  was requested. The value may be also smaller than the requested resolution.
	 *
	 *  The default value is zero. Ignored when timer type is periodic.
	 */
	uint64_t min_tmo;

	/** Maximum relative timeout in nanoseconds
	 *
	 *  All requested timeouts will be at most this many nanoseconds after the current
	 *  time of the timer pool. Timer set functions return an error, if too long timeout was
	 *  requested.
	 *
	 *  Ignored when timer type is periodic.
	 */
	uint64_t max_tmo;

	/** Periodic timer parameters
	 *
	 *  Additional parameters for periodic timers. Ignored when timer type is single shot.
	 */
	struct {
		/** Timer pool base frequency in hertz
		 *
		 *  A periodic timer pool has a base frequency. Each timer of the pool has
		 *  an expiration frequency that is an integer multiple of the base frequency.
		 *  Depending on the implementation, base frequency may need to be selected
		 *  carefully to avoid timer periods to drift against the source clock.
		 *  Use odp_timer_periodic_capability() to check base frequency support,
		 *  and resulting max_multiplier and resolution values.
		 *
		 *  Fraction part of the value is always less than one, see
		 *  odp_timer_periodic_capability_t::base_freq_hz for details. The default value
		 *  is zero.
		 *
		 *  An example with two timer frequencies:
		 *       base_freq_hz.integer = 33333, .numer = 1, .denom = 3
		 *       max_multiplier = 30
		 *       timer A: freq_multiplier = 2
		 *                timer frequency: 2 * 33333 1/3 Hz = 66.6666..kHz
		 *       timer B: freq_multiplier = 30
		 *                timer frequency: 30 * 33333 1/3 Hz = 1 MHz
		 */
		odp_fract_u64_t base_freq_hz;

		/** Maximum base frequency multiplier
		 *
		 *  This is the maximum base frequency multiplier value
		 *  (odp_timer_periodic_start_t::freq_multiplier) for any timer in the pool.
		 */
		uint64_t max_multiplier;

	} periodic;

	/** Number of timers in the pool. */
	uint32_t num_timers;

	/** Thread private timer pool. When zero, multiple thread may use the
	 *  timer pool concurrently. When non-zero, only single thread uses the
	 *  timer pool (concurrently). The default value is zero. */
	int priv;

} odp_timer_pool_param_t;

/**
 * Timer tick type
 */
typedef enum {
	/** Relative ticks
	 *
	 *  Timer tick value is relative to the current time (odp_timer_current_tick())
	 *  of the timer pool.
	 */
	ODP_TIMER_TICK_REL = 0,

	/** Absolute ticks
	 *
	 *  Timer tick value is absolute timer pool ticks.
	 */
	ODP_TIMER_TICK_ABS

} odp_timer_tick_type_t;

/**
 * Timer start parameters
 */
typedef struct odp_timer_start_t {
	/** Tick type
	 *
	 *  Defines if expiration time ticks are absolute or relative.
	 */
	odp_timer_tick_type_t tick_type;

	/** Expiration time in ticks
	 *
	 *  New expiration time for the timer to be started/restarted. When 'tick_type' is
	 *  ODP_TIMER_TICK_REL, expiration time is odp_timer_current_tick() + 'tick'.*/
	uint64_t tick;

	/** Timeout event
	 *
	 *  When the timer expires, this event is enqueued to the destination queue of the timer.
	 *  The event type can be ODP_EVENT_BUFFER, ODP_EVENT_PACKET or ODP_EVENT_TIMEOUT. It is
	 *  recommended to use ODP_EVENT_TIMEOUT type events. Those (odp_timeout_t) carry also
	 *  timeout specific metadata.
	 *
	 *  This field is ignored by odp_timer_restart() calls.
	 */
	odp_event_t tmo_ev;

} odp_timer_start_t;

/**
 * Periodic timer start parameters
 *
 * A periodic timer pool can be thought as a wall clock, where the base frequency
 * (odp_timer_pool_param_t::base_freq_hz) defines how many times per second a pointer travels
 * around the clock face. When a timer (see "Timer A" in the figure) is started with the base
 * frequency multiplier (odp_timer_periodic_start_t::freq_multiplier) of one, a single reference
 * to it is placed into the clock face. When a timer (see "Timer B") is started with the multiplier
 * value of two, two references to it is placed into opposite sides of the clock face, etc. When the
 * pointer reaches a timer reference, the timer expires and a timeout event is sent to the
 * destination queue. The maximum base frequency multiplier (odp_timer_pool_param_t::max_multiplier)
 * defines the maximum number of references a timer can have on the clock face. The first
 * expiration time parameter (odp_timer_periodic_start_t::first_tick) is used to tune timer
 * reference placement on the clock face against the current time (the current pointer location).
 *
 * @code{.unparsed}
 *
 *            Periodic timer pool
 *
 *                     o
 *                o         o <--- Timer B
 *
 *              o      \      o
 *                      \
 *   Timer B ---> o      \  o <--- Timer A
 *                     o
 *
 *
 *   Timer pool: max_multiplier  = 8
 *   Timer A:    freq_multiplier = 1
 *   Timer B:    freq_multiplier = 2
 *
 * @endcode
 *
 */
typedef struct odp_timer_periodic_start_t {
	/** First expiration time
	 *
	 *  The first expiration time in absolute timer ticks. When zero, the first expiration time
	 *  is one period after the current time, or as close to that as the implementation can
	 *  achieve. After the first expiration, timer expiration continues with the defined
	 *  frequency. The tick value must be less than one timer period after the current time.
	 */
	uint64_t first_tick;

	/** Base frequency multiplier
	 *
	 *  Periodic timer expiration frequency is defined as a multiple of the timer pool
	 *  base frequency: timer frequency (Hz) = base_freq_hz * freq_multiplier. Valid values
	 *  range from 1 to timer pool parameter 'max_multiplier'.
	 *
	 *  Depending on the implementation, a multiplier value that is a divisor of
	 *  'max_multiplier' may improve timer expiration accuracy:
	 *  max_multiplier = k * freq_multiplier, where k is an integer.
	 */
	uint64_t freq_multiplier;

	/** Number of timeout events
	 *
	 *  Number of timeout events in the tmo_ev array. This value is set by calling
	 *  odp_timer_periodic_events().
	 */
	uint32_t num_tmo_ev;

	/** Array of timeout events
	 *
	 *  One of these events is enqueued to the destination queue when the timer expires. The
	 *  event type of the events must be ODP_EVENT_TIMEOUT. The application may free these
	 *  events after receiving a return value of 2 (last event) from odp_timer_periodic_ack().
	 */
	odp_event_t *tmo_ev;

} odp_timer_periodic_start_t;

/**
 * Return values for timer start, restart and cancel calls
 */
typedef enum {
	/**
	 * Timer operation succeeded
	 *
	 * Timer start, restart and cancel operations may return this value.
	 */
	ODP_TIMER_SUCCESS = 0,

	/**
	 * Timer operation failed, too near to the current time
	 *
	 * The operation failed because the requested time/timer has expired already, or is too
	 * near to the current time. Timer start, restart and cancel operations may return this
	 * value.
	 */
	ODP_TIMER_TOO_NEAR = -1,

	/**
	 * Timer operation failed, too far from the current time
	 *
	 * The operation failed because the requested time is too far from the current time.
	 * Only timer start and restart operations may return this value.
	 */
	ODP_TIMER_TOO_FAR = -2,

	/**
	 * Timer operation failed
	 *
	 * The operation failed due to some other reason than timing of the request. Timer start,
	 * restart and cancel operations may return this value.
	 */
	ODP_TIMER_FAIL = -3

} odp_timer_retval_t;

/**
 * For backwards compatibility, odp_timer_set_t is synonym of odp_timer_retval_t
 *
 * @deprecated Use odp_timer_retval_t instead.
 */
typedef odp_timer_retval_t odp_timer_set_t;

#if ODP_DEPRECATED_API
/**
 * For backwards compatibility, ODP_TIMER_TOOEARLY is synonym of ODP_TIMER_TOO_NEAR.
 *
 * @deprecated Use #ODP_TIMER_TOO_NEAR instead.
 */
#define ODP_TIMER_TOOEARLY ODP_TIMER_TOO_NEAR

/**
 * For backwards compatibility, ODP_TIMER_TOOLATE is synonym of ODP_TIMER_TOO_FAR.
 *
 * @deprecated Use #ODP_TIMER_TOO_FAR instead.
 */
#define ODP_TIMER_TOOLATE  ODP_TIMER_TOO_FAR

/**
 * For backwards compatibility, ODP_TIMER_NOEVENT is synonym of ODP_TIMER_FAIL.
 *
 * @deprecated Use #ODP_TIMER_FAIL instead.
 */
#define ODP_TIMER_NOEVENT ODP_TIMER_FAIL
#endif

/**
 * Timer tick information
 */
typedef struct odp_timer_tick_info_t {
	/**
	 * Timer tick frequency in hertz
	 *
	 * Timer tick frequency expressed as a fractional number. The integer part contains
	 * full hertz. The fraction part (numerator / denominator) contains parts of
	 * a hertz to be added with the integer.
	 *
	 * For example, a timer tick frequency of 333 333 and 1/3 Hz could be presented with
	 * these values: integer = 333 333, numer = 1, denom = 3. Implementation may choose numer
	 * and denom values freely.
	 */
	odp_fract_u64_t freq;

	/**
	 * One timer tick in nanoseconds
	 *
	 * Nanoseconds per tick is expressed as a fractional number. The integer part contains
	 * full nanoseconds. The fraction part (numerator / denominator) contains parts of
	 * a nanosecond to be added with the integer.
	 *
	 * For example, a timer tick period of 3.125 nanoseconds (320MHz) could be presented with
	 * these values: integer = 3, numer = 125 000 000, denom = 1 000 000 000. Implementation
	 * may choose numer and denom values freely.
	 */
	odp_fract_u64_t nsec;

	/**
	 * One timer tick in source clock cycles
	 *
	 * The clock cycle count is expressed as a fractional number. The integer part contains
	 * full clock cycles. The fraction part (numerator / denominator) contains parts of
	 * a clock cycle to be added with the integer.
	 *
	 * For example, a timer tick period of 42 and 1/3 source clock cycles could be presented
	 * with these values: integer = 42, numer = 1, denom = 3. Implementation may choose numer
	 * and denom values freely.
	 *
	 * The value is zero, when there is no direct connection between tick and the source
	 * clock signal.
	 */
	odp_fract_u64_t clk_cycle;

} odp_timer_tick_info_t;

/**
 * ODP timer pool information and configuration
 */
typedef struct {
	/** Parameters specified at creation */
	odp_timer_pool_param_t param;

	/** Number of currently allocated timers */
	uint32_t cur_timers;

	/** High watermark of allocated timers */
	uint32_t hwm_timers;

	/** Name of timer pool */
	const char *name;

	/** Timer pool tick information */
	odp_timer_tick_info_t tick_info;

} odp_timer_pool_info_t;

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
