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
 * ODP timer API type definitions
 */

#ifndef ODP_API_SPEC_TIMER_TYPES_H_
#define ODP_API_SPEC_TIMER_TYPES_H_
#include <odp/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

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
 * Timer capability
 */
typedef struct {
	/** Maximum number of timer pools over all clock sources
	 *
	 * The total number of timer pools that can be created combining
	 * different clock sources.
	 */
	uint32_t max_pools_combined;

	/** Maximum number of timer pools for the requested clock source */
	uint32_t max_pools;

	/** Maximum number of timers in a pool
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

/** For backwards compatibility, ODP_CLOCK_CPU is synonym of ODP_CLOCK_DEFAULT.
 *  This will be deprecated in the future. */
#define ODP_CLOCK_CPU ODP_CLOCK_DEFAULT

/** For backwards compatibility, ODP_CLOCK_EXT is synonym of ODP_CLOCK_SRC_1.
 *  This will be deprecated in the future. */
#define ODP_CLOCK_EXT ODP_CLOCK_SRC_1

/**
 * Timer pool parameters
 */
typedef struct {
	/** Timeout resolution in nanoseconds. Timer pool must serve timeouts
	 *  with this or higher resolution. The minimum valid value (highest
	 *  resolution) is defined by timer resolution capability. When this
	 *  parameter is used, set 'res_hz' to zero. The default value is zero. */
	uint64_t res_ns;

	/** Timeout resolution in hertz. This may be used to specify the highest
	 *  required resolution in hertz instead of nanoseconds. When this
	 *  parameter is used, set 'res_ns' to zero. The default value is zero. */
	uint64_t res_hz;

	/** Minimum relative timeout in nanoseconds. All requested timeouts
	 *  will be at least this many nanoseconds after the current
	 *  time of the timer pool. Timer set functions return an error, if too
	 *  short timeout was requested. The value may be also smaller than
	 *  the requested resolution. The default value is zero. */
	uint64_t min_tmo;

	/** Maximum relative timeout in nanoseconds. All requested timeouts
	 *  will be at most this many nanoseconds after the current
	 *  time of the timer pool. Timer set functions return an error, if too
	 *  long timeout was requested. */
	uint64_t max_tmo;

	/** Number of timers needed. Application will create in maximum this
	 *  many concurrent timers from the timer pool. */
	uint32_t num_timers;

	/** Thread private timer pool. When zero, multiple thread may use the
	 *  timer pool concurrently. When non-zero, only single thread uses the
	 *  timer pool (concurrently). The default value is zero. */
	int priv;

	/** Clock source for timers
	 *
	 *  The default value is ODP_CLOCK_DEFAULT. */
	odp_timer_clk_src_t clk_src;

} odp_timer_pool_param_t;

/**
 * Return values of timer set calls.
 */
typedef enum {
	/** Timer set operation succeeded */
	ODP_TIMER_SUCCESS = 0,

	/** Timer set operation failed because expiration time is too near to
	 *  the current time. */
	ODP_TIMER_TOO_NEAR = -1,

	/** Timer set operation failed because expiration time is too far from
	 *  the current time. */
	ODP_TIMER_TOO_FAR = -2,

	/** Timer set operation failed */
	ODP_TIMER_FAIL = -3

} odp_timer_set_t;

/** For backwards compatibility, ODP_TIMER_TOOEARLY is synonym of ODP_TIMER_TOO_NEAR.
 *  This will be deprecated in the future. */
#define ODP_TIMER_TOOEARLY ODP_TIMER_TOO_NEAR

/** For backwards compatibility, ODP_TIMER_TOOLATE is synonym of ODP_TIMER_TOO_FAR.
 *  This will be deprecated in the future. */
#define ODP_TIMER_TOOLATE  ODP_TIMER_TOO_FAR

/** For backwards compatibility, ODP_TIMER_NOEVENT is synonym of ODP_TIMER_FAIL.
 *  This will be deprecated in the future. */
#define ODP_TIMER_NOEVENT ODP_TIMER_FAIL

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
