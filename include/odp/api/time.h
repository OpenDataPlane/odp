/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP time
 */

#ifndef ODP_API_TIME_H_
#define ODP_API_TIME_H_

#ifdef __cplusplus
extern "C" {
#endif


/** @defgroup odp_time ODP TIME
 *  @{
 */

/* Time in nanoseconds */
#define ODP_TIME_USEC 1000ULL       /**< Microsecond in nsec */
#define ODP_TIME_MSEC 1000000ULL    /**< Millisecond in nsec */
#define ODP_TIME_SEC  1000000000ULL /**< Second in nsec */


/**
 * Current time in CPU cycles
 *
 * @return Current time in CPU cycles
 */
uint64_t odp_time_cycles(void);


/**
 * Time difference
 *
 * @param t1    First time stamp
 * @param t2    Second time stamp
 *
 * @return Difference of time stamps in CPU cycles
 */
uint64_t odp_time_diff_cycles(uint64_t t1, uint64_t t2);


/**
 * Convert CPU cycles to nanoseconds
 *
 * @param cycles  Time in CPU cycles
 *
 * @return Time in nanoseconds
 */
uint64_t odp_time_cycles_to_ns(uint64_t cycles);


/**
 * Convert nanoseconds to CPU cycles
 *
 * @param ns      Time in nanoseconds
 *
 * @return Time in CPU cycles
 */
uint64_t odp_time_ns_to_cycles(uint64_t ns);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
