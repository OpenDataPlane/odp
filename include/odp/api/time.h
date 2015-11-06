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
#define ODP_TIME_USEC_IN_NS	1000ULL       /**< Microsecond in nsec */
#define ODP_TIME_MSEC_IN_NS	1000000ULL    /**< Millisecond in nsec */
#define ODP_TIME_SEC_IN_NS	1000000000ULL /**< Second in nsec */

/**
 * @typedef odp_time_t
 * ODP time stamp. Time stamp can represent a time stamp from local or global
 * time source. A local time stamp must not be shared between threads. API calls
 * work correctly only when all time stamps for input are from the same time
 * source.
 */

/**
 * @def ODP_TIME_NULL
 * Zero time stamp
 */

/**
 * Current local time
 *
 * Returns current local time stamp value. The local time source provides high
 * resolution time.
 *
 * @return Local time stamp.
 */
odp_time_t odp_time_local(void);

/**
 * Time difference
 *
 * @param t1    First time stamp
 * @param t2    Second time stamp
 *
 * @return Difference of time stamps
 */
odp_time_t odp_time_diff(odp_time_t t1, odp_time_t t2);

/**
 * Time sum
 *
 * @param t1    Time stamp
 * @param t2    Time stamp
 *
 * @return Sum of time stamps
 */
odp_time_t odp_time_sum(odp_time_t t1, odp_time_t t2);

/**
 * Convert time to nanoseconds
 *
 * @param time  Time
 *
 * @return Time in nanoseconds
 */
uint64_t odp_time_to_ns(odp_time_t time);

/**
 * Convert nanoseconds to local time
 *
 * @param ns    Time in nanoseconds
 *
 * @return Local time stamp
 */
odp_time_t odp_time_local_from_ns(uint64_t ns);

/**
 * Compare two times
 *
 * @param t2    Second time
 * @param t1    First time
 *
 * @retval <0 if t2 < t1, >0 if t1 = t2, 1 if t2 > t1
 */
int odp_time_cmp(odp_time_t t2, odp_time_t t1);

/**
 * Get printable value for an odp_time_t
 *
 * @param time time to be printed
 *
 * @return uint64_t value that can be used to print/display this time
 *
 * @note This routine is intended to be used for diagnostic purposes
 * to enable applications to generate a printable value that represents
 * an odp_time_t time.
 */
uint64_t odp_time_to_u64(odp_time_t time);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
