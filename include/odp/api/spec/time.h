/* Copyright (c) 2013-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP time
 */

#ifndef ODP_API_SPEC_TIME_H_
#define ODP_API_SPEC_TIME_H_
#include <odp/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @defgroup odp_time ODP TIME
 *  @{
 */

/** A microsecond in nanoseconds */
#define ODP_TIME_USEC_IN_NS  1000ULL

/** A millisecond in nanoseconds */
#define ODP_TIME_MSEC_IN_NS  1000000ULL

/** A second in nanoseconds */
#define ODP_TIME_SEC_IN_NS   1000000000ULL

/** A minute in nanoseconds */
#define ODP_TIME_MIN_IN_NS   60000000000ULL

/** An hour in nanoseconds */
#define ODP_TIME_HOUR_IN_NS  3600000000000ULL

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
 * resolution time, it is initialized to zero during ODP startup and will not
 * wrap around in at least 10 years.
 * Local time stamps are local to the calling thread and must not be shared
 * with other threads.
 *
 * @return Local time stamp.
 */
odp_time_t odp_time_local(void);

/**
 * Current global time
 *
 * Returns current global time stamp value. The global time source provides high
 * resolution time, it is initialized to zero during ODP startup and will not
 * wrap around in at least 10 years.
 * Global time stamps can be shared between threads.
 *
 * @return Global time stamp.
 */
odp_time_t odp_time_global(void);

/**
 * Time difference
 *
 * @param t2    Second time stamp
 * @param t1    First time stamp
 *
 * @return Difference of time stamps
 */
odp_time_t odp_time_diff(odp_time_t t2, odp_time_t t1);

/**
 * Time difference in nanoseconds
 *
 * @param t2    Second time stamp
 * @param t1    First time stamp
 *
 * @return Difference of time stamps (t2 - t1) in nanoseconds
 */
uint64_t odp_time_diff_ns(odp_time_t t2, odp_time_t t1);

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
 * Convert nanoseconds to global time
 *
 * @param ns    Time in nanoseconds
 *
 * @return Global time stamp
 */
odp_time_t odp_time_global_from_ns(uint64_t ns);

/**
 * Compare two times
 *
 * @param t2    Second time
 * @param t1    First time
 *
 * @retval <0 when t2 < t1
 * @retval  0 when t2 == t1
 * @retval >0 when t2 > t1
 */
int odp_time_cmp(odp_time_t t2, odp_time_t t1);

/**
 * Local time resolution in hertz
 *
 * @return      Local time resolution in hertz
 */
uint64_t odp_time_local_res(void);

/**
 * Global time resolution in hertz
 *
 * @return      Global time resolution in hertz
 */
uint64_t odp_time_global_res(void);

/**
 * Wait until the specified (wall clock) time has been reached
 *
 * The thread potentially busy loop the entire wait time.
 *
 * @param time  Time to reach before continue
 */
void odp_time_wait_until(odp_time_t time);

/**
 * Wait the specified number of nanoseconds
 *
 * The thread potentially busy loop the entire wait time.
 *
 * @param ns    Time in nanoseconds to wait
 */
void odp_time_wait_ns(uint64_t ns);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
