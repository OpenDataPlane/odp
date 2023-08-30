/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2013-2018 Linaro Limited
 * Copyright (c) 2020-2023 Nokia
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

#include <odp/api/std_types.h>
#include <odp/api/time_types.h>

/** @defgroup odp_time ODP TIME
 *  Chip and CPU level wall clock time.
 *  @{
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
 * Current local time in nanoseconds
 *
 * Like odp_time_local(), but the time stamp value is converted into nanoseconds.
 *
 * @return Local time stamp in nanoseconds
 */
uint64_t odp_time_local_ns(void);

/**
 * Current local time (strict)
 *
 * Like odp_time_local(), but reads the time stamp value more strictly in the program order.
 * The function may decrease CPU performance around the call, as it may include additional
 * barrier instructions or otherwise limit out-of-order execution.
 *
 * @return Local time stamp
 */
odp_time_t odp_time_local_strict(void);

/**
 * Current local time in nanoseconds (strict)
 *
 * Like odp_time_local_strict(), but the time stamp value is converted into nanoseconds.
 *
 * @return Local time stamp in nanoseconds
 */
uint64_t odp_time_local_strict_ns(void);

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
 * Current global time in nanoseconds
 *
 * Like odp_time_global(), but the time stamp value is converted into nanoseconds.
 *
 * @return Global time stamp in nanoseconds
 */
uint64_t odp_time_global_ns(void);

/**
 * Current global time (strict)
 *
 * Like odp_time_global(), but reads the time stamp value more strictly (see
 * odp_time_local_strict() documentation) in the program order.
 *
 * @return Global time stamp
 */
odp_time_t odp_time_global_strict(void);

/**
 * Current global time in nanoseconds (strict)
 *
 * Like odp_time_global_strict(), but the time stamp value is converted into nanoseconds.
 *
 * @return Global time stamp in nanoseconds
 */
uint64_t odp_time_global_strict_ns(void);

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
