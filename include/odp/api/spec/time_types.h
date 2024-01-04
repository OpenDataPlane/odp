/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2013-2018 Linaro Limited
 * Copyright (c) 2020-2023 Nokia
 */

/**
 * @file
 *
 * ODP time
 */

#ifndef ODP_API_SPEC_TIME_TYPES_H_
#define ODP_API_SPEC_TIME_TYPES_H_
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
 * Time stamp values at ODP startup
 */
typedef struct odp_time_startup_t {
	/** Global time at ODP startup */
	odp_time_t global;

	/** Global time in nanoseconds at ODP startup */
	uint64_t global_ns;

} odp_time_startup_t;

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
