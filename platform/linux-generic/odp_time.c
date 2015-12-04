/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#define _POSIX_C_SOURCE 200809L

#include <time.h>
#include <odp/time.h>
#include <odp/hints.h>
#include <odp_debug_internal.h>

odp_time_t odp_time_local(void)
{
	int ret;
	struct timespec time;

	ret = clock_gettime(CLOCK_MONOTONIC_RAW, &time);
	if (odp_unlikely(ret != 0))
		ODP_ABORT("clock_gettime failed\n");

	return time;
}

odp_time_t odp_time_diff(odp_time_t t2, odp_time_t t1)
{
	uint64_t ns1, ns2;
	struct timespec time;

	ns1 = odp_time_to_ns(t1);
	ns2 = odp_time_to_ns(t2);
	if (ns2 < ns1)
		return (struct timespec) {0, 1};

	time.tv_sec = t2.tv_sec - t1.tv_sec;
	time.tv_nsec = t2.tv_nsec - t1.tv_nsec;

	if (time.tv_nsec < 0) {
		time.tv_nsec += ODP_TIME_SEC_IN_NS;
		--time.tv_sec;
	}

	return time;
}

uint64_t odp_time_to_ns(odp_time_t time)
{
	uint64_t ns;

	ns = time.tv_sec * ODP_TIME_SEC_IN_NS;
	ns += time.tv_nsec;

	return ns;
}

odp_time_t odp_time_local_from_ns(uint64_t ns)
{
	struct timespec time;

	time.tv_sec = ns / ODP_TIME_SEC_IN_NS;
	time.tv_nsec = ns % ODP_TIME_SEC_IN_NS;

	return time;
}

int odp_time_cmp(odp_time_t t2, odp_time_t t1)
{
	if (t2.tv_sec < t1.tv_sec)
		return -1;

	if (t2.tv_sec > t1.tv_sec)
		return 1;

	return t2.tv_nsec - t1.tv_nsec;
}

odp_time_t odp_time_sum(odp_time_t t1, odp_time_t t2)
{
	struct timespec time;

	time.tv_sec = t2.tv_sec + t1.tv_sec;
	time.tv_nsec = t2.tv_nsec + t1.tv_nsec;

	if (time.tv_nsec >= (long)ODP_TIME_SEC_IN_NS) {
		time.tv_nsec -= ODP_TIME_SEC_IN_NS;
		++time.tv_sec;
	}

	return time;
}

uint64_t odp_time_to_u64(odp_time_t time)
{
	int ret;
	struct timespec tres;
	uint64_t resolution;

	ret = clock_getres(CLOCK_MONOTONIC_RAW, &tres);
	if (odp_unlikely(ret != 0))
		ODP_ABORT("clock_getres failed\n");

	resolution = (uint64_t)tres.tv_nsec;

	return odp_time_to_ns(time) / resolution;
}

odp_time_t odp_time_null(void)
{
	return (struct timespec) {0, 0};
}
