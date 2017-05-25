/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_posix_extensions.h>

#include <time.h>
#include <odp/api/time.h>
#include <odp/api/hints.h>
#include <odp_debug_internal.h>
#include <odp_time_internal.h>
#include <string.h>
#include <inttypes.h>

typedef struct time_global_t {
	struct timespec spec_start;
	int             use_hw;
	uint64_t        hw_start;
	uint64_t        hw_freq_hz;
} time_global_t;

static time_global_t global;

/*
 * Posix timespec based functions
 */

static inline uint64_t time_spec_diff_nsec(struct timespec *t2,
					   struct timespec *t1)
{
	struct timespec diff;
	uint64_t nsec;

	diff.tv_sec  = t2->tv_sec  - t1->tv_sec;
	diff.tv_nsec = t2->tv_nsec - t1->tv_nsec;

	if (diff.tv_nsec < 0) {
		diff.tv_nsec += ODP_TIME_SEC_IN_NS;
		diff.tv_sec  -= 1;
	}

	nsec = (diff.tv_sec * ODP_TIME_SEC_IN_NS) + diff.tv_nsec;

	return nsec;
}

static inline odp_time_t time_spec_cur(void)
{
	int ret;
	odp_time_t time;
	struct timespec sys_time;

	ret = clock_gettime(CLOCK_MONOTONIC_RAW, &sys_time);
	if (odp_unlikely(ret != 0))
		ODP_ABORT("clock_gettime failed\n");

	time.nsec = time_spec_diff_nsec(&sys_time, &global.spec_start);

	return time;
}

static inline uint64_t time_spec_res(void)
{
	int ret;
	struct timespec tres;

	ret = clock_getres(CLOCK_MONOTONIC_RAW, &tres);
	if (odp_unlikely(ret != 0))
		ODP_ABORT("clock_getres failed\n");

	return ODP_TIME_SEC_IN_NS / (uint64_t)tres.tv_nsec;
}

static inline uint64_t time_spec_to_ns(odp_time_t time)
{
	return time.nsec;
}

static inline odp_time_t time_spec_from_ns(uint64_t ns)
{
	odp_time_t time;

	time.nsec = ns;

	return time;
}

/*
 * HW time counter based functions
 */

static inline odp_time_t time_hw_cur(void)
{
	odp_time_t time;

	time.count = cpu_global_time() - global.hw_start;

	return time;
}

static inline uint64_t time_hw_res(void)
{
	/* Promise a bit lower resolution than average cycle counter
	 * frequency */
	return global.hw_freq_hz / 10;
}

static inline uint64_t time_hw_to_ns(odp_time_t time)
{
	uint64_t nsec;
	uint64_t freq_hz = global.hw_freq_hz;
	uint64_t count = time.count;
	uint64_t sec = 0;

	if (count >= freq_hz) {
		sec   = count / freq_hz;
		count = count - sec * freq_hz;
	}

	nsec = (ODP_TIME_SEC_IN_NS * count) / freq_hz;

	return (sec * ODP_TIME_SEC_IN_NS) + nsec;
}

static inline odp_time_t time_hw_from_ns(uint64_t ns)
{
	odp_time_t time;
	uint64_t count;
	uint64_t freq_hz = global.hw_freq_hz;
	uint64_t sec = 0;

	if (ns >= ODP_TIME_SEC_IN_NS) {
		sec = ns / ODP_TIME_SEC_IN_NS;
		ns  = ns - sec * ODP_TIME_SEC_IN_NS;
	}

	count  = sec * freq_hz;
	count += (ns * freq_hz) / ODP_TIME_SEC_IN_NS;

	time.count = count;

	return time;
}

/*
 * Common functions
 */

static inline odp_time_t time_cur(void)
{
	if (global.use_hw)
		return time_hw_cur();

	return time_spec_cur();
}

static inline uint64_t time_res(void)
{
	if (global.use_hw)
		return time_hw_res();

	return time_spec_res();
}

static inline int time_cmp(odp_time_t t2, odp_time_t t1)
{
	if (odp_likely(t2.u64 > t1.u64))
		return 1;

	if (t2.u64 < t1.u64)
		return -1;

	return 0;
}

static inline odp_time_t time_sum(odp_time_t t1, odp_time_t t2)
{
	odp_time_t time;

	time.u64 = t1.u64 + t2.u64;

	return time;
}

static inline uint64_t time_to_ns(odp_time_t time)
{
	if (global.use_hw)
		return time_hw_to_ns(time);

	return time_spec_to_ns(time);
}

static inline odp_time_t time_from_ns(uint64_t ns)
{
	if (global.use_hw)
		return time_hw_from_ns(ns);

	return time_spec_from_ns(ns);
}

static inline void time_wait_until(odp_time_t time)
{
	odp_time_t cur;

	do {
		cur = time_cur();
	} while (time_cmp(time, cur) > 0);
}

odp_time_t odp_time_local(void)
{
	return time_cur();
}

odp_time_t odp_time_global(void)
{
	return time_cur();
}

odp_time_t odp_time_diff(odp_time_t t2, odp_time_t t1)
{
	odp_time_t time;

	time.u64 = t2.u64 - t1.u64;

	return time;
}

uint64_t odp_time_to_ns(odp_time_t time)
{
	return time_to_ns(time);
}

odp_time_t odp_time_local_from_ns(uint64_t ns)
{
	return time_from_ns(ns);
}

odp_time_t odp_time_global_from_ns(uint64_t ns)
{
	return time_from_ns(ns);
}

int odp_time_cmp(odp_time_t t2, odp_time_t t1)
{
	return time_cmp(t2, t1);
}

odp_time_t odp_time_sum(odp_time_t t1, odp_time_t t2)
{
	return time_sum(t1, t2);
}

uint64_t odp_time_local_res(void)
{
	return time_res();
}

uint64_t odp_time_global_res(void)
{
	return time_res();
}

void odp_time_wait_ns(uint64_t ns)
{
	odp_time_t cur = time_cur();
	odp_time_t wait = time_from_ns(ns);
	odp_time_t end_time = time_sum(cur, wait);

	time_wait_until(end_time);
}

void odp_time_wait_until(odp_time_t time)
{
	return time_wait_until(time);
}

int odp_time_init_global(void)
{
	int ret = 0;

	memset(&global, 0, sizeof(time_global_t));

	if (cpu_has_global_time()) {
		global.use_hw = 1;
		global.hw_freq_hz  = cpu_global_time_freq();

		if (global.hw_freq_hz == 0)
			return -1;

		printf("HW time counter freq: %" PRIu64 " hz\n\n",
		       global.hw_freq_hz);

		global.hw_start = cpu_global_time();
		return 0;
	}

	global.spec_start.tv_sec  = 0;
	global.spec_start.tv_nsec = 0;

	ret = clock_gettime(CLOCK_MONOTONIC_RAW, &global.spec_start);

	return ret;
}

int odp_time_term_global(void)
{
	return 0;
}
