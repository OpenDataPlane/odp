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
#include <rte_cycles.h>
#include <string.h>

typedef union {
	odp_time_t      ex;
	struct timespec in;
} _odp_time_t;

static odp_time_t start_time;
static time_handler_t time_handler;

static inline uint64_t time_local_res_dpdk(void)
{
	return rte_get_timer_hz();
}

static inline
uint64_t time_to_ns(odp_time_t time)
{
	uint64_t ns;

	ns = time.tv_sec * ODP_TIME_SEC_IN_NS;
	ns += time.tv_nsec;

	return ns;
}

static inline uint64_t time_to_ns_dpdk(odp_time_t time)
{
	return (time.ticks * ODP_TIME_SEC_IN_NS / time_local_res_dpdk());
}

static inline odp_time_t time_diff(odp_time_t t2, odp_time_t t1)
{
	odp_time_t time;

	time.tv_sec = t2.tv_sec - t1.tv_sec;
	time.tv_nsec = t2.tv_nsec - t1.tv_nsec;

	if (time.tv_nsec < 0) {
		time.tv_nsec += ODP_TIME_SEC_IN_NS;
		--time.tv_sec;
	}

	return time;
}

static inline odp_time_t time_diff_dpdk(odp_time_t t2, odp_time_t t1)
{
	odp_time_t time;

	time.ticks = t2.ticks - t1.ticks;
	return time;
}

static inline odp_time_t time_curr(void)
{
	int ret;
	_odp_time_t time;

	ret = clock_gettime(CLOCK_MONOTONIC_RAW, &time.in);
	if (odp_unlikely(ret != 0))
		ODP_ABORT("clock_gettime failed\n");
	return time.ex;
}

static inline odp_time_t time_curr_dpdk(void)
{
	odp_time_t time;

	time.ticks = rte_get_timer_cycles();
	return time;
}

static inline odp_time_t time_local(void)
{
	odp_time_t time;

	time = time_handler.time_curr();
	return time_handler.time_diff(time, start_time);
}

static inline int time_cmp(odp_time_t t2, odp_time_t t1)
{
	if (t2.tv_sec < t1.tv_sec)
		return -1;

	if (t2.tv_sec > t1.tv_sec)
		return 1;

	return t2.tv_nsec - t1.tv_nsec;
}

static inline int time_cmp_dpdk(odp_time_t t2, odp_time_t t1)
{
	if (t2.ticks < t1.ticks)
		return -1;
	if (t2.ticks > t1.ticks)
		return 1;
	return 0;
}

static inline odp_time_t time_sum(odp_time_t t1, odp_time_t t2)
{
	odp_time_t time;

	time.tv_sec = t2.tv_sec + t1.tv_sec;
	time.tv_nsec = t2.tv_nsec + t1.tv_nsec;

	if (time.tv_nsec >= (long)ODP_TIME_SEC_IN_NS) {
		time.tv_nsec -= ODP_TIME_SEC_IN_NS;
		++time.tv_sec;
	}

	return time;
}

static inline odp_time_t time_sum_dpdk(odp_time_t t1, odp_time_t t2)
{
	odp_time_t time;

	time.ticks = t2.ticks + t1.ticks;
	return time;
}

static inline odp_time_t time_local_from_ns(uint64_t ns)
{
	odp_time_t time;

	time.tv_sec = ns / ODP_TIME_SEC_IN_NS;
	time.tv_nsec = ns - time.tv_sec * ODP_TIME_SEC_IN_NS;

	return time;
}

static inline odp_time_t time_local_from_ns_dpdk(uint64_t ns)
{
	odp_time_t time;

	time.ticks = ns * time_local_res_dpdk() / ODP_TIME_SEC_IN_NS;
	return time;
}

static inline void time_wait_until(odp_time_t time)
{
	odp_time_t cur;

	do {
		cur = time_local();
	} while (time_handler.time_cmp(time, cur) > 0);
}

static inline uint64_t time_local_res(void)
{
	int ret;
	struct timespec tres;

	ret = clock_getres(CLOCK_MONOTONIC_RAW, &tres);
	if (odp_unlikely(ret != 0))
		ODP_ABORT("clock_getres failed\n");

	return ODP_TIME_SEC_IN_NS / (uint64_t)tres.tv_nsec;
}

odp_time_t odp_time_local(void)
{
	return time_local();
}

odp_time_t odp_time_global(void)
{
	return time_local();
}

odp_time_t odp_time_diff(odp_time_t t2, odp_time_t t1)
{
	return time_handler.time_diff(t2, t1);
}

uint64_t odp_time_to_ns(odp_time_t time)
{
	return time_handler.time_to_ns(time);
}

odp_time_t odp_time_local_from_ns(uint64_t ns)
{
	return time_handler.time_local_from_ns(ns);
}

odp_time_t odp_time_global_from_ns(uint64_t ns)
{
	return time_handler.time_local_from_ns(ns);
}

int odp_time_cmp(odp_time_t t2, odp_time_t t1)
{
	return time_handler.time_cmp(t2, t1);
}

odp_time_t odp_time_sum(odp_time_t t1, odp_time_t t2)
{
	return time_handler.time_sum(t1, t2);
}

uint64_t odp_time_local_res(void)
{
	return time_handler.time_local_res();
}

uint64_t odp_time_global_res(void)
{
	return time_handler.time_local_res();
}

void odp_time_wait_ns(uint64_t ns)
{
	odp_time_t cur = time_local();
	odp_time_t wait = time_handler.time_local_from_ns(ns);
	odp_time_t end_time = time_handler.time_sum(cur, wait);

	time_wait_until(end_time);
}

void odp_time_wait_until(odp_time_t time)
{
	return time_wait_until(time);
}

static uint64_t time_to_u64(odp_time_t time)
{
	int ret;
	struct timespec tres;
	uint64_t resolution;

	ret = clock_getres(CLOCK_MONOTONIC_RAW, &tres);
	if (odp_unlikely(ret != 0))
		ODP_ABORT("clock_getres failed\n");

	resolution = (uint64_t)tres.tv_nsec;

	return time_handler.time_to_ns(time) / resolution;
}

static uint64_t time_to_u64_dpdk(odp_time_t time)
{
	return time.ticks;
}

uint64_t odp_time_to_u64(odp_time_t time)
{
	return time_handler.time_to_u64(time);
}

static odp_bool_t is_invariant_tsc_supported(void)
{
	FILE  *file;
	char  *line = NULL;
	size_t len = 0;
	odp_bool_t nonstop_tsc  = false;
	odp_bool_t constant_tsc = false;
	odp_bool_t ret = false;

	file = fopen("/proc/cpuinfo", "rt");
	while (getline(&line, &len, file) != -1) {
		if (strstr(line, "flags") != NULL) {
			if (strstr(line, "constant_tsc") != NULL)
				constant_tsc = true;
			if (strstr(line, "nonstop_tsc") != NULL)
				nonstop_tsc = true;

			if (constant_tsc && nonstop_tsc)
				ret = true;
			else
				ret = false;

			free(line);
			fclose(file);
			return ret;
		}
	}
	free(line);
	fclose(file);
	return false;
}

static inline odp_bool_t is_dpdk_timer_cycles_support(void)
{
	if (is_invariant_tsc_supported() == true)
		return true;

#ifdef RTE_LIBEAL_USE_HPET
	if (rte_eal_hpet_init(1) == 0)
		return true;
#endif
	return false;
}

int odp_time_init_global(void)
{
	if (is_dpdk_timer_cycles_support()) {
		time_handler.time_to_ns         = time_to_ns_dpdk;
		time_handler.time_diff          = time_diff_dpdk;
		time_handler.time_curr          = time_curr_dpdk;
		time_handler.time_cmp           = time_cmp_dpdk;
		time_handler.time_sum           = time_sum_dpdk;
		time_handler.time_local_from_ns = time_local_from_ns_dpdk;
		time_handler.time_local_res     = time_local_res_dpdk;
		time_handler.time_to_u64        = time_to_u64_dpdk;
	} else {
		time_handler.time_to_ns         = time_to_ns;
		time_handler.time_diff          = time_diff;
		time_handler.time_curr          = time_curr;
		time_handler.time_cmp           = time_cmp;
		time_handler.time_sum           = time_sum;
		time_handler.time_local_from_ns = time_local_from_ns;
		time_handler.time_local_res     = time_local_res;
		time_handler.time_to_u64        = time_to_u64;
	}

	start_time = time_handler.time_curr();
	if (time_handler.time_cmp(start_time, ODP_TIME_NULL) == 0) {
		ODP_ABORT("initiate odp time failed\n");
		return -1;
	} else {
		return 0;
	}
}

int odp_time_term_global(void)
{
	return 0;
}
