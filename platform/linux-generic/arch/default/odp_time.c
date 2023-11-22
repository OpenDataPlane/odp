/* Copyright (c) 2013-2018, Linaro Limited
 * Copyright (c) 2020-2023, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_posix_extensions.h>

#include <odp/api/align.h>
#include <odp/api/hints.h>
#include <odp/api/time_types.h>

#include <odp/api/abi/time_inlines.h>

#include <odp_debug_internal.h>
#include <odp_init_internal.h>

#include <inttypes.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#define YEAR_IN_SEC (365 * 24 * 3600)

typedef struct _odp_time_global_t {
	struct timespec start_time;
	uint64_t start_time_ns;

} _odp_time_global_t;

_odp_time_global_t _odp_time_glob;

static inline uint64_t time_nsec(struct timespec *t)
{
	uint64_t nsec = (t->tv_sec * ODP_TIME_SEC_IN_NS) + t->tv_nsec;

	return nsec;
}

#include <odp/visibility_begin.h>

odp_time_t _odp_time_cur(void)
{
	int ret;
	odp_time_t time;
	struct timespec sys_time;

	ret = clock_gettime(CLOCK_MONOTONIC_RAW, &sys_time);
	if (odp_unlikely(ret != 0))
		_ODP_ABORT("clock_gettime() failed\n");

	time.nsec = time_nsec(&sys_time);

	return time;
}

uint64_t _odp_time_res(void)
{
	int ret;
	struct timespec tres;

	ret = clock_getres(CLOCK_MONOTONIC_RAW, &tres);
	if (odp_unlikely(ret != 0))
		_ODP_ABORT("clock_getres() failed\n");

	return ODP_TIME_SEC_IN_NS / (uint64_t)tres.tv_nsec;
}

void _odp_time_startup(odp_time_startup_t *startup)
{
	startup->global.nsec = _odp_time_glob.start_time_ns;
	startup->global_ns   = _odp_time_glob.start_time_ns;
}

#include <odp/visibility_end.h>

int _odp_time_init_global(void)
{
	struct timespec *start_time;
	uint64_t diff, years;
	int ret = 0;
	_odp_time_global_t *global = &_odp_time_glob;

	memset(global, 0, sizeof(_odp_time_global_t));

	start_time = &global->start_time;
	start_time->tv_sec  = 0;
	start_time->tv_nsec = 0;

	ret = clock_gettime(CLOCK_MONOTONIC_RAW, start_time);
	if (ret)
		_ODP_ERR("clock_gettime() failed: %d\n", ret);

	global->start_time_ns = time_nsec(start_time);

	diff = UINT64_MAX - global->start_time_ns;
	years = (diff / ODP_TIME_SEC_IN_NS) / YEAR_IN_SEC;

	if (years < 10) {
		_ODP_ERR("Time in nsec would wrap in 10 years: %" PRIu64 "\n",
			 global->start_time_ns);
		return -1;
	}

	return ret;
}

int _odp_time_term_global(void)
{
	return 0;
}
