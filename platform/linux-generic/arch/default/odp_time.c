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

#include <stdint.h>
#include <string.h>
#include <time.h>

typedef struct _odp_time_global_t {
	struct timespec start_time;

} _odp_time_global_t;

_odp_time_global_t _odp_time_glob;

static inline uint64_t time_diff_nsec(struct timespec *t2, struct timespec *t1)
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

#include <odp/visibility_begin.h>

odp_time_t _odp_time_cur(void)
{
	int ret;
	odp_time_t time;
	struct timespec sys_time;
	struct timespec *start_time = &_odp_time_glob.start_time;

	ret = clock_gettime(CLOCK_MONOTONIC_RAW, &sys_time);
	if (odp_unlikely(ret != 0))
		_ODP_ABORT("clock_gettime() failed\n");

	time.nsec = time_diff_nsec(&sys_time, start_time);

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

#include <odp/visibility_end.h>

int _odp_time_init_global(void)
{
	struct timespec *start_time;
	int ret = 0;
	_odp_time_global_t *global = &_odp_time_glob;

	memset(global, 0, sizeof(_odp_time_global_t));

	start_time = &global->start_time;
	start_time->tv_sec  = 0;
	start_time->tv_nsec = 0;

	ret = clock_gettime(CLOCK_MONOTONIC_RAW, start_time);
	if (ret)
		_ODP_ERR("clock_gettime() failed: %d\n", ret);

	return ret;
}

int _odp_time_term_global(void)
{
	return 0;
}
