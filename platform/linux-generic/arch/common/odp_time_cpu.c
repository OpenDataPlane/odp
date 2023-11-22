/* Copyright (c) 2013-2018, Linaro Limited
 * Copyright (c) 2020-2023, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/time_types.h>

#include <odp/api/abi/time_cpu.h>
#include <odp/api/abi/time_cpu_inlines.h>

#include <odp_debug_internal.h>
#include <odp_init_internal.h>

#include <inttypes.h>
#include <stdint.h>
#include <string.h>

#define YEAR_IN_SEC (365 * 24 * 3600)

#include <odp/visibility_begin.h>

_odp_time_global_t _odp_time_glob;

#include <odp/visibility_end.h>

int _odp_time_init_global(void)
{
	uint64_t count, diff, years;
	odp_time_t time;
	_odp_time_global_t *global = &_odp_time_glob;

	memset(global, 0, sizeof(_odp_time_global_t));

	if (!_odp_time_cpu_global_freq_is_const())
		return -1;

	global->freq_hz  = _odp_time_cpu_global_freq();
	if (global->freq_hz == 0)
		return -1;

	_ODP_PRINT("HW time counter freq: %" PRIu64 " hz\n\n", global->freq_hz);

	count = _odp_time_cpu_global();
	time.count = count;
	global->start_time = count;
	global->start_time_ns = _odp_time_to_ns(time);

	/* Make sure that counters will not wrap */
	diff = UINT64_MAX - count;
	years = (diff / global->freq_hz) / YEAR_IN_SEC;

	if (years < 10) {
		_ODP_ERR("Time counter would wrap in 10 years: %" PRIu64 "\n", count);
		return -1;
	}

	diff = UINT64_MAX - global->start_time_ns;
	years = (diff / ODP_TIME_SEC_IN_NS) / YEAR_IN_SEC;

	if (years < 10) {
		_ODP_ERR("Time in nsec would wrap in 10 years: %" PRIu64 "\n",
			 global->start_time_ns);
		return -1;
	}

	return 0;
}

int _odp_time_term_global(void)
{
	return 0;
}
