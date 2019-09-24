/* Copyright (c) 2015-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_posix_extensions.h>

#include <stdlib.h>
#include <time.h>

#include <odp/api/cpu.h>
#include <odp_debug_internal.h>
#include <odp_init_internal.h>

#define GIGA 1000000000

uint64_t odp_cpu_cycles(void)
{
	struct timespec time;
	uint64_t sec, ns, hz, cycles;
	int ret;

	ret = clock_gettime(CLOCK_MONOTONIC_RAW, &time);

	if (ret != 0)
		ODP_ABORT("clock_gettime failed\n");

	hz  = odp_cpu_hz_max();
	sec = (uint64_t)time.tv_sec;
	ns  = (uint64_t)time.tv_nsec;

	cycles  = sec * hz;
	cycles += (ns * hz) / GIGA;

	return cycles;
}

uint64_t odp_cpu_cycles_max(void)
{
	return UINT64_MAX;
}

uint64_t odp_cpu_cycles_resolution(void)
{
	return 1;
}

int _odp_cpu_cycles_init_global(void)
{
	return 0;
}
