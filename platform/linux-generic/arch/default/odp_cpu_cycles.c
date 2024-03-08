/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2015-2018 Linaro Limited
 * Copyright (c) 2021 Nokia
 */

#include <odp_posix_extensions.h>

#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#include <odp_debug_internal.h>
#include <odp_global_data.h>
#include <odp_init_internal.h>

#define GIGA 1000000000

#include <odp/api/abi/cpu_generic.h>

uint64_t _odp_cpu_cycles(void)
{
	struct timespec time;
	uint64_t sec, ns, hz, cycles;
	int ret;

	ret = clock_gettime(CLOCK_MONOTONIC_RAW, &time);

	if (ret != 0)
		_ODP_ABORT("clock_gettime failed\n");

	hz  = odp_global_ro.system_info.cpu_hz_max[0];

	sec = (uint64_t)time.tv_sec;
	ns  = (uint64_t)time.tv_nsec;

	cycles  = sec * hz;
	cycles += (ns * hz) / GIGA;

	return cycles;
}

int _odp_cpu_cycles_init_global(void)
{
	return 0;
}
