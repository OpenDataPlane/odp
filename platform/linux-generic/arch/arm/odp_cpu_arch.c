/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "config.h"

#include <odp_posix_extensions.h>

#include <stdlib.h>
#include <time.h>

#include <odp/api/cpu.h>
#include <odp/api/hints.h>
#include <odp/api/system_info.h>
#include <odp_debug_internal.h>
#include <odp_time_internal.h>

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

int cpu_has_global_time(void)
{
	uint64_t hz = cpu_global_time_freq();

	/*
	 * The system counter portion of the architected timer must
	 * provide a uniform view of system time to all processing
	 * elements in the system. This should hold true even for
	 * heterogeneous SoCs.
	 *
	 * Determine whether the system has 'global time' by checking
	 * whether a read of the architected timer frequency sys reg
	 * returns a sane value. Sane is considered to be within
	 * 1MHz and 6GHz (1us and .1667ns period).
	 */
	return hz >= 1000000 && hz <= 6000000000;
}

uint64_t cpu_global_time(void)
{
#ifdef __aarch64__
	uint64_t cntvct;

	/*
	 * To be consistent with other architectures, do not issue a
	 * serializing instruction, e.g. ISB, before reading this
	 * sys reg.
	 */

	/* Memory clobber to minimize optimization around load from sys reg. */
	__asm__ volatile("mrs %0, cntvct_el0" : "=r"(cntvct) : : "memory");

	return cntvct;
#else
	return 0;
#endif
}

uint64_t cpu_global_time_freq(void)
{
#ifdef __aarch64__
	uint64_t cntfrq;

	__asm__ volatile("mrs %0, cntfrq_el0" : "=r"(cntfrq) : : );

	return cntfrq;
#else
	return 0;
#endif
}
