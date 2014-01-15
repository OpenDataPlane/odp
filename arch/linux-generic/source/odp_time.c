/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


#include <odp_time.h>
#include <odp_hints.h>
#include <odp_system_info.h>

#include <stdio.h>


#if defined __x86_64__ || defined __i386__

uint64_t odp_time_get_cycles(void)
{
	union {
		uint64_t tsc_64;
		struct {
			uint32_t lo_32;
			uint32_t hi_32;
		};
	} tsc;

	asm volatile("rdtsc" :
		     "=a" (tsc.lo_32),
		     "=d" (tsc.hi_32));

	return tsc.tsc_64;
}

#else

#include <time.h>
#include <stdlib.h>

uint64_t odp_time_get_cycles(void)
{
	struct timespec time;
	uint64_t sec, ns, hz, cycles;
	int ret;

	ret = clock_gettime(CLOCK_MONOTONIC_RAW, &time);

	if (ret != 0) {
		printf("clock_gettime failed\n");
		exit(EXIT_FAILURE);
	}

	hz  = odp_sys_cpu_hz();
	sec = (uint64_t) time.tv_sec;
	ns  = (uint64_t) time.tv_nsec;

	cycles  = sec * hz;
	cycles += (ns * hz) / 1000000000;

	return cycles;
}

#endif


uint64_t odp_time_diff_cycles(uint64_t t1, uint64_t t2)
{
	if (odp_likely(t2 > t1))
		return t2 - t1;

	return t2 + (UINT64_MAX - t1);
}


uint64_t odp_time_cycles_to_ns(uint64_t cycles)
{
	uint64_t hz = odp_sys_cpu_hz();

	if (cycles > hz)
		return 1000000000*(cycles/hz);

	return (1000000000*cycles)/hz;
}


