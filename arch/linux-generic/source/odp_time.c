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

uint64_t odp_time_get_cycles(void)
{
	/* printf("odp_time_get_cycles(): implementation missing\n"); */
	return 0;
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

	return (cycles*1000000000)/hz;
}


