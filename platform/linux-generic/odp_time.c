/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_time.h>
#include <odp_hints.h>
#include <odp_system_info.h>

#define GIGA 1000000000

#if defined __x86_64__ || defined __i386__

uint64_t odp_time_cycles(void)
{
	union {
		uint64_t tsc_64;
		struct {
			uint32_t lo_32;
			uint32_t hi_32;
		};
	} tsc;

	__asm__ __volatile__ ("rdtsc" :
		     "=a" (tsc.lo_32),
		     "=d" (tsc.hi_32) : : "memory");

	return tsc.tsc_64;
}


#elif defined __OCTEON__

uint64_t odp_time_cycles(void)
{
	#define CVMX_TMP_STR(x) CVMX_TMP_STR2(x)
	#define CVMX_TMP_STR2(x) #x
	uint64_t cycle;

	__asm__ __volatile__ ("rdhwr %[rt],$" CVMX_TMP_STR(31) :
			   [rt] "=d" (cycle) : : "memory");

	return cycle;
}

#else

#include <time.h>
#include <stdlib.h>
#include <odp_debug_internal.h>

uint64_t odp_time_cycles(void)
{
	struct timespec time;
	uint64_t sec, ns, hz, cycles;
	int ret;

	ret = clock_gettime(CLOCK_MONOTONIC_RAW, &time);

	if (ret != 0) {
		ODP_ABORT("clock_gettime failed\n");
	}

	hz  = odp_sys_cpu_hz();
	sec = (uint64_t) time.tv_sec;
	ns  = (uint64_t) time.tv_nsec;

	cycles  = sec * hz;
	cycles += (ns * hz) / GIGA;

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

	if (cycles > (UINT64_MAX / GIGA))
		return (cycles/hz)*GIGA;

	return (cycles*GIGA)/hz;
}


uint64_t odp_time_ns_to_cycles(uint64_t ns)
{
	uint64_t hz = odp_sys_cpu_hz();

	if (ns > (UINT64_MAX / hz))
		return (ns/GIGA)*hz;

	return (ns*hz)/GIGA;
}
