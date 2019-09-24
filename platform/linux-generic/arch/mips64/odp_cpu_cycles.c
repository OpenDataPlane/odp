/* Copyright (c) 2015-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/cpu.h>
#include <odp/api/hints.h>
#include <odp/api/system_info.h>
#include <odp_init_internal.h>

uint64_t odp_cpu_cycles(void)
{
	#define CVMX_TMP_STR(x) CVMX_TMP_STR2(x)
	#define CVMX_TMP_STR2(x) #x
	uint64_t cycle;

	__asm__ __volatile__ ("rdhwr %[rt],$" CVMX_TMP_STR(31) :
			   [rt] "=d" (cycle) : : "memory");

	return cycle;
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
