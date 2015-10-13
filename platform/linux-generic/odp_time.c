/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#define _POSIX_C_SOURCE 200809L

#include <odp/time.h>
#include <odp/hints.h>
#include <odp/system_info.h>
#include <odp/cpu.h>
#include <odp_cpu_internal.h>

#define GIGA 1000000000

uint64_t odp_time_cycles(void)
{
	return odp_cpu_cycles();
}

uint64_t odp_time_diff_cycles(uint64_t t1, uint64_t t2)
{
	return _odp_cpu_cycles_diff(t1, t2);
}

uint64_t odp_time_cycles_to_ns(uint64_t cycles)
{
	uint64_t hz = odp_cpu_hz_max();

	if (cycles > (UINT64_MAX / GIGA))
		return (cycles/hz)*GIGA;

	return (cycles*GIGA)/hz;
}


uint64_t odp_time_ns_to_cycles(uint64_t ns)
{
	uint64_t hz = odp_cpu_hz_max();

	if (ns > (UINT64_MAX / hz))
		return (ns/GIGA)*hz;

	return (ns*hz)/GIGA;
}
