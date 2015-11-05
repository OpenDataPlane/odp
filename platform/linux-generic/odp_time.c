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

static inline
uint64_t time_to_tick(odp_time_t time)
{
	return (uint64_t)time;
}

static inline
odp_time_t tick_to_time(uint64_t tick)
{
	return (odp_time_t)tick;
}

odp_time_t odp_time_local(void)
{
	return tick_to_time(odp_cpu_cycles());
}

odp_time_t odp_time_diff(odp_time_t t2, odp_time_t t1)
{
	return tick_to_time(_odp_cpu_cycles_diff(t2, t1));
}

uint64_t odp_time_to_ns(odp_time_t time)
{
	uint64_t hz = odp_cpu_hz_max();
	uint64_t tick = time_to_tick(time);

	if (tick > (UINT64_MAX / GIGA))
		return (tick / hz) * GIGA;

	return (tick * GIGA) / hz;
}


odp_time_t odp_time_local_from_ns(uint64_t ns)
{
	uint64_t hz = odp_cpu_hz_max();

	if (ns > (UINT64_MAX / hz))
		return tick_to_time((ns / GIGA) * hz);

	return tick_to_time((ns * hz) / GIGA);
}

int odp_time_cmp(odp_time_t t2, odp_time_t t1)
{
	uint64_t tick1 = time_to_tick(t1);
	uint64_t tick2 = time_to_tick(t2);

	if (tick1 < tick2)
		return 1;

	if (tick1 > tick2)
		return -1;

	return 0;
}

odp_time_t odp_time_sum(odp_time_t t1, odp_time_t t2)
{
	uint64_t tick1 = time_to_tick(t1);
	uint64_t tick2 = time_to_tick(t2);

	return tick_to_time(tick1 + tick2);
}

uint64_t odp_time_to_u64(odp_time_t hdl)
{
	return time_to_tick(hdl);
}
