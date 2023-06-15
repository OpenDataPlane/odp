/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Nokia
 */

#include <odp/api/cpu.h>

#include <odp/api/abi/cpu_inlines.h>
#include <odp/api/abi/time_cpu.h>

#include <odp_debug_internal.h>
#include <odp_init_internal.h>

#include <string.h>

#include <odp/visibility_begin.h>

_odp_cpu_cycles_global_t _odp_cpu_cycles_glob;

#include <odp/visibility_end.h>

int _odp_cpu_cycles_init_global(void)
{
	uint64_t cpu_hz, cpu_time_hz;

	memset(&_odp_cpu_cycles_glob, 0, sizeof(_odp_cpu_cycles_global_t));

	cpu_time_hz = _odp_time_cpu_global_freq();
	if (cpu_time_hz == 0) {
		_ODP_ERR("CPU time counter frequency not available\n");
		return -1;
	}

	cpu_hz = odp_cpu_hz_max_id(0);
	if (cpu_hz == 0) {
		_ODP_ERR("CPU frequency not available\n");
		return -1;
	}

	_odp_cpu_cycles_glob.res_shifted = (cpu_hz << _ODP_CPU_FREQ_SHIFT) / cpu_time_hz;

	_odp_cpu_cycles_glob.res = cpu_hz > cpu_time_hz ?
		(_odp_cpu_cycles_glob.res_shifted >> _ODP_CPU_FREQ_SHIFT) : 1;

	_odp_cpu_cycles_glob.max = (UINT64_MAX >> _ODP_CPU_FREQ_SHIFT) -
				   (UINT64_MAX % _odp_cpu_cycles_glob.res);

	return 0;
}
