/* Copyright (c) 2013-2018, Linaro Limited
 * Copyright (c) 2020-2023, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/time_types.h>

#include <odp/api/abi/time_cpu.h>
#include <odp/api/abi/time_cpu_inlines.h>

#include <odp_debug_internal.h>
#include <odp_init_internal.h>

#include <inttypes.h>
#include <stdint.h>
#include <string.h>

#include <odp/visibility_begin.h>

_odp_time_global_t _odp_time_glob;

#include <odp/visibility_end.h>

int _odp_time_init_global(void)
{
	_odp_time_global_t *global = &_odp_time_glob;

	memset(global, 0, sizeof(_odp_time_global_t));

	if (!_odp_time_cpu_global_freq_const())
		_ODP_ERR("HW time frequency may change\n");

	global->freq_hz  = _odp_time_cpu_global_freq();
	if (global->freq_hz == 0)
		return -1;

	_ODP_PRINT("HW time counter freq: %" PRIu64 " hz\n\n", global->freq_hz);

	global->start_time = _odp_time_cpu_global();
	return 0;
}

int _odp_time_term_global(void)
{
	return 0;
}
