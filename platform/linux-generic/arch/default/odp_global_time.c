/* Copyright (c) 2015-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/abi/cpu_time.h>

#include <odp/visibility_begin.h>

uint64_t _odp_cpu_global_time(void)
{
	return 0;
}

#include <odp/visibility_end.h>

int _odp_cpu_has_global_time(void)
{
	return 0;
}

uint64_t _odp_cpu_global_time_freq(void)
{
	return 0;
}
