/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_arch_time_internal.h>

int cpu_has_global_time(void)
{
	return 0;
}

uint64_t cpu_global_time(void)
{
	return 0;
}

uint64_t cpu_global_time_freq(void)
{
	return 0;
}
