/* Copyright (c) 2016-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_sysinfo_internal.h>

int cpuinfo_parser(FILE *file ODP_UNUSED, system_info_t *sysinfo)
{
	return _odp_dummy_cpuinfo(sysinfo);
}

void sys_info_print_arch(void)
{
}

uint64_t odp_cpu_arch_hz_current(int id ODP_UNUSED)
{
	return 0;
}
