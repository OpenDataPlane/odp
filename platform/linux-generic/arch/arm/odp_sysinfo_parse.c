/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020 Nokia
 */

#include <odp_global_data.h>
#include <odp_sysinfo_internal.h>

int _odp_cpuinfo_parser(FILE *file ODP_UNUSED, system_info_t *sysinfo)
{
	sysinfo->cpu_arch = ODP_CPU_ARCH_ARM;
	sysinfo->cpu_isa_sw.arm = ODP_CPU_ARCH_ARM_UNKNOWN;
	sysinfo->cpu_isa_hw.arm = ODP_CPU_ARCH_ARM_UNKNOWN;

#if defined(__ARM_ARCH)
	if (__ARM_ARCH == 6)
		sysinfo->cpu_isa_sw.arm = ODP_CPU_ARCH_ARMV6;
	else if (__ARM_ARCH == 7)
		sysinfo->cpu_isa_sw.arm = ODP_CPU_ARCH_ARMV7;
#endif

	return _odp_dummy_cpuinfo(sysinfo);
}

void _odp_sys_info_print_arch(void)
{
}

uint64_t odp_cpu_arch_hz_current(int id ODP_UNUSED)
{
	return odp_global_ro.system_info.default_cpu_hz;
}
