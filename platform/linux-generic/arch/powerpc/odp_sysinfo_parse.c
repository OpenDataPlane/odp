/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2018 Linaro Limited
 */

#include <odp_global_data.h>
#include <odp_sysinfo_internal.h>
#include <odp_string_internal.h>
#include <string.h>

int _odp_cpuinfo_parser(FILE *file, system_info_t *sysinfo)
{
	char str[1024];
	char *pos;
	double mhz = 0.0;
	uint64_t hz;
	int model = 0;
	int count = 2;
	int id = 0;

	sysinfo->cpu_arch       = ODP_CPU_ARCH_PPC;
	sysinfo->cpu_isa_sw.ppc = ODP_CPU_ARCH_PPC_UNKNOWN;
	sysinfo->cpu_isa_hw.ppc = ODP_CPU_ARCH_PPC_UNKNOWN;

	strcpy(sysinfo->cpu_arch_str, "powerpc");
	while (fgets(str, sizeof(str), file) != NULL && id < CONFIG_NUM_CPU_IDS) {
		if (!mhz) {
			pos = strstr(str, "clock");

			if (pos)
				if (sscanf(pos, "clock : %lf", &mhz) == 1) {
					hz = (uint64_t)(mhz * 1000000.0);
					sysinfo->cpu_hz_max[id] = hz;
					count--;
				}
		}

		if (!model) {
			pos = strstr(str, "cpu");

			if (pos) {
				pos = strchr(str, ':');
				_odp_strcpy(sysinfo->model_str[id], pos + 2,
					    MODEL_STR_SIZE);
				model = 1;
				count--;
			}
		}

		if (count == 0) {
			mhz = 0.0;
			model = 0;
			count = 2;
			id++;
		}
	}

	return 0;
}

void _odp_sys_info_print_arch(void)
{
}

uint64_t odp_cpu_arch_hz_current(int id ODP_UNUSED)
{
	return odp_global_ro.system_info.default_cpu_hz;
}
