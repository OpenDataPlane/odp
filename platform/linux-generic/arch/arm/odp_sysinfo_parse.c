/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_internal.h>
#include <odp_debug_internal.h>
#include <string.h>

int cpuinfo_parser(FILE *file ODP_UNUSED, system_info_t *sysinfo)
{
	int i;
	FILE *fp;
	char path[256], buffer[256], *endptr = NULL;

	for (i = 0; i < MAX_CPU_NUMBER; i++) {
		sysinfo->cpu_hz_max[i] = 1400000000;
		strcpy(sysinfo->model_str[i], "UNKNOWN");

		snprintf(path, sizeof(path),
			 "/sys/devices/system/cpu/cpu%d/cpufreq/cpuinfo_max_freq",
			 i);

		fp = fopen(path, "r");
		if (fp == NULL) {
			ODP_DBG("Warning: use dummy values for freq\n");
			continue;
		}

		if (fgets(buffer, sizeof(buffer), fp) == NULL)
			ODP_DBG("Warning: use dummy values for freq\n");
		else
			sysinfo->cpu_hz_max[i] = strtoull(buffer, &endptr, 0);

		fclose(fp);
	}

	return 0;
}

uint64_t odp_cpu_hz_current(int id ODP_UNUSED)
{
	FILE *fp;
	char path[256], buffer[256], *endptr = NULL;

	snprintf(path, sizeof(path),
		 "/sys/devices/system/cpu/cpu%d/cpufreq/cpuinfo_cur_freq", id);

	fp = fopen(path, "r");
	if (fp == NULL)
		return 0;

	if (fgets(buffer, sizeof(buffer), fp) == NULL) {
		fclose(fp);
		return 0;
	}

	fclose(fp);

	return strtoull(buffer, &endptr, 0);
}

void sys_info_print_arch(void)
{
}
