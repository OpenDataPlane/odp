/* Copyright (c) 2016-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_sysinfo_internal.h>
#include "cpu_flags.h"
#include <string.h>

int cpuinfo_parser(FILE *file, system_info_t *sysinfo)
{
	char str[1024];
	char *pos, *pos_end;
	double ghz = 0.0;
	double mhz = 0.0;
	uint64_t hz;
	int id = 0;
	bool freq_set = false;

	strcpy(sysinfo->cpu_arch_str, "x86");
	while (fgets(str, sizeof(str), file) != NULL && id < CONFIG_NUM_CPU) {
		pos = strstr(str, "model name");
		if (pos) {
			freq_set = false;

			/* Copy model name between : and @ characters */
			pos     = strchr(str, ':');
			pos_end = strchr(str, '@');
			if (pos == NULL)
				continue;

			if (pos_end != NULL)
				*(pos_end - 1) = '\0';

			strncpy(sysinfo->model_str[id], pos + 2,
				MODEL_STR_SIZE - 1);

			if (sysinfo->cpu_hz_max[id]) {
				freq_set = true;
				id++;
				continue;
			}

			/* max frequency needs to be set */
			if (pos_end != NULL &&
			    sscanf(pos_end, "@ %lfGHz", &ghz) == 1) {
				hz = (uint64_t)(ghz * 1000000000.0);
				sysinfo->cpu_hz_max[id++] = hz;
				freq_set = true;
			}
		} else if (!freq_set &&
			   strstr(str, "bogomips") != NULL) {
			pos     = strchr(str, ':');
			if (pos == NULL)
				continue;

			if (sscanf(pos + 2, "%lf", &mhz) == 1) {
				/* On typical x86 BogoMIPS is freq * 2 */
				hz = (uint64_t)(mhz * 1000000.0 / 2);
				sysinfo->cpu_hz_max[id++] = hz;
				freq_set = true;
			}
		}
	}

	return 0;
}

void sys_info_print_arch(void)
{
	cpu_flags_print_all();
}

uint64_t odp_cpu_arch_hz_current(int id)
{
	char str[1024];
	FILE *file;
	int cpu;
	char *pos;
	double mhz = 0.0;

	file = fopen("/proc/cpuinfo", "rt");
	if (!file)
		return 0;

	/* find the correct processor instance */
	while (fgets(str, sizeof(str), file) != NULL) {
		pos = strstr(str, "processor");
		if (pos) {
			if (sscanf(pos, "processor : %d", &cpu) == 1)
				if (cpu == id)
					break;
		}
	}

	/* extract the cpu current speed */
	while (fgets(str, sizeof(str), file) != NULL) {
		pos = strstr(str, "cpu MHz");
		if (pos) {
			if (sscanf(pos, "cpu MHz : %lf", &mhz) == 1)
				break;
		}
	}

	fclose(file);
	if (mhz)
		return (uint64_t)(mhz * 1000000.0);

	return 0;
}
