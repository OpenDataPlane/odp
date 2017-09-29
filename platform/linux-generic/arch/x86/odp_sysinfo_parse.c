/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "config.h"

#include <odp_internal.h>
#include <cpu_flags.h>
#include <string.h>

int cpuinfo_parser(FILE *file, system_info_t *sysinfo)
{
	char str[1024];
	char *pos;
	double ghz = 0.0;
	uint64_t hz;
	int id = 0;

	strcpy(sysinfo->cpu_arch_str, "x86");
	while (fgets(str, sizeof(str), file) != NULL && id < MAX_CPU_NUMBER) {
		pos = strstr(str, "model name");
		if (pos) {
			pos = strchr(str, ':');
			strncpy(sysinfo->model_str[id], pos + 2,
				sizeof(sysinfo->model_str[id]) - 1);

			pos = strchr(sysinfo->model_str[id], '@');
			if (pos) {
				*(pos - 1) = '\0';
				if (sscanf(pos, "@ %lfGHz", &ghz) == 1) {
					hz = (uint64_t)(ghz * 1000000000.0);
					sysinfo->cpu_hz_max[id] = hz;
				}
			}
			id++;
		}
	}

	return 0;
}

void sys_info_print_arch(void)
{
	cpu_flags_print_all();
}
