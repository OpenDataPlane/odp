/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_internal.h>
#include <string.h>

int odp_cpuinfo_parser(FILE *file, odp_system_info_t *sysinfo)
{
	char str[1024];
	char *pos;
	double mhz = 0.0;
	int model = 0;
	int count = 2;

	while (fgets(str, sizeof(str), file) != NULL && count > 0) {
		if (!mhz) {
			pos = strstr(str, "BogoMIPS");

			if (pos)
				if (sscanf(pos, "BogoMIPS : %lf", &mhz) == 1)
					count--;
		}

		if (!model) {
			pos = strstr(str, "cpu model");

			if (pos) {
				int len;

				pos = strchr(str, ':');
				strncpy(sysinfo->model_str[0], pos + 2,
					sizeof(sysinfo->model_str[0]));
				len = strlen(sysinfo->model_str[0]);
				sysinfo->model_str[0][len - 1] = 0;
				model = 1;
				count--;
			}
		}
	}

	/* bogomips seems to be 2x freq */
	sysinfo->cpu_hz[0] = (uint64_t)(mhz * 1000000.0 / 2.0);

	return 0;
}

uint64_t odp_cpu_hz_current(int id ODP_UNUSED)
{
	return -1;
}
