/* Copyright (c) 2013-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_SYSINFO_INTERNAL_H_
#define ODP_SYSINFO_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp_global_data.h>

int cpuinfo_parser(FILE *file, system_info_t *sysinfo);
uint64_t odp_cpufreq_id(const char *filename, int id);
uint64_t odp_cpu_hz_current(int id);
uint64_t odp_cpu_arch_hz_current(int id);
void sys_info_print_arch(void);

#ifdef __cplusplus
}
#endif

#endif
