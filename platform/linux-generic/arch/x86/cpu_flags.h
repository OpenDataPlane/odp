/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2017-2018 Linaro Limited
 */

#ifndef ODP_PLAT_CPU_FLAGS_H_
#define ODP_PLAT_CPU_FLAGS_H_

#ifdef __cplusplus
extern "C" {
#endif

void _odp_cpu_flags_print_all(void);
int _odp_cpu_flags_has_rdtsc(void);

#ifdef __cplusplus
}
#endif

#endif
