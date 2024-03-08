/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2015-2018 Linaro Limited
 * Copyright (c) 2021 Nokia
 */

#ifndef ODP_API_ABI_CPU_GENERIC_H_
#define ODP_API_ABI_CPU_GENERIC_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

uint64_t _odp_cpu_cycles(void);
int _odp_cpu_cycles_init_global(void);

static inline uint64_t _odp_cpu_cycles_max(void)
{
	return UINT64_MAX;
}

static inline uint64_t _odp_cpu_cycles_resolution(void)
{
	return 1;
}

#ifdef __cplusplus
}
#endif

#endif
