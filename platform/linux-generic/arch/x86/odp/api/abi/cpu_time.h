/* Copyright (c) 2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_ARCH_CPU_TIME_H_
#define ODP_ARCH_CPU_TIME_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <odp/api/abi/cpu_rdtsc.h>

static inline uint64_t _odp_cpu_global_time(void)
{
	return _odp_cpu_rdtsc();
}

int _odp_cpu_has_global_time(void);
uint64_t _odp_cpu_global_time_freq(void);

#ifdef __cplusplus
}
#endif

#endif
