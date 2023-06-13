/* Copyright (c) 2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_ARCH_TIME_CPU_H_
#define ODP_ARCH_TIME_CPU_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <odp/api/abi/cpu_rdtsc.h>

static inline uint64_t _odp_time_cpu_global(void)
{
	return _odp_cpu_rdtsc();
}

static inline uint64_t _odp_time_cpu_global_strict(void)
{
	__atomic_thread_fence(__ATOMIC_SEQ_CST);
	return _odp_cpu_rdtsc();
}

int _odp_time_cpu_global_freq_is_const(void);
uint64_t _odp_time_cpu_global_freq(void);

#ifdef __cplusplus
}
#endif

#endif
