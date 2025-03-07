/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 Nokia
 */

#ifndef ODP_API_ABI_TIME_CPU_H_
#define ODP_API_ABI_TIME_CPU_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

static inline uint64_t _odp_time_cpu_global(void)
{
	uint64_t cntvct;

	__asm__ volatile("mrs %0, cntvct_el0" : "=r"(cntvct) : : "memory");

	return cntvct;
}

static inline uint64_t _odp_time_cpu_global_strict(void)
{
	uint64_t cntvct;

	__asm__ volatile("isb" ::: "memory");
	__asm__ volatile("mrs %0, cntvct_el0" : "=r"(cntvct) : : "memory");

	return cntvct;
}

static inline uint64_t _odp_time_cpu_global_freq(void)
{
	uint64_t cntfrq;

	__asm__ volatile("mrs %0, cntfrq_el0" : "=r"(cntfrq) : : );

	return cntfrq;
}

static inline int _odp_time_cpu_global_freq_is_const(void)
{
	return 1;
}

#ifdef __cplusplus
}
#endif

#endif
