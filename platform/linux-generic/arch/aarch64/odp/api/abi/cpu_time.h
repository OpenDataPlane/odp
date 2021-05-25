/* Copyright (c) 2021, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_API_ABI_CPU_TIME_H_
#define ODP_API_ABI_CPU_TIME_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

static inline uint64_t _odp_cpu_global_time(void)
{
	uint64_t cntvct;

	__asm__ volatile("mrs %0, cntvct_el0" : "=r"(cntvct) : : "memory");

	return cntvct;
}

static inline uint64_t _odp_cpu_global_time_strict(void)
{
	uint64_t cntvct;

	__asm__ volatile("isb" ::: "memory");
	__asm__ volatile("mrs %0, cntvct_el0" : "=r"(cntvct) : : "memory");

	return cntvct;
}

static inline uint64_t _odp_cpu_global_time_freq(void)
{
	uint64_t cntfrq;

	__asm__ volatile("mrs %0, cntfrq_el0" : "=r"(cntfrq) : : );

	return cntfrq;
}

int _odp_cpu_has_global_time(void);

#ifdef __cplusplus
}
#endif

#endif
