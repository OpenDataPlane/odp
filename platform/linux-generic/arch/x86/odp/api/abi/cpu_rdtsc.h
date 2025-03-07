/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2018 Linaro Limited
 */

#ifndef ODP_ARCH_CPU_RDTSC_H_
#define ODP_ARCH_CPU_RDTSC_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

static inline uint64_t _odp_cpu_rdtsc(void)
{
	union {
		uint64_t tsc_64;
		struct {
			uint32_t lo_32;
			uint32_t hi_32;
		};
	} tsc;

	__asm__ __volatile__ ("rdtsc" :
		     "=a" (tsc.lo_32),
		     "=d" (tsc.hi_32) : : "memory");

	return tsc.tsc_64;
}

#ifdef __cplusplus
}
#endif

#endif
