/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2018 Linaro Limited
 * Copyright (c) 2021-2023 Nokia
 */

#ifndef ODP_ARCH_CPU_INLINES_H_
#define ODP_ARCH_CPU_INLINES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/abi/time_cpu.h>

#include <stdint.h>

/* CPU frequency is shifted to decrease integer division error */
#define _ODP_CPU_FREQ_SHIFT 16

typedef struct _odp_cpu_cycles_global_t {
	uint64_t res;
	uint64_t res_shifted;
	uint64_t max;

} _odp_cpu_cycles_global_t;

extern _odp_cpu_cycles_global_t _odp_cpu_cycles_glob;

static inline void _odp_cpu_pause(void)
{
	/* YIELD hints the CPU to switch to another thread if possible
	 * and executes as a NOP otherwise.
	 * ISB flushes the pipeline, then restarts. This is guaranteed to
	 * stall the CPU a number of cycles.
	 */
	__asm volatile("isb" ::: "memory");
}

static inline uint64_t _odp_cpu_cycles(void)
{
	return (_odp_time_cpu_global() * _odp_cpu_cycles_glob.res_shifted) >> _ODP_CPU_FREQ_SHIFT;
}

static inline  uint64_t _odp_cpu_cycles_resolution(void)
{
	return _odp_cpu_cycles_glob.res;
}

static inline  uint64_t _odp_cpu_cycles_max(void)
{
	return _odp_cpu_cycles_glob.max;
}

static inline void _odp_prefetch_l1i(const void *addr)
{
	__asm__ volatile("prfm plil1keep, [%[addr]]" : : [addr] "r" (addr));
}

#ifdef __cplusplus
}
#endif

#endif
