/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2018 Linaro Limited
 * Copyright (c) 2021-2025 Nokia
 */

#ifndef ODP_ARCH_CPU_INLINES_H_
#define ODP_ARCH_CPU_INLINES_H_

#include <odp/api/abi/cpu_rdtsc.h>

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

static inline void _odp_cpu_pause(void)
{
#ifdef __SSE2__
	__asm__ __volatile__ ("pause");
#else
	__asm__ __volatile__ ("rep; nop");
#endif
}

static inline uint64_t _odp_cpu_cycles(void)
{
	return _odp_cpu_rdtsc();
}

static inline uint64_t _odp_cpu_cycles_strict(void)
{
	__atomic_thread_fence(__ATOMIC_SEQ_CST);
	return _odp_cpu_rdtsc();
}

static inline uint64_t _odp_cpu_cycles_max(void)
{
	return UINT64_MAX;
}

static inline uint64_t _odp_cpu_cycles_resolution(void)
{
	return 1;
}

static inline void _odp_prefetch_l1i(const void *addr)
{
	(void)addr;
}

#ifdef __cplusplus
}
#endif

#endif
