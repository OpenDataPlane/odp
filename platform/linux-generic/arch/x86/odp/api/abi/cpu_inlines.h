/* Copyright (c) 2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_ARCH_CPU_INLINES_H_
#define ODP_ARCH_CPU_INLINES_H_

#include <stdint.h>
#include <odp/api/abi/cpu_rdtsc.h>

_ODP_INLINE void odp_cpu_pause(void)
{
#ifdef __SSE2__
	__asm__ __volatile__ ("pause");
#else
	__asm__ __volatile__ ("rep; nop");
#endif
}

_ODP_INLINE uint64_t odp_cpu_cycles(void)
{
	return _odp_cpu_rdtsc();
}

_ODP_INLINE uint64_t odp_cpu_cycles_max(void)
{
	return UINT64_MAX;
}

_ODP_INLINE uint64_t odp_cpu_cycles_resolution(void)
{
	return 1;
}

#endif
