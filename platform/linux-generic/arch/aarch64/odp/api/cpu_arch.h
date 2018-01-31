/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_PLAT_CPU_ARCH_H_
#define ODP_PLAT_CPU_ARCH_H_

#ifdef __cplusplus
extern "C" {
#endif

#define _ODP_CACHE_LINE_SIZE 64

static inline void odp_cpu_pause(void)
{
	/* YIELD hints the CPU to switch to another thread if possible
	 * and executes as a NOP otherwise.
	 * ISB flushes the pipeline, then restarts. This is guaranteed to
	 * stall the CPU a number of cycles.
	 */
	__asm volatile("isb" ::: "memory");
}

#ifdef __cplusplus
}
#endif

#endif
