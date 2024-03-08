/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2018 Linaro Limited
 * Copyright (c) 2021 Nokia
 */

#ifndef ODP_ARCH_CPU_INLINES_H_
#define ODP_ARCH_CPU_INLINES_H_

#ifdef __cplusplus
extern "C" {
#endif

static inline void _odp_cpu_pause(void)
{
	/* YIELD hints the CPU to switch to another thread if possible
	 * and executes as a NOP otherwise.
	 * ISB flushes the pipeline, then restarts. This is guaranteed to
	 * stall the CPU a number of cycles.
	 */
	__asm volatile("isb" ::: "memory");
}

/* Use generic implementations for the rest of the functions */
#include <odp/api/abi/cpu_generic.h>

#ifdef __cplusplus
}
#endif

#endif
