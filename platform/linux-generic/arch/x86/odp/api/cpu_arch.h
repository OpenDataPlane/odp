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

/** @ingroup odp_compiler_optim
 *  @{
 */

#define ODP_CACHE_LINE_SIZE 64

/**
 * @}
 */

static inline void odp_cpu_pause(void)
{
#ifdef __SSE2__
	__asm__ __volatile__ ("pause");
#else
	__asm__ __volatile__ ("rep; nop");
#endif
}

#ifdef __cplusplus
}
#endif

#endif
