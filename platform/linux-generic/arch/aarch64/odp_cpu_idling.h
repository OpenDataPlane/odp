/* Copyright (c) 2017, ARM Limited. All rights reserved.
 *
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef PLATFORM_LINUXGENERIC_ARCH_ARM_CPU_IDLING_H
#define PLATFORM_LINUXGENERIC_ARCH_ARM_CPU_IDLING_H

#ifndef PLATFORM_LINUXGENERIC_ARCH_ARM_ODP_CPU_H
#error This file should not be included directly, please include odp_cpu.h
#endif

static inline void sevl(void)
{
#ifdef CONFIG_WFE
	__asm__ volatile("sevl" : : : );
#endif
}

static inline int wfe(void)
{
#ifdef CONFIG_WFE
	__asm__ volatile("wfe" : : : "memory");
#endif
	return 1;
}

static inline void doze(void)
{
#ifndef CONFIG_WFE
	/* When using WFE do not stall the pipeline using other means */
	odp_cpu_pause();
#endif
}

#ifdef CONFIG_WFE
#define monitor128(addr, mo) lld((addr), (mo))
#define monitor64(addr, mo) ll64((addr), (mo))
#define monitor32(addr, mo) ll32((addr), (mo))
#define monitor8(addr, mo) ll8((addr), (mo))
#else
#define monitor128(addr, mo) __atomic_load_n((addr), (mo))
#define monitor64(addr, mo) __atomic_load_n((addr), (mo))
#define monitor32(addr, mo) __atomic_load_n((addr), (mo))
#define monitor8(addr, mo) __atomic_load_n((addr), (mo))
#endif

#endif  /* PLATFORM_LINUXGENERIC_ARCH_ARM_CPU_IDLING_H */
