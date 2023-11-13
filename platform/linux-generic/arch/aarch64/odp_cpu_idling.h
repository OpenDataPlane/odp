/* Copyright (c) 2017, ARM Limited. All rights reserved.
 *
 * Copyright (c) 2017-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef PLATFORM_LINUXGENERIC_ARCH_ARM_CPU_IDLING_H
#define PLATFORM_LINUXGENERIC_ARCH_ARM_CPU_IDLING_H

#ifndef PLATFORM_LINUXGENERIC_ARCH_ARM_ODP_CPU_H
#error This file should not be included directly, please include odp_cpu.h
#endif

#ifndef CONFIG_WFE

#include "../default/odp_wait_until.h"

#else /* CONFIG_WFE */

static inline void sevl(void)
{
	__asm__ volatile("sevl" : : : );
}

static inline int wfe(void)
{
	__asm__ volatile("wfe" : : : "memory");
	return 1;
}

#define monitor128(addr, mo) lld((addr), (mo))
#define monitor64(addr, mo) ll64((addr), (mo))
#define monitor32(addr, mo) ll32((addr), (mo))
#define monitor8(addr, mo) ll8((addr), (mo))
#endif /* CONFIG_WFE */

#endif  /* PLATFORM_LINUXGENERIC_ARCH_ARM_CPU_IDLING_H */
