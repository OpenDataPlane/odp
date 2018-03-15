/* Copyright (c) 2017, ARM Limited. All rights reserved.
 *
 * Copyright (c) 2017-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef PLATFORM_LINUXGENERIC_ARCH_ARM_ODP_CPU_H
#define PLATFORM_LINUXGENERIC_ARCH_ARM_ODP_CPU_H

#if !defined(__aarch64__)
#error Use this file only when compiling for ARMv8 architecture
#endif

#include <odp_debug_internal.h>

/*
 * Use LLD/SCD atomic primitives instead of lock-based code path in llqueue
 * LLD/SCD is on ARM the fastest way to enqueue and dequeue elements from a
 * linked list queue.
 */
// #define CONFIG_LLDSCD

/*
 * Use DMB;STR instead of STRL on ARM
 * On early ARMv8 implementations (e.g. Cortex-A57) this is noticeably more
 * performant than using store-release.
 * This also allows for load-only barriers (DMB ISHLD) which are much cheaper
 * than a full barrier
 */
#define CONFIG_DMBSTR

/*
 * Use ARM event signalling mechanism
 * Event signalling minimises spinning (busy waiting) which decreases
 * cache coherency traffic when spinning on shared locations (thus faster and
 * more scalable) and enables the CPU to enter a sleep state (lower power
 * consumption).
 */
#define CONFIG_WFE

static inline void _odp_dmb(void)
{
	__asm__ volatile("dmb" : : : "memory");
}

/* Only ARMv8 supports DMB ISHLD */
/* A load only barrier is much cheaper than full barrier */
#define _odp_release_barrier(ro) \
do {							     \
	if (ro)						     \
		__asm__ volatile("dmb ishld" ::: "memory");  \
	else						     \
		__asm__ volatile("dmb ish" ::: "memory");    \
} while (0)

#include "odp_llsc.h"
#include "odp_atomic.h"
#include "odp_cpu_idling.h"

#endif  /* PLATFORM_LINUXGENERIC_ARCH_ARM_ODP_CPU_H */
