/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2017 ARM Limited
 * Copyright (c) 2017-2018 Linaro Limited
 */

#ifndef PLATFORM_LINUXGENERIC_ARCH_ARM_ODP_CPU_H
#define PLATFORM_LINUXGENERIC_ARCH_ARM_ODP_CPU_H

#if !defined(__arm__)
#error Use this file only when compiling for ARM architecture
#endif

#include <odp_debug_internal.h>

/*
 * Use LLD/SCD atomic primitives instead of lock-based code path in llqueue
 * LLD/SCD is on ARM the fastest way to enqueue and dequeue elements from a
 * linked list queue.
 */
#define CONFIG_LLDSCD

/*
 * Use DMB;STR instead of STRL on ARM
 * On early ARMv8 implementations (e.g. Cortex-A57) this is noticeably more
 * performant than using store-release.
 * This also allows for load-only barriers (DMB ISHLD) which are much cheaper
 * than a full barrier
 */
#define CONFIG_DMBSTR

static inline uint64_t lld(uint64_t *var, int mm)
{
	uint64_t old;

	__asm__ volatile("ldrexd %0, %H0, [%1]"
			 : "=&r" (old)
			 : "r" (var)
			 : );
	/* Barrier after an acquiring load */
	if (mm == __ATOMIC_ACQUIRE)
		__asm__ volatile("dmb" : : : "memory");
	return old;
}

/* Return 0 on success, 1 on failure */
static inline uint32_t scd(uint64_t *var, uint64_t neu, int mm)
{
	uint32_t ret;

	/* Barrier before a releasing store */
	if (mm == __ATOMIC_RELEASE)
		__asm__ volatile("dmb" : : : "memory");
	__asm__ volatile("strexd %0, %1, %H1, [%2]"
			 : "=&r" (ret)
			 : "r" (neu), "r" (var)
			 : );
	return ret;
}

#ifdef CONFIG_DMBSTR

#define atomic_store_release(loc, val, ro)		\
do {							\
	__atomic_thread_fence(__ATOMIC_RELEASE);	\
	__atomic_store_n(loc, val, __ATOMIC_RELAXED);	\
} while (0)

#else

#define atomic_store_release(loc, val, ro) \
	__atomic_store_n(loc, val, __ATOMIC_RELEASE)

#endif  /* CONFIG_DMBSTR */

#include "../default/odp_atomic.h"
#include "../default/odp_wait_until.h"

#ifdef __ARM_FEATURE_UNALIGNED
#define _ODP_UNALIGNED 1
#else
#define _ODP_UNALIGNED 0
#endif

#endif  /* PLATFORM_LINUXGENERIC_ARCH_ARM_ODP_CPU_H */
