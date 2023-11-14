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
#include <odp_types_internal.h>

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

/* Only ARMv8 supports DMB ISHLD */
/* A load only barrier is much cheaper than full barrier */
#define _odp_release_barrier(ro) \
do {							     \
	if (ro)						     \
		__asm__ volatile("dmb ishld" ::: "memory");  \
	else						     \
		__asm__ volatile("dmb ish" ::: "memory");    \
} while (0)

static inline uint16_t ll8(uint8_t *var, int mm)
{
	uint16_t old;

	if (mm == __ATOMIC_ACQUIRE)
		__asm__ volatile("ldaxrb %w0, [%1]"
				 : "=&r" (old)
				 : "r" (var)
				 : "memory");
	else if (mm == __ATOMIC_RELAXED)
		__asm__ volatile("ldxrb %w0, [%1]"
				 : "=&r" (old)
				 : "r" (var)
				 : );
	else
		_ODP_ABORT();
	return old;
}

static inline uint32_t ll32(uint32_t *var, int mm)
{
	uint32_t old;

	if (mm == __ATOMIC_ACQUIRE)
		__asm__ volatile("ldaxr %w0, [%1]"
				 : "=&r" (old)
				 : "r" (var)
				 : "memory");
	else if (mm == __ATOMIC_RELAXED)
		__asm__ volatile("ldxr %w0, [%1]"
				 : "=&r" (old)
				 : "r" (var)
				 : );
	else
		_ODP_ABORT();
	return old;
}

/* Return 0 on success, 1 on failure */
static inline uint32_t sc32(uint32_t *var, uint32_t neu, int mm)
{
	uint32_t ret;

	if (mm == __ATOMIC_RELEASE)
		__asm__ volatile("stlxr %w0, %w1, [%2]"
				 : "=&r" (ret)
				 : "r" (neu), "r" (var)
				 : "memory");
	else if (mm == __ATOMIC_RELAXED)
		__asm__ volatile("stxr %w0, %w1, [%2]"
				 : "=&r" (ret)
				 : "r" (neu), "r" (var)
				 : );
	else
		_ODP_ABORT();
	return ret;
}

static inline uint64_t ll64(uint64_t *var, int mm)
{
	uint64_t old;

	if (mm == __ATOMIC_ACQUIRE)
		__asm__ volatile("ldaxr %0, [%1]"
				 : "=&r" (old)
				 : "r" (var)
				 : "memory");
	else if (mm == __ATOMIC_RELAXED)
		__asm__ volatile("ldxr %0, [%1]"
				 : "=&r" (old)
				 : "r" (var)
				 : );
	else
		_ODP_ABORT();
	return old;
}

/* Return 0 on success, 1 on failure */
static inline uint32_t sc64(uint64_t *var, uint64_t neu, int mm)
{
	uint32_t ret;

	if (mm == __ATOMIC_RELEASE)
		__asm__ volatile("stlxr %w0, %1, [%2]"
				 : "=&r" (ret)
				 : "r" (neu), "r" (var)
				 : "memory");
	else if (mm == __ATOMIC_RELAXED)
		__asm__ volatile("stxr %w0, %1, [%2]"
				 : "=&r" (ret)
				 : "r" (neu), "r" (var)
				 : );
	else
		_ODP_ABORT();
	return ret;
}

union i128 {
	_odp_u128_t i128;
	int64_t  i64[2];
};

static inline _odp_u128_t lld(_odp_u128_t *var, int mm)
{
	union i128 old;

	if (mm == __ATOMIC_ACQUIRE)
		__asm__ volatile("ldaxp %0, %1, [%2]"
				 : "=&r" (old.i64[0]), "=&r" (old.i64[1])
				 : "r" (var)
				 : "memory");
	else if (mm == __ATOMIC_RELAXED)
		__asm__ volatile("ldxp %0, %1, [%2]"
				 : "=&r" (old.i64[0]), "=&r" (old.i64[1])
				 : "r" (var)
				 : );
	else
		_ODP_ABORT();
	return old.i128;
}

/* Return 0 on success, 1 on failure */
static inline uint32_t scd(_odp_u128_t *var, _odp_u128_t neu, int mm)
{
	uint32_t ret;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
	if (mm == __ATOMIC_RELEASE)
		__asm__ volatile("stlxp %w0, %1, %2, [%3]"
				 : "=&r" (ret)
				 : "r" (((*(union i128 *)&neu)).i64[0]),
				   "r" (((*(union i128 *)&neu)).i64[1]),
				   "r" (var)
				 : "memory");
	else if (mm == __ATOMIC_RELAXED)
		__asm__ volatile("stxp %w0, %1, %2, [%3]"
				 : "=&r" (ret)
				 : "r" (((*(union i128 *)&neu)).i64[0]),
				   "r" (((*(union i128 *)&neu)).i64[1]),
				   "r" (var)
				 : );
	else
		_ODP_ABORT();
#pragma GCC diagnostic pop
	return ret;
}

#include "odp_atomic.h"
#include "odp_wait_until.h"

#ifdef __ARM_FEATURE_UNALIGNED
#define _ODP_UNALIGNED 1
#else
#define _ODP_UNALIGNED 0
#endif

#endif  /* PLATFORM_LINUXGENERIC_ARCH_ARM_ODP_CPU_H */
