/* Copyright (c) 2017, ARM Limited. All rights reserved.
 *
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef PLATFORM_LINUXGENERIC_ARCH_ARM_LLSC_H
#define PLATFORM_LINUXGENERIC_ARCH_ARM_LLSC_H

#ifndef PLATFORM_LINUXGENERIC_ARCH_ARM_ODP_CPU_H
#error This file should not be included directly, please include odp_cpu.h
#endif

static inline uint32_t ll8(uint8_t *var, int mm)
{
	uint8_t old;

	__asm__ volatile("ldrexb %0, [%1]"
			 : "=&r" (old)
			 : "r" (var)
			 : );
	/* Barrier after an acquiring load */
	if (mm == __ATOMIC_ACQUIRE)
		_odp_dmb();
	return old;
}

static inline uint32_t ll(uint32_t *var, int mm)
{
	uint32_t old;

	__asm__ volatile("ldrex %0, [%1]"
			 : "=&r" (old)
			 : "r" (var)
			 : );
	/* Barrier after an acquiring load */
	if (mm == __ATOMIC_ACQUIRE)
		_odp_dmb();
	return old;
}

#define ll32(a, b) ll((a), (b))

/* Return 0 on success, 1 on failure */
static inline uint32_t sc(uint32_t *var, uint32_t neu, int mm)
{
	uint32_t ret;

	/* Barrier before a releasing store */
	if (mm == __ATOMIC_RELEASE)
		_odp_dmb();
	__asm__ volatile("strex %0, %1, [%2]"
			 : "=&r" (ret)
			 : "r" (neu), "r" (var)
			 : );
	return ret;
}

#define sc32(a, b, c) sc((a), (b), (c))

static inline uint64_t lld(uint64_t *var, int mm)
{
	uint64_t old;

	__asm__ volatile("ldrexd %0, %H0, [%1]"
			 : "=&r" (old)
			 : "r" (var)
			 : );
	/* Barrier after an acquiring load */
	if (mm == __ATOMIC_ACQUIRE)
		_odp_dmb();
	return old;
}

#define ll64(a, b) lld((a), (b))

/* Return 0 on success, 1 on failure */
static inline uint32_t scd(uint64_t *var, uint64_t neu, int mm)
{
	uint32_t ret;

	/* Barrier before a releasing store */
	if (mm == __ATOMIC_RELEASE)
		_odp_dmb();
	__asm__ volatile("strexd %0, %1, %H1, [%2]"
			 : "=&r" (ret)
			 : "r" (neu), "r" (var)
			 : );
	return ret;
}

#define sc64(a, b, c) scd((a), (b), (c))

#endif  /* PLATFORM_LINUXGENERIC_ARCH_ARM_LLSC_H */
