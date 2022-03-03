/* Copyright (c) 2017-2021, ARM Limited. All rights reserved.
 * Copyright (c) 2017-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef PLATFORM_LINUXGENERIC_ARCH_ARM_ODP_ATOMIC_H
#define PLATFORM_LINUXGENERIC_ARCH_ARM_ODP_ATOMIC_H

#ifndef PLATFORM_LINUXGENERIC_ARCH_ARM_ODP_CPU_H
#error This file should not be included directly, please include odp_cpu.h
#endif

#include <odp_types_internal.h>
#include <limits.h>

#ifdef CONFIG_DMBSTR

#define atomic_store_release(loc, val, ro)		\
do {							\
	_odp_release_barrier(ro);			\
	__atomic_store_n(loc, val, __ATOMIC_RELAXED);   \
} while (0)

#else

#define atomic_store_release(loc, val, ro) \
	__atomic_store_n(loc, val, __ATOMIC_RELEASE)

#endif  /* CONFIG_DMBSTR */

/** Atomic bit set operations with memory ordering */
#if __GCC_ATOMIC_LLONG_LOCK_FREE == 2 && \
	__SIZEOF_LONG_LONG__ != __SIZEOF_LONG__
typedef unsigned long long bitset_t;
#define ATOM_BITSET_SIZE (CHAR_BIT * __SIZEOF_LONG_LONG__)

#elif __GCC_ATOMIC_LONG_LOCK_FREE == 2 && __SIZEOF_LONG__ != __SIZEOF_INT__
typedef unsigned long bitset_t;
#define ATOM_BITSET_SIZE (CHAR_BIT * __SIZEOF_LONG__)

#elif __GCC_ATOMIC_INT_LOCK_FREE == 2
typedef unsigned int bitset_t;
#define ATOM_BITSET_SIZE (CHAR_BIT * __SIZEOF_INT__)

#else
/* Target does not support lock-free atomic operations */
typedef unsigned int bitset_t;
#define ATOM_BITSET_SIZE (CHAR_BIT * __SIZEOF_INT__)
#endif

#if ATOM_BITSET_SIZE <= 32

static inline bitset_t bitset_mask(uint32_t bit)
{
	return 1UL << bit;
}

#elif ATOM_BITSET_SIZE <= 64

static inline bitset_t bitset_mask(uint32_t bit)
{
	return 1ULL << bit;
}

#elif ATOM_BITSET_SIZE <= 128

static inline bitset_t bitset_mask(uint32_t bit)
{
	if (bit < 64)
		return 1ULL << bit;
	else
		return (_odp_u128_t)(1ULL << (bit - 64)) << 64;
}

#else
#error Unsupported size of bit sets (ATOM_BITSET_SIZE)
#endif

static inline bitset_t atom_bitset_load(bitset_t *bs, int mo)
{
	return __atomic_load_n(bs, mo);
}

static inline void atom_bitset_set(bitset_t *bs, uint32_t bit, int mo)
{
	(void)__atomic_fetch_or(bs, bitset_mask(bit), mo);
}

static inline void atom_bitset_clr(bitset_t *bs, uint32_t bit, int mo)
{
	(void)__atomic_fetch_and(bs, ~bitset_mask(bit), mo);
}

static inline bitset_t atom_bitset_xchg(bitset_t *bs, bitset_t neu, int mo)
{
	return __atomic_exchange_n(bs, neu, mo);
}

static inline bitset_t atom_bitset_cmpxchg(bitset_t *bs, bitset_t *old,
					   bitset_t neu, bool weak,
					   int mo_success, int mo_failure)
{
	return __atomic_compare_exchange_n(bs, old, neu, weak, mo_success,
					   mo_failure);
}

#endif  /* PLATFORM_LINUXGENERIC_ARCH_ARM_ODP_ATOMIC_H */
