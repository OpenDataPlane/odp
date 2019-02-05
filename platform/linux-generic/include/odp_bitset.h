/* Copyright (c) 2017, ARM Limited. All rights reserved.
 *
 * Copyright (c) 2017-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _ODP_BITSET_H_
#define _ODP_BITSET_H_

#include <odp_cpu.h>

#include <limits.h>

/******************************************************************************
 * bitset abstract data type
 *****************************************************************************/
/* This could be a struct of scalars to support larger bit sets */

/*
 * Size of atomic bit set. This limits the max number of threads,
 * scheduler groups and reorder windows. On ARMv8/64-bit and x86-64, the
 * (lock-free) max is 128
 */

/* Find a suitable data type that supports lock-free atomic operations */
#if defined(__aarch64__) && defined(__SIZEOF_INT128__) && \
	__SIZEOF_INT128__ == 16
#define LOCKFREE16
typedef __int128 bitset_t;
#define ATOM_BITSET_SIZE (CHAR_BIT * __SIZEOF_INT128__)

#elif __GCC_ATOMIC_LLONG_LOCK_FREE == 2 && \
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

/* Return first-bit-set with StdC ffs() semantics */
static inline uint32_t bitset_ffs(bitset_t b)
{
	return __builtin_ffsl(b);
}

/* Load-exclusive with memory ordering */
static inline bitset_t bitset_monitor(bitset_t *bs, int mo)
{
	return monitor32(bs, mo);
}

#elif ATOM_BITSET_SIZE <= 64

static inline bitset_t bitset_mask(uint32_t bit)
{
	return 1ULL << bit;
}

/* Return first-bit-set with StdC ffs() semantics */
static inline uint32_t bitset_ffs(bitset_t b)
{
	return __builtin_ffsll(b);
}

/* Load-exclusive with memory ordering */
static inline bitset_t bitset_monitor(bitset_t *bs, int mo)
{
	return monitor64(bs, mo);
}

#elif ATOM_BITSET_SIZE <= 128

static inline bitset_t bitset_mask(uint32_t bit)
{
	if (bit < 64)
		return 1ULL << bit;
	else
		return (unsigned __int128)(1ULL << (bit - 64)) << 64;
}

/* Return first-bit-set with StdC ffs() semantics */
static inline uint32_t bitset_ffs(bitset_t b)
{
	if ((uint64_t)b != 0)
		return __builtin_ffsll((uint64_t)b);
	else if ((b >> 64) != 0)
		return __builtin_ffsll((uint64_t)(b >> 64)) + 64;
	else
		return 0;
}

/* Load-exclusive with memory ordering */
static inline bitset_t bitset_monitor(bitset_t *bs, int mo)
{
	return monitor128(bs, mo);
}

#else
#error Unsupported size of bit sets (ATOM_BITSET_SIZE)
#endif

/* Atomic load with memory ordering */
static inline bitset_t atom_bitset_load(bitset_t *bs, int mo)
{
#ifdef LOCKFREE16
	return __lockfree_load_16(bs, mo);
#else
	return __atomic_load_n(bs, mo);
#endif
}

/* Atomic bit set with memory ordering */
static inline void atom_bitset_set(bitset_t *bs, uint32_t bit, int mo)
{
#ifdef LOCKFREE16
	(void)__lockfree_fetch_or_16(bs, bitset_mask(bit), mo);
#else
	(void)__atomic_fetch_or(bs, bitset_mask(bit), mo);
#endif
}

/* Atomic bit clear with memory ordering */
static inline void atom_bitset_clr(bitset_t *bs, uint32_t bit, int mo)
{
#ifdef LOCKFREE16
	(void)__lockfree_fetch_and_16(bs, ~bitset_mask(bit), mo);
#else
	(void)__atomic_fetch_and(bs, ~bitset_mask(bit), mo);
#endif
}

/* Atomic exchange with memory ordering */
static inline bitset_t atom_bitset_xchg(bitset_t *bs, bitset_t neu, int mo)
{
#ifdef LOCKFREE16
	return __lockfree_exchange_16(bs, neu, mo);
#else
	return __atomic_exchange_n(bs, neu, mo);
#endif
}

/* Atomic compare&exchange with memory ordering */
static inline bitset_t atom_bitset_cmpxchg(bitset_t *bs, bitset_t *old,
					   bitset_t neu, bool weak,
					   int mo_success, int mo_failure)
{
#ifdef LOCKFREE16
	return __lockfree_compare_exchange_16(bs, old, neu, weak, mo_success,
					      mo_failure);
#else
	return __atomic_compare_exchange_n(bs, old, neu, weak, mo_success,
					   mo_failure);
#endif
}

/* Return a & ~b */
static inline bitset_t bitset_andn(bitset_t a, bitset_t b)
{
	return a & ~b;
}

static inline bool bitset_is_eql(bitset_t a, bitset_t b)
{
	return a == b;
}

static inline bitset_t bitset_clr(bitset_t bs, uint32_t bit)
{
	return bs & ~bitset_mask(bit);
}

static inline bitset_t bitset_set(bitset_t bs, uint32_t bit)
{
	return bs | bitset_mask(bit);
}

static inline bitset_t bitset_null(void)
{
	return 0U;
}

static inline bool bitset_is_null(bitset_t a)
{
	return a == 0U;
}

static inline bool bitset_is_set(bitset_t a, uint32_t bit)
{
	return (a & bitset_mask(bit)) != 0;
}

#endif
