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

#if ATOM_BITSET_SIZE <= 32

/* Return first-bit-set with StdC ffs() semantics */
static inline uint32_t bitset_ffs(bitset_t b)
{
	return __builtin_ffsl(b);
}

#elif ATOM_BITSET_SIZE <= 64

/* Return first-bit-set with StdC ffs() semantics */
static inline uint32_t bitset_ffs(bitset_t b)
{
	return __builtin_ffsll(b);
}

#elif ATOM_BITSET_SIZE <= 128

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

#else
#error Unsupported size of bit sets (ATOM_BITSET_SIZE)
#endif

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
