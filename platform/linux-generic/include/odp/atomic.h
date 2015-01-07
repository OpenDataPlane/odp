/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP atomic operations
 */

#ifndef ODP_PLAT_ATOMIC_H_
#define ODP_PLAT_ATOMIC_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <odp/align.h>
#include <odp/plat/atomic_types.h>

/** @ingroup odp_synchronizers
 *  @{
 */

static inline void odp_atomic_init_u32(odp_atomic_u32_t *atom, uint32_t val)
{
	__atomic_store_n(&atom->v, val, __ATOMIC_RELAXED);
}

static inline uint32_t odp_atomic_load_u32(odp_atomic_u32_t *atom)
{
	return __atomic_load_n(&atom->v, __ATOMIC_RELAXED);
}

static inline void odp_atomic_store_u32(odp_atomic_u32_t *atom,
					uint32_t val)
{
	__atomic_store_n(&atom->v, val, __ATOMIC_RELAXED);
}

static inline uint32_t odp_atomic_fetch_add_u32(odp_atomic_u32_t *atom,
						uint32_t val)
{
	return __atomic_fetch_add(&atom->v, val, __ATOMIC_RELAXED);
}

static inline void odp_atomic_add_u32(odp_atomic_u32_t *atom,
				      uint32_t val)
{
	(void)__atomic_fetch_add(&atom->v, val, __ATOMIC_RELAXED);
}

static inline uint32_t odp_atomic_fetch_sub_u32(odp_atomic_u32_t *atom,
						uint32_t val)
{
	return __atomic_fetch_sub(&atom->v, val, __ATOMIC_RELAXED);
}

static inline void odp_atomic_sub_u32(odp_atomic_u32_t *atom,
				      uint32_t val)
{
	(void)__atomic_fetch_sub(&atom->v, val, __ATOMIC_RELAXED);
}

static inline uint32_t odp_atomic_fetch_inc_u32(odp_atomic_u32_t *atom)
{
	return __atomic_fetch_add(&atom->v, 1, __ATOMIC_RELAXED);
}

static inline void odp_atomic_inc_u32(odp_atomic_u32_t *atom)
{
	(void)__atomic_fetch_add(&atom->v, 1, __ATOMIC_RELAXED);
}

static inline uint32_t odp_atomic_fetch_dec_u32(odp_atomic_u32_t *atom)
{
	return __atomic_fetch_sub(&atom->v, 1, __ATOMIC_RELAXED);
}

static inline void odp_atomic_dec_u32(odp_atomic_u32_t *atom)
{
	(void)__atomic_fetch_sub(&atom->v, 1, __ATOMIC_RELAXED);
}

static inline void odp_atomic_init_u64(odp_atomic_u64_t *atom, uint64_t val)
{
	atom->v = val;
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	__atomic_clear(&atom->lock, __ATOMIC_RELAXED);
#endif
}

static inline uint64_t odp_atomic_load_u64(odp_atomic_u64_t *atom)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	return ATOMIC_OP(atom, (void)0);
#else
	return __atomic_load_n(&atom->v, __ATOMIC_RELAXED);
#endif
}

static inline void odp_atomic_store_u64(odp_atomic_u64_t *atom,
					uint64_t val)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	(void)ATOMIC_OP(atom, atom->v = val);
#else
	__atomic_store_n(&atom->v, val, __ATOMIC_RELAXED);
#endif
}

static inline uint64_t odp_atomic_fetch_add_u64(odp_atomic_u64_t *atom,
						uint64_t val)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	return ATOMIC_OP(atom, atom->v += val);
#else
	return __atomic_fetch_add(&atom->v, val, __ATOMIC_RELAXED);
#endif
}

static inline void odp_atomic_add_u64(odp_atomic_u64_t *atom, uint64_t val)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	(void)ATOMIC_OP(atom, atom->v += val);
#else
	(void)__atomic_fetch_add(&atom->v, val, __ATOMIC_RELAXED);
#endif
}

static inline uint64_t odp_atomic_fetch_sub_u64(odp_atomic_u64_t *atom,
						uint64_t val)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	return ATOMIC_OP(atom, atom->v -= val);
#else
	return __atomic_fetch_sub(&atom->v, val, __ATOMIC_RELAXED);
#endif
}

static inline void odp_atomic_sub_u64(odp_atomic_u64_t *atom, uint64_t val)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	(void)ATOMIC_OP(atom, atom->v -= val);
#else
	(void)__atomic_fetch_sub(&atom->v, val, __ATOMIC_RELAXED);
#endif
}

static inline uint64_t odp_atomic_fetch_inc_u64(odp_atomic_u64_t *atom)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	return ATOMIC_OP(atom, atom->v++);
#else
	return __atomic_fetch_add(&atom->v, 1, __ATOMIC_RELAXED);
#endif
}

static inline void odp_atomic_inc_u64(odp_atomic_u64_t *atom)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	(void)ATOMIC_OP(atom, atom->v++);
#else
	(void)__atomic_fetch_add(&atom->v, 1, __ATOMIC_RELAXED);
#endif
}

static inline uint64_t odp_atomic_fetch_dec_u64(odp_atomic_u64_t *atom)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	return ATOMIC_OP(atom, atom->v--);
#else
	return __atomic_fetch_sub(&atom->v, 1, __ATOMIC_RELAXED);
#endif
}

static inline void odp_atomic_dec_u64(odp_atomic_u64_t *atom)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	(void)ATOMIC_OP(atom, atom->v--);
#else
	(void)__atomic_fetch_sub(&atom->v, 1, __ATOMIC_RELAXED);
#endif
}

/**
 * @}
 */

#include <odp/api/atomic.h>

#ifdef __cplusplus
}
#endif

#endif
