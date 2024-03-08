/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2014-2018 Linaro Limited
 */

/**
 * @file
 *
 * ODP atomic types and operations, semantically a subset of C11 atomics.
 * Reuse the 32-bit and 64-bit type definitions from odp_atomic.h. Introduces
 * new atomic pointer and flag types.
 * Atomic functions must be used to operate on atomic variables!
 */

#ifndef ODP_ATOMIC_INTERNAL_H_
#define ODP_ATOMIC_INTERNAL_H_

#include <odp/api/std_types.h>
#include <odp/api/align.h>
#include <odp/api/hints.h>
#include <odp/api/atomic.h>
#include <odp_types_internal.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Atomic flag (boolean) type
 * @Note this is not the same as a plain boolean type.
 * _odp_atomic_flag_t is guaranteed to be able to operate on atomically.
 */
typedef char _odp_atomic_flag_t;

/**
 * Memory orderings supported by ODP.
 */
typedef enum {
/** Relaxed memory ordering, no ordering of other accesses enforced.
 * Atomic operations with relaxed memory ordering cannot be used for
 * synchronization */
	_ODP_MEMMODEL_RLX = __ATOMIC_RELAXED,
/** Acquire memory ordering, synchronize with release stores from another
 * thread (later accesses cannot move before acquire operation).
 * Use acquire and release memory ordering for Release Consistency */
	_ODP_MEMMODEL_ACQ = __ATOMIC_ACQUIRE,
/** Release memory ordering, synchronize with acquire loads from another
 * thread (earlier accesses cannot move after release operation).
 * Use acquire and release memory ordering for Release Consistency */
	_ODP_MEMMODEL_RLS = __ATOMIC_RELEASE,
/** Acquire&release memory ordering, synchronize with acquire loads and release
 * stores in another (one other) thread */
	_ODP_MEMMODEL_ACQ_RLS = __ATOMIC_ACQ_REL

} _odp_memmodel_t;

/*****************************************************************************
 * Operations on flag atomics
 * _odp_atomic_flag_init - no return value
 * _odp_atomic_flag_load - return current value
 * _odp_atomic_flag_tas - return old value
 * _odp_atomic_flag_clear - no return value
 *
 * Flag atomics use Release Consistency memory consistency model, acquire
 * semantics for TAS and release semantics for clear.
 *****************************************************************************/

/**
 * Initialize a flag atomic variable
 *
 * @param[out] flag Pointer to a flag atomic variable
 * @param val The initial value of the variable
 */
static inline void _odp_atomic_flag_init(_odp_atomic_flag_t *flag,
					 odp_bool_t val)
{
	__atomic_clear(flag, __ATOMIC_RELAXED);
	if (val)
		__atomic_test_and_set(flag, __ATOMIC_RELAXED);
}

/**
 * Load atomic flag variable
 * @Note Operation has relaxed semantics.
 *
 * @param flag Pointer to a flag atomic variable
 * @return The current value of the variable
 */
static inline int _odp_atomic_flag_load(_odp_atomic_flag_t *flag)
{
	return __atomic_load_n(flag, __ATOMIC_RELAXED);
}

/**
 * Test-and-set of atomic flag variable
 * @Note Operation has acquire semantics. It pairs with a later
 * release operation.
 *
 * @param[in,out] flag Pointer to a flag atomic variable
 *
 * @retval 1 if the flag was already true - lock not taken
 * @retval 0 if the flag was false and is now set to true - lock taken
 */
static inline int _odp_atomic_flag_tas(_odp_atomic_flag_t *flag)
{
	return __atomic_test_and_set(flag, __ATOMIC_ACQUIRE);
}

/**
 * Clear atomic flag variable
 * The flag variable is cleared (set to false).
 * @Note Operation has release semantics. It pairs with an earlier
 * acquire operation or a later load operation.
 *
 * @param[out] flag Pointer to a flag atomic variable
 */
static inline void _odp_atomic_flag_clear(_odp_atomic_flag_t *flag)
{
	__atomic_clear(flag, __ATOMIC_RELEASE);
}

/* Check if target and compiler supports 128-bit scalars and corresponding
 * exchange and CAS operations */
/* GCC/clang on x86-64 needs -mcx16 compiler option */
#if defined __SIZEOF_INT128__ && defined __GCC_HAVE_SYNC_COMPARE_AND_SWAP_16

#if defined(__clang__)

#if ((__clang_major__ * 100 +  __clang_minor__) >= 306)
#define ODP_ATOMIC_U128
#endif

#else /* gcc */
#define ODP_ATOMIC_U128
#endif
#endif

#ifdef ODP_ATOMIC_U128

/** Atomic 128-bit type */
typedef struct ODP_ALIGNED(16) {
	_odp_u128_t v; /**< Actual storage for the atomic variable */
} _odp_atomic_u128_t;

/**
 * 16-byte atomic exchange operation
 *
 * @param ptr   Pointer to a 16-byte atomic variable
 * @param val   Pointer to new value to write
 * @param old   Pointer to location for old value
 * @param       mmodel Memory model associated with the exchange operation
 */
static inline void _odp_atomic_u128_xchg_mm(_odp_atomic_u128_t *ptr,
					    _odp_u128_t *val,
		_odp_u128_t *old,
		_odp_memmodel_t mm)
{
	__atomic_exchange(&ptr->v, val, old, mm);
}
#endif

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
