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

#ifndef ODP_ATOMIC_H_
#define ODP_ATOMIC_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <odp/align.h>

/** @addtogroup odp_synchronizers
 *  Atomic types and relaxed operations. These operations cannot be used for
 *  synchronization.
 *  @{
 */


/**
 * Atomic 64-bit unsigned integer
 */
typedef struct {
	uint64_t v; /**< Actual storage for the atomic variable */
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	/* Some architectures do not support lock-free operations on 64-bit
	 * data types. We use a spin lock to ensure atomicity. */
	char lock; /**< Spin lock (if needed) used to ensure atomic access */
#endif
} odp_atomic_u64_t
ODP_ALIGNED(sizeof(uint64_t)); /* Enforce alignement! */


/**
 * Atomic 32-bit unsigned integer
 */
typedef struct {
	uint32_t v; /**< Actual storage for the atomic variable */
} odp_atomic_u32_t
ODP_ALIGNED(sizeof(uint32_t)); /* Enforce alignement! */


/**
 * Initialize atomic uint32 variable
 * @note Relaxed memory order, cannot be used for synchronization
 *
 * @param[out] atom Pointer to an atomic uint32 variable
 * @param val Value to initialize the variable with
 */
static inline void odp_atomic_init_u32(odp_atomic_u32_t *atom, uint32_t val)
{
	__atomic_store_n(&atom->v, val, __ATOMIC_RELAXED);
}

/**
 * Load value of atomic uint32 variable
 * @note Relaxed memory order, cannot be used for synchronization
 *
 * @param atom Pointer to an atomic uint32 variable
 *
 * @return Value of the variable
 */
static inline uint32_t odp_atomic_load_u32(odp_atomic_u32_t *atom)
{
	return __atomic_load_n(&atom->v, __ATOMIC_RELAXED);
}

/**
 * Store value to atomic uint32 variable
 * @note Relaxed memory order, cannot be used for synchronization
 *
 * @param[out] atom Pointer to an atomic uint32 variable
 * @param val Value to store in the variable
 */
static inline void odp_atomic_store_u32(odp_atomic_u32_t *atom,
					uint32_t val)
{
	__atomic_store_n(&atom->v, val, __ATOMIC_RELAXED);
}

/**
 * Fetch and add to atomic uint32 variable
 * @note Relaxed memory order, cannot be used for synchronization
 *
 * @param[in,out] atom Pointer to an atomic uint32 variable
 * @param val Value to be added to the variable
 *
 * @return Value of the variable before the addition
 */
static inline uint32_t odp_atomic_fetch_add_u32(odp_atomic_u32_t *atom,
						uint32_t val)
{
	return __atomic_fetch_add(&atom->v, val, __ATOMIC_RELAXED);
}

/**
 * Add to atomic uint32 variable
 * @note Relaxed memory order, cannot be used for synchronization
 *
 * @param[in,out] atom Pointer to an atomic uint32 variable
 * @param val A value to be added to the variable
 */
static inline void odp_atomic_add_u32(odp_atomic_u32_t *atom,
				      uint32_t val)
{
	(void)__atomic_fetch_add(&atom->v, val, __ATOMIC_RELAXED);
}

/**
 * Fetch and subtract from atomic uint32 variable
 * @note Relaxed memory order, cannot be used for synchronization
 *
 * @param[in,out] atom Pointer to an atomic uint32 variable
 * @param val A value to be subracted from the variable
 *
 * @return Value of the variable before the subtraction
 */
static inline uint32_t odp_atomic_fetch_sub_u32(odp_atomic_u32_t *atom,
						uint32_t val)
{
	return __atomic_fetch_sub(&atom->v, val, __ATOMIC_RELAXED);
}

/**
 * Subtract from atomic uint32 variable
 * @note Relaxed memory order, cannot be used for synchronization
 *
 * @param[in,out] atom Pointer to an atomic uint32 variable
 * @param val Value to be subtracted from the variable
 */
static inline void odp_atomic_sub_u32(odp_atomic_u32_t *atom,
				      uint32_t val)
{
	(void)__atomic_fetch_sub(&atom->v, val, __ATOMIC_RELAXED);
}

/**
 * Fetch and increment atomic uint32 variable
 * @note Relaxed memory order, cannot be used for synchronization
 *
 * @param[in,out] atom Pointer to an atomic uint32 variable
 *
 * @return Value of the variable before the increment
 */

static inline uint32_t odp_atomic_fetch_inc_u32(odp_atomic_u32_t *atom)
{
	return __atomic_fetch_add(&atom->v, 1, __ATOMIC_RELAXED);
}

/**
 * Increment atomic uint32 variable
 * @note Relaxed memory order, cannot be used for synchronization
 *
 * @param[in,out] atom Pointer to an atomic uint32 variable
 */
static inline void odp_atomic_inc_u32(odp_atomic_u32_t *atom)
{
	(void)__atomic_fetch_add(&atom->v, 1, __ATOMIC_RELAXED);
}

/**
 * Fetch and decrement atomic uint32 variable
 * @note Relaxed memory order, cannot be used for synchronization
 *
 * @param[in,out] atom Pointer to an atomic uint32 variable
 *
 * @return Value of the variable before the subtraction
 */
static inline uint32_t odp_atomic_fetch_dec_u32(odp_atomic_u32_t *atom)
{
	return __atomic_fetch_sub(&atom->v, 1, __ATOMIC_RELAXED);
}

/**
 * Decrement atomic uint32 variable
 * @note Relaxed memory order, cannot be used for synchronization
 *
 * @param[in,out] atom Pointer to an atomic uint32 variable
 */
static inline void odp_atomic_dec_u32(odp_atomic_u32_t *atom)
{
	(void)__atomic_fetch_sub(&atom->v, 1, __ATOMIC_RELAXED);
}

/**
 * Initialize atomic uint64 variable
 * @note Relaxed memory order, cannot be used for synchronization
 *
 * @param[out] atom Pointer to an atomic uint64 variable
 * @param val Value to initialize the variable with
 */
static inline void odp_atomic_init_u64(odp_atomic_u64_t *atom, uint64_t val)
{
	atom->v = val;
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	__atomic_clear(&atom->lock, __ATOMIC_RELAXED);
#endif
}

#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
/**
 * @internal
 * Helper macro for lock-based atomic operations on 64-bit integers
 * @param[in,out] atom Pointer to the 64-bit atomic variable
 * @param expr Expression used update the variable.
 * @return The old value of the variable.
 */
#define ATOMIC_OP(atom, expr) \
({ \
	uint64_t old_val; \
	/* Loop while lock is already taken, stop when lock becomes clear */ \
	while (__atomic_test_and_set(&(atom)->lock, __ATOMIC_ACQUIRE)) \
		(void)0; \
	old_val = (atom)->v; \
	(expr); /* Perform whatever update is desired */ \
	__atomic_clear(&(atom)->lock, __ATOMIC_RELEASE); \
	old_val; /* Return old value */ \
})
#endif

/**
 * Load value of atomic uint64 variable
 * @note Relaxed memory order, cannot be used for synchronization
 *
 * @param atom Pointer to an atomic uint64 variable
 *
 * @return Value of the variable
 */
static inline uint64_t odp_atomic_load_u64(odp_atomic_u64_t *atom)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	return ATOMIC_OP(atom, (void)0);
#else
	return __atomic_load_n(&atom->v, __ATOMIC_RELAXED);
#endif
}

/**
 * Store value to atomic uint64 variable
 * @note Relaxed memory order, cannot be used for synchronization
 *
 * @param[out] atom Pointer to an atomic uint64 variable
 * @param val Value to store in the variable
 */
static inline void odp_atomic_store_u64(odp_atomic_u64_t *atom,
					uint64_t val)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	(void)ATOMIC_OP(atom, atom->v = val);
#else
	__atomic_store_n(&atom->v, val, __ATOMIC_RELAXED);
#endif
}

/**
 * Fetch and add to atomic uint64 variable
 * @note Relaxed memory order, cannot be used for synchronization
 *
 * @param[in,out] atom Pointer to an atomic uint64 variable
 * @param val Value to be added to the variable
 *
 * @return Value of the variable before the addition
 */

static inline uint64_t odp_atomic_fetch_add_u64(odp_atomic_u64_t *atom,
						uint64_t val)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	return ATOMIC_OP(atom, atom->v += val);
#else
	return __atomic_fetch_add(&atom->v, val, __ATOMIC_RELAXED);
#endif
}

/**
 * Add to atomic uint64 variable
 * @note Relaxed memory order, cannot be used for synchronization
 *
 * @param[in,out] atom Pointer to an atomic uint64 variable
 * @param val Value to be added to the variable
 *
 */
static inline void odp_atomic_add_u64(odp_atomic_u64_t *atom, uint64_t val)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	(void)ATOMIC_OP(atom, atom->v += val);
#else
	(void)__atomic_fetch_add(&atom->v, val, __ATOMIC_RELAXED);
#endif
}

/**
 * Fetch and subtract from atomic uint64 variable
 * @note Relaxed memory order, cannot be used for synchronization
 *
 * @param[in,out] atom Pointer to an atomic uint64 variable
 * @param val Value to be subtracted from the variable
 *
 * @return Value of the variable before the subtraction
 */
static inline uint64_t odp_atomic_fetch_sub_u64(odp_atomic_u64_t *atom,
						uint64_t val)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	return ATOMIC_OP(atom, atom->v -= val);
#else
	return __atomic_fetch_sub(&atom->v, val, __ATOMIC_RELAXED);
#endif
}

/**
 * Subtract from atomic uint64 variable
 * @note Relaxed memory order, cannot be used for synchronization
 *
 * @param[in,out] atom Pointer to an atomic uint64 variable
 * @param val Value to be subtracted from the variable
 */
static inline void odp_atomic_sub_u64(odp_atomic_u64_t *atom, uint64_t val)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	(void)ATOMIC_OP(atom, atom->v -= val);
#else
	(void)__atomic_fetch_sub(&atom->v, val, __ATOMIC_RELAXED);
#endif
}

/**
 * Fetch and increment atomic uint64 variable
 * @note Relaxed memory order, cannot be used for synchronization
 *
 * @param[in,out] atom Pointer to an atomic uint64 variable
 *
 * @return Value of the variable before the increment
 */
static inline uint64_t odp_atomic_fetch_inc_u64(odp_atomic_u64_t *atom)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	return ATOMIC_OP(atom, atom->v++);
#else
	return __atomic_fetch_add(&atom->v, 1, __ATOMIC_RELAXED);
#endif
}

/**
 * Increment atomic uint64 variable
 * @note Relaxed memory order, cannot be used for synchronization
 *
 * @param[in,out] atom Pointer to an atomic uint64 variable
 */
static inline void odp_atomic_inc_u64(odp_atomic_u64_t *atom)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	(void)ATOMIC_OP(atom, atom->v++);
#else
	(void)__atomic_fetch_add(&atom->v, 1, __ATOMIC_RELAXED);
#endif
}

/**
 * Fetch and decrement atomic uint64 variable
 * @note Relaxed memory order, cannot be used for synchronization
 *
 * @param[in,out] atom Pointer to an atomic uint64 variable
 *
 * @return Value of the variable before the decrement
 */
static inline uint64_t odp_atomic_fetch_dec_u64(odp_atomic_u64_t *atom)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	return ATOMIC_OP(atom, atom->v--);
#else
	return __atomic_fetch_sub(&atom->v, 1, __ATOMIC_RELAXED);
#endif
}

/**
 * Decrement atomic uint64 variable
 * @note Relaxed memory order, cannot be used for synchronization
 *
 * @param[in,out] atom Pointer to an atomic uint64 variable
 */
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

#ifdef __cplusplus
}
#endif

#endif
