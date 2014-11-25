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
#include <odp_align.h>

/** @addtogroup odp_synchronizers
 *  Atomic types and relaxed operations. These operations cannot be used for
 *  synchronization.
 *  @{
 */


/**
 * Atomic unsigned integer 64 bits
 */
typedef struct {
	uint64_t v; /**< Actual storage for the atomic variable */
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	/* Some architectures do not support lock-free operations on 64-bit
	 * data types. We use a spin lock to ensure atomicity. */
	char lock; /**< Spin lock used to ensure atomic access */
#endif
} odp_atomic_u64_t
ODP_ALIGNED(sizeof(uint64_t)); /* Enforce alignement! */


/**
 * Atomic unsigned integer 32 bits
 */
typedef struct {
	uint32_t v; /**< Actual storage for the atomic variable */
} odp_atomic_u32_t
ODP_ALIGNED(sizeof(uint32_t)); /* Enforce alignement! */


/**
 * Initialize atomic uint32
 * @note Relaxed memory order, cannot be used for synchronization
 *
 * @param ptr    An atomic variable
 * @param val    Value to initialize the variable with
 */
static inline void odp_atomic_init_u32(odp_atomic_u32_t *ptr, uint32_t val)
{
	__atomic_store_n(&ptr->v, val, __ATOMIC_RELAXED);
}

/**
 * Load value of atomic uint32
 * @note Relaxed memory order, cannot be used for synchronization
 *
 * @param ptr    An atomic variable
 *
 * @return Value of the variable
 */
static inline uint32_t odp_atomic_load_u32(odp_atomic_u32_t *ptr)
{
	return __atomic_load_n(&ptr->v, __ATOMIC_RELAXED);
}

/**
 * Store value to atomic uint32
 * @note Relaxed memory order, cannot be used for synchronization
 *
 * @param ptr        An atomic variable
 * @param new_value  Store new_value to a variable
 */
static inline void odp_atomic_store_u32(odp_atomic_u32_t *ptr,
					uint32_t new_value)
{
	__atomic_store_n(&ptr->v, new_value, __ATOMIC_RELAXED);
}

/**
 * Fetch and add atomic uint32
 * @note Relaxed memory order, cannot be used for synchronization
 *
 * @param ptr    An atomic variable
 * @param value  A value to be added to the variable
 *
 * @return Value of the variable before the operation
 */
static inline uint32_t odp_atomic_fetch_add_u32(odp_atomic_u32_t *ptr,
						uint32_t value)
{
	return __atomic_fetch_add(&ptr->v, value, __ATOMIC_RELAXED);
}

/**
 * Add atomic uint32
 * @note Relaxed memory order, cannot be used for synchronization
 *
 * @param ptr    An atomic variable
 * @param value  A value to be added to the variable
 */
static inline void odp_atomic_add_u32(odp_atomic_u32_t *ptr,
				      uint32_t value)
{
	(void)__atomic_fetch_add(&ptr->v, value, __ATOMIC_RELAXED);
}

/**
 * Fetch and subtract uint32
 * @note Relaxed memory order, cannot be used for synchronization
 *
 * @param ptr    An atomic variable
 * @param value  A value to be sub to the variable
 *
 * @return Value of the variable before the operation
 */
static inline uint32_t odp_atomic_fetch_sub_u32(odp_atomic_u32_t *ptr,
						uint32_t value)
{
	return __atomic_fetch_sub(&ptr->v, value, __ATOMIC_RELAXED);
}

/**
 * Subtract uint32
 * @note Relaxed memory order, cannot be used for synchronization
 *
 * @param ptr    An atomic variable
 * @param value  A value to be subtract from the variable
 */
static inline void odp_atomic_sub_u32(odp_atomic_u32_t *ptr,
				      uint32_t value)
{
	(void)__atomic_fetch_sub(&ptr->v, value, __ATOMIC_RELAXED);
}

/**
 * Fetch and increment atomic uint32 by 1
 * @note Relaxed memory order, cannot be used for synchronization
 *
 * @param ptr    An atomic variable
 *
 * @return Value of the variable before the operation
 */

static inline uint32_t odp_atomic_fetch_inc_u32(odp_atomic_u32_t *ptr)
{
#if defined __OCTEON__
	uint32_t ret;
	__asm__ __volatile__ ("syncws");
	__asm__ __volatile__ ("lai %0,(%2)" : "=r" (ret), "+m" (ptr) :
			      "r" (ptr));
	return ret;
#else
	return __atomic_fetch_add(&ptr->v, 1, __ATOMIC_RELAXED);
#endif
}

/**
 * Increment atomic uint32 by 1
 * @note Relaxed memory order, cannot be used for synchronization
 *
 * @param ptr    An atomic variable
 *
 */
static inline void odp_atomic_inc_u32(odp_atomic_u32_t *ptr)
{
	(void)__atomic_fetch_add(&ptr->v, 1, __ATOMIC_RELAXED);
}

/**
 * Fetch and decrement uint32 by 1
 * @note Relaxed memory order, cannot be used for synchronization
 *
 * @param ptr    An atomic variable
 *
 * @return Value of the variable before the operation
 */
static inline uint32_t odp_atomic_fetch_dec_u32(odp_atomic_u32_t *ptr)
{
	return __atomic_fetch_sub(&ptr->v, 1, __ATOMIC_RELAXED);
}

/**
 * Decrement atomic uint32 by 1
 * @note Relaxed memory order, cannot be used for synchronization
 *
 * @param ptr    An atomic variable
 *
 */
static inline void odp_atomic_dec_u32(odp_atomic_u32_t *ptr)
{
	(void)__atomic_fetch_sub(&ptr->v, 1, __ATOMIC_RELAXED);
}

/**
 * Initialize atomic uint64
 * @note Relaxed memory order, cannot be used for synchronization
 *
 * @param ptr    An atomic variable
 * @param val    Value to initialize the variable with
 */
static inline void odp_atomic_init_u64(odp_atomic_u64_t *ptr, uint64_t val)
{
	ptr->v = val;
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	__atomic_clear(&ptr->lock, __ATOMIC_RELAXED);
#endif
}

#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
/**
 * @internal
 * Helper macro for lock-based atomic operations on 64-bit integers
 * @param ptr Pointer to the 64-bit atomic variable
 * @param expr Expression used update the variable.
 * @return The old value of the variable.
 */
#define ATOMIC_OP(ptr, expr) \
({ \
	uint64_t old_val; \
	/* Loop while lock is already taken, stop when lock becomes clear */ \
	while (__atomic_test_and_set(&(ptr)->lock, __ATOMIC_ACQUIRE)) \
		(void)0; \
	old_val = (ptr)->v; \
	(expr); /* Perform whatever update is desired */ \
	__atomic_clear(&(ptr)->lock, __ATOMIC_RELEASE); \
	old_val; /* Return old value */ \
})
#endif

/**
 * Load value of atomic uint64
 * @note Relaxed memory order, cannot be used for synchronization
 *
 * @param ptr    An atomic variable
 *
 * @return atomic uint64 value
 */
static inline uint64_t odp_atomic_load_u64(odp_atomic_u64_t *ptr)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	return ATOMIC_OP(ptr, (void)0);
#else
	return __atomic_load_n(&ptr->v, __ATOMIC_RELAXED);
#endif
}

/**
 * Store value to atomic uint64
 * @note Relaxed memory order, cannot be used for synchronization
 *
 * @param ptr        An atomic variable
 * @param new_value  Store new_value to a variable
 *
 * @note The operation is not synchronized with other threads
 */
static inline void odp_atomic_store_u64(odp_atomic_u64_t *ptr,
					uint64_t new_value)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	(void)ATOMIC_OP(ptr, ptr->v = new_value);
#else
	__atomic_store_n(&ptr->v, new_value, __ATOMIC_RELAXED);
#endif
}

/**
 * Fetch and add atomic uint64
 * @note Relaxed memory order, cannot be used for synchronization
 *
 * @param ptr    An atomic variable
 * @param value  A value to be added to the variable
 *
 * @return Value of the variable before the operation
 */

static inline uint64_t odp_atomic_fetch_add_u64(odp_atomic_u64_t *ptr,
						uint64_t value)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	return ATOMIC_OP(ptr, ptr->v += value);
#else
	return __atomic_fetch_add(&ptr->v, value, __ATOMIC_RELAXED);
#endif
}

/**
 * Add atomic uint64
 * @note Relaxed memory order, cannot be used for synchronization
 *
 * @param ptr    An atomic variable
 * @param value  A value to be added to the variable
 *
 */
static inline void odp_atomic_add_u64(odp_atomic_u64_t *ptr, uint64_t value)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	(void)ATOMIC_OP(ptr, ptr->v += value);
#else
	(void)__atomic_fetch_add(&ptr->v, value, __ATOMIC_RELAXED);
#endif
}

/**
 * Fetch and subtract atomic uint64
 * @note Relaxed memory order, cannot be used for synchronization
 *
 * @param ptr    An atomic variable
 * @param value  A value to be subtracted from the variable
 *
 * @return Value of the variable before the operation
 */
static inline uint64_t odp_atomic_fetch_sub_u64(odp_atomic_u64_t *ptr,
						uint64_t value)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	return ATOMIC_OP(ptr, ptr->v -= value);
#else
	return __atomic_fetch_sub(&ptr->v, value, __ATOMIC_RELAXED);
#endif
}

/**
 * Subtract atomic uint64
 * @note Relaxed memory order, cannot be used for synchronization
 *
 * @param ptr    An atomic variable
 * @param value  A value to be subtracted from the variable
 *
 */
static inline void odp_atomic_sub_u64(odp_atomic_u64_t *ptr, uint64_t value)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	(void)ATOMIC_OP(ptr, ptr->v -= value);
#else
	(void)__atomic_fetch_sub(&ptr->v, value, __ATOMIC_RELAXED);
#endif
}

/**
 * Fetch and increment atomic uint64 by 1
 * @note Relaxed memory order, cannot be used for synchronization
 *
 * @param ptr    An atomic variable
 *
 * @return Value of the variable before the operation
 */
static inline uint64_t odp_atomic_fetch_inc_u64(odp_atomic_u64_t *ptr)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	return ATOMIC_OP(ptr, ptr->v++);
#else
	return __atomic_fetch_add(&ptr->v, 1, __ATOMIC_RELAXED);
#endif
}

/**
 * Increment atomic uint64 by 1
 * @note Relaxed memory order, cannot be used for synchronization
 *
 * @param ptr    An atomic variable
 *
 */
static inline void odp_atomic_inc_u64(odp_atomic_u64_t *ptr)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	(void)ATOMIC_OP(ptr, ptr->v++);
#else
	(void)__atomic_fetch_add(&ptr->v, 1, __ATOMIC_RELAXED);
#endif
}

/**
 * Fetch and decrement atomic uint64 by 1
 * @note Relaxed memory order, cannot be used for synchronization
 *
 * @param ptr    An atomic variable
 *
 * @return Value of the variable before the operation
 */
static inline uint64_t odp_atomic_fetch_dec_u64(odp_atomic_u64_t *ptr)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	return ATOMIC_OP(ptr, ptr->v--);
#else
	return __atomic_fetch_sub(&ptr->v, 1, __ATOMIC_RELAXED);
#endif
}

/**
 * Decrement atomic uint64 by 1
 * @note Relaxed memory order, cannot be used for synchronization
 *
 * @param ptr    An atomic variable
 *
 */
static inline void odp_atomic_dec_u64(odp_atomic_u64_t *ptr)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	(void)ATOMIC_OP(ptr, ptr->v--);
#else
	(void)__atomic_fetch_sub(&ptr->v, 1, __ATOMIC_RELAXED);
#endif
}

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
