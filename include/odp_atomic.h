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


#include <odp_std_types.h>


/**
 * Atomic integer
 */
typedef volatile int32_t odp_atomic_int_t;

/**
 * Atomic unsigned integer 64 bits
 */
typedef volatile uint64_t odp_atomic_u64_t;

/**
 * Atomic unsigned integer 32 bits
 */
typedef volatile uint32_t odp_atomic_u32_t;


/**
 * Initialize atomic integer
 *
 * @param ptr    An integer atomic variable
 *
 * @note The operation is not atomic
 */
static inline void odp_atomic_init_int(odp_atomic_int_t *ptr)
{
	*ptr = 0;
}

/**
 * Load value of atomic integer
 *
 * @param ptr    An atomic variable
 *
 * @return atomic integer value
 *
 * @note The operation is not atomic
 */
static inline int odp_atomic_load_int(odp_atomic_int_t *ptr)
{
	return *ptr;
}

/**
 * Store value to atomic integer
 *
 * @param ptr        An atomic variable
 * @param new_value  Store new_value to a variable
 *
 * @note The operation is not atomic
 */
static inline void odp_atomic_store_int(odp_atomic_int_t *ptr, int new_value)
{
	*ptr = new_value;
}

/**
 * Fetch and add atomic integer
 *
 * @param ptr    An atomic variable
 * @param value  A value to be added to the variable
 *
 * @return Value of the variable before the operation
 */
static inline int odp_atomic_fetch_add_int(odp_atomic_int_t *ptr, int value)
{
	return __sync_fetch_and_add(ptr, value);
}

/**
 * Fetch and substract atomic integer
 *
 * @param ptr    An atomic int variable
 * @param value  A value to be subtracted from the variable
 *
 * @return Value of the variable before the operation
 */
static inline int odp_atomic_fetch_sub_int(odp_atomic_int_t *ptr, int value)
{
	return __sync_fetch_and_sub(ptr, value);
}

/**
 * Fetch and increment atomic integer by 1
 *
 * @param ptr    An atomic variable
 *
 * @return Value of the variable before the operation
 */
static inline int odp_atomic_fetch_inc_int(odp_atomic_int_t *ptr)
{
	return odp_atomic_fetch_add_int(ptr, 1);
}

/**
 * Increment atomic integer by 1
 *
 * @param ptr    An atomic variable
 *
 */
static inline void odp_atomic_inc_int(odp_atomic_int_t *ptr)
{
	odp_atomic_fetch_add_int(ptr, 1);
}

/**
 * Fetch and decrement atomic integer by 1
 *
 * @param ptr    An atomic int variable
 *
 * @return Value of the variable before the operation
 */
static inline int odp_atomic_fetch_dec_int(odp_atomic_int_t *ptr)
{
	return odp_atomic_fetch_sub_int(ptr, 1);
}

/**
 * Decrement atomic integer by 1
 *
 * @param ptr    An atomic variable
 *
 */
static inline void odp_atomic_dec_int(odp_atomic_int_t *ptr)
{
	odp_atomic_fetch_sub_int(ptr, 1);
}

/**
 * Initialize atomic uint32
 *
 * @param ptr    An atomic variable
 *
 * @note The operation is not atomic
 */
static inline void odp_atomic_init_u32(odp_atomic_u32_t *ptr)
{
	*ptr = 0;
}

/**
 * Load value of atomic uint32
 *
 * @param ptr    An atomic variable
 *
 * @return atomic uint32 value
 *
 * @note The operation is not atomic
 */
static inline uint32_t odp_atomic_load_u32(odp_atomic_u32_t *ptr)
{
	return *ptr;
}

/**
 * Store value to atomic uint32
 *
 * @param ptr        An atomic variable
 * @param new_value  Store new_value to a variable
 *
 * @note The operation is not atomic
 */
static inline void odp_atomic_store_u32(odp_atomic_u32_t *ptr,
					uint32_t new_value)
{
	*ptr = new_value;
}

/**
 * Fetch and add atomic uint32
 *
 * @param ptr    An atomic variable
 * @param value  A value to be added to the variable
 *
 * @return Value of the variable before the operation
 */
static inline uint32_t odp_atomic_fetch_add_u32(odp_atomic_u32_t *ptr,
						uint32_t value)
{
	return __sync_fetch_and_add(ptr, value);
}

/**
 * Fetch and substract uint32
 *
 * @param ptr    An atomic variable
 * @param value  A value to be sub to the variable
 *
 * @return Value of the variable before the operation
 */
static inline uint32_t odp_atomic_fetch_sub_u32(odp_atomic_u32_t *ptr,
						uint32_t value)
{
	return __sync_fetch_and_sub(ptr, value);
}

/**
 * Fetch and increment atomic uint32 by 1
 *
 * @param ptr    An atomic variable
 *
 * @return Value of the variable before the operation
 */
static inline uint32_t odp_atomic_fetch_inc_u32(odp_atomic_u32_t *ptr)
{
	return odp_atomic_fetch_add_u32(ptr, 1);
}

/**
 * Increment atomic uint32 by 1
 *
 * @param ptr    An atomic variable
 *
 */
static inline void odp_atomic_inc_u32(odp_atomic_u32_t *ptr)
{
	odp_atomic_fetch_add_u32(ptr, 1);
}

/**
 * Fetch and decrement uint32 by 1
 *
 * @param ptr    An atomic variable
 *
 * @return Value of the variable before the operation
 */
static inline uint32_t odp_atomic_fetch_dec_u32(odp_atomic_u32_t *ptr)
{
	return odp_atomic_fetch_sub_u32(ptr, 1);
}

/**
 * Decrement atomic uint32 by 1
 *
 * @param ptr    An atomic variable
 *
 */
static inline void odp_atomic_dec_u32(odp_atomic_u32_t *ptr)
{
	odp_atomic_fetch_sub_u32(ptr, 1);
}

/**
 * Atomic compare and set for 32bit
 *
 * @param dst destination location into which the value will be written.
 * @param exp expected value.
 * @param src new value.
 * @return Non-zero on success; 0 on failure.
 */
static inline int
odp_atomic32_cmpset(odp_atomic_u32_t *dst, uint32_t exp, uint32_t src)
{
	return __sync_bool_compare_and_swap(dst, exp, src);
}

/**
 * Initialize atomic uint64
 *
 * @param ptr    An atomic variable
 *
 * @note The operation is not atomic
 */
static inline void odp_atomic_init_u64(odp_atomic_u64_t *ptr)
{
	*ptr = 0;
}

/**
 * Load value of atomic uint64
 *
 * @param ptr    An atomic variable
 *
 * @return atomic uint64 value
 *
 * @note The operation is not atomic
 */
static inline uint64_t odp_atomic_load_u64(odp_atomic_u64_t *ptr)
{
	return *ptr;
}

/**
 * Store value to atomic uint64
 *
 * @param ptr        An atomic variable
 * @param new_value  Store new_value to a variable
 *
 * @note The operation is not atomic
 */
static inline void odp_atomic_store_u64(odp_atomic_u64_t *ptr,
					uint64_t new_value)
{
	*ptr = new_value;
}

/**
 * Add atomic uint64
 *
 * @param ptr    An atomic variable
 * @param value  A value to be added to the variable
 *
 */
static inline void odp_atomic_add_u64(odp_atomic_u64_t *ptr, uint64_t value)
{
	__sync_fetch_and_add(ptr, value);
}

/**
 * Fetch and add atomic uint64
 *
 * @param ptr    An atomic variable
 * @param value  A value to be added to the variable
 *
 * @return Value of the variable before the operation
 */
static inline uint64_t odp_atomic_fetch_add_u64(odp_atomic_u64_t *ptr,
						uint64_t value)
{
	return __sync_fetch_and_add(ptr, value);
}

/**
 * Subtract atomic uint64
 *
 * @param ptr    An atomic variable
 * @param value  A value to be subtracted from the variable
 *
 */
static inline void odp_atomic_sub_u64(odp_atomic_u64_t *ptr, uint64_t value)
{
	__sync_fetch_and_sub(ptr, value);
}

/**
 * Fetch and subtract atomic uint64
 *
 * @param ptr    An atomic variable
 * @param value  A value to be subtracted from the variable
 *
 * @return Value of the variable before the operation
 */
static inline uint64_t odp_atomic_fetch_sub_u64(odp_atomic_u64_t *ptr,
						uint64_t value)
{
	return __sync_fetch_and_sub(ptr, value);
}

/**
 * Fetch and increment atomic uint64 by 1
 *
 * @param ptr    An atomic variable
 *
 * @return Value of the variable before the operation
 */
static inline uint64_t odp_atomic_fetch_inc_u64(odp_atomic_u64_t *ptr)
{
	return odp_atomic_fetch_add_u64(ptr, 1);
}

/**
 * Increment atomic uint64 by 1
 *
 * @param ptr    An atomic variable
 *
 */
static inline void odp_atomic_inc_u64(odp_atomic_u64_t *ptr)
{
	odp_atomic_fetch_add_u64(ptr, 1);
}

/**
 * Fetch and decement atomic uint64 by 1
 *
 * @param ptr    An atomic variable
 *
 * @return Value of the variable before the operation
 */
static inline uint64_t odp_atomic_fetch_dec_u64(odp_atomic_u64_t *ptr)
{
	return odp_atomic_fetch_sub_u64(ptr, 1);
}

/**
 * Deccrement atomic uint64 by 1
 *
 * @param ptr    An atomic variable
 *
 */
static inline void odp_atomic_dec_u64(odp_atomic_u64_t *ptr)
{
	odp_atomic_fetch_sub_u64(ptr, 1);
}

/**
 * Atomic compare and set for 64bit
 *
 * @param dst destination location into which the value will be written.
 * @param exp expected value.
 * @param src new value.
 * @return Non-zero on success; 0 on failure.
 */
static inline int
odp_atomic64_cmpset(odp_atomic_u64_t *dst, uint64_t exp, uint64_t src)
{
	return __sync_bool_compare_and_swap(dst, exp, src);
}

#ifdef __cplusplus
}
#endif

#endif

