/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
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

#include <stdint.h>
#include <stdbool.h>
#include <odp_align.h>
#include <odp_hints.h>
#include <odp_atomic.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup odp_synchronizers
 *  Atomic operations.
 *  @{
 */

/**
 * Pointer atomic type
 */
typedef struct {
	void *v; /**< Actual storage for the atomic variable */
} _odp_atomic_ptr_t
ODP_ALIGNED(sizeof(void *)); /* Enforce alignement! */

/**
 * Atomic flag (boolean) type
 * @Note this is not the same as a plain boolean type.
 * _odp_atomic_flag_t is guaranteed to be able to operate on atomically.
 */
typedef char _odp_atomic_flag_t;

/**
 * Memory consistency models supported by ODP.
 */
typedef enum {
/** Relaxed memory model, no ordering of other accesses enforced.
 * Atomic operations with relaxed memory model cannot be used for
 * synchronization */
	_ODP_MEMMODEL_RLX = __ATOMIC_RELAXED,
/** Acquire memory model, synchronize with release stores from another
 * thread (later accesses cannot move before acquire operation).
 * Use acquire and release memory models for Release Consistency */
	_ODP_MEMMODEL_ACQ = __ATOMIC_ACQUIRE,
/** Release memory model, synchronize with acquire loads from another
 * thread (earlier accesses cannot move after release operation).
 * Use acquire and release memory models for Release Consistency */
	_ODP_MEMMODEL_RLS = __ATOMIC_RELEASE,
/** Acquire&release memory model, synchronize with acquire loads and release
 * stores in another (one other) thread */
	_ODP_MEMMODEL_ACQ_RLS = __ATOMIC_ACQ_REL,
/** Sequential consistent memory model, synchronize with acquire loads and
 * release stores in all threads */
	_ODP_MEMMODEL_SC = __ATOMIC_SEQ_CST
} _odp_memmodel_t;

/**
 * Insert a full memory barrier (fence) in the compiler and instruction
 * sequence.
 */
#define _ODP_FULL_BARRIER() __atomic_thread_fence(__ATOMIC_SEQ_CST)

/*****************************************************************************
 * Operations on 32-bit atomics
 * _odp_atomic_u32_load_mm - return current value
 * _odp_atomic_u32_store_mm - no return value
 * _odp_atomic_u32_xchg_mm - return old value
 * _odp_atomic_u32_cmp_xchg_strong_mm - return bool
 * _odp_atomic_u32_fetch_add_mm - return old value
 * _odp_atomic_u32_add_mm - no return value
 * _odp_atomic_u32_fetch_sub_mm - return old value
 * _odp_atomic_u32_sub_mm - no return value
 *****************************************************************************/

/**
 * Atomic load of 32-bit atomic variable
 *
 * @param ptr   Pointer to a 32-bit atomic variable
 * @param mmodel Memory model associated with the load operation
 *
 * @return Value of the variable
 */
static inline uint32_t _odp_atomic_u32_load_mm(const odp_atomic_u32_t *ptr,
		_odp_memmodel_t mmodel)
{
	return __atomic_load_n(&ptr->v, mmodel);
}

/**
 * Atomic store to 32-bit atomic variable
 *
 * @param ptr    Pointer to a 32-bit atomic variable
 * @param val    Value to store in the atomic variable
 * @param mmodel Memory model associated with the store operation
 */
static inline void _odp_atomic_u32_store_mm(odp_atomic_u32_t *ptr,
		uint32_t val,
		_odp_memmodel_t mmodel)
{
	__atomic_store_n(&ptr->v, val, mmodel);
}

/**
 * Atomic exchange (swap) of 32-bit atomic variable
 *
 * @param ptr    Pointer to a 32-bit atomic variable
 * @param val    New value to store in the atomic variable
 * @param mmodel Memory model associated with the exchange operation
 *
 * @return Old value of the variable
 */
static inline uint32_t _odp_atomic_u32_xchg_mm(odp_atomic_u32_t *ptr,
		uint32_t val,
		_odp_memmodel_t mmodel)

{
	return __atomic_exchange_n(&ptr->v, val, mmodel);
}

/**
 * Atomic compare and exchange (swap) of 32-bit atomic variable
 * "Strong" semantics, will not fail spuriously.
 *
 * @param ptr   Pointer to a 32-bit atomic variable
 * @param exp_p Pointer to expected value (updated on failure)
 * @param val   New value to write
 * @param succ  Memory model associated with a successful compare-and-swap
 * operation
 * @param fail  Memory model associated with a failed compare-and-swap
 * operation
 *
 * @return 1 (true) if exchange successful, 0 (false) if not successful (and
 * '*exp_p' updated with current value)
 */
static inline int _odp_atomic_u32_cmp_xchg_strong_mm(odp_atomic_u32_t *ptr,
		uint32_t *exp_p,
		uint32_t val,
		_odp_memmodel_t succ,
		_odp_memmodel_t fail)
{
	return __atomic_compare_exchange_n(&ptr->v, exp_p, val,
			false/*strong*/, succ, fail);
}

/**
 * Atomic fetch and add of 32-bit atomic variable
 *
 * @param ptr Pointer to a 32-bit atomic variable
 * @param val Value to add to the atomic variable
 * @param mmodel Memory model associated with the add operation
 *
 * @return Value of the atomic variable before the addition
 */
static inline uint32_t _odp_atomic_u32_fetch_add_mm(odp_atomic_u32_t *ptr,
		uint32_t val,
		_odp_memmodel_t mmodel)
{
	return __atomic_fetch_add(&ptr->v, val, mmodel);
}

/**
 * Atomic add of 32-bit atomic variable
 *
 * @param ptr Pointer to a 32-bit atomic variable
 * @param val Value to add to the atomic variable
 * @param mmodel Memory model associated with the add operation
 */
static inline void _odp_atomic_u32_add_mm(odp_atomic_u32_t *ptr,
		uint32_t val,
		_odp_memmodel_t mmodel)

{
	(void)__atomic_fetch_add(&ptr->v, val, mmodel);
}

/**
 * Atomic fetch and subtract of 32-bit atomic variable
 *
 * @param ptr Pointer to a 32-bit atomic variable
 * @param val Value to subtract from the atomic variable
 * @param mmodel Memory model associated with the subtract operation
 *
 * @return Value of the atomic variable before the subtraction
 */
static inline uint32_t _odp_atomic_u32_fetch_sub_mm(odp_atomic_u32_t *ptr,
		uint32_t val,
		_odp_memmodel_t mmodel)
{
	return __atomic_fetch_sub(&ptr->v, val, mmodel);
}

/**
 * Atomic subtract of 32-bit atomic variable
 *
 * @param ptr Pointer to a 32-bit atomic variable
 * @param val Value to subtract from the atomic variable
 * @param mmodel Memory model associated with the subtract operation
 */
static inline void _odp_atomic_u32_sub_mm(odp_atomic_u32_t *ptr,
		uint32_t val,
		_odp_memmodel_t mmodel)

{
	(void)__atomic_fetch_sub(&ptr->v, val, mmodel);
}

/*****************************************************************************
 * Operations on 64-bit atomics
 * _odp_atomic_u64_load_mm - return current value
 * _odp_atomic_u64_store_mm - no return value
 * _odp_atomic_u64_xchg_mm - return old value
 * _odp_atomic_u64_cmp_xchg_strong_mm - return bool
 * _odp_atomic_u64_fetch_add_mm - return old value
 * _odp_atomic_u64_add_mm - no return value
 * _odp_atomic_u64_fetch_sub_mm - return old value
 * _odp_atomic_u64_sub_mm - no return value
 *****************************************************************************/

/* Check if the compiler support lock-less atomic operations on 64-bit types */
#if !defined __GCC_ATOMIC_LLONG_LOCK_FREE ||  __GCC_ATOMIC_LLONG_LOCK_FREE < 2
/**
 * @internal
 * Helper macro for lock-based atomic operations on 64-bit integers
 * @param ptr Pointer to the 64-bit atomic variable
 * @param expr Expression used update the variable.
 * @param mm Memory model to use.
 * @return The old value of the variable.
 */
#define ATOMIC_OP_MM(ptr, expr, mm) \
({ \
	 uint64_t old_val; \
	 /* Loop while lock is already taken, stop when lock becomes clear */ \
	 while (__atomic_test_and_set(&(ptr)->lock, \
		(mm) == _ODP_MEMMODELSC ? \
		__ATOMIC_SEQ_CST : __ATOMIC_ACQUIRE)) \
		(void)0; \
	 old_val = (ptr)->v; \
	 (expr); /* Perform whatever update is desired */ \
	 __atomic_clear(&(ptr)->lock, \
		 (mm) == _ODP_MEMMODELSC ? \
		 __ATOMIC_SEQ_CST : __ATOMIC_RELEASE); \
	 old_val; /* Return old value */ \
})
#endif

/**
 * Atomic load of 64-bit atomic variable
 *
 * @param ptr   Pointer to a 64-bit atomic variable
 * @param mmodel Memory model associated with the load operation
 *
 * @return Value of the variable
 */
static inline uint64_t _odp_atomic_u64_load_mm(odp_atomic_u64_t *ptr,
		_odp_memmodel_t mmodel)
{
#if !defined __GCC_ATOMIC_LLONG_LOCK_FREE ||  __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	return ATOMIC_OP_MM(ptr, (void)0, mmodel);
#else
	return __atomic_load_n(&ptr->v, mmodel);
#endif
}

/**
 * Atomic store to 64-bit atomic variable
 *
 * @param ptr  Pointer to a 64-bit atomic variable
 * @param val  Value to write to the atomic variable
 * @param mmodel Memory model associated with the store operation
 */
static inline void _odp_atomic_u64_store_mm(odp_atomic_u64_t *ptr,
		uint64_t val,
		_odp_memmodel_t mmodel)
{
#if !defined __GCC_ATOMIC_LLONG_LOCK_FREE ||  __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	(void)ATOMIC_OP_MM(ptr, ptr->v = val, mmodel);
#else
	__atomic_store_n(&ptr->v, val, mmodel);
#endif
}

/**
 * Atomic exchange (swap) of 64-bit atomic variable
 *
 * @param ptr   Pointer to a 64-bit atomic variable
 * @param val   New value to write to the atomic variable
 * @param mmodel Memory model associated with the exchange operation
 *
 * @return Old value of variable
 */
static inline uint64_t _odp_atomic_u64_xchg_mm(odp_atomic_u64_t *ptr,
		uint64_t val,
		_odp_memmodel_t mmodel)

{
#if !defined __GCC_ATOMIC_LLONG_LOCK_FREE ||  __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	return ATOMIC_OP_MM(ptr, ptr->v = val, mmodel);
#else
	return __atomic_exchange_n(&ptr->v, val, mmodel);
#endif
}

/**
 * Atomic compare and exchange (swap) of 64-bit atomic variable
 * "Strong" semantics, will not fail spuriously.
 *
 * @param ptr   Pointer to a 64-bit atomic variable
 * @param exp_p Pointer to expected value (updated on failure)
 * @param val   New value to write
 * @param succ Memory model associated with a successful compare-and-swap
 * operation
 * @param fail Memory model associated with a failed compare-and-swap operation
 *
 * @return 1 (true) if exchange successful, 0 (false) if not successful (and
 * '*exp_p' updated with current value)
 */
static inline int _odp_atomic_u64_cmp_xchg_strong_mm(odp_atomic_u64_t *ptr,
		uint64_t *exp_p,
		uint64_t val,
		_odp_memmodel_t succ,
		_odp_memmodel_t fail)
{
#if !defined __GCC_ATOMIC_LLONG_LOCK_FREE ||  __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	/* Possibly we are a bit pessimistic with the memory models */
	int success;
	/* Loop while lock is already taken, stop when lock becomes clear */
	while (__atomic_test_and_set(&(ptr)->lock,
		(succ) == _ODP_MEMMODELSC ?
		__ATOMIC_SEQ_CST : __ATOMIC_ACQUIRE))
		(void)0;
	if (ptr->v == *exp_p) {
		ptr->v = val;
		success = 1;
	} else {
		*exp_p = ptr->v;
		success = 0;
		succ = fail;
	}
	__atomic_clear(&(ptr)->lock,
		       (succ) == _ODP_MEMMODELSC ?
		       __ATOMIC_SEQ_CST : __ATOMIC_RELEASE);
	return success;
#else
	return __atomic_compare_exchange_n(&ptr->v, exp_p, val,
			false, succ, fail);
#endif
}

/**
 * Atomic fetch and add of 64-bit atomic variable
 *
 * @param ptr   Pointer to a 64-bit atomic variable
 * @param val   Value to add to the atomic variable
 * @param mmodel Memory model associated with the add operation
 *
 * @return Value of the atomic variable before the addition
 */
static inline uint64_t _odp_atomic_u64_fetch_add_mm(odp_atomic_u64_t *ptr,
		uint64_t val,
		_odp_memmodel_t mmodel)
{
#if !defined __GCC_ATOMIC_LLONG_LOCK_FREE ||  __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	return ATOMIC_OP_MM(ptr, ptr->v += val, mmodel);
#else
	return __atomic_fetch_add(&ptr->v, val, mmodel);
#endif
}

/**
 * Atomic add of 64-bit atomic variable
 *
 * @param ptr   Pointer to a 64-bit atomic variable
 * @param val   Value to add to the atomic variable
 * @param mmodel Memory model associated with the add operation.
 */
static inline void _odp_atomic_u64_add_mm(odp_atomic_u64_t *ptr,
		uint64_t val,
		_odp_memmodel_t mmodel)

{
#if !defined __GCC_ATOMIC_LLONG_LOCK_FREE ||  __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	(void)ATOMIC_OP_MM(ptr, ptr->v += val, mmodel);
#else
	(void)__atomic_fetch_add(&ptr->v, val, mmodel);
#endif
}

/**
 * Atomic fetch and subtract of 64-bit atomic variable
 *
 * @param ptr   Pointer to a 64-bit atomic variable
 * @param val   Value to subtract from the atomic variable
 * @param mmodel Memory model associated with the subtract operation
 *
 * @return Value of the atomic variable before the subtraction
 */
static inline uint64_t _odp_atomic_u64_fetch_sub_mm(odp_atomic_u64_t *ptr,
		uint64_t val,
		_odp_memmodel_t mmodel)
{
#if !defined __GCC_ATOMIC_LLONG_LOCK_FREE ||  __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	return ATOMIC_OP_MM(ptr, ptr->v -= val, mmodel);
#else
	return __atomic_fetch_sub(&ptr->v, val, mmodel);
#endif
}

/**
 * Atomic subtract of 64-bit atomic variable
 *
 * @param ptr   Pointer to a 64-bit atomic variable
 * @param val   Value to subtract from the atomic variable
 * @param mmodel Memory model associated with the subtract operation
 */
static inline void _odp_atomic_u64_sub_mm(odp_atomic_u64_t *ptr,
		uint64_t val,
		_odp_memmodel_t mmodel)

{
#if !defined __GCC_ATOMIC_LLONG_LOCK_FREE ||  __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	(void)ATOMIC_OP_MM(ptr, ptr->v -= val, mmodel);
#else
	(void)__atomic_fetch_sub(&ptr->v, val, mmodel);
#endif
}

#if !defined __GCC_ATOMIC_LLONG_LOCK_FREE ||  __GCC_ATOMIC_LLONG_LOCK_FREE < 2
#undef ATOMIC_OP_MM
#endif

/*****************************************************************************
 * Operations on pointer atomics
 * _odp_atomic_ptr_init - no return value
 * _odp_atomic_ptr_load - return current value
 * _odp_atomic_ptr_store - no return value
 * _odp_atomic_ptr_xchg - return old value
 *****************************************************************************/

/**
 * Initialization of pointer atomic variable
 *
 * @param ptr   Pointer to a pointer atomic variable
 * @param val   Value to initialize the variable with
 */
static inline void _odp_atomic_ptr_init(_odp_atomic_ptr_t *ptr, void *val)
{
	__atomic_store_n(&ptr->v, val, __ATOMIC_RELAXED);
}

/**
 * Atomic load of pointer atomic variable
 *
 * @param ptr   Pointer to a pointer atomic variable
 * @param mmodel Memory model associated with the load operation
 *
 * @return Value of the variable
 */
static inline void *_odp_atomic_ptr_load(const _odp_atomic_ptr_t *ptr,
		_odp_memmodel_t mmodel)
{
	return __atomic_load_n(&ptr->v, mmodel);
}

/**
 * Atomic store to pointer atomic variable
 *
 * @param ptr  Pointer to a pointer atomic variable
 * @param val  Value to write to the atomic variable
 * @param mmodel Memory model associated with the store operation
 */
static inline void _odp_atomic_ptr_store(_odp_atomic_ptr_t *ptr,
		void *val,
		_odp_memmodel_t mmodel)
{
	__atomic_store_n(&ptr->v, val, mmodel);
}

/**
 * Atomic exchange (swap) of pointer atomic variable
 *
 * @param ptr   Pointer to a pointer atomic variable
 * @param val   New value to write
 * @param       mmodel Memory model associated with the exchange operation
 *
 * @return Old value of variable
 */
static inline void *_odp_atomic_ptr_xchg(_odp_atomic_ptr_t *ptr,
		void *val,
		_odp_memmodel_t mmodel)
{
	return __atomic_exchange_n(&ptr->v, val, mmodel);
}

/**
 * Atomic compare and exchange (swap) of pointer atomic variable
 * "Strong" semantics, will not fail spuriously.
 *
 * @param ptr   Pointer to a pointer atomic variable
 * @param exp_p Pointer to expected value (updated on failure)
 * @param val   New value to write
 * @param       succ Memory model associated with a successful compare-and-swap
 * operation
 * @param       fail Memory model associated with a failed compare-and-swap
 * operation
 *
 * @return 1 (true) if exchange successful, 0 (false) if not successful (and
 * '*exp_p' updated with current value)
 */
static inline int _odp_atomic_ptr_cmp_xchg_strong(_odp_atomic_ptr_t *ptr,
		void **exp_p,
		void *val,
		_odp_memmodel_t succ,
		_odp_memmodel_t fail)
{
	return __atomic_compare_exchange_n(&ptr->v, exp_p, val,
			false/*strong*/, succ, fail);
}

/*****************************************************************************
 * Operations on flag atomics
 * _odp_atomic_flag_init - no return value
 * _odp_atomic_flag_load - return current value
 * _odp_atomic_flag_tas - return old value
 * _odp_atomic_flag_clear - no return value
 *
 * Flag atomics use Release Consistency memory consistency model, acquire
 * model for TAS and release model for clear. 
 *****************************************************************************/

/**
 * Initialize a flag atomic variable
 *
 * @param ptr Pointer to a flag atomic variable
 * @param val The initial value (true or false) of the variable
 */
static inline void _odp_atomic_flag_init(_odp_atomic_flag_t *ptr, int val)
{
	__atomic_clear(ptr, __ATOMIC_RELAXED);
	if (val)
		__atomic_test_and_set(ptr, __ATOMIC_RELAXED);
}

/**
 * Load atomic flag variable
 * @Note Load operation has relaxed memory model.
 *
 * @param ptr Pointer to a flag atomic variable
 * @return The current value (true or false) of the variable
 */
static inline int _odp_atomic_flag_load(_odp_atomic_flag_t *ptr)
{
	return __atomic_load_n(ptr, __ATOMIC_RELAXED);
}

/**
 * Test-and-set of atomic flag variable
 * @Note Operation has acquire memory model. It pairs with a later
 * release operation in some thread.
 *
 * @param ptr Pointer to a flag atomic variable
 * @return The old value (true or false) of the variable
 */
static inline int _odp_atomic_flag_tas(_odp_atomic_flag_t *ptr)
{
	return __atomic_test_and_set(ptr, __ATOMIC_ACQUIRE);
}

/**
 * Clear atomic flag variable
 * The flag variable is cleared (set to the false value).
 * @Note Operation has release memory model. It pairs with an earlier
 * acquire operation in some thread.
 *
 * @param ptr   Pointer to a flag atomic variable
 */
static inline void _odp_atomic_flag_clear(_odp_atomic_flag_t *ptr)
{
	__atomic_clear(ptr, __ATOMIC_RELEASE);
}

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
