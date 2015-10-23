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

#ifndef ODP_API_ATOMIC_H_
#define ODP_API_ATOMIC_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup odp_atomic ODP ATOMIC
 * @details
 * <b> Atomic integers </b>
 *
 * Atomic integer types (odp_atomic_u32_t and odp_atomic_u64_t) can be used to
 * implement e.g. shared counters. If not otherwise documented, operations in
 * this API are implemented using <b> RELAXED memory ordering </b> (see memory
 * order descriptions in the C11 specification). Relaxed operations do not
 * provide synchronization or ordering for other memory accesses (initiated
 * before or after the operation), only atomicity of the operation itself is
 * guaranteed.
 *
 * @{
 */

/**
 * @typedef odp_atomic_u64_t
 * Atomic 64-bit unsigned integer
 *
 * @typedef odp_atomic_u32_t
 * Atomic 32-bit unsigned integer
 */

/**
 * Initialize atomic uint32 variable
 *
 * @param atom    Pointer to atomic variable
 * @param val     Value to initialize the variable with
 */
void odp_atomic_init_u32(odp_atomic_u32_t *atom, uint32_t val);

/**
 * Load value of atomic uint32 variable
 *
 * @param atom    Pointer to atomic variable
 *
 * @return Value of the variable
 */
uint32_t odp_atomic_load_u32(odp_atomic_u32_t *atom);

/**
 * Store value to atomic uint32 variable
 *
 * @param atom    Pointer to atomic variable
 * @param val     Value to store in the variable
 */
void odp_atomic_store_u32(odp_atomic_u32_t *atom, uint32_t val);

/**
 * Fetch and add to atomic uint32 variable
 *
 * @param atom    Pointer to atomic variable
 * @param val     Value to be added to the variable
 *
 * @return Value of the variable before the addition
 */
uint32_t odp_atomic_fetch_add_u32(odp_atomic_u32_t *atom, uint32_t val);

/**
 * Add to atomic uint32 variable
 *
 * @param atom    Pointer to atomic variable
 * @param val     Value to be added to the variable
 */
void odp_atomic_add_u32(odp_atomic_u32_t *atom, uint32_t val);

/**
 * Fetch and subtract from atomic uint32 variable
 *
 * @param atom    Pointer to atomic variable
 * @param val     Value to be subracted from the variable
 *
 * @return Value of the variable before the subtraction
 */
uint32_t odp_atomic_fetch_sub_u32(odp_atomic_u32_t *atom, uint32_t val);

/**
 * Subtract from atomic uint32 variable
 *
 * @param atom    Pointer to atomic variable
 * @param val     Value to be subtracted from the variable
 */
void odp_atomic_sub_u32(odp_atomic_u32_t *atom, uint32_t val);

/**
 * Fetch and increment atomic uint32 variable
 *
 * @param atom    Pointer to atomic variable
 *
 * @return Value of the variable before the increment
 */
uint32_t odp_atomic_fetch_inc_u32(odp_atomic_u32_t *atom);

/**
 * Increment atomic uint32 variable
 *
 * @param atom    Pointer to atomic variable
 */
void odp_atomic_inc_u32(odp_atomic_u32_t *atom);

/**
 * Fetch and decrement atomic uint32 variable
 *
 * @param atom    Pointer to atomic variable
 *
 * @return Value of the variable before the subtraction
 */
uint32_t odp_atomic_fetch_dec_u32(odp_atomic_u32_t *atom);

/**
 * Decrement atomic uint32 variable
 *
 * @param atom    Pointer to atomic variable
 */
void odp_atomic_dec_u32(odp_atomic_u32_t *atom);

/**
 * Initialize atomic uint64 variable
 *
 * @param atom    Pointer to atomic variable
 * @param val     Value to initialize the variable with
 */
void odp_atomic_init_u64(odp_atomic_u64_t *atom, uint64_t val);

/**
 * Load value of atomic uint64 variable
 *
 * @param atom    Pointer to atomic variable
 *
 * @return Value of the variable
 */
uint64_t odp_atomic_load_u64(odp_atomic_u64_t *atom);

/**
 * Store value to atomic uint64 variable
 *
 * @param atom    Pointer to atomic variable
 * @param val     Value to store in the variable
 */
void odp_atomic_store_u64(odp_atomic_u64_t *atom, uint64_t val);

/**
 * Fetch and add to atomic uint64 variable
 *
 * @param atom    Pointer to atomic variable
 * @param val     Value to be added to the variable
 *
 * @return Value of the variable before the addition
 */
uint64_t odp_atomic_fetch_add_u64(odp_atomic_u64_t *atom, uint64_t val);

/**
 * Add to atomic uint64 variable
 *
 * @param atom    Pointer to atomic variable
 * @param val     Value to be added to the variable
 */
void odp_atomic_add_u64(odp_atomic_u64_t *atom, uint64_t val);

/**
 * Fetch and subtract from atomic uint64 variable
 *
 * @param atom    Pointer to atomic variable
 * @param val     Value to be subtracted from the variable
 *
 * @return Value of the variable before the subtraction
 */
uint64_t odp_atomic_fetch_sub_u64(odp_atomic_u64_t *atom, uint64_t val);

/**
 * Subtract from atomic uint64 variable
 *
 * @param atom    Pointer to atomic variable
 * @param val     Value to be subtracted from the variable
 */
void odp_atomic_sub_u64(odp_atomic_u64_t *atom, uint64_t val);

/**
 * Fetch and increment atomic uint64 variable
 *
 * @param atom    Pointer to atomic variable
 *
 * @return Value of the variable before the increment
 */
uint64_t odp_atomic_fetch_inc_u64(odp_atomic_u64_t *atom);

/**
 * Increment atomic uint64 variable
 *
 * @param atom    Pointer to atomic variable
 */
void odp_atomic_inc_u64(odp_atomic_u64_t *atom);

/**
 * Fetch and decrement atomic uint64 variable
 *
 * @param atom    Pointer to atomic variable
 *
 * @return Value of the variable before the decrement
 */
uint64_t odp_atomic_fetch_dec_u64(odp_atomic_u64_t *atom);

/**
 * Decrement atomic uint64 variable
 *
 * @param atom    Pointer to atomic variable
 */
void odp_atomic_dec_u64(odp_atomic_u64_t *atom);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
