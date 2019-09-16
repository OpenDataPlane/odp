/* Copyright (c) 2017-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_FRAGREASS_PP_ATOMICS_H_
#define ODP_FRAGREASS_PP_ATOMICS_H_

#if __SIZEOF_POINTER__ == 4
/**
 * A wrapper function to perform a 64-bit "strong" atomic compare and swap
 * (CAS) operation. This generic version of the function is used if an
 * architecture-specific (e.g. lockless) variant is not specified.
 *
 * @param var		The location at which the CAS should take place
 * @param exp		A pointer to the expected value
 * @param neu		A pointer to the new value to be written on success
 * @param mo_success	The memory order on success
 * @param mo_failure	The memory order on failure
 *
 * @return Whether the operation succeeded
 */
static inline bool atomic_strong_cas_dblptr(uint64_t *var, uint64_t *exp,
					    uint64_t neu, int mo_success,
					    int mo_failure)
{
	return __atomic_compare_exchange_n(var, exp, neu, 0, mo_success,
					   mo_failure);
}
#elif __SIZEOF_POINTER__ == 8
/**
 * A wrapper function to perform a 128-bit "strong" atomic compare and swap
 * (CAS) operation. This generic version of the function is used if an
 * architecture-specific (e.g. lockless) variant is not specified.
 *
 * @param var		The location at which the CAS should take place
 * @param exp		A pointer to the expected value
 * @param neu		A pointer to the new value to be written on success
 * @param mo_success	The memory order on success
 * @param mo_failure	The memory order on failure
 *
 * @return Whether the operation succeeded
 */
static inline bool atomic_strong_cas_dblptr(__int128 *var, __int128 *exp,
					    __int128 neu, int mo_success,
					    int mo_failure)
{
	return __atomic_compare_exchange_n(var, exp, neu, 0, mo_success,
					   mo_failure);
}
#endif
#endif
