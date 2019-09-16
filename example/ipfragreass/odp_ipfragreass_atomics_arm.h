/* Copyright (c) 2017-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_FRAGREASS_PP_ATOMICS_ARM_H_
#define ODP_FRAGREASS_PP_ATOMICS_ARM_H_

#include <odp_api.h>

#if __SIZEOF_POINTER__ == 8 && defined(__aarch64__)
static inline __int128 lld(__int128 *var, int mo)
{
	__int128 old;
	uint64_t lo, hi;

	if (mo == __ATOMIC_ACQUIRE)
		__asm__ volatile("ldaxp %0, %1, [%2]" : "=&r" (lo), "=&r" (hi)
				 : "r" (var) : "memory");
	else /* mo == __ATOMIC_RELAXED */
		__asm__ volatile("ldxp %0, %1, [%2]" : "=&r" (lo), "=&r" (hi)
				 : "r" (var) : );
	old = hi;
	old <<= 64;
	old |= lo;

	return old;

}

static inline uint32_t scd(__int128 *var, __int128 neu, int mo)
{
	uint32_t ret;
	uint64_t lo = neu, hi = neu >> 64;

	if (mo == __ATOMIC_RELEASE)
		__asm__ volatile("stlxp %w0, %1, %2, [%3]" : "=&r" (ret)
				 : "r" (lo), "r" (hi), "r" (var) : "memory");
	else /* mo == __ATOMIC_RELAXED */
		__asm__ volatile("stxp %w0, %1, %2, [%3]" : "=&r" (ret)
				 : "r" (lo), "r" (hi), "r" (var) : "memory");
	return ret;
}

static inline bool atomic_strong_cas_dblptr(__int128 *var, __int128 *exp,
					    __int128 neu, int mo_success,
					    int mo_failure ODP_UNUSED)
{
	register __int128 old;
	register __int128 expected = *exp;
	int ll_mo, sc_mo;

	ll_mo = (mo_success != __ATOMIC_RELAXED &&
		 mo_success != __ATOMIC_RELEASE) ? __ATOMIC_ACQUIRE
						 : __ATOMIC_RELAXED;
	sc_mo = (mo_success == __ATOMIC_RELEASE ||
		 mo_success == __ATOMIC_ACQ_REL ||
		 mo_success == __ATOMIC_SEQ_CST) ? __ATOMIC_RELEASE
						 : __ATOMIC_RELAXED;

	/*
	 * To prevent spurious failures and ensure atomicity, we must write some
	 * value back -- whether it's the value we wanted to write, or the value
	 * that is currently there. Repeat until we perform a successful write.
	 */
	do {
		old = lld(var, ll_mo);
	} while (scd(var, old == expected ? neu : old, sc_mo));

	*exp = old;
	return (old == expected);
}
#elif __SIZEOF_POINTER__ == 4 && defined(__ARM_ARCH) && __ARM_ARCH == 7
static inline uint64_t lld(uint64_t *var, int mo)
{
	uint64_t old;

	__asm__ volatile("ldrexd %0, %H0, [%1]" : "=&r" (old) : "r" (var) : );
	if (mo == __ATOMIC_ACQUIRE)
		__asm__ volatile("dmb ish" ::: "memory");
	return old;
}

static inline uint32_t scd(uint64_t *var, uint64_t neu, int mo)
{
	uint32_t ret;

	if (mo == __ATOMIC_RELEASE)
		__asm__ volatile("dmb ish" ::: "memory");
	__asm__ volatile("strexd %0, %1, %H1, [%2]" : "=&r" (ret)
			 : "r" (neu), "r" (var) : );
	return ret;
}

static inline bool atomic_strong_cas_dblptr(uint64_t *var, uint64_t *exp,
					    uint64_t neu, int mo_success,
					    int mo_failure ODP_UNUSED)
{
	register uint64_t old;
	register uint64_t expected = *exp;
	int ll_mo, sc_mo;

	ll_mo = (mo_success != __ATOMIC_RELAXED &&
		 mo_success != __ATOMIC_RELEASE) ? __ATOMIC_ACQUIRE
						 : __ATOMIC_RELAXED;
	sc_mo = (mo_success == __ATOMIC_RELEASE ||
		 mo_success == __ATOMIC_ACQ_REL ||
		 mo_success == __ATOMIC_SEQ_CST) ? __ATOMIC_RELEASE
						 : __ATOMIC_RELAXED;

	/*
	 * To prevent spurious failures and ensure atomicity, we must write some
	 * value back -- whether it's the value we wanted to write, or the value
	 * that is currently there. Repeat until we perform a successful write.
	 */
	do {
		old = lld(var, ll_mo);
	} while (scd(var, old == expected ? neu : old, sc_mo));

	*exp = old;
	return (old == expected);
}
#else
#include "odp_ipfragreass_atomics.h"
#endif
#endif
