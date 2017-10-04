/* Copyright (c) 2017, ARM Limited. All rights reserved.
 *
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef PLATFORM_LINUXGENERIC_ARCH_ARM_ODP_ATOMIC_H
#define PLATFORM_LINUXGENERIC_ARCH_ARM_ODP_ATOMIC_H

#ifndef PLATFORM_LINUXGENERIC_ARCH_ARM_ODP_CPU_H
#error This file should not be included directly, please include odp_cpu.h
#endif

#ifdef CONFIG_DMBSTR

#define atomic_store_release(loc, val, ro)		\
do {							\
	_odp_release_barrier(ro);			\
	__atomic_store_n(loc, val, __ATOMIC_RELAXED);   \
} while (0)

#else

#define atomic_store_release(loc, val, ro) \
	__atomic_store_n(loc, val, __ATOMIC_RELEASE)

#endif  /* CONFIG_DMBSTR */

#define HAS_ACQ(mo) ((mo) != __ATOMIC_RELAXED && (mo) != __ATOMIC_RELEASE)
#define HAS_RLS(mo) ((mo) == __ATOMIC_RELEASE || (mo) == __ATOMIC_ACQ_REL || \
		     (mo) == __ATOMIC_SEQ_CST)

#define LL_MO(mo) (HAS_ACQ((mo)) ? __ATOMIC_ACQUIRE : __ATOMIC_RELAXED)
#define SC_MO(mo) (HAS_RLS((mo)) ? __ATOMIC_RELEASE : __ATOMIC_RELAXED)

#ifndef __ARM_FEATURE_QRDMX /* Feature only available in v8.1a and beyond */
static inline bool
__lockfree_compare_exchange_16(register __int128 *var, __int128 *exp,
			       register __int128 neu, bool weak, int mo_success,
			       int mo_failure)
{
	(void)weak; /* Always do strong CAS or we can't perform atomic read */
	/* Ignore memory ordering for failure, memory order for
	 * success must be stronger or equal. */
	(void)mo_failure;
	register __int128 old;
	register __int128 expected;
	int ll_mo = LL_MO(mo_success);
	int sc_mo = SC_MO(mo_success);

	expected = *exp;
	__asm__ volatile("" ::: "memory");
	do {
		/* Atomicity of LLD is not guaranteed */
		old = lld(var, ll_mo);
		/* Must write back neu or old to verify atomicity of LLD */
	} while (odp_unlikely(scd(var, old == expected ? neu : old, sc_mo)));
	*exp = old; /* Always update, atomically read value */
	return old == expected;
}

static inline __int128 __lockfree_exchange_16(__int128 *var, __int128 neu,
					      int mo)
{
	register __int128 old;
	int ll_mo = LL_MO(mo);
	int sc_mo = SC_MO(mo);

	do {
		/* Atomicity of LLD is not guaranteed */
		old = lld(var, ll_mo);
		/* Must successfully write back to verify atomicity of LLD */
	} while (odp_unlikely(scd(var, neu, sc_mo)));
	return old;
}

static inline __int128 __lockfree_fetch_and_16(__int128 *var, __int128 mask,
					       int mo)
{
	register __int128 old;
	int ll_mo = LL_MO(mo);
	int sc_mo = SC_MO(mo);

	do {
		/* Atomicity of LLD is not guaranteed */
		old = lld(var, ll_mo);
		/* Must successfully write back to verify atomicity of LLD */
	} while (odp_unlikely(scd(var, old & mask, sc_mo)));
	return old;
}

static inline __int128 __lockfree_fetch_or_16(__int128 *var, __int128 mask,
					      int mo)
{
	register __int128 old;
	int ll_mo = LL_MO(mo);
	int sc_mo = SC_MO(mo);

	do {
		/* Atomicity of LLD is not guaranteed */
		old = lld(var, ll_mo);
		/* Must successfully write back to verify atomicity of LLD */
	} while (odp_unlikely(scd(var, old | mask, sc_mo)));
	return old;
}

#else

static inline __int128 casp(__int128 *var, __int128 old, __int128 neu, int mo)
{
	if (mo == __ATOMIC_RELAXED) {
		__asm__ volatile("casp %0, %H0, %1, %H1, [%2]"
				 : "+r" (old)
				 : "r" (neu), "r" (var)
				 : "memory");
	} else if (mo == __ATOMIC_ACQUIRE) {
		__asm__ volatile("caspa %0, %H0, %1, %H1, [%2]"
				 : "+r" (old)
				 : "r" (neu), "r" (var)
				 : "memory");
	} else if (mo == __ATOMIC_ACQ_REL) {
		__asm__ volatile("caspal %0, %H0, %1, %H1, [%2]"
				 : "+r" (old)
				 : "r" (neu), "r" (var)
				 : "memory");
	} else if (mo == __ATOMIC_RELEASE) {
		__asm__ volatile("caspl %0, %H0, %1, %H1, [%2]"
				 : "+r" (old)
				 : "r" (neu), "r" (var)
				 : "memory");
	} else {
		abort();
	}
	return old;
}

static inline bool
__lockfree_compare_exchange_16(register __int128 *var, __int128 *exp,
			       register __int128 neu, bool weak, int mo_success,
			       int mo_failure)
{
	(void)weak;
	(void)mo_failure;
	__int128 old;
	__int128 expected;

	expected = *exp;
	old = casp(var, expected, neu, mo_success);
	*exp = old; /* Always update, atomically read value */
	return old == expected;
}

static inline __int128 __lockfree_exchange_16(__int128 *var, __int128 neu,
					      int mo)
{
	__int128 old;
	__int128 expected;

	do {
		expected = *var;
		old = casp(var, expected, neu, mo);
	} while (old != expected);
	return old;
}

static inline __int128 __lockfree_fetch_and_16(__int128 *var, __int128 mask,
					       int mo)
{
	__int128 old;
	__int128 expected;

	do {
		expected = *var;
		old = casp(var, expected, expected & mask, mo);
	} while (old != expected);
	return old;
}

static inline __int128 __lockfree_fetch_or_16(__int128 *var, __int128 mask,
					      int mo)
{
	__int128 old;
	__int128 expected;

	do {
		expected = *var;
		old = casp(var, expected, expected | mask, mo);
	} while (old != expected);
	return old;
}

#endif  /* __ARM_FEATURE_QRDMX */

static inline __int128 __lockfree_load_16(__int128 *var, int mo)
{
	__int128 old = *var; /* Possibly torn read */

	/* Do CAS to ensure atomicity
	 * Either CAS succeeds (writing back the same value)
	 * Or CAS fails and returns the old value (atomic read)
	 */
	(void)__lockfree_compare_exchange_16(var, &old, old, false, mo, mo);
	return old;
}

#endif  /* PLATFORM_LINUXGENERIC_ARCH_ARM_ODP_ATOMIC_H */
