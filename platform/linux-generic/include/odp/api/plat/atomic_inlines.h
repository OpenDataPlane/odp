/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/**
 * @file
 *
 * ODP Atomic inline functions
 */

#ifndef _ODP_PLAT_ATOMIC_INLINES_H_
#define _ODP_PLAT_ATOMIC_INLINES_H_

_STATIC void odp_atomic_init_u32(odp_atomic_u32_t *atom, uint32_t val)
{
	__atomic_store_n(&atom->v, val, __ATOMIC_RELAXED);
}

_STATIC uint32_t odp_atomic_load_u32(odp_atomic_u32_t *atom)
{
	return __atomic_load_n(&atom->v, __ATOMIC_RELAXED);
}

_STATIC void odp_atomic_store_u32(odp_atomic_u32_t *atom, uint32_t val)
{
	__atomic_store_n(&atom->v, val, __ATOMIC_RELAXED);
}

_STATIC uint32_t odp_atomic_fetch_add_u32(odp_atomic_u32_t *atom, uint32_t val)
{
	return __atomic_fetch_add(&atom->v, val, __ATOMIC_RELAXED);
}

_STATIC void odp_atomic_add_u32(odp_atomic_u32_t *atom, uint32_t val)
{
	(void)__atomic_fetch_add(&atom->v, val, __ATOMIC_RELAXED);
}

_STATIC uint32_t odp_atomic_fetch_sub_u32(odp_atomic_u32_t *atom, uint32_t val)
{
	return __atomic_fetch_sub(&atom->v, val, __ATOMIC_RELAXED);
}

_STATIC void odp_atomic_sub_u32(odp_atomic_u32_t *atom, uint32_t val)
{
	(void)__atomic_fetch_sub(&atom->v, val, __ATOMIC_RELAXED);
}

_STATIC uint32_t odp_atomic_fetch_inc_u32(odp_atomic_u32_t *atom)
{
	return __atomic_fetch_add(&atom->v, 1, __ATOMIC_RELAXED);
}

_STATIC void odp_atomic_inc_u32(odp_atomic_u32_t *atom)
{
	(void)__atomic_fetch_add(&atom->v, 1, __ATOMIC_RELAXED);
}

_STATIC uint32_t odp_atomic_fetch_dec_u32(odp_atomic_u32_t *atom)
{
	return __atomic_fetch_sub(&atom->v, 1, __ATOMIC_RELAXED);
}

_STATIC void odp_atomic_dec_u32(odp_atomic_u32_t *atom)
{
	(void)__atomic_fetch_sub(&atom->v, 1, __ATOMIC_RELAXED);
}

_STATIC int odp_atomic_cas_u32(odp_atomic_u32_t *atom, uint32_t *old_val,
			       uint32_t new_val)
{
	return __atomic_compare_exchange_n(&atom->v, old_val, new_val,
					   0 /* strong */,
					   __ATOMIC_RELAXED,
					   __ATOMIC_RELAXED);
}

_STATIC uint32_t odp_atomic_xchg_u32(odp_atomic_u32_t *atom, uint32_t new_val)
{
	return __atomic_exchange_n(&atom->v, new_val, __ATOMIC_RELAXED);
}

_STATIC void odp_atomic_max_u32(odp_atomic_u32_t *atom, uint32_t new_max)
{
	uint32_t old_val;

	old_val = odp_atomic_load_u32(atom);

	while (new_max > old_val) {
		if (odp_atomic_cas_u32(atom, &old_val, new_max))
			break;
	}
}

_STATIC void odp_atomic_min_u32(odp_atomic_u32_t *atom, uint32_t new_min)
{
	uint32_t old_val;

	old_val = odp_atomic_load_u32(atom);

	while (new_min < old_val) {
		if (odp_atomic_cas_u32(atom, &old_val, new_min))
			break;
	}
}

_STATIC void odp_atomic_init_u64(odp_atomic_u64_t *atom, uint64_t val)
{
	atom->v = val;
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	__atomic_clear(&atom->lock, __ATOMIC_RELAXED);
#endif
}

_STATIC uint64_t odp_atomic_load_u64(odp_atomic_u64_t *atom)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	return ATOMIC_OP(atom, (void)0);
#else
	return __atomic_load_n(&atom->v, __ATOMIC_RELAXED);
#endif
}

_STATIC void odp_atomic_store_u64(odp_atomic_u64_t *atom, uint64_t val)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	(void)ATOMIC_OP(atom, atom->v = val);
#else
	__atomic_store_n(&atom->v, val, __ATOMIC_RELAXED);
#endif
}

_STATIC uint64_t odp_atomic_fetch_add_u64(odp_atomic_u64_t *atom, uint64_t val)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	return ATOMIC_OP(atom, atom->v += val);
#else
	return __atomic_fetch_add(&atom->v, val, __ATOMIC_RELAXED);
#endif
}

_STATIC void odp_atomic_add_u64(odp_atomic_u64_t *atom, uint64_t val)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	(void)ATOMIC_OP(atom, atom->v += val);
#else
	(void)__atomic_fetch_add(&atom->v, val, __ATOMIC_RELAXED);
#endif
}

_STATIC uint64_t odp_atomic_fetch_sub_u64(odp_atomic_u64_t *atom, uint64_t val)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	return ATOMIC_OP(atom, atom->v -= val);
#else
	return __atomic_fetch_sub(&atom->v, val, __ATOMIC_RELAXED);
#endif
}

_STATIC void odp_atomic_sub_u64(odp_atomic_u64_t *atom, uint64_t val)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	(void)ATOMIC_OP(atom, atom->v -= val);
#else
	(void)__atomic_fetch_sub(&atom->v, val, __ATOMIC_RELAXED);
#endif
}

_STATIC uint64_t odp_atomic_fetch_inc_u64(odp_atomic_u64_t *atom)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	return ATOMIC_OP(atom, atom->v++);
#else
	return __atomic_fetch_add(&atom->v, 1, __ATOMIC_RELAXED);
#endif
}

_STATIC void odp_atomic_inc_u64(odp_atomic_u64_t *atom)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	(void)ATOMIC_OP(atom, atom->v++);
#else
	(void)__atomic_fetch_add(&atom->v, 1, __ATOMIC_RELAXED);
#endif
}

_STATIC uint64_t odp_atomic_fetch_dec_u64(odp_atomic_u64_t *atom)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	return ATOMIC_OP(atom, atom->v--);
#else
	return __atomic_fetch_sub(&atom->v, 1, __ATOMIC_RELAXED);
#endif
}

_STATIC void odp_atomic_dec_u64(odp_atomic_u64_t *atom)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	(void)ATOMIC_OP(atom, atom->v--);
#else
	(void)__atomic_fetch_sub(&atom->v, 1, __ATOMIC_RELAXED);
#endif
}

_STATIC int odp_atomic_cas_u64(odp_atomic_u64_t *atom, uint64_t *old_val,
			       uint64_t new_val)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	int ret;
	*old_val = ATOMIC_OP(atom, ATOMIC_CAS_OP(&ret, *old_val, new_val));
	return ret;
#else
	return __atomic_compare_exchange_n(&atom->v, old_val, new_val,
					   0 /* strong */,
					   __ATOMIC_RELAXED,
					   __ATOMIC_RELAXED);
#endif
}

_STATIC uint64_t odp_atomic_xchg_u64(odp_atomic_u64_t *atom, uint64_t new_val)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	return ATOMIC_OP(atom, atom->v = new_val);
#else
	return __atomic_exchange_n(&atom->v, new_val, __ATOMIC_RELAXED);
#endif
}

_STATIC void odp_atomic_max_u64(odp_atomic_u64_t *atom, uint64_t new_max)
{
	uint64_t old_val;

	old_val = odp_atomic_load_u64(atom);

	while (new_max > old_val) {
		if (odp_atomic_cas_u64(atom, &old_val, new_max))
			break;
	}
}

_STATIC void odp_atomic_min_u64(odp_atomic_u64_t *atom, uint64_t new_min)
{
	uint64_t old_val;

	old_val = odp_atomic_load_u64(atom);

	while (new_min < old_val) {
		if (odp_atomic_cas_u64(atom, &old_val, new_min))
			break;
	}
}

_STATIC uint32_t odp_atomic_load_acq_u32(odp_atomic_u32_t *atom)
{
	return __atomic_load_n(&atom->v, __ATOMIC_ACQUIRE);
}

_STATIC void odp_atomic_store_rel_u32(odp_atomic_u32_t *atom, uint32_t val)
{
	__atomic_store_n(&atom->v, val, __ATOMIC_RELEASE);
}

_STATIC void odp_atomic_add_rel_u32(odp_atomic_u32_t *atom, uint32_t val)
{
	(void)__atomic_fetch_add(&atom->v, val, __ATOMIC_RELEASE);
}

_STATIC void odp_atomic_sub_rel_u32(odp_atomic_u32_t *atom, uint32_t val)
{
	(void)__atomic_fetch_sub(&atom->v, val, __ATOMIC_RELEASE);
}

_STATIC int odp_atomic_cas_acq_u32(odp_atomic_u32_t *atom,
				   uint32_t *old_val, uint32_t new_val)
{
	return __atomic_compare_exchange_n(&atom->v, old_val, new_val,
					   0 /* strong */,
					   __ATOMIC_ACQUIRE,
					   __ATOMIC_RELAXED);
}

_STATIC int odp_atomic_cas_rel_u32(odp_atomic_u32_t *atom,
				   uint32_t *old_val, uint32_t new_val)
{
	return __atomic_compare_exchange_n(&atom->v, old_val, new_val,
					   0 /* strong */,
					   __ATOMIC_RELEASE,
					   __ATOMIC_RELAXED);
}

_STATIC int odp_atomic_cas_acq_rel_u32(odp_atomic_u32_t *atom,
				       uint32_t *old_val,
				       uint32_t new_val)
{
	return __atomic_compare_exchange_n(&atom->v, old_val, new_val,
					   0 /* strong */,
					   __ATOMIC_ACQ_REL,
					   __ATOMIC_RELAXED);
}

_STATIC uint64_t odp_atomic_load_acq_u64(odp_atomic_u64_t *atom)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	return ATOMIC_OP(atom, (void)0);
#else
	return __atomic_load_n(&atom->v, __ATOMIC_ACQUIRE);
#endif
}

_STATIC void odp_atomic_store_rel_u64(odp_atomic_u64_t *atom, uint64_t val)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	(void)ATOMIC_OP(atom, atom->v = val);
#else
	__atomic_store_n(&atom->v, val, __ATOMIC_RELEASE);
#endif
}

_STATIC void odp_atomic_add_rel_u64(odp_atomic_u64_t *atom, uint64_t val)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	(void)ATOMIC_OP(atom, atom->v += val);
#else
	(void)__atomic_fetch_add(&atom->v, val, __ATOMIC_RELEASE);
#endif
}

_STATIC void odp_atomic_sub_rel_u64(odp_atomic_u64_t *atom, uint64_t val)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	(void)ATOMIC_OP(atom, atom->v -= val);
#else
	(void)__atomic_fetch_sub(&atom->v, val, __ATOMIC_RELEASE);
#endif
}

_STATIC int odp_atomic_cas_acq_u64(odp_atomic_u64_t *atom,
				   uint64_t *old_val, uint64_t new_val)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	int ret;
	*old_val = ATOMIC_OP(atom, ATOMIC_CAS_OP(&ret, *old_val, new_val));
	return ret;
#else
	return __atomic_compare_exchange_n(&atom->v, old_val, new_val,
					   0 /* strong */,
					   __ATOMIC_ACQUIRE,
					   __ATOMIC_RELAXED);
#endif
}

_STATIC int odp_atomic_cas_rel_u64(odp_atomic_u64_t *atom,
				   uint64_t *old_val, uint64_t new_val)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	int ret;
	*old_val = ATOMIC_OP(atom, ATOMIC_CAS_OP(&ret, *old_val, new_val));
	return ret;
#else
	return __atomic_compare_exchange_n(&atom->v, old_val, new_val,
					   0 /* strong */,
					   __ATOMIC_RELEASE,
					   __ATOMIC_RELAXED);
#endif
}

_STATIC int odp_atomic_cas_acq_rel_u64(odp_atomic_u64_t *atom,
				       uint64_t *old_val,
				       uint64_t new_val)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	int ret;
	*old_val = ATOMIC_OP(atom, ATOMIC_CAS_OP(&ret, *old_val, new_val));
	return ret;
#else
	return __atomic_compare_exchange_n(&atom->v, old_val, new_val,
					   0 /* strong */,
					   __ATOMIC_ACQ_REL,
					   __ATOMIC_RELAXED);
#endif
}

#endif
