/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2018 Linaro Limited
 * Copyright (c) 2021 Nokia
 */

/**
 * @file
 *
 * ODP Atomic inline functions
 */

#ifndef _ODP_PLAT_ATOMIC_INLINES_H_
#define _ODP_PLAT_ATOMIC_INLINES_H_

#include <odp/api/abi/atomic_inlines.h>

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

#ifndef _ODP_NO_INLINE
	/* Inline functions by default */
	#define _ODP_INLINE static inline
	#define odp_atomic_init_u32 __odp_atomic_init_u32
	#define odp_atomic_load_u32 __odp_atomic_load_u32
	#define odp_atomic_store_u32 __odp_atomic_store_u32
	#define odp_atomic_fetch_add_u32 __odp_atomic_fetch_add_u32
	#define odp_atomic_add_u32 __odp_atomic_add_u32
	#define odp_atomic_fetch_sub_u32 __odp_atomic_fetch_sub_u32
	#define odp_atomic_sub_u32 __odp_atomic_sub_u32
	#define odp_atomic_fetch_inc_u32 __odp_atomic_fetch_inc_u32
	#define odp_atomic_inc_u32 __odp_atomic_inc_u32
	#define odp_atomic_fetch_dec_u32 __odp_atomic_fetch_dec_u32
	#define odp_atomic_dec_u32 __odp_atomic_dec_u32
	#define odp_atomic_cas_u32 __odp_atomic_cas_u32
	#define odp_atomic_xchg_u32 __odp_atomic_xchg_u32
	#define odp_atomic_load_acq_u32 __odp_atomic_load_acq_u32
	#define odp_atomic_store_rel_u32 __odp_atomic_store_rel_u32
	#define odp_atomic_add_rel_u32 __odp_atomic_add_rel_u32
	#define odp_atomic_sub_rel_u32 __odp_atomic_sub_rel_u32
	#define odp_atomic_cas_acq_u32 __odp_atomic_cas_acq_u32
	#define odp_atomic_cas_rel_u32 __odp_atomic_cas_rel_u32
	#define odp_atomic_cas_acq_rel_u32 __odp_atomic_cas_acq_rel_u32
	#define odp_atomic_max_u32 __odp_atomic_max_u32
	#define odp_atomic_min_u32 __odp_atomic_min_u32
	#define odp_atomic_init_u64 __odp_atomic_init_u64
	#define odp_atomic_load_u64 __odp_atomic_load_u64
	#define odp_atomic_store_u64 __odp_atomic_store_u64
	#define odp_atomic_fetch_add_u64 __odp_atomic_fetch_add_u64
	#define odp_atomic_add_u64 __odp_atomic_add_u64
	#define odp_atomic_fetch_sub_u64 __odp_atomic_fetch_sub_u64
	#define odp_atomic_sub_u64 __odp_atomic_sub_u64
	#define odp_atomic_fetch_inc_u64 __odp_atomic_fetch_inc_u64
	#define odp_atomic_inc_u64 __odp_atomic_inc_u64
	#define odp_atomic_fetch_dec_u64 __odp_atomic_fetch_dec_u64
	#define odp_atomic_dec_u64 __odp_atomic_dec_u64
	#define odp_atomic_cas_u64 __odp_atomic_cas_u64
	#define odp_atomic_xchg_u64 __odp_atomic_xchg_u64
	#define odp_atomic_load_acq_u64 __odp_atomic_load_acq_u64
	#define odp_atomic_store_rel_u64 __odp_atomic_store_rel_u64
	#define odp_atomic_add_rel_u64 __odp_atomic_add_rel_u64
	#define odp_atomic_sub_rel_u64 __odp_atomic_sub_rel_u64
	#define odp_atomic_cas_acq_u64 __odp_atomic_cas_acq_u64
	#define odp_atomic_cas_rel_u64 __odp_atomic_cas_rel_u64
	#define odp_atomic_cas_acq_rel_u64 __odp_atomic_cas_acq_rel_u64
	#define odp_atomic_max_u64 __odp_atomic_max_u64
	#define odp_atomic_min_u64 __odp_atomic_min_u64
	#define odp_atomic_init_u128 __odp_atomic_init_u128
	#define odp_atomic_load_u128 __odp_atomic_load_u128
	#define odp_atomic_store_u128 __odp_atomic_store_u128
	#define odp_atomic_cas_u128 __odp_atomic_cas_u128
	#define odp_atomic_cas_acq_u128 __odp_atomic_cas_acq_u128
	#define odp_atomic_cas_rel_u128 __odp_atomic_cas_rel_u128
	#define odp_atomic_cas_acq_rel_u128 __odp_atomic_cas_acq_rel_u128

#else
	#define _ODP_INLINE
#endif

_ODP_INLINE void odp_atomic_init_u32(odp_atomic_u32_t *atom, uint32_t val)
{
	__atomic_store_n(&atom->v, val, __ATOMIC_RELAXED);
}

_ODP_INLINE uint32_t odp_atomic_load_u32(odp_atomic_u32_t *atom)
{
	return __atomic_load_n(&atom->v, __ATOMIC_RELAXED);
}

_ODP_INLINE void odp_atomic_store_u32(odp_atomic_u32_t *atom, uint32_t val)
{
	__atomic_store_n(&atom->v, val, __ATOMIC_RELAXED);
}

_ODP_INLINE uint32_t odp_atomic_fetch_add_u32(odp_atomic_u32_t *atom,
					      uint32_t val)
{
	return __atomic_fetch_add(&atom->v, val, __ATOMIC_RELAXED);
}

_ODP_INLINE void odp_atomic_add_u32(odp_atomic_u32_t *atom, uint32_t val)
{
	_odp_atomic_add_u32(atom, val);
}

_ODP_INLINE uint32_t odp_atomic_fetch_sub_u32(odp_atomic_u32_t *atom,
					      uint32_t val)
{
	return __atomic_fetch_sub(&atom->v, val, __ATOMIC_RELAXED);
}

_ODP_INLINE void odp_atomic_sub_u32(odp_atomic_u32_t *atom, uint32_t val)
{
	_odp_atomic_sub_u32(atom, val);
}

_ODP_INLINE uint32_t odp_atomic_fetch_inc_u32(odp_atomic_u32_t *atom)
{
	return __atomic_fetch_add(&atom->v, 1, __ATOMIC_RELAXED);
}

_ODP_INLINE void odp_atomic_inc_u32(odp_atomic_u32_t *atom)
{
	_odp_atomic_inc_u32(atom);
}

_ODP_INLINE uint32_t odp_atomic_fetch_dec_u32(odp_atomic_u32_t *atom)
{
	return __atomic_fetch_sub(&atom->v, 1, __ATOMIC_RELAXED);
}

_ODP_INLINE void odp_atomic_dec_u32(odp_atomic_u32_t *atom)
{
	_odp_atomic_dec_u32(atom);
}

_ODP_INLINE int odp_atomic_cas_u32(odp_atomic_u32_t *atom, uint32_t *old_val,
				   uint32_t new_val)
{
	return __atomic_compare_exchange_n(&atom->v, old_val, new_val,
					   0 /* strong */,
					   __ATOMIC_RELAXED,
					   __ATOMIC_RELAXED);
}

_ODP_INLINE uint32_t odp_atomic_xchg_u32(odp_atomic_u32_t *atom,
					 uint32_t new_val)
{
	return __atomic_exchange_n(&atom->v, new_val, __ATOMIC_RELAXED);
}

_ODP_INLINE void odp_atomic_max_u32(odp_atomic_u32_t *atom, uint32_t val)
{
	_odp_atomic_max_u32(atom, val);
}

_ODP_INLINE void odp_atomic_min_u32(odp_atomic_u32_t *atom, uint32_t val)
{
	_odp_atomic_min_u32(atom, val);
}

#ifdef ODP_ATOMIC_U64_LOCK

/**
 * @internal
 * CAS operation expression for the ATOMIC_OP macro
 */
#define ATOMIC_CAS_OP(ret_ptr, old_val, new_val) \
__extension__ ({ \
	if (atom->v == (old_val)) { \
		atom->v = (new_val); \
		*(ret_ptr) = 1; \
	} else { \
		*(ret_ptr) = 0; \
	} \
})

/**
 * @internal
 * Helper macro for lock-based atomic operations on 64-bit integers
 * @param[in,out] atom Pointer to the 64-bit atomic variable
 * @param expr Expression used update the variable.
 * @return The old value of the variable.
 */
#define ATOMIC_OP(atom, expr) \
__extension__ ({ \
	uint64_t _old_val; \
	/* Loop while lock is already taken, stop when lock becomes clear */ \
	while (__atomic_test_and_set(&(atom)->lock, __ATOMIC_ACQUIRE)) \
		(void)0; \
	_old_val = (atom)->v; \
	(expr); /* Perform whatever update is desired */ \
	__atomic_clear(&(atom)->lock, __ATOMIC_RELEASE); \
	_old_val; /* Return old value */ \
})

_ODP_INLINE void odp_atomic_init_u64(odp_atomic_u64_t *atom, uint64_t val)
{
	atom->v = val;
	__atomic_clear(&atom->lock, __ATOMIC_RELAXED);
}

_ODP_INLINE uint64_t odp_atomic_load_u64(odp_atomic_u64_t *atom)
{
	return ATOMIC_OP(atom, (void)0);
}

_ODP_INLINE void odp_atomic_store_u64(odp_atomic_u64_t *atom, uint64_t val)
{
	(void)ATOMIC_OP(atom, atom->v = val);
}

_ODP_INLINE uint64_t odp_atomic_fetch_add_u64(odp_atomic_u64_t *atom,
					      uint64_t val)
{
	return ATOMIC_OP(atom, atom->v += val);
}

_ODP_INLINE void odp_atomic_add_u64(odp_atomic_u64_t *atom, uint64_t val)
{
	(void)ATOMIC_OP(atom, atom->v += val);
}

_ODP_INLINE uint64_t odp_atomic_fetch_sub_u64(odp_atomic_u64_t *atom,
					      uint64_t val)
{
	return ATOMIC_OP(atom, atom->v -= val);
}

_ODP_INLINE void odp_atomic_sub_u64(odp_atomic_u64_t *atom, uint64_t val)
{
	(void)ATOMIC_OP(atom, atom->v -= val);
}

_ODP_INLINE uint64_t odp_atomic_fetch_inc_u64(odp_atomic_u64_t *atom)
{
	return ATOMIC_OP(atom, atom->v++);
}

_ODP_INLINE void odp_atomic_inc_u64(odp_atomic_u64_t *atom)
{
	(void)ATOMIC_OP(atom, atom->v++);
}

_ODP_INLINE uint64_t odp_atomic_fetch_dec_u64(odp_atomic_u64_t *atom)
{
	return ATOMIC_OP(atom, atom->v--);
}

_ODP_INLINE void odp_atomic_dec_u64(odp_atomic_u64_t *atom)
{
	(void)ATOMIC_OP(atom, atom->v--);
}

_ODP_INLINE int odp_atomic_cas_u64(odp_atomic_u64_t *atom, uint64_t *old_val,
				   uint64_t new_val)
{
	int ret;
	*old_val = ATOMIC_OP(atom, ATOMIC_CAS_OP(&ret, *old_val, new_val));
	return ret;
}

_ODP_INLINE uint64_t odp_atomic_xchg_u64(odp_atomic_u64_t *atom,
					 uint64_t new_val)
{
	return ATOMIC_OP(atom, atom->v = new_val);
}

_ODP_INLINE uint64_t odp_atomic_load_acq_u64(odp_atomic_u64_t *atom)
{
	return ATOMIC_OP(atom, (void)0);
}

_ODP_INLINE void odp_atomic_store_rel_u64(odp_atomic_u64_t *atom, uint64_t val)
{
	(void)ATOMIC_OP(atom, atom->v = val);
}

_ODP_INLINE void odp_atomic_add_rel_u64(odp_atomic_u64_t *atom, uint64_t val)
{
	(void)ATOMIC_OP(atom, atom->v += val);
}

_ODP_INLINE void odp_atomic_sub_rel_u64(odp_atomic_u64_t *atom, uint64_t val)
{
	(void)ATOMIC_OP(atom, atom->v -= val);
}

_ODP_INLINE int odp_atomic_cas_acq_u64(odp_atomic_u64_t *atom,
				       uint64_t *old_val, uint64_t new_val)
{
	int ret;
	*old_val = ATOMIC_OP(atom, ATOMIC_CAS_OP(&ret, *old_val, new_val));
	return ret;
}

_ODP_INLINE int odp_atomic_cas_rel_u64(odp_atomic_u64_t *atom,
				       uint64_t *old_val, uint64_t new_val)
{
	int ret;
	*old_val = ATOMIC_OP(atom, ATOMIC_CAS_OP(&ret, *old_val, new_val));
	return ret;
}

_ODP_INLINE int odp_atomic_cas_acq_rel_u64(odp_atomic_u64_t *atom,
					   uint64_t *old_val,
					   uint64_t new_val)
{
	int ret;
	*old_val = ATOMIC_OP(atom, ATOMIC_CAS_OP(&ret, *old_val, new_val));
	return ret;
}

_ODP_INLINE void odp_atomic_max_u64(odp_atomic_u64_t *atom, uint64_t new_val)
{
	uint64_t old_val;

	old_val = odp_atomic_load_u64(atom);

	while (new_val > old_val) {
		if (odp_atomic_cas_u64(atom, &old_val, new_val))
			break;
	}
}

_ODP_INLINE void odp_atomic_min_u64(odp_atomic_u64_t *atom, uint64_t new_val)
{
	uint64_t old_val;

	old_val = odp_atomic_load_u64(atom);

	while (new_val < old_val) {
		if (odp_atomic_cas_u64(atom, &old_val, new_val))
			break;
	}
}

#else /* !ODP_ATOMIC_U64_LOCK */

_ODP_INLINE void odp_atomic_init_u64(odp_atomic_u64_t *atom, uint64_t val)
{
	atom->v = val;
}

_ODP_INLINE uint64_t odp_atomic_load_u64(odp_atomic_u64_t *atom)
{
	return __atomic_load_n(&atom->v, __ATOMIC_RELAXED);
}

_ODP_INLINE void odp_atomic_store_u64(odp_atomic_u64_t *atom, uint64_t val)
{
	__atomic_store_n(&atom->v, val, __ATOMIC_RELAXED);
}

_ODP_INLINE uint64_t odp_atomic_fetch_add_u64(odp_atomic_u64_t *atom,
					      uint64_t val)
{
	return __atomic_fetch_add(&atom->v, val, __ATOMIC_RELAXED);
}

_ODP_INLINE void odp_atomic_add_u64(odp_atomic_u64_t *atom, uint64_t val)
{
	_odp_atomic_add_u64(atom, val);
}

_ODP_INLINE uint64_t odp_atomic_fetch_sub_u64(odp_atomic_u64_t *atom,
					      uint64_t val)
{
	return __atomic_fetch_sub(&atom->v, val, __ATOMIC_RELAXED);
}

_ODP_INLINE void odp_atomic_sub_u64(odp_atomic_u64_t *atom, uint64_t val)
{
	_odp_atomic_sub_u64(atom, val);
}

_ODP_INLINE uint64_t odp_atomic_fetch_inc_u64(odp_atomic_u64_t *atom)
{
	return __atomic_fetch_add(&atom->v, 1, __ATOMIC_RELAXED);
}

_ODP_INLINE void odp_atomic_inc_u64(odp_atomic_u64_t *atom)
{
	_odp_atomic_inc_u64(atom);
}

_ODP_INLINE uint64_t odp_atomic_fetch_dec_u64(odp_atomic_u64_t *atom)
{
	return __atomic_fetch_sub(&atom->v, 1, __ATOMIC_RELAXED);
}

_ODP_INLINE void odp_atomic_dec_u64(odp_atomic_u64_t *atom)
{
	_odp_atomic_dec_u64(atom);
}

_ODP_INLINE int odp_atomic_cas_u64(odp_atomic_u64_t *atom, uint64_t *old_val,
				   uint64_t new_val)
{
	return __atomic_compare_exchange_n(&atom->v, old_val, new_val,
					   0 /* strong */,
					   __ATOMIC_RELAXED,
					   __ATOMIC_RELAXED);
}

_ODP_INLINE uint64_t odp_atomic_xchg_u64(odp_atomic_u64_t *atom,
					 uint64_t new_val)
{
	return __atomic_exchange_n(&atom->v, new_val, __ATOMIC_RELAXED);
}

_ODP_INLINE uint64_t odp_atomic_load_acq_u64(odp_atomic_u64_t *atom)
{
	return __atomic_load_n(&atom->v, __ATOMIC_ACQUIRE);
}

_ODP_INLINE void odp_atomic_store_rel_u64(odp_atomic_u64_t *atom, uint64_t val)
{
	__atomic_store_n(&atom->v, val, __ATOMIC_RELEASE);
}

_ODP_INLINE void odp_atomic_add_rel_u64(odp_atomic_u64_t *atom, uint64_t val)
{
	_odp_atomic_add_rel_u64(atom, val);
}

_ODP_INLINE void odp_atomic_sub_rel_u64(odp_atomic_u64_t *atom, uint64_t val)
{
	_odp_atomic_sub_rel_u64(atom, val);
}

_ODP_INLINE int odp_atomic_cas_acq_u64(odp_atomic_u64_t *atom,
				       uint64_t *old_val, uint64_t new_val)
{
	return __atomic_compare_exchange_n(&atom->v, old_val, new_val,
					   0 /* strong */,
					   __ATOMIC_ACQUIRE,
					   __ATOMIC_RELAXED);
}

_ODP_INLINE int odp_atomic_cas_rel_u64(odp_atomic_u64_t *atom,
				       uint64_t *old_val, uint64_t new_val)
{
	return __atomic_compare_exchange_n(&atom->v, old_val, new_val,
					   0 /* strong */,
					   __ATOMIC_RELEASE,
					   __ATOMIC_RELAXED);
}

_ODP_INLINE int odp_atomic_cas_acq_rel_u64(odp_atomic_u64_t *atom,
					   uint64_t *old_val,
					   uint64_t new_val)
{
	return __atomic_compare_exchange_n(&atom->v, old_val, new_val,
					   0 /* strong */,
					   __ATOMIC_ACQ_REL,
					   __ATOMIC_RELAXED);
}

_ODP_INLINE void odp_atomic_max_u64(odp_atomic_u64_t *atom, uint64_t val)
{
	_odp_atomic_max_u64(atom, val);
}

_ODP_INLINE void odp_atomic_min_u64(odp_atomic_u64_t *atom, uint64_t val)
{
	_odp_atomic_min_u64(atom, val);
}

#endif /* !ODP_ATOMIC_U64_LOCK */

_ODP_INLINE uint32_t odp_atomic_load_acq_u32(odp_atomic_u32_t *atom)
{
	return __atomic_load_n(&atom->v, __ATOMIC_ACQUIRE);
}

_ODP_INLINE void odp_atomic_store_rel_u32(odp_atomic_u32_t *atom, uint32_t val)
{
	__atomic_store_n(&atom->v, val, __ATOMIC_RELEASE);
}

_ODP_INLINE void odp_atomic_add_rel_u32(odp_atomic_u32_t *atom, uint32_t val)
{
	_odp_atomic_add_rel_u32(atom, val);
}

_ODP_INLINE void odp_atomic_sub_rel_u32(odp_atomic_u32_t *atom, uint32_t val)
{
	_odp_atomic_sub_rel_u32(atom, val);
}

_ODP_INLINE int odp_atomic_cas_acq_u32(odp_atomic_u32_t *atom,
				       uint32_t *old_val, uint32_t new_val)
{
	return __atomic_compare_exchange_n(&atom->v, old_val, new_val,
					   0 /* strong */,
					   __ATOMIC_ACQUIRE,
					   __ATOMIC_RELAXED);
}

_ODP_INLINE int odp_atomic_cas_rel_u32(odp_atomic_u32_t *atom,
				       uint32_t *old_val, uint32_t new_val)
{
	return __atomic_compare_exchange_n(&atom->v, old_val, new_val,
					   0 /* strong */,
					   __ATOMIC_RELEASE,
					   __ATOMIC_RELAXED);
}

_ODP_INLINE int odp_atomic_cas_acq_rel_u32(odp_atomic_u32_t *atom,
					   uint32_t *old_val,
					   uint32_t new_val)
{
	return __atomic_compare_exchange_n(&atom->v, old_val, new_val,
					   0 /* strong */,
					   __ATOMIC_ACQ_REL,
					   __ATOMIC_RELAXED);
}

_ODP_INLINE void odp_atomic_init_u128(odp_atomic_u128_t *atom, odp_u128_t val)
{
	_odp_atomic_init_u128(atom, val);
}

_ODP_INLINE odp_u128_t odp_atomic_load_u128(odp_atomic_u128_t *atom)
{
	return _odp_atomic_load_u128(atom);
}

_ODP_INLINE void odp_atomic_store_u128(odp_atomic_u128_t *atom, odp_u128_t val)
{
	_odp_atomic_store_u128(atom, val);
}

_ODP_INLINE int odp_atomic_cas_u128(odp_atomic_u128_t *atom,
				    odp_u128_t *old_val, odp_u128_t new_val)
{
	return _odp_atomic_cas_u128(atom, old_val, new_val);
}

_ODP_INLINE int odp_atomic_cas_acq_u128(odp_atomic_u128_t *atom,
					odp_u128_t *old_val, odp_u128_t new_val)
{
	return _odp_atomic_cas_acq_u128(atom, old_val, new_val);
}

_ODP_INLINE int odp_atomic_cas_rel_u128(odp_atomic_u128_t *atom,
					odp_u128_t *old_val, odp_u128_t new_val)
{
	return _odp_atomic_cas_rel_u128(atom, old_val, new_val);
}

_ODP_INLINE int odp_atomic_cas_acq_rel_u128(odp_atomic_u128_t *atom,
					    odp_u128_t *old_val, odp_u128_t new_val)
{
	return _odp_atomic_cas_acq_rel_u128(atom, old_val, new_val);
}

/** @endcond */

#endif
