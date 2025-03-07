/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ARM Limited
 * Copyright (c) 2021-2024 Nokia
 */

#ifndef ODP_API_ABI_ATOMIC_GENERIC_H_
#define ODP_API_ABI_ATOMIC_GENERIC_H_

#include <odp/api/atomic.h>

#ifdef __cplusplus
extern "C" {
#endif

static inline void _odp_atomic_add_u32(odp_atomic_u32_t *atom, uint32_t val)
{
	(void)__atomic_fetch_add(&atom->v, val, __ATOMIC_RELAXED);
}

static inline void _odp_atomic_sub_u32(odp_atomic_u32_t *atom, uint32_t val)
{
	(void)__atomic_fetch_sub(&atom->v, val, __ATOMIC_RELAXED);
}

static inline void _odp_atomic_inc_u32(odp_atomic_u32_t *atom)
{
	(void)__atomic_fetch_add(&atom->v, 1, __ATOMIC_RELAXED);
}

static inline void _odp_atomic_dec_u32(odp_atomic_u32_t *atom)
{
	(void)__atomic_fetch_sub(&atom->v, 1, __ATOMIC_RELAXED);
}

static inline void _odp_atomic_max_u32(odp_atomic_u32_t *atom, uint32_t new_val)
{
	uint32_t old_val;

	old_val = __atomic_load_n(&atom->v, __ATOMIC_RELAXED);

	while (new_val > old_val) {
		if (__atomic_compare_exchange_n(&atom->v, &old_val, new_val, 0 /* strong */,
						__ATOMIC_RELAXED, __ATOMIC_RELAXED))
			break;
	}
}

static inline uint32_t _odp_atomic_fetch_max_u32(odp_atomic_u32_t *atom, uint32_t new_val)
{
	uint32_t old_val;

	old_val = __atomic_load_n(&atom->v, __ATOMIC_RELAXED);

	while (new_val > old_val) {
		if (__atomic_compare_exchange_n(&atom->v, &old_val, new_val, 0 /* strong */,
						__ATOMIC_RELAXED, __ATOMIC_RELAXED))
			break;
	}
	return old_val;
}

static inline void _odp_atomic_min_u32(odp_atomic_u32_t *atom, uint32_t new_val)
{
	uint32_t old_val;

	old_val = __atomic_load_n(&atom->v, __ATOMIC_RELAXED);

	while (new_val < old_val) {
		if (__atomic_compare_exchange_n(&atom->v, &old_val, new_val, 0 /* strong */,
						__ATOMIC_RELAXED, __ATOMIC_RELAXED))
			break;
	}
}

static inline uint32_t _odp_atomic_fetch_min_u32(odp_atomic_u32_t *atom, uint32_t new_val)
{
	uint32_t old_val;

	old_val = __atomic_load_n(&atom->v, __ATOMIC_RELAXED);

	while (new_val < old_val) {
		if (__atomic_compare_exchange_n(&atom->v, &old_val, new_val, 0 /* strong */,
						__ATOMIC_RELAXED, __ATOMIC_RELAXED))
			break;
	}
	return old_val;
}

static inline void _odp_atomic_add_rel_u32(odp_atomic_u32_t *atom, uint32_t val)
{
	(void)__atomic_fetch_add(&atom->v, val, __ATOMIC_RELEASE);
}

static inline void _odp_atomic_sub_rel_u32(odp_atomic_u32_t *atom, uint32_t val)
{
	(void)__atomic_fetch_sub(&atom->v, val, __ATOMIC_RELEASE);
}

static inline void _odp_atomic_add_u64(odp_atomic_u64_t *atom, uint64_t val)
{
	(void)__atomic_fetch_add(&atom->v, val, __ATOMIC_RELAXED);
}

static inline void _odp_atomic_sub_u64(odp_atomic_u64_t *atom, uint64_t val)
{
	(void)__atomic_fetch_sub(&atom->v, val, __ATOMIC_RELAXED);
}

static inline void _odp_atomic_inc_u64(odp_atomic_u64_t *atom)
{
	(void)__atomic_fetch_add(&atom->v, 1, __ATOMIC_RELAXED);
}

static inline void _odp_atomic_dec_u64(odp_atomic_u64_t *atom)
{
	(void)__atomic_fetch_sub(&atom->v, 1, __ATOMIC_RELAXED);
}

static inline void _odp_atomic_max_u64(odp_atomic_u64_t *atom, uint64_t new_val)
{
	uint64_t old_val;

	old_val = __atomic_load_n(&atom->v, __ATOMIC_RELAXED);

	while (new_val > old_val) {
		if (__atomic_compare_exchange_n(&atom->v, &old_val, new_val, 0 /* strong */,
						__ATOMIC_RELAXED, __ATOMIC_RELAXED))
			break;
	}
}

static inline uint64_t _odp_atomic_fetch_max_u64(odp_atomic_u64_t *atom, uint64_t new_val)
{
	uint64_t old_val;

	old_val = __atomic_load_n(&atom->v, __ATOMIC_RELAXED);

	while (new_val > old_val) {
		if (__atomic_compare_exchange_n(&atom->v, &old_val, new_val, 0 /* strong */,
						__ATOMIC_RELAXED, __ATOMIC_RELAXED))
			break;
	}
	return old_val;
}

static inline void _odp_atomic_min_u64(odp_atomic_u64_t *atom, uint64_t new_val)
{
	uint64_t old_val;

	old_val = __atomic_load_n(&atom->v, __ATOMIC_RELAXED);

	while (new_val < old_val) {
		if (__atomic_compare_exchange_n(&atom->v, &old_val, new_val, 0 /* strong */,
						__ATOMIC_RELAXED, __ATOMIC_RELAXED))
			break;
	}
}

static inline uint64_t _odp_atomic_fetch_min_u64(odp_atomic_u64_t *atom, uint64_t new_val)
{
	uint64_t old_val;

	old_val = __atomic_load_n(&atom->v, __ATOMIC_RELAXED);

	while (new_val < old_val) {
		if (__atomic_compare_exchange_n(&atom->v, &old_val, new_val, 0 /* strong */,
						__ATOMIC_RELAXED, __ATOMIC_RELAXED))
			break;
	}
	return old_val;
}

#ifndef ODP_ATOMIC_U64_LOCK
static inline void _odp_atomic_add_rel_u64(odp_atomic_u64_t *atom, uint64_t val)
{
	(void)__atomic_fetch_add(&atom->v, val, __ATOMIC_RELEASE);
}

static inline void _odp_atomic_sub_rel_u64(odp_atomic_u64_t *atom, uint64_t val)
{
	(void)__atomic_fetch_sub(&atom->v, val, __ATOMIC_RELEASE);
}
#endif

#ifdef __SIZEOF_INT128__

static inline void _odp_atomic_init_u128(odp_atomic_u128_t *atom, odp_u128_t val)
{
	atom->v = val;
}

static inline odp_u128_t _odp_atomic_load_u128(odp_atomic_u128_t *atom)
{
	odp_u128_t val;

	val.u128 = __atomic_load_n(&atom->v.u128, __ATOMIC_RELAXED);
	return val;
}

static inline void _odp_atomic_store_u128(odp_atomic_u128_t *atom, odp_u128_t val)
{
	__atomic_store_n(&atom->v.u128, val.u128, __ATOMIC_RELAXED);
}

static inline int _odp_atomic_cas_u128(odp_atomic_u128_t *atom, odp_u128_t *old_val,
				       odp_u128_t new_val)
{
	return __atomic_compare_exchange_n(&atom->v.u128, &old_val->u128,
					   new_val.u128, 0 /* strong */,
					   __ATOMIC_RELAXED, __ATOMIC_RELAXED);
}

static inline int _odp_atomic_cas_acq_u128(odp_atomic_u128_t *atom, odp_u128_t *old_val,
					   odp_u128_t new_val)
{
	return __atomic_compare_exchange_n(&atom->v.u128, &old_val->u128,
					   new_val.u128, 0 /* strong */,
					   __ATOMIC_ACQUIRE, __ATOMIC_RELAXED);
}

static inline int _odp_atomic_cas_rel_u128(odp_atomic_u128_t *atom, odp_u128_t *old_val,
					   odp_u128_t new_val)
{
	return __atomic_compare_exchange_n(&atom->v.u128, &old_val->u128,
					   new_val.u128, 0 /* strong */,
					   __ATOMIC_RELEASE, __ATOMIC_RELAXED);
}

static inline int _odp_atomic_cas_acq_rel_u128(odp_atomic_u128_t *atom, odp_u128_t *old_val,
					       odp_u128_t new_val)
{
	return __atomic_compare_exchange_n(&atom->v.u128, &old_val->u128,
					   new_val.u128, 0 /* strong */,
					   __ATOMIC_ACQ_REL, __ATOMIC_RELAXED);
}

#else /* Lock-based implementation */

/**
 * @internal
 * 128 bit store operation expression for the ATOMIC_OP macro
 */
#define ATOMIC_STORE_OP_128(new_val) \
({ \
	(_atom)->v = (new_val); \
})

/**
 * @internal
 * 128 bit CAS operation expression for the ATOMIC_OP macro
 */
#define ATOMIC_CAS_OP_128(ret_ptr, old_val, new_val) \
__extension__ ({ \
	int *_ret_ptr = ret_ptr; \
	odp_u128_t *_cas_old = old_val; \
	odp_u128_t _cas_new = new_val; \
	if (((_atom)->v.u64[0] == (_cas_old)->u64[0]) && \
	    ((_atom)->v.u64[1] == (_cas_old)->u64[1])) { \
		(_atom)->v = (_cas_new); \
		*(_ret_ptr) = 1; \
	} else { \
		*(_ret_ptr) = 0; \
	} \
})

/**
 * @internal
 * Helper macro for lock-based atomic operations on 128-bit integers
 * @param[in,out] atom Pointer to the 128-bit atomic variable
 * @param expr Expression used update the variable.
 * @return The old value of the variable.
 */
#define ATOMIC_OP_128(atom, expr) \
__extension__ ({ \
	odp_u128_t _old_val; \
	odp_atomic_u128_t *_atom = atom; \
	/* Loop while lock is already taken, stop when lock becomes clear */ \
	while (__atomic_test_and_set(&(_atom)->lock, __ATOMIC_ACQUIRE)) \
		(void)0; \
	_old_val = (_atom)->v; \
	(expr); /* Perform whatever update is desired */ \
	__atomic_clear(&(_atom)->lock, __ATOMIC_RELEASE); \
	_old_val; /* Return old value */ \
})

static inline void _odp_atomic_init_u128(odp_atomic_u128_t *atom, odp_u128_t val)
{
	atom->v.u64[0] = val.u64[0];
	atom->v.u64[1] = val.u64[1];
	atom->lock = 0;
}

static inline odp_u128_t _odp_atomic_load_u128(odp_atomic_u128_t *atom)
{
	return ATOMIC_OP_128(atom, (void)0);
}

static inline void _odp_atomic_store_u128(odp_atomic_u128_t *atom, odp_u128_t val)
{
	ATOMIC_OP_128(atom, ATOMIC_STORE_OP_128(val));
}

static inline int _odp_atomic_cas_u128(odp_atomic_u128_t *atom, odp_u128_t *old_val,
				       odp_u128_t new_val)
{
	int ret;

	*old_val = ATOMIC_OP_128(atom, ATOMIC_CAS_OP_128(&ret, old_val, new_val));
	return ret;
}

static inline int _odp_atomic_cas_acq_u128(odp_atomic_u128_t *atom, odp_u128_t *old_val,
					   odp_u128_t new_val)
{
	return _odp_atomic_cas_u128(atom, old_val, new_val);
}

static inline int _odp_atomic_cas_rel_u128(odp_atomic_u128_t *atom, odp_u128_t *old_val,
					   odp_u128_t new_val)
{
	return _odp_atomic_cas_u128(atom, old_val, new_val);
}

static inline int _odp_atomic_cas_acq_rel_u128(odp_atomic_u128_t *atom, odp_u128_t *old_val,
					       odp_u128_t new_val)
{
	return _odp_atomic_cas_u128(atom, old_val, new_val);
}
#endif

#ifdef __cplusplus
}
#endif

#endif
