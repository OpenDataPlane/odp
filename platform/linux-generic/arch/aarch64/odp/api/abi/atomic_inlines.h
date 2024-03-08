/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ARM Limited
 * Copyright (c) 2021 Nokia
 */

#ifndef ODP_API_ABI_ATOMIC_INLINES_H_
#define ODP_API_ABI_ATOMIC_INLINES_H_

#include <odp/api/atomic.h>

#ifdef _ODP_LOCK_FREE_128BIT_ATOMICS

/**
 * @internal
 * Helper macro for lockless atomic CAS operations on 128-bit integers
 * @param[in,out] atom Pointer to the 128-bit atomic variable
 * @param oper CAS operation
 * @param old_val Old value
 * @param new_val New value to be swapped
 * @return 1 for success and 0 for fail
 */
#define ATOMIC_CAS_OP_128(atom, oper, old_val, new_val, val) \
__extension__ ({ \
	odp_u128_t _val; \
	odp_atomic_u128_t *_atom = atom; \
	odp_u128_t *_old_val = old_val; \
	odp_u128_t _new_val = new_val; \
	odp_u128_t *ptr = (odp_u128_t *)(_atom); \
	register uint64_t old0 __asm__ ("x0"); \
	register uint64_t old1 __asm__ ("x1"); \
	register uint64_t new0 __asm__ ("x2"); \
	register uint64_t new1 __asm__ ("x3"); \
	old0 = (uint64_t)(_old_val)->u64[0]; \
	old1 = (uint64_t)(_old_val)->u64[1]; \
	new0 = (uint64_t)(_new_val).u64[0]; \
	new1 = (uint64_t)(_new_val).u64[1]; \
	__asm__ volatile(oper " %[old0], %[old1], %[new0], %[new1], [%[ptr]]" \
			: [old0] "+r" (old0), [old1] "+r" (old1) \
			: [new0] "r"  (new0), [new1] "r"  (new1), \
			[ptr] "r" (ptr) \
			: "memory"); \
	_val.u64[0] = old0; \
	_val.u64[1] = old1; \
	val = _val; \
})

#define ATOMIC_CAS_OP_128_NO_ORDER(atom, old_value, new_value, val) \
	ATOMIC_CAS_OP_128(atom, "casp", old_value, new_value, val)

#define ATOMIC_CAS_OP_128_ACQ(atom, old_value, new_value, val) \
	ATOMIC_CAS_OP_128(atom, "caspa", old_value, new_value, val)

#define ATOMIC_CAS_OP_128_REL(atom, old_value, new_value, val) \
	ATOMIC_CAS_OP_128(atom, "caspl", old_value, new_value, val)

#define ATOMIC_CAS_OP_128_ACQ_REL(atom, old_value, new_value, val) \
	ATOMIC_CAS_OP_128(atom, "caspal", old_value, new_value, val)

static inline void _odp_atomic_init_u128(odp_atomic_u128_t *atom, odp_u128_t new_val)
{
	atom->v = new_val;
}

static inline odp_u128_t _odp_atomic_load_u128(odp_atomic_u128_t *atom)
{
	odp_u128_t val, exp;

	exp.u64[0] = 0;
	exp.u64[1] = 0;
	ATOMIC_CAS_OP_128_NO_ORDER(atom, &exp, exp, val);
	return val;
}

static inline void _odp_atomic_store_u128(odp_atomic_u128_t *atom, odp_u128_t new_val)
{
	odp_u128_t old, val;

	old = atom->v;

	while (1) {
		ATOMIC_CAS_OP_128_NO_ORDER(atom, &old, new_val, val);

		if ((val.u64[0] == old.u64[0]) && (val.u64[1] == old.u64[1]))
			return;

		old = val;
	}
}

static inline int _odp_atomic_cas_u128(odp_atomic_u128_t *atom, odp_u128_t *old_val,
				       odp_u128_t new_val)
{
	odp_u128_t val;

	ATOMIC_CAS_OP_128_NO_ORDER(atom, old_val, new_val, val);

	if ((val.u64[0] == old_val->u64[0]) && (val.u64[1] == old_val->u64[1]))
		return 1;

	old_val->u64[0] = val.u64[0];
	old_val->u64[1] = val.u64[1];

	return 0;
}

static inline int _odp_atomic_cas_acq_u128(odp_atomic_u128_t *atom, odp_u128_t *old_val,
					   odp_u128_t new_val)
{
	odp_u128_t val;

	ATOMIC_CAS_OP_128_ACQ(atom, old_val, new_val, val);

	if ((val.u64[0] == old_val->u64[0]) && (val.u64[1] == old_val->u64[1]))
		return 1;

	old_val->u64[0] = val.u64[0];
	old_val->u64[1] = val.u64[1];

	return 0;
}

static inline int _odp_atomic_cas_rel_u128(odp_atomic_u128_t *atom, odp_u128_t *old_val,
					   odp_u128_t new_val)
{
	odp_u128_t val;

	ATOMIC_CAS_OP_128_REL(atom, old_val, new_val, val);

	if ((val.u64[0] == old_val->u64[0]) && (val.u64[1] == old_val->u64[1]))
		return 1;

	old_val->u64[0] = val.u64[0];
	old_val->u64[1] = val.u64[1];

	return 0;
}

static inline int _odp_atomic_cas_acq_rel_u128(odp_atomic_u128_t *atom, odp_u128_t *old_val,
					       odp_u128_t new_val)
{
	odp_u128_t val;

	ATOMIC_CAS_OP_128_ACQ_REL(atom, old_val, new_val, val);

	if ((val.u64[0] == old_val->u64[0]) && (val.u64[1] == old_val->u64[1]))
		return 1;

	old_val->u64[0] = val.u64[0];
	old_val->u64[1] = val.u64[1];

	return 0;
}

static inline void _odp_atomic_add_u32(odp_atomic_u32_t *atom, uint32_t val)
{
	__asm__ volatile("stadd   %w[val], %[atom]"
			 : [atom] "+Q" (atom->v)
			 : [val] "r" (val));
}

static inline void _odp_atomic_sub_u32(odp_atomic_u32_t *atom, uint32_t val)
{
	int32_t neg_val = (int32_t)-val;

	__asm__ volatile("stadd   %w[neg_val], %[atom]"
			 : [atom] "+Q" (atom->v)
			 : [neg_val] "r" (neg_val));
}

static inline void _odp_atomic_inc_u32(odp_atomic_u32_t *atom)
{
	_odp_atomic_add_u32(atom, 1);
}

static inline void _odp_atomic_dec_u32(odp_atomic_u32_t *atom)
{
	_odp_atomic_sub_u32(atom, 1);
}

static inline void _odp_atomic_add_u64(odp_atomic_u64_t *atom, uint64_t val)
{
	__asm__ volatile("stadd   %[val], %[atom]"
			 : [atom] "+Q" (atom->v)
			 : [val] "r" (val));
}

static inline void _odp_atomic_sub_u64(odp_atomic_u64_t *atom, uint64_t val)
{
	int64_t neg_val = (int64_t)-val;

	__asm__ volatile("stadd   %[neg_val], %[atom]"
			 : [atom] "+Q" (atom->v)
			 : [neg_val] "r" (neg_val));
}

static inline void _odp_atomic_inc_u64(odp_atomic_u64_t *atom)
{
	_odp_atomic_add_u64(atom, 1);
}

static inline void _odp_atomic_dec_u64(odp_atomic_u64_t *atom)
{
	_odp_atomic_sub_u64(atom, 1);
}

static inline void _odp_atomic_max_u32(odp_atomic_u32_t *atom, uint32_t val)
{
	__asm__ volatile("stumax   %w[val], %[atom]"
			 : [atom] "+Q" (atom->v)
			 : [val] "r" (val));
}

static inline void _odp_atomic_min_u32(odp_atomic_u32_t *atom, uint32_t val)
{
	__asm__ volatile("stumin   %w[val], %[atom]"
			 : [atom] "+Q" (atom->v)
			 : [val] "r" (val));
}

static inline void _odp_atomic_max_u64(odp_atomic_u64_t *atom, uint64_t val)
{
	__asm__ volatile("stumax   %[val], %[atom]"
			 : [atom] "+Q" (atom->v)
			 : [val] "r" (val));
}

static inline void _odp_atomic_min_u64(odp_atomic_u64_t *atom, uint64_t val)
{
	__asm__ volatile("stumin   %[val], %[atom]"
			 : [atom] "+Q" (atom->v)
			 : [val] "r" (val));
}

static inline void _odp_atomic_add_rel_u32(odp_atomic_u32_t *atom, uint32_t val)
{
	__asm__ volatile("staddl   %w[val], %[atom]"
			 : [atom] "+Q" (atom->v)
			 : [val] "r" (val)
			 : "memory");
}

static inline void _odp_atomic_sub_rel_u32(odp_atomic_u32_t *atom, uint32_t val)
{
	int32_t neg_val = (int32_t)-val;

	__asm__ volatile("staddl   %w[neg_val], %[atom]"
			 : [atom] "+Q" (atom->v)
			 : [neg_val] "r" (neg_val)
			 : "memory");
}

static inline void _odp_atomic_add_rel_u64(odp_atomic_u64_t *atom, uint64_t val)
{
	__asm__ volatile("staddl   %[val], %[atom]"
			 : [atom] "+Q" (atom->v)
			 : [val] "r" (val)
			 : "memory");
}

static inline void _odp_atomic_sub_rel_u64(odp_atomic_u64_t *atom, uint64_t val)
{
	int64_t neg_val = (int64_t)-val;

	__asm__ volatile("staddl   %[neg_val], %[atom]"
			 : [atom] "+Q" (atom->v)
			 : [neg_val] "r" (neg_val)
			 : "memory");
}

#else /* !_ODP_LOCK_FREE_128BIT_ATOMICS */

/* Use generic implementation */
#include <odp/api/abi/atomic_generic.h>

#endif
#endif
