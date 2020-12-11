/* Copyright (c) 2015-2018, Linaro Limited
 * Copyright (c) 2021, ARM Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/atomic.h>
#include <odp_cpu.h>

int odp_atomic_lock_free_u64(odp_atomic_op_t *atomic_op)
{
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	/* All operations have locks */
	if (atomic_op)
		atomic_op->all_bits = 0;

	return 0;
#else
	/* All operations are lock-free */
	if (atomic_op) {
		atomic_op->all_bits = ~((uint32_t)0);
		atomic_op->op.init  = 0;
	}

	return 2;
#endif
}

int odp_atomic_lock_free_u128(odp_atomic_op_t *atomic_op)
{
#ifdef _ODP_LOCK_FREE_128BIT_ATOMICS
	if (atomic_op) {
		atomic_op->all_bits = 0;
		atomic_op->op.load  = 1;
		atomic_op->op.store = 1;
		atomic_op->op.cas  = 1;
	}

	return 2;
#else
	/* All operations have locks */
	if (atomic_op)
		atomic_op->all_bits = 0;

	return 0;
#endif
}

#ifdef _ODP_LOCK_FREE_128BIT_ATOMICS

static void __atomic_init_u128(odp_atomic_u128_t *atom, odp_u128_t new_val)
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

static odp_u128_t __atomic_load_u128(odp_atomic_u128_t *atom)
{
	odp_u128_t val, exp;

	exp.u64[0] = 0;
	exp.u64[1] = 0;
	ATOMIC_CAS_OP_128_NO_ORDER(atom, &exp, exp, val);
	return val;
}

static void __atomic_store_u128(odp_atomic_u128_t *atom, odp_u128_t new_val)
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

static int __atomic_cas_u128(odp_atomic_u128_t *atom,
			     odp_u128_t *old_val, odp_u128_t new_val)
{
	int ret = 0;
	odp_u128_t val;

	ATOMIC_CAS_OP_128_NO_ORDER(atom, old_val, new_val, val);

	if ((val.u64[0] == old_val->u64[0]) && (val.u64[1] == old_val->u64[1]))
		ret = 1;

	old_val->u64[0] = val.u64[0];
	old_val->u64[1] = val.u64[1];

	return ret;
}

static int __atomic_cas_acq_u128(odp_atomic_u128_t *atom,
				 odp_u128_t *old_val, odp_u128_t new_val)
{
	int ret = 0;
	odp_u128_t val;

	ATOMIC_CAS_OP_128_ACQ(atom, old_val, new_val, val);

	if ((val.u64[0] == old_val->u64[0]) && (val.u64[1] == old_val->u64[1]))
		ret = 1;

	old_val->u64[0] = val.u64[0];
	old_val->u64[1] = val.u64[1];

	return ret;
}

static int __atomic_cas_rel_u128(odp_atomic_u128_t *atom,
				 odp_u128_t *old_val, odp_u128_t new_val)
{
	int ret = 0;
	odp_u128_t val;

	ATOMIC_CAS_OP_128_REL(atom, old_val, new_val, val);

	if ((val.u64[0] == old_val->u64[0]) && (val.u64[1] == old_val->u64[1]))
		ret = 1;

	old_val->u64[0] = val.u64[0];
	old_val->u64[1] = val.u64[1];

	return ret;
}

static int __atomic_cas_acq_rel_u128(odp_atomic_u128_t *atom,
				     odp_u128_t *old_val,
				     odp_u128_t new_val)
{
	int ret = 0;
	odp_u128_t val;

	ATOMIC_CAS_OP_128_ACQ_REL(atom, old_val, new_val, val);

	if ((val.u64[0] == old_val->u64[0]) && (val.u64[1] == old_val->u64[1]))
		ret = 1;

	old_val->u64[0] = val.u64[0];
	old_val->u64[1] = val.u64[1];

	return ret;
}

#else /* Locked version */

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
({ \
	int *_ret_ptr = ret_ptr; \
	odp_u128_t *_old_val = old_val; \
	odp_u128_t _new_val = new_val; \
	if (((_atom)->v.u64[0] == (_old_val)->u64[0]) && \
	    ((_atom)->v.u64[1] == (_old_val)->u64[1])) { \
		(_atom)->v = (_new_val); \
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
({ \
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

static void __atomic_init_u128(odp_atomic_u128_t *atom, odp_u128_t val)
{
	atom->lock = 0;
	ATOMIC_OP_128(atom, ATOMIC_STORE_OP_128(val));
}

static odp_u128_t __atomic_load_u128(odp_atomic_u128_t *atom)
{
	return ATOMIC_OP_128(atom, (void)0);
}

static void __atomic_store_u128(odp_atomic_u128_t *atom, odp_u128_t val)
{
	ATOMIC_OP_128(atom, ATOMIC_STORE_OP_128(val));
}

static int __atomic_cas_u128(odp_atomic_u128_t *atom,
			     odp_u128_t *old_val, odp_u128_t new_val)
{
	int ret;
	*old_val = ATOMIC_OP_128(atom, ATOMIC_CAS_OP_128(&ret, old_val,
							 new_val));
	return ret;
}

static int __atomic_cas_acq_u128(odp_atomic_u128_t *atom,
				 odp_u128_t *old_val,
				 odp_u128_t new_val)
{
	int ret;
	*old_val = ATOMIC_OP_128(atom, ATOMIC_CAS_OP_128(&ret, old_val,
							 new_val));
	return ret;
}

static int __atomic_cas_rel_u128(odp_atomic_u128_t *atom,
				 odp_u128_t *old_val,
				 odp_u128_t new_val)
{
	int ret;
	*old_val = ATOMIC_OP_128(atom, ATOMIC_CAS_OP_128(&ret, old_val,
							 new_val));
	return ret;
}

static int __atomic_cas_acq_rel_u128(odp_atomic_u128_t *atom,
				     odp_u128_t *old_val,
				     odp_u128_t new_val)
{
	int ret;
	*old_val = ATOMIC_OP_128(atom, ATOMIC_CAS_OP_128(&ret, old_val,
							 new_val));
	return ret;
}

#endif

void odp_atomic_init_u128(odp_atomic_u128_t *atom, odp_u128_t val)
{
	__atomic_init_u128(atom, val);
}

odp_u128_t odp_atomic_load_u128(odp_atomic_u128_t *atom)
{
	return __atomic_load_u128(atom);
}

void odp_atomic_store_u128(odp_atomic_u128_t *atom, odp_u128_t val)
{
	__atomic_store_u128(atom, val);
}

int odp_atomic_cas_u128(odp_atomic_u128_t *atom,
			odp_u128_t *old_val, odp_u128_t new_val)
{
	return __atomic_cas_u128(atom, old_val, new_val);
}

int odp_atomic_cas_acq_u128(odp_atomic_u128_t *atom,
			    odp_u128_t *old_val, odp_u128_t new_val)
{
	return __atomic_cas_acq_u128(atom, old_val, new_val);
}

int odp_atomic_cas_rel_u128(odp_atomic_u128_t *atom,
			    odp_u128_t *old_val, odp_u128_t new_val)
{
	return __atomic_cas_rel_u128(atom, old_val, new_val);
}

int odp_atomic_cas_acq_rel_u128(odp_atomic_u128_t *atom,
				odp_u128_t *old_val, odp_u128_t new_val)
{
	return __atomic_cas_acq_rel_u128(atom, old_val, new_val);
}
