/* Copyright (c) 2021, Arm Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_DEFAULT_ATOMIC_H_
#define ODP_DEFAULT_ATOMIC_H_

#ifdef __SIZEOF_INT128__

typedef unsigned __int128 _u128_t;

static inline _u128_t lockfree_load_u128(_u128_t *atomic)
{
	return __atomic_load_n(atomic, __ATOMIC_RELAXED);
}

static inline int lockfree_cas_acq_rel_u128(_u128_t *atomic,
					    _u128_t old_val,
					    _u128_t new_val)
{
	return __atomic_compare_exchange_n(atomic, &old_val, new_val,
					   0 /* strong */,
					   __ATOMIC_ACQ_REL,
					   __ATOMIC_RELAXED);
}

static inline int lockfree_check_u128(void)
{
	return __atomic_is_lock_free(16, NULL);
}

#endif

#endif
