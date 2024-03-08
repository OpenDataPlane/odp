/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2015-2018 Linaro Limited
 * Copyright (c) 2021 ARM Limited
 */

#include <odp/api/atomic.h>

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
#ifdef __SIZEOF_INT128__
	if (__atomic_is_lock_free(16, NULL)) {
		if (atomic_op) {
			atomic_op->all_bits = 0;
			atomic_op->op.load  = 1;
			atomic_op->op.store = 1;
			atomic_op->op.cas  = 1;
		}
		return 2;
	}
#endif
	/* All operations have locks */
	if (atomic_op)
		atomic_op->all_bits = 0;

	return 0;
}
