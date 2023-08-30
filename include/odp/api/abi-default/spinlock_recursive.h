/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2015-2018 Linaro Limited
 */

/**
 * @file
 *
 * ODP recursive spinlock
 */

#ifndef ODP_ABI_SPINLOCK_RECURSIVE_H_
#define ODP_ABI_SPINLOCK_RECURSIVE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/spinlock.h>
#include <odp/api/std_types.h>

/** @internal */
typedef struct odp_spinlock_recursive_s {
	odp_spinlock_t lock; /**< the lock */
	int owner;           /**< thread owning the lock */
	uint32_t cnt;        /**< recursion count */
} odp_spinlock_recursive_t;

#ifdef __cplusplus
}
#endif

#endif
