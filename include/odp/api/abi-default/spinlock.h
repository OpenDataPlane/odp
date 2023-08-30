/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2015-2018 Linaro Limited
 */

/**
 * @file
 *
 * ODP spinlock
 */

#ifndef ODP_ABI_SPINLOCK_H_
#define ODP_ABI_SPINLOCK_H_

#ifdef __cplusplus
extern "C" {
#endif

/** @internal */
typedef struct odp_spinlock_s {
	char lock;  /**< lock flag, should match odp_atomic_flag_t */
} odp_spinlock_t;

#ifdef __cplusplus
}
#endif

#endif
