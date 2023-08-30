/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2015-2018 Linaro Limited
 */

/**
 * @file
 *
 * ODP rwlock
 */

#ifndef ODP_ABI_RWLOCK_H_
#define ODP_ABI_RWLOCK_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/atomic.h>

/** @internal */
typedef struct odp_rwlock_s {
	odp_atomic_u32_t cnt; /**< lock count
				0 lock not taken
				-1 write lock taken
				>0 read lock(s) taken */
} odp_rwlock_t;

#ifdef __cplusplus
}
#endif

#endif
