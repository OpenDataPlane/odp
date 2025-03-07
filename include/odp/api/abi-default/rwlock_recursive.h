/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2015-2018 Linaro Limited
 */

/**
 * @file
 *
 * ODP recursive read/write lock
 */

#ifndef ODP_ABI_RWLOCK_RECURSIVE_H_
#define ODP_ABI_RWLOCK_RECURSIVE_H_

#include <odp/api/rwlock.h>
#include <odp/api/std_types.h>
#include <odp/api/thread.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @internal */
typedef struct odp_rwlock_recursive_s {
	odp_rwlock_t lock;                     /**< the lock */
	int wr_owner;                          /**< write owner thread */
	uint32_t wr_cnt;                       /**< write recursion count */
	uint8_t  rd_cnt[ODP_THREAD_COUNT_MAX]; /**< read recursion count */
} odp_rwlock_recursive_t;

#ifdef __cplusplus
}
#endif

#endif
