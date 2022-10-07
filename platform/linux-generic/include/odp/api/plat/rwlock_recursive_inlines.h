/* Copyright (c) 2013-2018, Linaro Limited
 * Copyright (c) 2022, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef ODP_PLAT_RWLOCK_RECURSIVE_INLINES_H_
#define ODP_PLAT_RWLOCK_RECURSIVE_INLINES_H_

#include <odp/api/rwlock.h>
#include <odp/api/thread.h>

#include <odp/api/abi/rwlock_recursive.h>

#include <odp/api/plat/debug_inlines.h>

#include <stdint.h>
#include <string.h>

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

#ifndef _ODP_NO_INLINE
	/* Inline functions by default */
	#define _ODP_INLINE static inline
	#define odp_rwlock_recursive_init __odp_rwlock_recursive_init
	#define odp_rwlock_recursive_read_lock __odp_rwlock_recursive_read_lock
	#define odp_rwlock_recursive_read_trylock __odp_rwlock_recursive_read_trylock
	#define odp_rwlock_recursive_read_unlock __odp_rwlock_recursive_read_unlock
	#define odp_rwlock_recursive_write_lock __odp_rwlock_recursive_write_lock
	#define odp_rwlock_recursive_write_trylock __odp_rwlock_recursive_write_trylock
	#define odp_rwlock_recursive_write_unlock __odp_rwlock_recursive_write_unlock
#else
	#undef _ODP_INLINE
	#define _ODP_INLINE
#endif

_ODP_INLINE void odp_rwlock_recursive_init(odp_rwlock_recursive_t *rlock)
{
	memset(rlock, 0, sizeof(odp_rwlock_recursive_t));
	odp_rwlock_init(&rlock->lock);
	rlock->wr_owner = -1;
}

/* Multiple readers can recurse the lock concurrently */
_ODP_INLINE void odp_rwlock_recursive_read_lock(odp_rwlock_recursive_t *rlock)
{
	int thr = odp_thread_id();

	if (rlock->rd_cnt[thr]) {
		_ODP_ASSERT(rlock->rd_cnt[thr] < UINT8_MAX);
		rlock->rd_cnt[thr]++;
		return;
	}

	odp_rwlock_read_lock(&rlock->lock);
	rlock->rd_cnt[thr] = 1;
}

/* Multiple readers can recurse the lock concurrently */
_ODP_INLINE int odp_rwlock_recursive_read_trylock(odp_rwlock_recursive_t *rlock)
{
	int thr = odp_thread_id();

	if (rlock->rd_cnt[thr]) {
		_ODP_ASSERT(rlock->rd_cnt[thr] < UINT8_MAX);
		rlock->rd_cnt[thr]++;
		return 1;
	}

	if (odp_rwlock_read_trylock(&rlock->lock)) {
		rlock->rd_cnt[thr] = 1;
		return 1;
	}

	return 0;
}

_ODP_INLINE void odp_rwlock_recursive_read_unlock(odp_rwlock_recursive_t *rlock)
{
	int thr = odp_thread_id();

	_ODP_ASSERT(rlock->rd_cnt[thr]);
	rlock->rd_cnt[thr]--;

	if (rlock->rd_cnt[thr] > 0)
		return;

	odp_rwlock_read_unlock(&rlock->lock);
}

/* Only one writer can recurse the lock */
_ODP_INLINE void odp_rwlock_recursive_write_lock(odp_rwlock_recursive_t *rlock)
{
	int thr = odp_thread_id();

	if (rlock->wr_owner == thr) {
		_ODP_ASSERT(rlock->wr_cnt < UINT32_MAX);
		rlock->wr_cnt++;
		return;
	}

	odp_rwlock_write_lock(&rlock->lock);
	rlock->wr_owner = thr;
	rlock->wr_cnt   = 1;
}

/* Only one writer can recurse the lock */
_ODP_INLINE int odp_rwlock_recursive_write_trylock(odp_rwlock_recursive_t *rlock)
{
	int thr = odp_thread_id();

	if (rlock->wr_owner == thr) {
		_ODP_ASSERT(rlock->wr_cnt < UINT32_MAX);
		rlock->wr_cnt++;
		return 1;
	}

	if (odp_rwlock_write_trylock(&rlock->lock)) {
		rlock->wr_owner = thr;
		rlock->wr_cnt   = 1;
		return 1;
	}

	return 0;
}

_ODP_INLINE void odp_rwlock_recursive_write_unlock(odp_rwlock_recursive_t *rlock)
{
	_ODP_ASSERT(rlock->wr_cnt);
	rlock->wr_cnt--;

	if (rlock->wr_cnt > 0)
		return;

	rlock->wr_owner = -1;
	odp_rwlock_write_unlock(&rlock->lock);
}

/** @endcond */

#endif
