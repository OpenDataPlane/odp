/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2018 Linaro Limited
 * Copyright (c) 2023 Nokia
 */

/**
 * @file
 *
 * ODP synchronisation inlines
 */

#ifndef ODP_PLAT_SYNC_INLINE_H_
#define ODP_PLAT_SYNC_INLINE_H_

#include <odp/api/abi/sync_inlines.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

#ifndef _ODP_NO_INLINE
	/* Inline functions by default */
	#define _ODP_INLINE static inline
	#define odp_mb_release __odp_mb_release
	#define odp_mb_acquire __odp_mb_acquire
	#define odp_mb_full __odp_mb_full
	#define odp_mb_sync __odp_mb_sync
	#define odp_mb_sync_load __odp_mb_sync_load
	#define odp_mb_sync_store __odp_mb_sync_store
#else
	#define _ODP_INLINE
#endif

_ODP_INLINE void odp_mb_release(void)
{
	__atomic_thread_fence(__ATOMIC_RELEASE);
}

_ODP_INLINE void odp_mb_acquire(void)
{
	__atomic_thread_fence(__ATOMIC_ACQUIRE);
}

_ODP_INLINE void odp_mb_full(void)
{
	__atomic_thread_fence(__ATOMIC_SEQ_CST);
}

_ODP_INLINE void odp_mb_sync(void)
{
	_odp_mb_sync();
}

_ODP_INLINE void odp_mb_sync_load(void)
{
	_odp_mb_sync_load();
}

_ODP_INLINE void odp_mb_sync_store(void)
{
	_odp_mb_sync_store();
}

/** @endcond */

#ifdef __cplusplus
}
#endif

#endif
