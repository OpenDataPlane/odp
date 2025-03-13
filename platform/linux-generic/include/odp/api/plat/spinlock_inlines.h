/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2013-2018 Linaro Limited
 * Copyright (c) 2022 Nokia
 */

#ifndef ODP_PLAT_SPINLOCK_INLINES_H_
#define ODP_PLAT_SPINLOCK_INLINES_H_

#include <odp/api/cpu.h>

#include <odp/api/abi/spinlock.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

#ifndef _ODP_NO_INLINE
	/* Inline functions by default */
	#define _ODP_INLINE static inline
	#define odp_spinlock_init __odp_spinlock_init
	#define odp_spinlock_lock __odp_spinlock_lock
	#define odp_spinlock_trylock __odp_spinlock_trylock
	#define odp_spinlock_unlock __odp_spinlock_unlock
	#define odp_spinlock_is_locked __odp_spinlock_is_locked
#else
	#undef _ODP_INLINE
	#define _ODP_INLINE
#endif

_ODP_INLINE void odp_spinlock_init(odp_spinlock_t *spinlock)
{
	__atomic_clear(&spinlock->lock, __ATOMIC_RELAXED);
}

_ODP_INLINE void odp_spinlock_lock(odp_spinlock_t *spinlock)
{
	/* While the lock is already taken... */
	while (__atomic_test_and_set(&spinlock->lock, __ATOMIC_ACQUIRE))
		/* ...spin reading the flag (relaxed MM),
		 * the loop will exit when the lock becomes available
		 * and we will retry the TAS operation above */
		while (__atomic_load_n(&spinlock->lock, __ATOMIC_RELAXED))
			odp_cpu_pause();
}

_ODP_INLINE int odp_spinlock_trylock(odp_spinlock_t *spinlock)
{
	return (__atomic_test_and_set(&spinlock->lock, __ATOMIC_ACQUIRE) == 0);
}

_ODP_INLINE void odp_spinlock_unlock(odp_spinlock_t *spinlock)
{
	__atomic_clear(&spinlock->lock, __ATOMIC_RELEASE);
}

_ODP_INLINE int odp_spinlock_is_locked(odp_spinlock_t *spinlock)
{
	return __atomic_load_n(&spinlock->lock, __ATOMIC_RELAXED) != 0;
}

/** @endcond */

#ifdef __cplusplus
}
#endif

#endif
