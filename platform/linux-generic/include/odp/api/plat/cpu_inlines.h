/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2018 Linaro Limited
 * Copyright (c) 2021-2023 Nokia
 */

#ifndef ODP_PLAT_CPU_INLINES_H_
#define ODP_PLAT_CPU_INLINES_H_

#include <odp/api/hints.h>

#include <odp/api/abi/cpu_inlines.h>

#include <stdint.h>

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

#ifndef _ODP_NO_INLINE
	/* Inline functions by default */
	#define _ODP_INLINE static inline
	#define odp_cpu_pause               __odp_cpu_pause
	#define odp_cpu_cycles              __odp_cpu_cycles
	#define odp_cpu_cycles_max          __odp_cpu_cycles_max
	#define odp_cpu_cycles_resolution   __odp_cpu_cycles_resolution
	#define odp_cpu_cycles_diff         __odp_cpu_cycles_diff
	#define odp_prefetch                __odp_prefetch
	#define odp_prefetch_l1             __odp_prefetch_l1
	#define odp_prefetch_l2             __odp_prefetch_l2
	#define odp_prefetch_l3             __odp_prefetch_l3
	#define odp_prefetch_store          __odp_prefetch_store
	#define odp_prefetch_store_l1       __odp_prefetch_store_l1
	#define odp_prefetch_store_l2       __odp_prefetch_store_l2
	#define odp_prefetch_store_l3       __odp_prefetch_store_l3
	#define odp_prefetch_strm_l1        __odp_prefetch_strm_l1
	#define odp_prefetch_store_strm_l1  __odp_prefetch_store_strm_l1
	#define odp_prefetch_l1i            __odp_prefetch_l1i
#else
	#define _ODP_INLINE
#endif

_ODP_INLINE void odp_cpu_pause(void)
{
	_odp_cpu_pause();
}

_ODP_INLINE uint64_t odp_cpu_cycles_max(void)
{
	return _odp_cpu_cycles_max();
}

_ODP_INLINE uint64_t odp_cpu_cycles_resolution(void)
{
	return _odp_cpu_cycles_resolution();
}

_ODP_INLINE uint64_t odp_cpu_cycles(void)
{
	return _odp_cpu_cycles();
}

_ODP_INLINE uint64_t odp_cpu_cycles_diff(uint64_t c2, uint64_t c1)
{
	if (odp_likely(c2 >= c1))
		return c2 - c1;

	return c2 + (odp_cpu_cycles_max() - c1) + _odp_cpu_cycles_resolution();
}

_ODP_INLINE void odp_prefetch(const void *ptr)
{
	/*
	 * __builtin_prefetch (const void *addr, rw, locality)
	 *
	 * rw 0..1       (0: read, 1: write)
	 * locality 0..3 (0: don't leave to cache, 3: leave on all cache levels)
	 */
	__builtin_prefetch(ptr, 0, 3);
}

_ODP_INLINE void odp_prefetch_l1(const void *ptr)
{
	__builtin_prefetch(ptr, 0, 3);
}

_ODP_INLINE void odp_prefetch_l2(const void *ptr)
{
	__builtin_prefetch(ptr, 0, 2);
}

_ODP_INLINE void odp_prefetch_l3(const void *ptr)
{
	__builtin_prefetch(ptr, 0, 1);
}

_ODP_INLINE void odp_prefetch_store(const void *ptr)
{
	__builtin_prefetch(ptr, 1, 3);
}

_ODP_INLINE void odp_prefetch_store_l1(const void *ptr)
{
	__builtin_prefetch(ptr, 1, 3);
}

_ODP_INLINE void odp_prefetch_store_l2(const void *ptr)
{
	__builtin_prefetch(ptr, 1, 2);
}

_ODP_INLINE void odp_prefetch_store_l3(const void *ptr)
{
	__builtin_prefetch(ptr, 1, 1);
}

_ODP_INLINE void odp_prefetch_strm_l1(const void *ptr)
{
	__builtin_prefetch(ptr, 0, 0);
}

_ODP_INLINE void odp_prefetch_store_strm_l1(const void *ptr)
{
	__builtin_prefetch(ptr, 1, 0);
}

_ODP_INLINE void odp_prefetch_l1i(const void *addr)
{
	_odp_prefetch_l1i(addr);
}

/** @endcond */

#endif
