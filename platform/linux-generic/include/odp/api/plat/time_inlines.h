/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2018 Linaro Limited
 * Copyright (c) 2020-2023 Nokia
 */

#ifndef ODP_PLAT_TIME_INLINES_H_
#define ODP_PLAT_TIME_INLINES_H_

#include <odp/api/align.h>
#include <odp/api/hints.h>
#include <odp/api/time_types.h>

#include <odp/api/abi/time_inlines.h>

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

#ifndef _ODP_NO_INLINE
	/* Inline functions by default */
	#define _ODP_INLINE static inline
	#define odp_time_local      __odp_time_local
	#define odp_time_global     __odp_time_global
	#define odp_time_to_ns      __odp_time_to_ns
	#define odp_time_local_ns   __odp_time_local_ns
	#define odp_time_global_ns  __odp_time_global_ns

	#define odp_time_local_strict      __odp_time_local_strict
	#define odp_time_global_strict     __odp_time_global_strict
	#define odp_time_local_strict_ns   __odp_time_local_strict_ns
	#define odp_time_global_strict_ns  __odp_time_global_strict_ns

	#define odp_time_cmp        __odp_time_cmp
	#define odp_time_diff       __odp_time_diff
	#define odp_time_diff_ns    __odp_time_diff_ns
	#define odp_time_add_ns     __odp_time_add_ns
	#define odp_time_sum        __odp_time_sum

	#define odp_time_local_from_ns __odp_time_local_from_ns
	#define odp_time_global_from_ns __odp_time_global_from_ns

	#define odp_time_local_res __odp_time_local_res
	#define odp_time_global_res __odp_time_global_res

	#define odp_time_wait_ns __odp_time_wait_ns
	#define odp_time_wait_until __odp_time_wait_until
	#define odp_time_startup __odp_time_startup
#else
	#define _ODP_INLINE
#endif

_ODP_INLINE odp_time_t odp_time_local(void)
{
	return _odp_time_cur();
}

_ODP_INLINE odp_time_t odp_time_global(void)
{
	return _odp_time_cur();
}

_ODP_INLINE odp_time_t odp_time_local_strict(void)
{
	return _odp_time_cur_strict();
}

_ODP_INLINE odp_time_t odp_time_global_strict(void)
{
	return _odp_time_cur_strict();
}

_ODP_INLINE uint64_t odp_time_local_ns(void)
{
	return _odp_time_to_ns(_odp_time_cur());
}

_ODP_INLINE uint64_t odp_time_global_ns(void)
{
	return _odp_time_to_ns(_odp_time_cur());
}

_ODP_INLINE uint64_t odp_time_local_strict_ns(void)
{
	return _odp_time_to_ns(_odp_time_cur_strict());
}

_ODP_INLINE uint64_t odp_time_global_strict_ns(void)
{
	return _odp_time_to_ns(_odp_time_cur_strict());
}

_ODP_INLINE uint64_t odp_time_to_ns(odp_time_t time)
{
	return _odp_time_to_ns(time);
}

_ODP_INLINE int odp_time_cmp(odp_time_t t2, odp_time_t t1)
{
	if (odp_likely(t2.u64 > t1.u64))
		return 1;

	if (t2.u64 < t1.u64)
		return -1;

	return 0;
}

_ODP_INLINE odp_time_t odp_time_diff(odp_time_t t2, odp_time_t t1)
{
	odp_time_t time;

	time.u64 = t2.u64 - t1.u64;

	return time;
}

_ODP_INLINE uint64_t odp_time_diff_ns(odp_time_t t2, odp_time_t t1)
{
	odp_time_t time;

	time.u64 = t2.u64 - t1.u64;

	return odp_time_to_ns(time);
}

_ODP_INLINE odp_time_t odp_time_add_ns(odp_time_t time, uint64_t ns)
{
	odp_time_t t = _odp_time_from_ns(ns);

	t.u64 += time.u64;

	return t;
}

_ODP_INLINE odp_time_t odp_time_sum(odp_time_t t1, odp_time_t t2)
{
	odp_time_t time;

	time.u64 = t1.u64 + t2.u64;

	return time;
}

_ODP_INLINE odp_time_t odp_time_local_from_ns(uint64_t ns)
{
	return _odp_time_from_ns(ns);
}

_ODP_INLINE odp_time_t odp_time_global_from_ns(uint64_t ns)
{
	return _odp_time_from_ns(ns);
}

_ODP_INLINE uint64_t odp_time_local_res(void)
{
	return _odp_time_res();
}

_ODP_INLINE uint64_t odp_time_global_res(void)
{
	return _odp_time_res();
}

_ODP_INLINE void odp_time_wait_until(odp_time_t time)
{
	odp_time_t cur;

	do {
		cur = _odp_time_cur();
	} while (odp_time_cmp(time, cur) > 0);
}

_ODP_INLINE void odp_time_wait_ns(uint64_t ns)
{
	odp_time_t cur = _odp_time_cur();
	odp_time_t wait = _odp_time_from_ns(ns);
	odp_time_t end_time = odp_time_sum(cur, wait);

	odp_time_wait_until(end_time);
}

_ODP_INLINE void odp_time_startup(odp_time_startup_t *startup)
{
	_odp_time_startup(startup);
}

/** @endcond */

#ifdef __cplusplus
}
#endif

#endif
