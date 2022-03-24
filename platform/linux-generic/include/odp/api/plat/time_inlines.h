/* Copyright (c) 2018, Linaro Limited
 * Copyright (c) 2020-2022, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_PLAT_TIME_INLINES_H_
#define ODP_PLAT_TIME_INLINES_H_

#include <stdint.h>
#include <odp/api/align.h>
#include <odp/api/hints.h>

#include <odp/api/abi/cpu_time.h>

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

#define _ODP_TIMESPEC_SIZE 16
#define _ODP_TIME_GIGA_HZ  1000000000ULL

typedef struct _odp_time_global_t {
	/* Storage space for struct timespec. Posix headers are not included
	 * here to avoid application exposure. */
	uint8_t timespec[_ODP_TIMESPEC_SIZE] ODP_ALIGNED(_ODP_TIMESPEC_SIZE);

	int             use_hw;
	uint64_t        hw_start;
	uint64_t        hw_freq_hz;

} _odp_time_global_t;

extern _odp_time_global_t _odp_time_glob;

odp_time_t _odp_timespec_cur(void);

static inline odp_time_t _odp_time_cur(void)
{
	if (_odp_time_glob.use_hw) {
		odp_time_t time;

		time.count = _odp_cpu_global_time() - _odp_time_glob.hw_start;
		return time;
	}

	return _odp_timespec_cur();
}

static inline odp_time_t _odp_time_cur_strict(void)
{
	if (_odp_time_glob.use_hw) {
		odp_time_t time;

		time.count = _odp_cpu_global_time_strict() - _odp_time_glob.hw_start;
		return time;
	}

	return _odp_timespec_cur();
}

static inline uint64_t _odp_time_hw_to_ns(odp_time_t time)
{
	uint64_t nsec;
	uint64_t freq_hz = _odp_time_glob.hw_freq_hz;
	uint64_t count = time.count;
	uint64_t sec = 0;

	if (count >= freq_hz) {
		sec   = count / freq_hz;
		count = count - sec * freq_hz;
	}

	nsec = (_ODP_TIME_GIGA_HZ * count) / freq_hz;

	return (sec * _ODP_TIME_GIGA_HZ) + nsec;
}

static inline uint64_t _odp_time_convert_to_ns(odp_time_t time)
{
	if (_odp_time_glob.use_hw)
		return _odp_time_hw_to_ns(time);

	return time.nsec;
}

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
	#define odp_time_sum        __odp_time_sum

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
	return _odp_time_convert_to_ns(_odp_time_cur());
}

_ODP_INLINE uint64_t odp_time_global_ns(void)
{
	return _odp_time_convert_to_ns(_odp_time_cur());
}

_ODP_INLINE uint64_t odp_time_local_strict_ns(void)
{
	return _odp_time_convert_to_ns(_odp_time_cur_strict());
}

_ODP_INLINE uint64_t odp_time_global_strict_ns(void)
{
	return _odp_time_convert_to_ns(_odp_time_cur_strict());
}

_ODP_INLINE uint64_t odp_time_to_ns(odp_time_t time)
{
	return _odp_time_convert_to_ns(time);
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

_ODP_INLINE odp_time_t odp_time_sum(odp_time_t t1, odp_time_t t2)
{
	odp_time_t time;

	time.u64 = t1.u64 + t2.u64;

	return time;
}

/** @endcond */

#endif
