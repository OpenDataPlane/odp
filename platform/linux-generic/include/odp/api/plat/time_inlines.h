/* Copyright (c) 2018, Linaro Limited
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

typedef struct _odp_time_global_t {
	/* Storage space for struct timespec. Posix headers are not included
	 * here to avoid application exposure. */
	uint8_t ODP_ALIGNED(_ODP_TIMESPEC_SIZE) timespec[_ODP_TIMESPEC_SIZE];

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

#ifndef _ODP_NO_INLINE
	/* Inline functions by default */
	#define _ODP_INLINE static inline
	#define odp_time_local   __odp_time_local
	#define odp_time_global  __odp_time_global
	#define odp_time_cmp     __odp_time_cmp
	#define odp_time_diff    __odp_time_diff
	#define odp_time_sum     __odp_time_sum

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

_ODP_INLINE odp_time_t odp_time_sum(odp_time_t t1, odp_time_t t2)
{
	odp_time_t time;

	time.u64 = t1.u64 + t2.u64;

	return time;
}

/** @endcond */

#endif
