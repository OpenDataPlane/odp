/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2013-2018 Linaro Limited
 * Copyright (c) 2020-2023 Nokia
 */

#ifndef ODP_ARCH_TIME_CPU_INLINES_H_
#define ODP_ARCH_TIME_CPU_INLINES_H_

#include <odp/api/time_types.h>

#include <odp/api/abi/time_cpu.h>

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define _ODP_TIME_GIGA_HZ  1000000000ULL

typedef struct _odp_time_global_t {
	uint64_t freq_hz;
	uint64_t start_time;
	uint64_t start_time_ns;
	uint64_t mult_to_ns;
	uint64_t mult_from_ns;
	uint32_t shift_to_ns;
	uint32_t shift_from_ns;

} _odp_time_global_t;

extern _odp_time_global_t _odp_time_glob;

static inline odp_time_t _odp_time_cur(void)
{
	odp_time_t time;

	time.count = _odp_time_cpu_global();
	return time;
}

static inline odp_time_t _odp_time_cur_strict(void)
{
	odp_time_t time;

	time.count = _odp_time_cpu_global_strict();
	return time;
}

static inline uint64_t _odp_time_to_ns(odp_time_t time)
{
	uint64_t count = time.count;

#ifdef __SIZEOF_INT128__
	return (uint64_t)(((__uint128_t)count * _odp_time_glob.mult_to_ns) >>
			  _odp_time_glob.shift_to_ns);
#else
	uint64_t nsec;
	uint64_t freq_hz = _odp_time_glob.freq_hz;
	uint64_t sec = 0;

	if (count >= freq_hz) {
		sec   = count / freq_hz;
		count = count - sec * freq_hz;
	}

	nsec = (_ODP_TIME_GIGA_HZ * count) / freq_hz;

	return (sec * _ODP_TIME_GIGA_HZ) + nsec;
#endif
}

static inline odp_time_t _odp_time_from_ns(uint64_t ns)
{
	odp_time_t time;
	uint64_t count;

#ifdef __SIZEOF_INT128__
	count = (uint64_t)(((__uint128_t)ns * _odp_time_glob.mult_from_ns) >>
			   _odp_time_glob.shift_from_ns);
#else
	uint64_t freq_hz = _odp_time_glob.freq_hz;
	uint64_t sec = 0;

	if (ns >= ODP_TIME_SEC_IN_NS) {
		sec = ns / ODP_TIME_SEC_IN_NS;
		ns  = ns - sec * ODP_TIME_SEC_IN_NS;
	}

	count  = sec * freq_hz;
	count += (ns * freq_hz) / ODP_TIME_SEC_IN_NS;
#endif
	time.count = count;

	return time;
}

static inline uint64_t _odp_time_res(void)
{
	return _odp_time_glob.freq_hz;
}

static inline void _odp_time_startup(odp_time_startup_t *startup)
{
	startup->global.count = _odp_time_glob.start_time;
	startup->global_ns    = _odp_time_glob.start_time_ns;
}

#ifdef __cplusplus
}
#endif

#endif
