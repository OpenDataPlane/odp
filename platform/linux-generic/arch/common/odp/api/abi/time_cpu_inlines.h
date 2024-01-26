/* Copyright (c) 2013-2018, Linaro Limited
 * Copyright (c) 2020-2024, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_ARCH_TIME_CPU_INLINES_H_
#define ODP_ARCH_TIME_CPU_INLINES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/time_types.h>

#include <odp/api/abi/time_cpu.h>

#include <stdint.h>

#define _ODP_TIME_GIGA_HZ  1000000000ULL

typedef struct _odp_time_global_t {
	uint64_t freq_hz;
	odp_time_t start_time;
	uint64_t start_time_ns;

} _odp_time_global_t;

extern _odp_time_global_t _odp_time_glob;

static inline uint64_t _odp_time_to_u64(odp_time_t time)
{
	return (uint64_t)time;
}

static inline odp_time_t _odp_time_from_u64(uint64_t val)
{
	return (odp_time_t)val;
}

static inline odp_time_t _odp_time_cur(void)
{
	return _odp_time_from_u64(_odp_time_cpu_global());
}

static inline odp_time_t _odp_time_cur_strict(void)
{
	return _odp_time_from_u64(_odp_time_cpu_global_strict());
}

static inline uint64_t _odp_time_to_ns(odp_time_t time)
{
	uint64_t nsec;
	uint64_t freq_hz = _odp_time_glob.freq_hz;
	uint64_t count = _odp_time_to_u64(time);
	uint64_t sec = 0;

	if (count >= freq_hz) {
		sec   = count / freq_hz;
		count = count - sec * freq_hz;
	}

	nsec = (_ODP_TIME_GIGA_HZ * count) / freq_hz;

	return (sec * _ODP_TIME_GIGA_HZ) + nsec;
}

static inline odp_time_t _odp_time_from_ns(uint64_t ns)
{
	uint64_t count;
	uint64_t freq_hz = _odp_time_glob.freq_hz;
	uint64_t sec = 0;

	if (ns >= ODP_TIME_SEC_IN_NS) {
		sec = ns / ODP_TIME_SEC_IN_NS;
		ns  = ns - sec * ODP_TIME_SEC_IN_NS;
	}

	count  = sec * freq_hz;
	count += (ns * freq_hz) / ODP_TIME_SEC_IN_NS;

	return _odp_time_from_u64(count);
}

static inline uint64_t _odp_time_res(void)
{
	return _odp_time_glob.freq_hz;
}

static inline void _odp_time_startup(odp_time_startup_t *startup)
{
	startup->global = _odp_time_glob.start_time;
	startup->global_ns = _odp_time_glob.start_time_ns;
}

#ifdef __cplusplus
}
#endif

#endif
