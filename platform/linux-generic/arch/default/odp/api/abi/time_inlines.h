/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2013-2018 Linaro Limited
 * Copyright (c) 2020-2025 Nokia
 */

#ifndef ODP_ARCH_TIME_INLINES_H_
#define ODP_ARCH_TIME_INLINES_H_

#include <odp/api/sync.h>
#include <odp/api/time_types.h>

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

odp_time_t _odp_time_cur(void);
uint64_t _odp_time_res(void);
void _odp_time_startup(odp_time_startup_t *startup);

static inline odp_time_t _odp_time_cur_strict(void)
{
	odp_mb_full();
	return _odp_time_cur();
}

static inline uint64_t _odp_time_to_ns(odp_time_t time)
{
	return time.nsec;
}

static inline odp_time_t _odp_time_from_ns(uint64_t ns)
{
	odp_time_t time;

	time.nsec = ns;

	return time;
}

#ifdef __cplusplus
}
#endif

#endif
