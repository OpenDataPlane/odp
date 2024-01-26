/* Copyright (c) 2013-2018, Linaro Limited
 * Copyright (c) 2020-2023, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_ARCH_TIME_INLINES_H_
#define ODP_ARCH_TIME_INLINES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/time_types.h>

#include <stdint.h>

odp_time_t _odp_time_cur(void);
uint64_t _odp_time_res(void);
void _odp_time_startup(odp_time_startup_t *startup);

static inline odp_time_t _odp_time_cur_strict(void)
{
	return _odp_time_cur();
}

static inline uint64_t _odp_time_to_ns(odp_time_t time)
{
	return (uint64_t)time;
}

static inline odp_time_t _odp_time_from_ns(uint64_t ns)
{
	return (odp_time_t)ns;
}

static inline uint64_t _odp_time_to_u64(odp_time_t time)
{
	return (uint64_t)time;
}

static inline odp_time_t _odp_time_from_u64(uint64_t val)
{
	return (odp_time_t)val;
}

#ifdef __cplusplus
}
#endif

#endif
