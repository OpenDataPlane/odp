/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_CPU_INTERNAL_H_
#define ODP_CPU_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/cpu.h>

static inline
uint64_t _odp_cpu_cycles_diff(uint64_t c1, uint64_t c2)
{
	if (odp_likely(c2 >= c1))
		return c2 - c1;

	return c2 + (odp_cpu_cycles_max() - c1) + 1;
}

#ifdef __cplusplus
}
#endif

#endif
