/* Copyright (c) 2018, Linaro Limited
 * Copyright (c) 2021-2023, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
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
	#define odp_cpu_pause             __odp_cpu_pause
	#define odp_cpu_cycles            __odp_cpu_cycles
	#define odp_cpu_cycles_max        __odp_cpu_cycles_max
	#define odp_cpu_cycles_resolution __odp_cpu_cycles_resolution
	#define odp_cpu_cycles_diff       __odp_cpu_cycles_diff
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

/** @endcond */

#endif
