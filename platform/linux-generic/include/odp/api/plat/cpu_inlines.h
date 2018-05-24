/* Copyright (c) 2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_PLAT_CPU_INLINES_H_
#define ODP_PLAT_CPU_INLINES_H_

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

#ifndef _ODP_NO_INLINE
	/* Inline functions by default */
	#define _ODP_INLINE static inline
	#define odp_cpu_pause             __odp_cpu_pause
	#define odp_cpu_cycles            __odp_cpu_cycles
	#define odp_cpu_cycles_max        __odp_cpu_cycles_max
	#define odp_cpu_cycles_resolution __odp_cpu_cycles_resolution
#else
	#define _ODP_INLINE
#endif

#include <odp/api/abi/cpu_inlines.h>

/** @endcond */

#endif
