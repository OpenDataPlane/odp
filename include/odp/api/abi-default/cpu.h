/* Copyright (c) 2016-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_ABI_CPU_H_
#define ODP_ABI_CPU_H_

#ifdef __cplusplus
extern "C" {
#endif

#ifndef ODP_CACHE_LINE_SIZE
#define ODP_CACHE_LINE_SIZE 64
#endif

#ifdef _ODP_NEED_GENERIC_CPU_PAUSE
static inline void odp_cpu_pause(void)
{
}
#endif

#ifdef __cplusplus
}
#endif

#endif
