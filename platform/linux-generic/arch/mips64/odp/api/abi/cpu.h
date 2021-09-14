/* Copyright (c) 2016-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_API_ABI_CPU_H_
#define ODP_API_ABI_CPU_H_

#ifdef __cplusplus
extern "C" {
#endif

#if defined __OCTEON__
#define ODP_CACHE_LINE_SIZE 128
#else
#error Please add support for your arch in cpu_arch.h
#endif

/* Inlined functions for non-ABI compat mode */
#include <odp/api/plat/cpu_inlines.h>

#ifdef __cplusplus
}
#endif

#endif
