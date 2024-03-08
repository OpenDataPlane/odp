/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2018 Linaro Limited
 */

#ifndef ODP_API_ABI_CPU_H_
#define ODP_API_ABI_CPU_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/autoheader_external.h>

#ifndef ODP_CACHE_LINE_SIZE
	#define ODP_CACHE_LINE_SIZE _ODP_CACHE_LINE_SIZE
#endif

/* Inlined functions for non-ABI compat mode */
#include <odp/api/plat/cpu_inlines.h>

#ifdef __cplusplus
}
#endif

#endif
