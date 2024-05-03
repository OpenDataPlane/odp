/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2018 Linaro Limited
 */

#ifndef ODP_ARCH_CPU_INLINES_H_
#define ODP_ARCH_CPU_INLINES_H_

#ifdef __cplusplus
extern "C" {
#endif

static inline void _odp_cpu_pause(void)
{
}

static inline void _odp_prefetch_l1i(const void *addr)
{
	(void)addr;
}

#include <odp/api/abi/cpu_generic.h>

#ifdef __cplusplus
}
#endif

#endif
