/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 ARM Limited
 */

#ifndef ODP_API_ABI_WAIT_UNTIL_H_
#define ODP_API_ABI_WAIT_UNTIL_H_

#include <odp/autoheader_external.h>

#ifdef _ODP_WFE_LOCKS

#include <stdint.h>

#include <odp/api/atomic.h>

#ifdef __cplusplus
extern "C" {
#endif

static inline void
_odp_wait_until_equal_acq_u32(odp_atomic_u32_t *addr, uint32_t expected)
{
	uint32_t value;
	uint32_t *var = &addr->v;

	__asm__ volatile("sevl" : : : "memory");
	do {
		__asm__ volatile("wfe" : : : "memory");
		__asm__ volatile("ldaxr %w0, [%1]"
					 : "=&r" (value)
					 : "r" (var)
					 : "memory");
	} while (expected != value);
}

#ifdef __cplusplus
}
#endif

#else /* !_ODP_WFE_LOCKS*/

/* Use generic implementation */
#include <odp/api/abi/wait_until_generic.h>

#endif

#endif
