/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 ARM Limited
 */

#ifndef ODP_API_ABI_WAIT_UNTIL_GENERIC_H_
#define ODP_API_ABI_WAIT_UNTIL_GENERIC_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/atomic.h>

static inline void
_odp_wait_until_equal_acq_u32(odp_atomic_u32_t *addr, uint32_t expected)
{
	while (odp_atomic_load_acq_u32(addr) != expected)
		odp_cpu_pause();
}

#ifdef __cplusplus
}
#endif

#endif
