/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2024 Nokia
 */

#ifndef ODP_DEFAULT_WAIT_UNTIL_H_
#define ODP_DEFAULT_WAIT_UNTIL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/plat/cpu_inlines.h>

#include <stdint.h>

/**
 * The _odp_wait_until_eq_*() functions defined in this header are intended to
 * be used only with the scalable scheduler and queue implementations. Even
 * though these functions use standard non-atomic parameter types, the
 * parameters must only be operated using atomic operations. If new functions
 * are added to this file, they should use _odp_wait_until_equal_*() prefix and
 * atomic parameter types.
 */

static inline void _odp_wait_until_eq_u32(uint32_t *val, uint32_t expected)
{
	while (__atomic_load_n(val, __ATOMIC_RELAXED) != expected)
		odp_cpu_pause();
}

static inline void _odp_wait_until_eq_acq_u8(uint8_t *val, uint8_t expected)
{
	while (__atomic_load_n(val, __ATOMIC_ACQUIRE) != expected)
		odp_cpu_pause();
}

static inline void _odp_wait_until_eq_acq_u32(uint32_t *val, uint32_t expected)
{
	while (__atomic_load_n(val, __ATOMIC_ACQUIRE) != expected)
		odp_cpu_pause();
}

#ifdef __cplusplus
}
#endif

#endif
