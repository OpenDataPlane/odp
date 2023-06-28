/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Nokia
 */

#ifndef ODP_ARCH_SYNC_INLINES_H_
#define ODP_ARCH_SYNC_INLINES_H_

#ifdef __cplusplus
extern "C" {
#endif

static inline void _odp_mb_sync(void)
{
	__asm__ volatile("dsb sy" ::: "memory");
}

static inline void _odp_mb_sync_load(void)
{
	__asm__ volatile("dsb ld" ::: "memory");
}

static inline void _odp_mb_sync_store(void)
{
	__asm__ volatile("dsb st" ::: "memory");
}

#ifdef __cplusplus
}
#endif

#endif
