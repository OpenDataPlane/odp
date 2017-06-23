/* Copyright (c) 2017, ARM Limited. All rights reserved.
 *
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef ODP_X86_CPU_H_
#define ODP_X86_CPU_H_

/******************************************************************************
 * Atomics
 *****************************************************************************/

#define atomic_store_release(loc, val, ro) \
	__atomic_store_n(loc, val, __ATOMIC_RELEASE)

/******************************************************************************
 * Idle mgmt
 *****************************************************************************/

static inline void sevl(void)
{
	/* empty */
}

static inline int wfe(void)
{
	return 1;
}

#define monitor128(addr, mo) __atomic_load_n((addr), (mo))
#define monitor64(addr, mo) __atomic_load_n((addr), (mo))
#define monitor32(addr, mo) __atomic_load_n((addr), (mo))
#define monitor8(addr, mo) __atomic_load_n((addr), (mo))

static inline void doze(void)
{
	odp_cpu_pause();
}

#endif
