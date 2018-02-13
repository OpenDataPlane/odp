/* Copyright (c) 2017, ARM Limited. All rights reserved.
 *
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef PLATFORM_LINUXGENERIC_ARCH_ARM_ODP_ATOMIC_H
#define PLATFORM_LINUXGENERIC_ARCH_ARM_ODP_ATOMIC_H

#ifndef PLATFORM_LINUXGENERIC_ARCH_ARM_ODP_CPU_H
#error This file should not be included directly, please include odp_cpu.h
#endif

#ifdef CONFIG_DMBSTR

#define atomic_store_release(loc, val, ro)		\
do {							\
	_odp_release_barrier(ro);			\
	__atomic_store_n(loc, val, __ATOMIC_RELAXED);   \
} while (0)

#else

#define atomic_store_release(loc, val, ro) \
	__atomic_store_n(loc, val, __ATOMIC_RELEASE)

#endif  /* CONFIG_DMBSTR */

#endif  /* PLATFORM_LINUXGENERIC_ARCH_ARM_ODP_ATOMIC_H */
