/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2015-2018 Linaro Limited
 */

/**
 * @file
 *
 * ODP atomic operations
 */

#ifndef ODP_API_ABI_ATOMIC_H_
#define ODP_API_ABI_ATOMIC_H_

#include <odp/api/align.h>
#include <odp/api/std_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @internal
 * Atomic 32-bit unsigned integer
 */
typedef struct ODP_ALIGNED(sizeof(uint32_t)) odp_atomic_u32_s {
	uint32_t v; /**< Actual storage for the atomic variable */
} odp_atomic_u32_t;

#if __GCC_ATOMIC_LLONG_LOCK_FREE >= 2

/**
 * @internal
 * Atomic 64-bit unsigned integer
 */
typedef struct ODP_ALIGNED(sizeof(uint64_t)) odp_atomic_u64_s {
	uint64_t v; /**< Actual storage for the atomic variable */
} odp_atomic_u64_t;

#else

#define ODP_ATOMIC_U64_LOCK	1

/**
 * @internal
 * Atomic 64-bit unsigned integer
 */
typedef struct ODP_ALIGNED(sizeof(uint64_t)) odp_atomic_u64_s {
	uint64_t v; /**< Actual storage for the atomic variable */
	/* Some architectures do not support lock-free operations on 64-bit
	 * data types. We use a spin lock to ensure atomicity. */
	char lock; /**< Spin lock (if needed) used to ensure atomic access */
} odp_atomic_u64_t;

#endif

#if defined(__SIZEOF_INT128__) || defined(_ODP_LOCK_FREE_128BIT_ATOMICS)

/**
 * @internal
 * Atomic 128-bit unsigned integer
 */
typedef struct ODP_ALIGNED(sizeof(odp_u128_t)) odp_atomic_u128_s {
	odp_u128_t v; /**< Actual storage for the atomic variable */
} odp_atomic_u128_t;

#else

/**
 * @internal
 * Atomic 128-bit unsigned integer
 */
typedef struct ODP_ALIGNED(sizeof(odp_u128_t)) odp_atomic_u128_s {
	odp_u128_t v; /**< Actual storage for the atomic variable */
	/* Some architectures do not support lock-free operations on 128-bit
	 * data types. We use a spin lock to ensure atomicity. */
	char lock; /**< Spin lock (if needed) used to ensure atomic access */
} odp_atomic_u128_t;

#endif

#ifdef __cplusplus
}
#endif

#include <odp/api/plat/atomic_inlines.h>

#endif
