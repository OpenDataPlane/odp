/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODPDRV barrier
 */

#ifndef ODPDRV_BARRIER_TYPES_H_
#define ODPDRV_BARRIER_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/drv/std_types.h>
#include <odp/drv/atomic.h>

/**
 * @internal
 * ODPDRV thread synchronization barrier
 */
struct odpdrv_barrier_s {
	uint32_t		count;  /**< Thread count */
	odpdrv_atomic_u32_t	bar;    /**< Barrier counter */
};

typedef struct odpdrv_barrier_s odpdrv_barrier_t;

#ifdef __cplusplus
}
#endif

#endif
