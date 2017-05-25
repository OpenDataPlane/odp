/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODPDRV spinlock
 */

#ifndef ODPDRV_SPINLOCK_TYPES_H_
#define ODPDRV_SPINLOCK_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/drv/std_types.h>

/** @internal */
struct odpdrv_spinlock_s {
	char lock;  /**< lock flag, should match odpdrv_atomic_flag_t */
};

typedef struct odpdrv_spinlock_s odpdrv_spinlock_t;

#ifdef __cplusplus
}
#endif

#endif
