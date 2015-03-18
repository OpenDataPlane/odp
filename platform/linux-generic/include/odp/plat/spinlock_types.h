/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP spinlock
 */

#ifndef ODP_SPINLOCK_TYPES_H_
#define ODP_SPINLOCK_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/std_types.h>

/**
 * @internal
 * ODP spinlock
 */
struct odp_spinlock_s {
	char lock;  /**< lock flag, should match odp_atomic_flag_t */
};


/** @addtogroup odp_synchronizers
 *  @{
 */

typedef struct odp_spinlock_s odp_spinlock_t;

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
