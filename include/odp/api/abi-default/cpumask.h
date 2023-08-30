/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2015-2018 Linaro Limited
 */

/**
 * @file
 *
 * ODP CPU masks and enumeration
 */

#ifndef ODP_ABI_CPUMASK_H_
#define ODP_ABI_CPUMASK_H_

#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup odp_cpumask
 *  @{
 */

#include <odp/api/std_types.h>
#include <odp/api/align.h>
#include <sched.h>

#define ODP_CPUMASK_SIZE (sizeof(cpu_set_t) * 8)

#define ODP_CPUMASK_STR_SIZE ((ODP_CPUMASK_SIZE + 3) / 4 + 3)

/**
 * CPU mask
 *
 * Don't access directly, use access functions.
 */
typedef struct ODP_ALIGNED(8) odp_cpumask_t {
	/** @private CPU mask storage
	  *
	  * This is private to the implementation.
	  * Don't access directly, use access functions.
	  */
	uint8_t _u8[ODP_CPUMASK_SIZE / 8];
} odp_cpumask_t;

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
