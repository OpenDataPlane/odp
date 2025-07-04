/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2015-2018 Linaro Limited
 */

/**
 * @file
 *
 * ODP thread masks
 */

#ifndef ODP_ABI_THRMASK_H_
#define ODP_ABI_THRMASK_H_

#include <odp/api/cpumask.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @internal */
struct odp_thrmask_s {
	/** @internal Thread mask storage
	  *
	  * This is private to the implementation.
	  * Don't access directly, use access functions.
	  */
	odp_cpumask_t m;
};

/** @addtogroup odp_thread
 *  @{
 */

typedef struct odp_thrmask_s odp_thrmask_t;

#define ODP_THRMASK_STR_SIZE ODP_CPUMASK_STR_SIZE

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
