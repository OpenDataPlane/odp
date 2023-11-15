/* Copyright (c) 2018-2018, Linaro Limited
 * Copyright (c) 2022, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_PLAT_THREAD_INLINE_TYPES_H_
#define ODP_PLAT_THREAD_INLINE_TYPES_H_

#include <odp/api/init.h>
#include <odp/api/thread_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

typedef struct {
	odp_log_func_t log_fn;
	odp_thread_type_t type;
	int thr;
	int cpu;

} _odp_thread_state_t;

extern __thread _odp_thread_state_t *_odp_this_thread;

/** @endcond */

#ifdef __cplusplus
}
#endif

#endif
