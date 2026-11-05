/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2018 Linaro Limited
 * Copyright (c) 2022 Nokia
 */

#ifndef ODP_PLAT_THREAD_INLINE_TYPES_H_
#define ODP_PLAT_THREAD_INLINE_TYPES_H_

#include <odp/api/init.h>
#include <odp/api/thread_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

/* Internal thread type. Extends the public odp_thread_type_t with thread types
 * used only by the linux-generic implementation (e.g. service threads created
 * by internal subsystems). Public values must match odp_thread_type_t. */
typedef enum {
	_ODP_THR_WORKER = ODP_THREAD_WORKER,
	_ODP_THR_CONTROL = ODP_THREAD_CONTROL,
	_ODP_THR_INTERNAL
} _odp_internal_thread_type_t;

typedef struct {
	odp_log_func_t log_fn;
	_odp_internal_thread_type_t type;
	int thr;

} _odp_thread_state_t;

extern __thread _odp_thread_state_t *_odp_this_thread;

/** @endcond */

#ifdef __cplusplus
}
#endif

#endif
