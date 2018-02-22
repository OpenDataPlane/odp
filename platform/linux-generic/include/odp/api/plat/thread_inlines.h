/* Copyright (c) 2018-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_PLAT_THREAD_INLINES_H_
#define ODP_PLAT_THREAD_INLINES_H_

#ifdef __cplusplus
extern "C" {
#endif

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

typedef struct {
	int thr;
	int cpu;
	odp_thread_type_t type;

} _odp_thread_state_t;

extern __thread _odp_thread_state_t *_odp_this_thread;

static inline int _odp_thread_id(void)
{
	return _odp_this_thread->thr;
}

static inline odp_thread_type_t _odp_thread_type(void)
{
	return _odp_this_thread->type;
}

static inline int _odp_cpu_id(void)
{
	return _odp_this_thread->cpu;
}

/** @endcond */

#ifdef __cplusplus
}
#endif

#endif
