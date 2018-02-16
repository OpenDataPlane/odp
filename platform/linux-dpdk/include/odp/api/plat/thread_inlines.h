/* Copyright (c) 2018, Linaro Limited
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

/* Emulate to-be-inlined functions through non-inlines */

#include <odp/api/spec/thread.h>
#include <odp/api/spec/cpu.h>

static inline int _odp_thread_id(void)
{
	return odp_thread_id();
}

static inline odp_thread_type_t _odp_thread_type(void)
{
	return odp_thread_type();
}

static inline int _odp_cpu_id(void)
{
	return odp_cpu_id();
}

/** @endcond */

#ifdef __cplusplus
}
#endif

#endif
