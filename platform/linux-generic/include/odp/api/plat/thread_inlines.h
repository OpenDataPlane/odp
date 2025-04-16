/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2018 Linaro Limited
 * Copyright (c) 2024 Nokia
 */

#ifndef ODP_PLAT_THREAD_INLINES_H_
#define ODP_PLAT_THREAD_INLINES_H_

#include <odp/api/thread_types.h>

#include <odp/api/plat/thread_inline_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

#ifndef _ODP_NO_INLINE
	/* Inline functions by default */
	#define _ODP_INLINE static inline
	#define odp_thread_id __odp_thread_id
	#define odp_thread_type __odp_thread_type
#else
	#define _ODP_INLINE
#endif

_ODP_INLINE int odp_thread_id(void)
{
	return _odp_this_thread->thr;
}

_ODP_INLINE odp_thread_type_t odp_thread_type(void)
{
	return _odp_this_thread->type;
}

/** @endcond */

#ifdef __cplusplus
}
#endif

#endif
