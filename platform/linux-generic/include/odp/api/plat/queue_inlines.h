/* Copyright (c) 2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_PLAT_QUEUE_INLINES_H_
#define ODP_PLAT_QUEUE_INLINES_H_

#include <odp/api/plat/queue_inline_types.h>

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

extern _odp_queue_inline_offset_t _odp_queue_inline_offset;

#ifndef _ODP_NO_INLINE
	/* Inline functions by default */
	#define _ODP_INLINE static inline
	#define odp_queue_context __odp_queue_context
#else
	#define _ODP_INLINE
#endif

_ODP_INLINE void *odp_queue_context(odp_queue_t handle)
{
	void *context;
	void *qentry = (void *)handle;

	context = _odp_qentry_field(qentry, void *, context);

	return context;
}

/** @endcond */

#endif
