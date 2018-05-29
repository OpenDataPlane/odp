/* Copyright (c) 2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_PLAT_QUEUE_INLINE_TYPES_H_
#define ODP_PLAT_QUEUE_INLINE_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

/* Queue entry field accessor */
#define _odp_qentry_field(qentry, cast, field) \
	(*(cast *)(uintptr_t)((uint8_t *)qentry + \
	 _odp_queue_inline_offset.field))

/* Queue entry field offsets for inline functions */
typedef struct _odp_queue_inline_offset_t {
	uint16_t context;

} _odp_queue_inline_offset_t;

/** @endcond */

#ifdef __cplusplus
}
#endif

#endif
