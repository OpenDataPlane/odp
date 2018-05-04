/* Copyright (c) 2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_PLAT_BUFFER_INLINE_TYPES_H_
#define ODP_PLAT_BUFFER_INLINE_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

/* Buffer header field accessor */
#define _odp_buf_hdr_field(buf_hdr, cast, field) \
	(*(cast *)(uintptr_t)((uint8_t *)buf_hdr + \
	 _odp_buffer_inline_offset.field))

/* Buffer header field offsets for inline functions */
typedef struct _odp_buffer_inline_offset_t {
	uint16_t event_type;

} _odp_buffer_inline_offset_t;

/** @endcond */

#ifdef __cplusplus
}
#endif

#endif
