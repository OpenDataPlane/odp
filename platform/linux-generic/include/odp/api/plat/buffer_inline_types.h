/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Nokia
 */

#ifndef ODP_PLAT_BUFFER_INLINE_TYPES_H_
#define ODP_PLAT_BUFFER_INLINE_TYPES_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

/* Buffer header field accessors */
#define _odp_buffer_get(buffer_hdr, cast, field) \
	(*(cast *)(uintptr_t)((uint8_t *)buffer_hdr + \
	 _odp_buffer_inline_offset.field))

/* Buffer header field offsets for inline functions */
typedef struct _odp_buffer_inline_offset_t {
	uint16_t uarea_addr;

} _odp_buffer_inline_offset_t;

extern const _odp_buffer_inline_offset_t _odp_buffer_inline_offset;

/** @endcond */

#ifdef __cplusplus
}
#endif

#endif
