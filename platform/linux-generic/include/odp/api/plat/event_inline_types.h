/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2018 Linaro Limited
 * Copyright (c) 2022 Nokia
 */

#ifndef ODP_PLAT_EVENT_INLINE_TYPES_H_
#define ODP_PLAT_EVENT_INLINE_TYPES_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

/* Event header field accessors */
#define _odp_event_hdr_field(event_hdr, cast, field) \
	(*(cast *)(uintptr_t)((uint8_t *)event_hdr + \
	 _odp_event_inline_offset.field))
#define _odp_event_hdr_ptr(event_hdr, cast, field) \
	((cast *)(uintptr_t)((uint8_t *)event_hdr + \
	_odp_event_inline_offset.field))

/* Event header field offsets for inline functions */
typedef struct _odp_event_inline_offset_t {
	uint16_t event_type;
	uint16_t base_data;
	uint16_t subtype;
	uint16_t flow_id;
	uint16_t pool;

} _odp_event_inline_offset_t;

extern const _odp_event_inline_offset_t _odp_event_inline_offset;

/** @endcond */

#ifdef __cplusplus
}
#endif

#endif
