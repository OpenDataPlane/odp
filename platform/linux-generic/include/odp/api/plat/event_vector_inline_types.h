/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020 Nokia
 */

#ifndef ODP_PLAT_EVENT_VECTOR_INLINE_TYPES_H_
#define ODP_PLAT_EVENT_VECTOR_INLINE_TYPES_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

typedef union {
	uint32_t all_flags;

	struct {
		uint32_t user_flag : 1;
	};

} _odp_event_vector_flags_t;

/* Event vector field accessors */
#define _odp_event_vect_get(vect, cast, field) \
	(*(cast *)(uintptr_t)((uint8_t *)vect + _odp_event_vector_inline.field))
#define _odp_event_vect_get_ptr(vect, cast, field) \
	((cast *)(uintptr_t)((uint8_t *)vect + _odp_event_vector_inline.field))

/* Event vector header field offsets for inline functions */
typedef struct _odp_event_vector_inline_offset_t {
	uint16_t event;
	uint16_t pool;
	uint16_t size;
	uint16_t uarea_addr;
	uint16_t flags;

} _odp_event_vector_inline_offset_t;

extern const _odp_event_vector_inline_offset_t _odp_event_vector_inline;

/** @endcond */

#ifdef __cplusplus
}
#endif

#endif /* ODP_PLAT_EVENT_VECTOR_INLINE_TYPES_H_ */
