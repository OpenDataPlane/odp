/* Copyright (c) 2020, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_PLAT_EVENT_VECTOR_INLINE_TYPES_H_
#define ODP_PLAT_EVENT_VECTOR_INLINE_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

/* Event vector field accessors */
#define _odp_event_vect_get(vect, cast, field) \
	(*(cast *)(uintptr_t)((uint8_t *)vect + _odp_event_vector_inline.field))
#define _odp_event_vect_get_ptr(vect, cast, field) \
	((cast *)(uintptr_t)((uint8_t *)vect + _odp_event_vector_inline.field))

/* Event vector header field offsets for inline functions */
typedef struct _odp_event_vector_inline_offset_t {
	uint16_t packet;
	uint16_t pool;
	uint16_t size;
	uint16_t uarea_addr;

} _odp_event_vector_inline_offset_t;

/** @endcond */

#ifdef __cplusplus
}
#endif

#endif /* ODP_PLAT_EVENT_VECTOR_INLINE_TYPES_H_ */
