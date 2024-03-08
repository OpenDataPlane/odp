/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2015-2018 Linaro Limited
 */

/**
 * @file
 *
 * ODP packet descriptor
 */

#ifndef ODP_POOL_INLINE_TYPES_H_
#define ODP_POOL_INLINE_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

/** Pool field accessor */
#define _odp_pool_get(pool, cast, field) \
	(*(cast *)(uintptr_t)((uint8_t *)pool + _odp_pool_inline.field))

/** Pool header field offsets for inline functions */
typedef struct _odp_pool_inline_offset_t {
	uint16_t index;
	uint16_t seg_len;
	uint16_t uarea_size;
	uint16_t trailer_size;
	uint16_t ext_head_offset;
	uint16_t ext_pkt_buf_size;

} _odp_pool_inline_offset_t;

extern const _odp_pool_inline_offset_t _odp_pool_inline;

/** @endcond */

#ifdef __cplusplus
}
#endif

#endif
