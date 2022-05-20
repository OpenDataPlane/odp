/* Copyright (c) 2015-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
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

/** @internal Pool field accessor */
#define _odp_pool_get(pool, cast, field) \
	(*(cast *)(uintptr_t)((uint8_t *)pool + _odp_pool_inline.field))

/** @internal Pool header field offsets for inline functions */
typedef struct _odp_pool_inline_offset_t {
	/** @internal field offset */
	uint16_t index;
	/** @internal field offset */
	uint16_t uarea_size;

} _odp_pool_inline_offset_t;

#ifdef __cplusplus
}
#endif

#endif
