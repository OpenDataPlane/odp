/* Copyright (c) 2022, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_PLAT_POOL_INLINES_H_
#define ODP_PLAT_POOL_INLINES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/pool_types.h>

#include <odp/api/plat/pool_inline_types.h>

#include <stdint.h>

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

extern const _odp_pool_inline_offset_t _odp_pool_inline;

#ifndef _ODP_NO_INLINE
	/* Inline functions by default */
	#define _ODP_INLINE static inline
	#define odp_pool_index __odp_pool_index
#else
	#define _ODP_INLINE
#endif

_ODP_INLINE int odp_pool_index(odp_pool_t pool)
{
	return _odp_pool_get(pool, uint32_t, index);
}

/** @endcond */

#ifdef __cplusplus
}
#endif

#endif
