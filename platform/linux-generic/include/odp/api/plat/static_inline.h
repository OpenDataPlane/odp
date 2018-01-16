/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/**
 * @file
 *
 * Macro for static inline functions
 */

#ifndef ODP_PLAT_STATIC_INLINE_H_
#define ODP_PLAT_STATIC_INLINE_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @internal
 * @def ODP_ABI_COMPAT
 * Control ABI compatibility
 */

/**
 * @internal
 * @def _ODP_INLINE
 * Define a function as inlined or not inlined (for ABI compatibility)
 */
#if 1
#define ODP_ABI_COMPAT 1
#define _ODP_INLINE
#else
#define ODP_ABI_COMPAT 0
#define _ODP_INLINE static inline
#endif

#ifdef __cplusplus
}
#endif

#endif
