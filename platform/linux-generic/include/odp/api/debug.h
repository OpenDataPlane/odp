/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP debug
 */

#ifndef ODP_PLAT_DEBUG_H_
#define ODP_PLAT_DEBUG_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/spec/debug.h>

/**
 * @internal _Static_assert was only added in GCC 4.6 and the C++ version
 * static_assert for g++ 6 and above.  Provide a weak replacement for previous
 * versions.
 */
#define _odp_merge(a, b) a##b
/** @internal */
#define _odp_label(a) _odp_merge(_ODP_SASSERT_, a)
/** @internal */
#define _ODP_SASSERT _odp_label(__COUNTER__)
/** @internal */
#define _ODP_SASSERT_ENUM(e) { _ODP_SASSERT = 1 / !!(e) }
/** @internal */
#define _odp_static_assert(e, s) enum _ODP_SASSERT_ENUM(e)

#if defined(__clang__)
#if defined(__cplusplus)
#if !__has_feature(cxx_static_assert) && !defined(static_assert)
/** @internal */
#define	static_assert(e, s) _odp_static_assert(e, s)
#endif
#elif !__has_feature(c_static_assert) && !defined(_Static_assert)
/** @internal */
#define _Static_assert(e, s) _odp_static_assert(e, s)
#endif

#elif defined(__GNUC__)
#if __GNUC__ < 4 || (__GNUC__ == 4 && (__GNUC_MINOR__ < 6)) ||	\
	(__GNUC__ < 6 && defined(__cplusplus))
#if defined(__cplusplus)
#if !defined(static_assert)
/** @intenral */
#define	static_assert(e, s) _odp_static_assert(e, s)
#endif
#elif !defined(_Static_assert)
/** @internal */
#define _Static_assert(e, s) _odp_static_assert(e, s)
#endif
#endif

#endif

/**
 * @internal Compile time assertion macro. Fails compilation and outputs 'msg'
 * if condition 'cond' is false. Macro definition is empty when compiler is not
 * supported or the compiler does not support static assertion.
 */
#ifndef __cplusplus
#define ODP_STATIC_ASSERT(cond, msg) _Static_assert(cond, msg)

#else
#define ODP_STATIC_ASSERT(cond, msg) static_assert(cond, msg)
}
#endif

#endif
