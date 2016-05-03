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

#if defined(__GNUC__) && !defined(__clang__)

#if __GNUC__ < 4 || (__GNUC__ == 4 && (__GNUC_MINOR__ < 6))

/**
 * @internal _Static_assert was only added in GCC 4.6. Provide a weak replacement
 * for previous versions.
 */
#define _Static_assert(e, s) (extern int (*static_assert_checker(void)) \
	[sizeof(struct { unsigned int error_if_negative:(e) ? 1 : -1; })])

#endif

#endif

/**
 * @internal Compile time assertion macro. Fails compilation and outputs 'msg'
 * if condition 'cond' is false. Macro definition is empty when compiler is not
 * supported or the compiler does not support static assertion.
 */
#define ODP_STATIC_ASSERT(cond, msg)  _Static_assert(cond, msg)

#ifdef __cplusplus
}
#endif

#endif
