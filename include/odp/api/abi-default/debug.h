/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2015-2018 Linaro Limited
 */

/**
 * @file
 *
 * ODP debug
 */

#ifndef ODP_ABI_DEBUG_H_
#define ODP_ABI_DEBUG_H_

#ifdef __cplusplus
extern "C" {
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
#endif

#ifdef __cplusplus
}
#endif

#endif
