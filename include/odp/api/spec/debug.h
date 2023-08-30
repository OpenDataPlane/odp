/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2013-2018 Linaro Limited
 */
/**
 * @file
 *
 * ODP debug
 */

#ifndef ODP_API_SPEC_DEBUG_H_
#define ODP_API_SPEC_DEBUG_H_
#include <odp/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @def ODP_STATIC_ASSERT
 * Compile time assertion macro. Fails compilation and outputs message 'msg'
 * if condition 'cond' is false. Macro definition is empty when the compiler
 * is not supported or the compiler does not support static assertion.
 *
 * @param cond Conditional expression to be evaluated at compile time
 *
 * @param msg  Compile time error message to be displayed if cond is false
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
