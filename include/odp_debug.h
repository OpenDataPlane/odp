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

#ifndef ODP_DEBUG_H_
#define ODP_DEBUG_H_

#ifdef __cplusplus
extern "C" {
#endif


#ifdef __GNUC__

/**
 * Indicate deprecated variables, functions or types
 */
#define ODP_DEPRECATED __attribute__((__deprecated__))

/**
 * Intentionally unused variables ot functions
 */
#define ODP_UNUSED     __attribute__((__unused__))


#else

#define ODP_DEPRECATED
#define ODP_UNUSED

#endif

/**
 * Compile time assertion-macro - fail compilation if cond is false.
 */
#define ODP_ASSERT(cond, msg)  typedef char msg[(cond) ? 1 : -1]



#ifdef __cplusplus
}
#endif

#endif







