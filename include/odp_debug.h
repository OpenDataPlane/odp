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

#include <stdio.h>

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


/**
 * Debug printing macro, which prints output when DEBUG flag is set.
 */
#define ODP_DBG(fmt, ...) \
		do { if (ODP_DEBUG == 1) printf(fmt, ##__VA_ARGS__); } while (0)

/**
 * Print output to stderr (file, line and function).
 */
#define ODP_ERR(fmt, ...) \
	fprintf(stderr, "%s:%d:%s(): " fmt, __FILE__, \
		__LINE__, __func__, ##__VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif







