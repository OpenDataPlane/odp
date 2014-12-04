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
#include <stdlib.h>
#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup odp_ver_abt_log_dbg
 *  Macros that allows different messages.
 *  @{
 */

#ifdef __GNUC__

/**
 * Indicate deprecated variables, functions or types
 */
#define ODP_DEPRECATED __attribute__((__deprecated__))

/**
 * Intentionally unused variables ot functions
 */
#define ODP_UNUSED     __attribute__((__unused__))

#if __GNUC__ < 4 || (__GNUC__ == 4 && (__GNUC_MINOR__ < 6))

/**
 * _Static_assert was only added in GCC 4.6. Provide a weak replacement
 * for previous versions.
 */
#define _Static_assert(e, s) extern int (*static_assert_checker (void)) \
	[sizeof (struct { unsigned int error_if_negative: (e) ? 1 : -1; })]

#endif

#else

#define ODP_DEPRECATED
#define ODP_UNUSED

#endif

/**
 * Runtime assertion-macro - aborts if 'cond' is false.
 */
#define ODP_ASSERT(cond, msg) \
	do { if ((ODP_DEBUG == 1) && (!(cond))) { \
		ODP_ERR("%s\n", msg); \
		abort(); } \
	} while (0)

/**
 * Compile time assertion-macro - fail compilation if cond is false.
 * @note This macro has zero runtime overhead
 */
#define ODP_STATIC_ASSERT(cond, msg)  _Static_assert(cond, msg)

/**
 * ODP log level.
 */
typedef enum odp_log_level {
	ODP_LOG_DBG,
	ODP_LOG_ERR,
	ODP_LOG_UNIMPLEMENTED,
	ODP_LOG_ABORT,
	ODP_LOG_PRINT
} odp_log_level_e;

/**
 * ODP log function
 *
 * Instead of direct prints to stdout/stderr all logging in ODP implementation
 * should be done via this function or its wrappers.
 * ODP platform MUST provide a default *weak* implementation of this function.
 * Application MAY override the function if needed by providing a strong
 * function.
 *
 * @param[in] level   Log level
 * @param[in] fmt     printf-style message format
 *
 * @return The number of characters logged if succeeded. Otherwise returns
 *         a negative number.
 */
extern int odp_override_log(odp_log_level_e level, const char *fmt, ...);

/**
 * ODP LOG macro.
 */
#define ODP_LOG(level, fmt, ...) \
	odp_override_log(level, "%s:%d:%s():" fmt, __FILE__, \
		__LINE__, __func__, ##__VA_ARGS__)

/**
 * Log print message when the application calls one of the ODP APIs
 * specifically for dumping internal data.
 */
#define ODP_PRINT(fmt, ...) \
		odp_override_log(ODP_LOG_PRINT, " " fmt, ##__VA_ARGS__)


/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
