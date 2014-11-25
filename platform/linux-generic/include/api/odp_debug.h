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
 * ODP default LOG macro.
 */
#define ODP_LOG(level, fmt, ...) \
do { \
	switch (level) { \
	case ODP_LOG_ERR: \
		fprintf(stderr, "%s:%d:%s():" fmt, __FILE__, \
		__LINE__, __func__, ##__VA_ARGS__); \
		break; \
	case ODP_LOG_DBG: \
		if (ODP_DEBUG_PRINT == 1) \
			fprintf(stderr, "%s:%d:%s():" fmt, __FILE__, \
			__LINE__, __func__, ##__VA_ARGS__); \
		break; \
	case ODP_LOG_PRINT: \
		fprintf(stdout, " " fmt, ##__VA_ARGS__); \
		break; \
	case ODP_LOG_ABORT: \
		fprintf(stderr, "%s:%d:%s(): " fmt, __FILE__, \
		__LINE__, __func__, ##__VA_ARGS__); \
		abort(); \
		break; \
	case ODP_LOG_UNIMPLEMENTED: \
		fprintf(stderr, \
			"%s:%d:The function %s() is not implemented\n" \
			fmt, __FILE__, __LINE__, __func__, ##__VA_ARGS__); \
		break; \
	default: \
		fprintf(stderr, "Unknown LOG level"); \
		break;\
	} \
} while (0)

/**
 * Printing macro, which prints output when the application
 * calls one of the ODP APIs specifically for dumping internal data.
 */
#define ODP_PRINT(fmt, ...) \
		ODP_LOG(ODP_LOG_PRINT, fmt, ##__VA_ARGS__)

/**
 * Debug printing macro, which prints output when DEBUG flag is set.
 */
#define ODP_DBG(fmt, ...) \
		ODP_LOG(ODP_LOG_DBG, fmt, ##__VA_ARGS__)

/**
 * Print output to stderr (file, line and function).
 */
#define ODP_ERR(fmt, ...) \
		ODP_LOG(ODP_LOG_ERR, fmt, ##__VA_ARGS__)

/**
 * Print output to stderr (file, line and function),
 * then abort.
 */
#define ODP_ABORT(fmt, ...) \
		ODP_LOG(ODP_LOG_ABORT, fmt, ##__VA_ARGS__)

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
