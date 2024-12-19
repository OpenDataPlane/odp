/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2015-2018 Linaro Limited
 * Copyright (c) 2019-2024 Nokia
 */

/**
 * @file
 *
 * Helper debug
 */

#ifndef ODPH_DEBUG_H_
#define ODPH_DEBUG_H_

#include <odp/helper/autoheader_external.h>

#include <stdio.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#pragma GCC diagnostic push

#ifdef __clang__
#pragma GCC diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"
#endif

/**
 * @defgroup odph_debug ODPH DEBUG
 * Debug logging
 *
 * @{
 */

/**
 * Log level
 */
typedef enum odph_log_level {
	ODPH_LOG_DBG,
	ODPH_LOG_ERR,
	ODPH_LOG_ABORT
} odph_log_level_e;

/**
 * Output a log with file, line and function information.
 *
 * Outputs a log if level is not ODPH_LOG_DBG, or if ODPH_DEBUG_PRINT is enabled
 * (--enable-helper-debug-print configure option). Calls odp_log_fn_get() to get
 * the current log function. If no log function is set, prints to stderr.
 *
 * Additionally, if level is ODPH_LOG_ABORT, calls odp_abort_fn_get() to get the
 * current abort function and calls it to abort the application. If no abort
 * function is set, calls abort().
 */
#define ODPH_LOG(level, fmt, ...) \
do { \
	if (level != ODPH_LOG_DBG || ODPH_DEBUG_PRINT == 1) { \
		const odp_log_func_t fn = odp_log_fn_get(); \
		if (fn) { \
			const odp_log_level_t lv = level == ODPH_LOG_ABORT ? ODP_LOG_ABORT : \
						   level == ODPH_LOG_ERR ? ODP_LOG_ERR : \
						   ODP_LOG_DBG; \
			fn(lv, "%s:%d:%s(): " fmt, __FILE__, __LINE__, __func__, ##__VA_ARGS__); \
		} else { \
			fprintf(stderr, "%s:%d:%s(): " fmt, __FILE__, __LINE__, __func__, \
				##__VA_ARGS__); \
		} \
	} \
	if (level == ODPH_LOG_ABORT) { \
		odp_abort_func_t fn = odp_abort_fn_get(); \
		if (fn) \
			fn(); \
		else \
			abort(); \
	} \
} while (0)

/**
 * Runtime assertion macro. No code is generated when ODPH_DEBUG=0. Prints error
 * message and aborts when ODPH_DEBUG=1 (--enable-helper-debug configure option)
 * and 'cond' is false.
 */
#define ODPH_ASSERT(cond) \
	do { \
		if ((ODPH_DEBUG == 1) && (!(cond))) \
			ODPH_LOG(ODPH_LOG_ABORT, "%s\n", #cond); \
	} while (0)

/**
 * Debug log macro. Outputs a log with level ODPH_LOG_DBG. See ODPH_LOG() for
 * more information.
 */
#define ODPH_DBG(...) \
	do { \
		__extension__ ({ \
			ODPH_LOG(ODPH_LOG_DBG, ##__VA_ARGS__); \
		}); \
	} while (0)

/**
 * Error log macro. Outputs a log with level ODPH_LOG_ERR. See ODPH_LOG() for
 * more information.
 */
#define ODPH_ERR(...) \
	do { \
		__extension__ ({ \
			ODPH_LOG(ODPH_LOG_ERR, ##__VA_ARGS__); \
		}); \
	} while (0)

/**
 * Abort macro. Outputs a log with level ODPH_LOG_ABORT and aborts the
 * application. See ODPH_LOG() for more information.
 */
#define ODPH_ABORT(...) \
	do { \
		__extension__ ({ \
			ODPH_LOG(ODPH_LOG_ABORT, ##__VA_ARGS__); \
		}); \
	} while (0)

/**
 * @}
 */

#pragma GCC diagnostic pop

#ifdef __cplusplus
}
#endif

#endif
