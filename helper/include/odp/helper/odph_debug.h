/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2015-2018 Linaro Limited
 * Copyright (c) 2019 Nokia
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
 * Assert macro for applications and helper code
 *
 * No code is generated when ODPH_DEBUG=0. Prints error message and aborts when
 * ODPH_DEBUG=1 and 'cond' is false.
 */
#define ODPH_ASSERT(cond) \
	do { \
		if ((ODPH_DEBUG == 1) && (!(cond))) { \
			fprintf(stderr, "%s:%d:%s(): %s\n", __FILE__, __LINE__,\
				__func__, #cond); \
			abort(); \
		} \
	} while (0)

/**
 * log level.
 */
typedef enum odph_log_level {
	ODPH_LOG_DBG,
	ODPH_LOG_ERR,
	ODPH_LOG_ABORT
} odph_log_level_e;

/**
 * default LOG macro.
 */
#define ODPH_LOG(level, fmt, ...) \
do { \
	if (level != ODPH_LOG_DBG || ODPH_DEBUG_PRINT == 1) \
		fprintf(stderr, "%s:%d:%s(): " fmt, __FILE__, \
		__LINE__, __func__, ##__VA_ARGS__); \
	if (level == ODPH_LOG_ABORT) \
		abort(); \
} while (0)

/**
 * Debug printing macro, which prints output when DEBUG flag is set.
 */
#define ODPH_DBG(...) \
	do { \
		__extension__ ({ \
			ODPH_LOG(ODPH_LOG_DBG, ##__VA_ARGS__); \
		}); \
	} while (0)

/**
 * Print output to stderr (file, line and function).
 */
#define ODPH_ERR(...) \
	do { \
		__extension__ ({ \
			ODPH_LOG(ODPH_LOG_ERR, ##__VA_ARGS__); \
		}); \
	} while (0)

/**
 * Print output to stderr (file, line and function),
 * then abort.
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
