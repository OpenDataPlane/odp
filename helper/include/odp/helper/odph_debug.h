/* Copyright (c) 2015-2018, Linaro Limited
 * Copyright (c) 2019, Nokia
 *
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * Helper debug
 */

#ifndef ODPH_DEBUG_H_
#define ODPH_DEBUG_H_

#include <odp/autoheader_external.h>

#include <stdio.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup odph_debug ODPH DEBUG
 *  @{
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
	switch (level) { \
	case ODPH_LOG_ERR: \
		fprintf(stderr, "%s:%d:%s():" fmt, __FILE__, \
		__LINE__, __func__, ##__VA_ARGS__); \
		break; \
	case ODPH_LOG_DBG: \
		if (ODPH_DEBUG_PRINT == 1) \
			fprintf(stderr, "%s:%d:%s():" fmt, __FILE__, \
			__LINE__, __func__, ##__VA_ARGS__); \
		break; \
	case ODPH_LOG_ABORT: \
		fprintf(stderr, "%s:%d:%s(): " fmt, __FILE__, \
		__LINE__, __func__, ##__VA_ARGS__); \
		abort(); \
		break; \
	default: \
		fprintf(stderr, "Unknown LOG level"); \
		break;\
	} \
} while (0)

/**
 * Debug printing macro, which prints output when DEBUG flag is set.
 */
#define ODPH_DBG(fmt, ...) \
		ODPH_LOG(ODPH_LOG_DBG, fmt, ##__VA_ARGS__)

/**
 * Print output to stderr (file, line and function).
 */
#define ODPH_ERR(fmt, ...) \
		ODPH_LOG(ODPH_LOG_ERR, fmt, ##__VA_ARGS__)

/**
 * Print output to stderr (file, line and function),
 * then abort.
 */
#define ODPH_ABORT(fmt, ...) \
		ODPH_LOG(ODPH_LOG_ABORT, fmt, ##__VA_ARGS__)

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
