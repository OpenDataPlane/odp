/* Copyright (c) 2014-2018, Linaro Limited
 * Copyright (c) 2020, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
/**
 * @file
 *
 * ODP Debug internal
 * This file contains implementer support functions for Debug capabilities.
 *
 * @warning These definitions are not part of ODP API, they are for
 * internal use by implementers and should not be called from any other scope.
 */

#ifndef ODP_DEBUG_INTERNAL_H_
#define ODP_DEBUG_INTERNAL_H_

#include <odp/autoheader_external.h>
#include <odp/api/debug.h>
#include <odp_global_data.h>
#include <odp/api/plat/thread_inlines.h>

#include <stdio.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Avoid "ISO C99 requires at least one argument for the "..."  in a variadic
 * macro" errors when building with 'pedantic' option. */
#pragma GCC system_header

/* Debug level configure option. Zero is the highest level. Value of N prints debug messages from
 * level 0 to N. */
#define CONFIG_DEBUG_LEVEL 0

#define _ODP_LOG_FN(level, fmt, ...) \
	do { \
		if (_odp_this_thread && _odp_this_thread->log_fn) \
			_odp_this_thread->log_fn(level, fmt, ##__VA_ARGS__); \
		else \
			odp_global_ro.log_fn(level, fmt, ##__VA_ARGS__); \
	} while (0)

/**
 * Runtime assertion-macro - aborts if 'cond' is false.
 */
#define ODP_ASSERT(cond) \
	do { if ((ODP_DEBUG == 1) && (!(cond))) { \
		ODP_ERR("%s\n", #cond); \
		odp_global_ro.abort_fn(); } \
	} while (0)

/**
 * This macro is used to indicate when a given function is not implemented
 */
#define ODP_UNIMPLEMENTED() \
		_ODP_LOG_FN(ODP_LOG_UNIMPLEMENTED, \
			"%s:%d:The function %s() is not implemented\n", \
			__FILE__, __LINE__, __func__)
/*
 * Print debug message to log, if ODP_DEBUG_PRINT flag is set (ignores CONFIG_DEBUG_LEVEL).
 */
#define ODP_DBG(fmt, ...) \
	do { \
		if (ODP_DEBUG_PRINT == 1) \
			ODP_LOG(ODP_LOG_DBG, fmt, ##__VA_ARGS__);\
	} while (0)

/*
 * Print debug message to log, if ODP_DEBUG_PRINT flag is set and CONFIG_DEBUG_LEVEL is high enough.
 */
#define ODP_DBG_LVL(level, fmt, ...) \
	do { \
		if (ODP_DEBUG_PRINT == 1 && CONFIG_DEBUG_LEVEL >= (level)) \
			ODP_LOG(ODP_LOG_DBG, fmt, ##__VA_ARGS__);\
	} while (0)

/*
 * Same as ODP_DBG_LVL() but does not add file/line/function name prefix
 */
#define ODP_DBG_RAW(level, fmt, ...) \
	do { \
		if (ODP_DEBUG_PRINT == 1 && CONFIG_DEBUG_LEVEL >= (level)) \
			_ODP_LOG_FN(ODP_LOG_DBG, fmt, ##__VA_ARGS__);\
	} while (0)

/**
 * Log error message.
 */
#define ODP_ERR(fmt, ...) \
		ODP_LOG(ODP_LOG_ERR, fmt, ##__VA_ARGS__)

/**
 * Log abort message and then stop execution (by default call abort()).
 * This function should not return.
 */
#define ODP_ABORT(fmt, ...) \
	do { \
		ODP_LOG(ODP_LOG_ABORT, fmt, ##__VA_ARGS__); \
		odp_global_ro.abort_fn(); \
	} while (0)

/**
 * ODP LOG macro.
 */
#define ODP_LOG(level, fmt, ...) \
	_ODP_LOG_FN(level, "%s:%d:%s():" fmt, __FILE__, \
	__LINE__, __func__, ##__VA_ARGS__)

/**
 * Log print message when the application calls one of the ODP APIs
 * specifically for dumping internal data.
 */
#define ODP_PRINT(fmt, ...) \
	_ODP_LOG_FN(ODP_LOG_PRINT, fmt, ##__VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif
