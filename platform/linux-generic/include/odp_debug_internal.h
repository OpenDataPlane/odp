/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2014-2018 Linaro Limited
 * Copyright (c) 2020-2022 Nokia
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

#include <odp/api/plat/debug_inlines.h>

#include <stdio.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#pragma GCC diagnostic push

#ifdef __clang__
#pragma GCC diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"
#endif

/* Debug level configure option. Zero is the highest level. Value of N prints debug messages from
 * level 0 to N. */
#define CONFIG_DEBUG_LEVEL 0

/**
 * This macro is used to indicate when a given function is not implemented
 */
#define ODP_UNIMPLEMENTED() \
		_ODP_LOG_FN(ODP_LOG_UNIMPLEMENTED, \
			"%s:%d:The function %s() is not implemented\n", \
			__FILE__, __LINE__, __func__)

/*
 * Print debug message to log, if ODP_DEBUG_PRINT flag is set and CONFIG_DEBUG_LEVEL is high enough.
 */
#define ODP_DBG_LVL(level, ...) \
	do { \
		if (ODP_DEBUG_PRINT == 1 && CONFIG_DEBUG_LEVEL >= (level)) \
			__extension__ ({ \
				_ODP_LOG(ODP_LOG_DBG, "DBG", ##__VA_ARGS__); \
			}); \
	} while (0)

/*
 * Same as ODP_DBG_LVL() but does not add file/line/function name prefix
 */
#define ODP_DBG_RAW(level, ...) \
	do { \
		if (ODP_DEBUG_PRINT == 1 && CONFIG_DEBUG_LEVEL >= (level)) \
			_ODP_LOG_FN(ODP_LOG_DBG, ##__VA_ARGS__); \
	} while (0)

#pragma GCC diagnostic pop

#ifdef __cplusplus
}
#endif

#endif
