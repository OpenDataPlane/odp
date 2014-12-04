/* Copyright (c) 2014, Linaro Limited
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

#ifdef __cplusplus
extern "C" {
#endif

#include <odp_debug.h>

/**
 * This macro is used to indicate when a given function is not implemented
 */
#define ODP_UNIMPLEMENTED() \
		odp_override_log(ODP_LOG_UNIMPLEMENTED, \
			"%s:%d:The function %s() is not implemented\n", \
			__FILE__, __LINE__, __func__)
/**
 * Log debug message if ODP_DEBUG_PRINT flag is set.
 */
#define ODP_DBG(fmt, ...) \
	do { \
		if (ODP_DEBUG_PRINT == 1) \
			ODP_LOG(ODP_LOG_DBG, fmt, ##__VA_ARGS__);\
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
		abort(); \
	} while (0)

#ifdef __cplusplus
}
#endif

#endif
