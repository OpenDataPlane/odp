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

#ifdef __cplusplus
}
#endif

#endif
