/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP feature API
 */

#ifndef ODP_API_FEATURE_H_
#define ODP_API_FEATURE_H_
#include <odp/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @defgroup odp_feature ODP feature
 *  Common API
 *  @{
 */

/**
 * ODP feature support
 */
typedef enum odp_feature_t {
	/**
	 * Feature is not supported
	 */
	ODP_FEATURE_UNSUPPORTED,
	/**
	 * Feature is supported
	 */
	ODP_FEATURE_SUPPORTED,
	/**
	 * Feature is supported and preferred
	 */
	ODP_FEATURE_PREFERRED
} odp_feature_t;

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
