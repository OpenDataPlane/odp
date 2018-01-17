/* Copyright (c) 2017-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP support API
 */

#ifndef ODP_API_SPEC_SUPPORT_H_
#define ODP_API_SPEC_SUPPORT_H_
#include <odp/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @defgroup odp_support ODP support
 *  Common API
 *  @{
 */

/**
 * ODP support support
 *
 * Support levels are specified in the relative order, where ODP_SUPPORT_NO is
 * the lowest level. E.g. if the examined support level is greater than
 * ODP_SUPPORT_NO, the feature is supported in some form.
 */
typedef enum odp_support_t {
	/**
	 * Feature is not supported
	 */
	ODP_SUPPORT_NO = 0,
	/**
	 * Feature is supported
	 */
	ODP_SUPPORT_YES,
	/**
	 * Feature is supported and preferred
	 */
	ODP_SUPPORT_PREFERRED
} odp_support_t;

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
