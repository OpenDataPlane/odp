/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP features.
 * Define various ODP feature sets that can be referenced by other
 * components.
 */

#ifndef ODP_API_FEATURE_H_
#define ODP_API_FEATURE_H_
#include <odp/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/std_types.h>
#include <odp/api/hints.h>
#include <odp/api/thread.h>
#include <odp/api/cpumask.h>

/** @defgroup odp_features ODP_FEATURES
 *  ODP feature definitions
 *  @{
 */

/** Definition of ODP features */
typedef union odp_feature_t {
	/** All features */
	uint32_t all_feat;

	/** Individual feature bits */
	struct {
		uint32_t classification:1;
		uint32_t crypto:1;
		uint32_t ipsec:1;
		uint32_t schedule:1;
		uint32_t time:1;
		uint32_t timer:1;
		uint32_t traffic_mngr:1;
	} feat;
} odp_feature_t;

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
