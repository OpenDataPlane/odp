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

/** @defgroup odp_features ODP_FEATURE
 *  ODP feature definitions
 *  @{
 */

/** Definition of ODP features */
typedef union odp_feature_t {
	/** All features */
	uint32_t all_feat;

	/** Individual feature bits */
	struct {
		/** Classifier APIs, e.g., odp_cls_xxx(), odp_cos_xxx() */
		uint32_t cls:1;

		/** Crypto APIs, e.g., odp_crypto_xxx() */
		uint32_t crypto:1;

		/** IPsec APIs, e.g., odp_ipsec_xxx() */
		uint32_t ipsec:1;

		/** Scheduler APIs, e.g., odp_schedule_xxx() */
		uint32_t schedule:1;

		/** Time APIs are, e.g., odp_time_xxx() */
		uint32_t time:1;

		/** Timer APIs, e.g., odp_timer_xxx(), odp_timeout_xxx()  */
		uint32_t timer:1;

		/** Traffic Manager APIs, e.g., odp_tm_xxx() */
		uint32_t tm:1;
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
