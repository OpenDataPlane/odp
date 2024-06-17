/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2013-2018 Linaro Limited
 * Copyright (c) 2021 ARM Limited
 * Copyright (c) 2021-2024 Nokia
 */

/**
 * @file
 *
 * Common types and definitions for ODP API files.
 *
 */

#ifndef ODP_API_SPEC_STD_TYPES_H_
#define ODP_API_SPEC_STD_TYPES_H_
#include <odp/visibility_begin.h>
/* uint64_t, uint32_t, etc */
#include <stdint.h>
#include <odp/api/align.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @defgroup odp_std ODP STD
 *  @{
 */

/**
 * @typedef odp_bool_t
 * Boolean type
 *
 * odp_bool_t type is provided for backward compatibility and is compliant with the C standard
 * booleans. When assigning values to odp_bool_t variables, any non-zero value is considered true
 * and zero is considered false. C standard 'true' and 'false' macros (C99) / predefined constants
 * (C23) can be used with odp_bool_t variables.
 */

/**
 * Percentage type
 *
 * Use odp_percent_t for specifying fields that are percentages. It is a fixed
 * point integer whose units are expressed as one-hundredth of a percent.
 * Hence 100% is represented as integer value 10000.
 */
typedef uint32_t odp_percent_t;

/** Unaligned uint16_t type */
typedef uint16_t odp_una_u16_t ODP_ALIGNED(1);

/** Unaligned uint32_t type */
typedef uint32_t odp_una_u32_t ODP_ALIGNED(1);

/** Unaligned uint64_t type */
typedef uint64_t odp_una_u64_t ODP_ALIGNED(1);

/**
 * @typedef odp_u128_t
 * 128-bit unsigned integer structure
 */

/**
 * 128-bit unsigned integer structure
 */
typedef struct ODP_ALIGNED(16) odp_u128_s {
	/** 128 bits in various sizes */
	union {
		/** 128 bits as uint64_t words */
		uint64_t u64[2];
		/** 128 bits as uint32_t words */
		uint32_t u32[4];
		/** 128 bits as uint16_t words */
		uint16_t u16[8];
		/** 128 bits as bytes */
		uint8_t  u8[16];
	};
} odp_u128_t;

/**
 * Unsigned 64 bit fractional number
 *
 * The number is composed of integer and fraction parts. The fraction part is composed of
 * two terms: numerator and denominator. Value of the number is sum of the integer and fraction
 * parts: value = integer + numer/denom. When the fraction part is zero, the numerator is zero and
 * the denominator may be zero.
 */
typedef struct odp_fract_u64_t {
		/** Integer part */
		uint64_t integer;

		/** Numerator of the fraction part */
		uint64_t numer;

		/** Denominator of the fraction part. This may be zero when the numerator
		 *  is zero. */
		uint64_t denom;

} odp_fract_u64_t;

/**
 * ODP support
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

/** Definition of ODP features */
typedef union odp_feature_t {
	/** All features */
	uint32_t all_feat;

	/** Individual feature bits */
	struct {
		/** Classifier APIs, e.g., odp_cls_xxx(), odp_cos_xxx() */
		uint32_t cls:1;

		/** Compression APIs, e.g., odp_comp_xxx() */
		uint32_t compress:1;

		/** Crypto APIs, e.g., odp_crypto_xxx() */
		uint32_t crypto:1;

		/** DMA APIs, e.g., odp_dma_xxx() */
		uint32_t dma:1;

		/** IPsec APIs, e.g., odp_ipsec_xxx() */
		uint32_t ipsec:1;

		/** Machine Learning APIs, e.g., odp_ml_xxx() */
		uint32_t ml:1;

		/** Scheduler APIs, e.g., odp_schedule_xxx() */
		uint32_t schedule:1;

		/** Stash APIs, e.g., odp_stash_xxx() */
		uint32_t stash:1;

		/** Time APIs, e.g., odp_time_xxx() */
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
