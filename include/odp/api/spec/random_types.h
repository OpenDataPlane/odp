/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2015-2018 Linaro Limited
 * Copyright (c) 2022 Nokia
 */

/**
 * @file
 *
 * ODP random number API
 */

#ifndef ODP_API_SPEC_RANDOM_TYPES_H_
#define ODP_API_SPEC_RANDOM_TYPES_H_
#include <odp/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/std_types.h>

/** @addtogroup odp_random
 *  @{
 */

/**
 * Random kind selector
 *
 * The kind of random denotes the statistical quality of the random data
 * returned. Basic random simply appears uniformly distributed, Cryptographic
 * random is statistically random and suitable for use by cryptographic
 * functions. True random is generated from a hardware entropy source rather
 * than an algorithm and is thus completely unpredictable. These form a
 * hierarchy where higher quality data is presumably more costly to generate
 * than lower quality data.
 */
typedef enum {
	/** Basic random, presumably pseudo-random generated by SW. This
	 *  is the lowest kind of random */
	ODP_RANDOM_BASIC,
	/** Cryptographic quality random */
	ODP_RANDOM_CRYPTO,
	/** True random, generated from a HW entropy source. This is the
	 *  highest kind of random */
	ODP_RANDOM_TRUE,
} odp_random_kind_t;

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
