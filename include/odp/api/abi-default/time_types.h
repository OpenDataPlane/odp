/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2015-2018 Linaro Limited
 */

#ifndef ODP_ABI_TIME_TYPES_H_
#define ODP_ABI_TIME_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/** @addtogroup odp_time
 *  @{
 **/

/**
 * @internal Time structure used for both POSIX timespec and HW counter
 * implementations.
 */
typedef struct odp_time_t {
	/** @internal Variant mappings for time type */
	union {
		/** @internal Used with generic 64 bit operations */
		uint64_t u64;

		/** @internal Nanoseconds */
		uint64_t nsec;

		/** @internal HW timer counter value */
		uint64_t count;

	};
} odp_time_t;

#define ODP_TIME_NULL ((odp_time_t){.u64 = 0})

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
