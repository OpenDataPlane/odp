/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2026 Nokia
 */

/**
 * @file
 *
 * ODP queue statistics types
 */

#ifndef ODP_API_SPEC_QUEUE_STATS_TYPES_H_
#define ODP_API_SPEC_QUEUE_STATS_TYPES_H_
#include <odp/visibility_begin.h>

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup odp_queue
 *  @{
 */

/**
 * Queue statistics counters options
 *
 * Statistics counters listed in a bit field structure.
 */
typedef union odp_queue_stats_opt_t {
	/** Option flags */
	struct {
		/** Queue length */
		uint64_t len : 1;

	} bit;

	/** All bits of the bit field structure
	 *
	 *  This field can be used to set/clear all flags, or for bitwise
	 *  operations over the entire structure. */
	uint64_t all;

} odp_queue_stats_opt_t;

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
