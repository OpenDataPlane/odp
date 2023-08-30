/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2017-2018 Linaro Limited
 */

/**
 * @file
 *
 * ODP threshold descriptor
 */

#ifndef ODP_API_SPEC_THRESHOLD_H_
#define ODP_API_SPEC_THRESHOLD_H_

#include <odp/visibility_begin.h>
#include <odp/api/std_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Supported threshold types
 *
 * Supported threshold types in a bit field structure.
 */
typedef union odp_threshold_types_t {
	/** bitfields for different threshold types */
	struct {
		/** Percentage of the total size of pool or queue */
		uint8_t percent:1;

		/** Total number of all transient packets */
		uint8_t packet:1;

		/** Total size of all transient packets in bytes */
		uint8_t bytes:1;
	};

	/** All bits of the bit field structure */
	uint8_t all_bits;
} odp_threshold_types_t;

/**
 * ODP Threshold types
 *
 * Different types of threshold measurements
 */
typedef enum odp_threshold_type_t {
	/** Percentage of the total size of pool or queue */
	ODP_THRESHOLD_PERCENT,

	/** Total number of all transient packets */
	ODP_THRESHOLD_PACKET,

	/** Total size of all transient packets in bytes */
	ODP_THRESHOLD_BYTE
} odp_threshold_type_t;

/**
 * ODP Threshold
 *
 * Threshold configuration
 */
typedef struct odp_threshold_t {
	/** Type of threshold */
	odp_threshold_type_t type;

	/** Different threshold types */
	union {
		/** Percentage */
		struct {
			/** Max percentage value */
			odp_percent_t max;

			/** Min percentage value */
			odp_percent_t min;
		} percent;

		/** Packet count */
		struct {
			/** Max packet count */
			uint64_t max;

			/** Min packet count */
			uint64_t min;
		} packet;

		/** Sum of all data bytes of all packets */
		struct {
			/** Max byte count */
			uint64_t max;

			/** Min byte count */
			uint64_t min;
		} byte;
	};
} odp_threshold_t;

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
