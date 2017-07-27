/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP Toeplitz hash function
 */

#ifndef ODPH_THASH_H_
#define ODPH_THASH_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <protocols/ip.h>

/** IPv4 tuple
 *
 */
typedef struct thash_ipv4_tuple {
	uint32_t src_addr;
	uint32_t dst_addr;
	union {
		struct {
			uint16_t sport;
			uint16_t dport;
		};
		uint32_t sctp_tag;
	};
} thash_ipv4_tuple_t;

typedef struct thash_ipv6_tuple {
	uint8_t src_addr[16];
	uint8_t dst_addr[16];
	union {
		struct {
			uint16_t sport;
			uint16_t dport;
		};
		uint32_t sctp_tag;
	};
} thash_ipv6_tuple_t;

#define ODP_THASH_V4_L4_LEN (sizeof(thash_ipv4_tuple_t) / 4)

#define ODP_THASH_V4_L3_LEN ((sizeof(thash_ipv4_tuple_t) - \
			sizeof(((thash_ipv4_tuple_t *)0)->sctp_tag)) / 4)

#define ODP_THASH_V6_L4_LEN (sizeof(thash_ipv6_tuple_t) / 4)

#define ODP_THASH_V6_L3_LEN ((sizeof(thash_ipv6_tuple_t) - \
			sizeof(((thash_ipv6_tuple_t *)0)->sctp_tag)) / 4)

typedef union {
	thash_ipv4_tuple_t v4;
	thash_ipv6_tuple_t v6;
} thash_tuple_t;

static inline
void thash_load_ipv6_addr(const _odp_ipv6hdr_t *ipv6,
			  thash_tuple_t *tuple)
{
	int i;

	for (i = 0; i < 4; i++) {
		*((uint32_t *)tuple->v6.src_addr + i) =
		odp_be_to_cpu_32(*((const uint32_t *)ipv6->src_addr.u32 + i));

		*((uint32_t *)tuple->v6.dst_addr + i) =
		odp_be_to_cpu_32(*((const uint32_t *)ipv6->dst_addr.u32 + i));
	}
}

static inline
uint32_t thash_softrss(uint32_t *tuple, uint8_t len,
		       const uint8_t *key)
{
	uint32_t i, j, ret;

	ret = 0;
	for (j = 0; j < len; j++) {
		for (i = 0; i < 32; i++) {
			if (tuple[j] & (1 << (31 - i))) {
				ret ^= odp_cpu_to_be_32(((const uint32_t *)
				key)[j]) << i | (uint32_t)((uint64_t)
				(odp_cpu_to_be_32(((const uint32_t *)key)
				[j + 1])) >> (32 - i));
			}
		}
	}

	return ret;
}

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
