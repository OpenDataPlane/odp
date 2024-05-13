/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2017-2018 Linaro Limited
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

#include <odp/api/align.h>
#include <odp/api/byteorder.h>
#include <odp/api/debug.h>

#include <protocols/ip.h>

#include <stdint.h>

/** rss data type */
typedef union {
	uint8_t u8[40];
	uint32_t u32[10];
} rss_key;

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

/** IPv6 tuple */
typedef struct thash_ipv6_tuple {
	_odp_ipv6_addr_t src_addr;
	_odp_ipv6_addr_t dst_addr;
	union {
		struct {
			uint16_t sport;
			uint16_t dport;
		};
		uint32_t sctp_tag;
	};
} thash_ipv6_tuple_t;

/** Thash tuple union */
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
		*(tuple->v6.src_addr.u32 + i) =
		odp_be_to_cpu_32(*(ipv6->src_addr.u32 + i));

		*(tuple->v6.dst_addr.u32 + i) =
		odp_be_to_cpu_32(*(ipv6->dst_addr.u32 + i));
	}
}

static inline
uint32_t thash_softrss(uint32_t *tuple, uint8_t len,
		       const rss_key key)
{
	uint32_t i, j, ret = 0;

	for (j = 0; j < len; j++) {
		for (i = 0; i < 32; i++) {
			if (tuple[j] & (1U << (31 - i))) {
				ret ^= odp_cpu_to_be_32(((const uint32_t *)
				key.u32)[j]) << i | (uint32_t)((uint64_t)
				(odp_cpu_to_be_32(((const uint32_t *)key.u32)
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
