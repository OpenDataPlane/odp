/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/**
 * @file
 *
 * ODP packet descriptor
 */

#ifndef ODP_PLAT_PACKET_FLAGS_H_
#define ODP_PLAT_PACKET_FLAGS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/std_types.h>
#include <odp/plat/event_types.h>
#include <odp/plat/packet_io_types.h>
#include <odp/plat/packet_types.h>
#include <odp/plat/buffer_types.h>
#include <odp/plat/pool_types.h>

/** @ingroup odp_packet
 *  @{
 */

extern const unsigned int ol_flags_offset;
extern const uint64_t rss_flag;

/*
 * NOTE: These functions are inlined because they are on a performance hot path.
 * As we can't force the application to directly include DPDK headers we have to
 * export these fields through constants calculated compile time in
 * odp_packet.c, where we can see the DPDK definitions.
 *
 */

static inline int odp_packet_has_flow_hash(odp_packet_t pkt) {
	return *(uint64_t *)((char *)pkt + ol_flags_offset) & rss_flag;
}

static inline void odp_packet_has_flow_hash_clr(odp_packet_t pkt) {
	*(uint64_t *)((char *)pkt + ol_flags_offset) &= ~rss_flag;
}

/**
 * @}
 */

#include <odp/api/packet_flags.h>

#ifdef __cplusplus
}
#endif

#endif /* ODP_PLAT_PACKET_FLAGS_H_ */
