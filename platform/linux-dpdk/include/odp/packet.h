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

#ifndef ODP_PLAT_PACKET_H_
#define ODP_PLAT_PACKET_H_

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

extern const unsigned int buf_addr_offset;
extern const unsigned int data_off_offset;
extern const unsigned int pkt_len_offset;
extern const unsigned int seg_len_offset;
extern const unsigned int udata_len_offset;
extern const unsigned int udata_offset;
extern const unsigned int rss_offset;
extern const unsigned int ol_flags_offset;
extern const uint64_t rss_flag;

/*
 * NOTE: These functions are inlined because they are on a performance hot path.
 * As we can't force the application to directly include DPDK headers we have to
 * export these fields through constants calculated compile time in
 * odp_packet.c, where we can see the DPDK definitions.
 *
 */
static inline uint32_t odp_packet_len(odp_packet_t pkt)
{
	return *(uint32_t *)((char *)pkt + pkt_len_offset);
}

static inline uint32_t odp_packet_seg_len(odp_packet_t pkt)
{
	return *(uint16_t *)((char *)pkt + seg_len_offset);
}

static inline void *odp_packet_user_area(odp_packet_t pkt)
{
	return (void *)((char *)pkt + udata_offset);
}

static inline uint32_t odp_packet_user_area_size(odp_packet_t pkt)
{
	return *(uint32_t *)((char *)pkt + udata_len_offset);
}

static inline void *odp_packet_data(odp_packet_t pkt)
{
	char** buf_addr = (char **)((char *)pkt + buf_addr_offset);
	uint16_t data_off = *(uint16_t *)((char *)pkt + data_off_offset);
	return (void *)(*buf_addr + data_off);
}

static inline uint32_t odp_packet_flow_hash(odp_packet_t pkt)
{
	return *(uint32_t *)((char *)pkt + rss_offset);
}

static inline void odp_packet_flow_hash_set(odp_packet_t pkt, uint32_t flow_hash)
{
	*(uint32_t *)((char *)pkt + rss_offset) = flow_hash;
	*(uint64_t *)((char *)pkt + ol_flags_offset) |= rss_flag;
}

/**
 * @}
 */

#include <odp/api/packet.h>

#ifdef __cplusplus
}
#endif

#endif /* ODP_PLAT_PACKET_H_ */
