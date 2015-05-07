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

extern const unsigned int pkt_len_offset;

/**
 * Packet data length
 *
 * Returns sum of data lengths over all packet segments.
 *
 * @param pkt  Packet handle
 *
 * @return Packet data length
 *
 * NOTE: This function is inlined because it's on a performance hot path. As we
 * can't force the application to directly include DPDK headers we have to
 * export this field through pkt_len_offset. It is calculated compile time in
 * odp_packet.c, where we can see the DPDK definitions.
 */
static inline uint32_t odp_packet_len(odp_packet_t pkt)
{
	return *(uint32_t *)((char *)pkt + pkt_len_offset);
}

/**
 * @}
 */

#include <odp/api/packet.h>

#ifdef __cplusplus
}
#endif

#endif /* ODP_PLAT_PACKET_H_ */
