/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * Optional ODP packet helper functions
 */

#ifndef ODP_PACKET_HELPER_H_
#define ODP_PACKET_HELPER_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp.h>

/**
 * Helper: Tests if packet is valid
 *
 * Allows for more thorough checking than "if (pkt == ODP_PACKET_INVALID)"
 *
 * @param pkt  Packet handle
 *
 * @return 1 if valid, otherwise 0
 */
static inline int odp_packet_is_valid(odp_packet_t pkt)
{
	odp_buffer_t buf = odp_buffer_from_packet(pkt);

	return odp_buffer_is_valid(buf);
}

/**
 * Helper: Allocate and initialize a packet buffer from a packet pool
 *
 * @param pool      Pool handle
 *
 * @note  The pool must have been created with 'buf_type=ODP_BUFFER_TYPE_PACKET'
 *
 * @return Packet handle or ODP_PACKET_INVALID
 */
static inline odp_packet_t odp_packet_alloc(odp_buffer_pool_t pool_id)
{
	odp_packet_t pkt;
	odp_buffer_t buf;

	buf = odp_buffer_alloc(pool_id);
	if (odp_unlikely(!odp_buffer_is_valid(buf)))
		return ODP_PACKET_INVALID;

	pkt = odp_packet_from_buffer(buf);
	odp_packet_init(pkt);

	return pkt;
}

/**
 * Helper: Free a packet buffer back into the packet pool
 *
 * @param pkt  Packet handle
 */
static inline void odp_packet_free(odp_packet_t pkt)
{
	odp_buffer_t buf = odp_buffer_from_packet(pkt);

	odp_buffer_free(buf);
}

/**
 * Helper: Packet buffer maximum data size
 *
 * @note odp_packet_buf_size(pkt) != odp_packet_get_len(pkt), the former returns
 *       the max length of the buffer, the latter the size of a received packet.
 *
 * @param pkt  Packet handle
 *
 * @return Packet buffer maximum data size
 */
static inline size_t odp_packet_buf_size(odp_packet_t pkt)
{
	odp_buffer_t buf = odp_buffer_from_packet(pkt);

	return odp_buffer_size(buf);
}

/**
 * Helper: Tests if packet is part of a scatter/gather list
 *
 * @param buf  Packet handle
 *
 * @return 1 if belongs to a scatter list, otherwise 0
 */
static inline int odp_packet_is_scatter(odp_packet_t pkt)
{
	odp_buffer_t buf = odp_buffer_from_packet(pkt);

	return odp_buffer_is_scatter(buf);
}


#ifdef __cplusplus
}
#endif

#endif
