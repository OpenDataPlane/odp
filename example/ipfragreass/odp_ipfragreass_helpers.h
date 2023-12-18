/* Copyright (c) 2017-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

#ifndef ODP_FRAGREASS_PP_HELPERS_H_
#define ODP_FRAGREASS_PP_HELPERS_H_

#include <odp/helper/ip.h>

/**
 * Generate a random IPv4 UDP packet from the specified parameters
 *
 * @param pool     The pool used to allocate the packet
 * @param ip_id    The IP ID of the packet to be generated
 * @param max_size The maximum size of the generated packet
 * @param min_size The minimum size of the generated packet
 *
 * @return A handle to the generated packet
 */
odp_packet_t pack_udp_ipv4_packet(odp_pool_t pool, odp_u16be_t ip_id,
				  uint32_t max_size, uint32_t min_size);

/**
 * Roughly perform a random shuffle on an array of packets
 *
 * @param packets     A pointer to the packets to shuffle
 * @param num_packets The number of packets in the array
 */
void shuffle(odp_packet_t *packets, int num_packets);

/**
 * Compare the contents of two packets
 *
 * @param a	   The first packet to compare
 * @param b	   The second packet to compare
 * @param offset_a The offset in the first packet to begin comparing at
 * @param offset_b The offset in the second packet to begin comparing at
 * @param length   The number of bytes to compare
 *
 * @return Returns the same values as memcmp (0 if both packets are equal)
 */
int packet_memcmp(odp_packet_t a, odp_packet_t b, uint32_t offset_a,
		  uint32_t offset_b, uint32_t length);

/**
 * Get the smallest of two uint32_t values
 *
 * @param a The first value
 * @param b The second value
 *
 * @return The smallest of the two input values
 */
static inline uint32_t min(uint32_t a, uint32_t b)
{
	return a < b ? a : b;
}

/**
 * Get the largest of two uint32_t values
 *
 * @param a The first value
 * @param b The second value
 *
 * @return The largest of the two input values
 */
static inline uint32_t max(uint32_t a, uint32_t b)
{
	return a > b ? a : b;
}

#endif
