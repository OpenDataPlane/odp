/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP packet descriptor
 */

#ifndef ODP_PACKET_H_
#define ODP_PACKET_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp_buffer.h>
#include <odp_platform_types.h>


/*
 * Packet API v0.5 notes
 * - Push/pull operations only on packet level
 * - Push/pull within limits of segment headroom/tailroom/data lengths
 * - Segment data length must be always at least one byte (i.e. there are no
 *   empty segments)
 * - Head/tailroom content belong to packet content (in addition to data
 *   and meta-data) and thus is preserved over packet ownership changes.
 * - _addr refer to a fixed address, which operations do not modify
 * - _ptr refer to pointer to data, which may be modified by operations
 */


/*
 *
 * Alloc and free
 * ********************************************************
 *
 */

/**
 * Allocate a packet from a buffer pool
 *
 * Allocates a packet of the requested length from the specified buffer pool.
 * Pool must have been created with buffer type ODP_BUFFER_TYPE_PACKET. The
 * packet is initialized with data pointers and lengths set according to the
 * specified len, and the default headroom and tailroom length settings. All
 * other packet metadata are set to their default values.
 *
 * @param pool          Pool handle
 * @param len           Packet data length
 *
 * @return Handle of allocated packet
 * @retval ODP_PACKET_INVALID  Packet could not be allocated
 *
 * @note The default headroom and tailroom used for packets is specified by
 * the ODP_CONFIG_PACKET_HEADROOM and ODP_CONFIG_PACKET_TAILROOM defines in
 * odp_config.h.
 */
odp_packet_t odp_packet_alloc(odp_buffer_pool_t pool, uint32_t len);

/**
 * Free packet
 *
 * Frees the packet into the buffer pool it was allocated from.
 *
 * @param pkt           Packet handle
 */
void odp_packet_free(odp_packet_t pkt);

/**
 * Reset the packet
 *
 * Resets all packet meta-data to their default values. Packet length is used
 * to initialize pointers and lengths. It must be less than the total buffer
 * length of the packet minus the default headroom length. Packet is not
 * modified on failure.
 *
 * @param pkt           Packet handle
 * @param len           Packet data length
 *
 * @retval 0 Success
 * @retval Non-zero Failure
 *
 * @see odp_packet_buf_len()
 */
int odp_packet_reset(odp_packet_t pkt, uint32_t len);

/**
 * Convert from packet handle to buffer handle
 *
 * @param buf  Buffer handle
 *
 * @return Packet handle
 */
odp_packet_t odp_packet_from_buffer(odp_buffer_t buf);

/**
 * Convert from buffer handle to packet handle
 *
 * @param pkt  Packet handle
 *
 * @return Buffer handle
 */
odp_buffer_t odp_buffer_from_packet(odp_packet_t pkt);

/**
 * Set the packet length
 *
 * @param pkt  Packet handle
 * @param len  Length of packet in bytes
 */
void odp_packet_set_len(odp_packet_t pkt, size_t len);

/**
 * Get the packet length
 *
 * @param pkt  Packet handle
 *
 * @return   Packet length in bytes
 */
size_t odp_packet_get_len(odp_packet_t pkt);

/**
 * Set packet user context
 *
 * @param buf      Packet handle
 * @param ctx      User context
 *
 */
void odp_packet_set_ctx(odp_packet_t buf, const void *ctx);

/**
 * Get packet user context
 *
 * @param buf      Packet handle
 *
 * @return User context
 */
void *odp_packet_get_ctx(odp_packet_t buf);

/**
 * Packet buffer start address
 *
 * Returns a pointer to the start of the packet buffer. The address is not
 * necessarily the same as packet data address. E.g. on a received Ethernet
 * frame, the protocol header may start 2 or 6 bytes within the buffer to
 * ensure 32 or 64-bit alignment of the IP header.
 *
 * Use odp_packet_l2(pkt) to get the start address of a received valid frame
 * or odp_packet_data(pkt) to get the current packet data address.
 *
 * @param pkt  Packet handle
 *
 * @return  Pointer to the start of the packet buffer
 *
 * @see odp_packet_l2(), odp_packet_data()
 */
uint8_t *odp_packet_addr(odp_packet_t pkt);

/**
 * Packet buffer maximum data size
 *
 * @note odp_packet_buf_size(pkt) != odp_packet_get_len(pkt), the former returns
 *       the max length of the buffer, the latter the size of a received packet.
 *
 * @param pkt  Packet handle
 *
 * @return Packet buffer maximum data size
 */
size_t odp_packet_buf_size(odp_packet_t pkt);

/**
 * Packet data address
 *
 * Returns the current packet data address. When a packet is received from
 * packet input, the data address points to the first byte of the packet.
 *
 * @param pkt  Packet handle
 *
 * @return  Pointer to the packet data
 *
 * @see odp_packet_l2(), odp_packet_addr()
 */
uint8_t *odp_packet_data(odp_packet_t pkt);

/**
 * Get pointer to the start of the L2 frame
 *
 * The L2 frame header address is not necessarily the same as the address of the
 * packet buffer, see odp_packet_addr()
 *
 * @param pkt  Packet handle
 *
 * @return  Pointer to L2 header or NULL if not found
 *
 * @see odp_packet_addr(), odp_packet_data()
 */
uint8_t *odp_packet_l2(odp_packet_t pkt);

/**
 * Return the byte offset from the packet buffer to the L2 frame
 *
 * @param pkt  Packet handle
 *
 * @return  L2 byte offset or ODP_PACKET_OFFSET_INVALID if not found
 */
size_t odp_packet_l2_offset(odp_packet_t pkt);

/**
 * Set the byte offset to the L2 frame
 *
 * @param pkt     Packet handle
 * @param offset  L2 byte offset
 */
void odp_packet_set_l2_offset(odp_packet_t pkt, size_t offset);


/**
 * Get pointer to the start of the L3 packet
 *
 * @param pkt  Packet handle
 *
 * @return  Pointer to L3 packet or NULL if not found
 *
 */
uint8_t *odp_packet_l3(odp_packet_t pkt);

/**
 * Return the byte offset from the packet buffer to the L3 packet
 *
 * @param pkt  Packet handle
 *
 * @return  L3 byte offset or ODP_PACKET_OFFSET_INVALID if not found
 */
size_t odp_packet_l3_offset(odp_packet_t pkt);

/**
 * Set the byte offset to the L3 packet
 *
 * @param pkt     Packet handle
 * @param offset  L3 byte offset
 */
void odp_packet_set_l3_offset(odp_packet_t pkt, size_t offset);


/**
 * Get pointer to the start of the L4 packet
 *
 * @param pkt  Packet handle
 *
 * @return  Pointer to L4 packet or NULL if not found
 *
 */
uint8_t *odp_packet_l4(odp_packet_t pkt);

/**
 * Return the byte offset from the packet buffer to the L4 packet
 *
 * @param pkt  Packet handle
 *
 * @return  L4 byte offset or ODP_PACKET_OFFSET_INVALID if not found
 */
size_t odp_packet_l4_offset(odp_packet_t pkt);

/**
 * Set the byte offset to the L4 packet
 *
 * @param pkt     Packet handle
 * @param offset  L4 byte offset
 */
void odp_packet_set_l4_offset(odp_packet_t pkt, size_t offset);

/**
 * Print (debug) information about the packet
 *
 * @param pkt  Packet handle
 */
void odp_packet_print(odp_packet_t pkt);

/**
 * Copy contents and metadata from pkt_src to pkt_dst
 * Useful when creating copies of packets
 *
 * @param pkt_dst Destination packet
 * @param pkt_src Source packet
 *
 * @return 0 if successful
 */
int odp_packet_copy(odp_packet_t pkt_dst, odp_packet_t pkt_src);

/**
 * Tests if packet is valid
 *
 * Allows for more thorough checking than "if (pkt == ODP_PACKET_INVALID)"
 *
 * @param pkt  Packet handle
 *
 * @return 1 if valid, otherwise 0
 */
int odp_packet_is_valid(odp_packet_t pkt);

#ifdef __cplusplus
}
#endif

#endif
