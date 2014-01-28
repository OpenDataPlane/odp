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


/**
 * ODP packet descriptor
 */
typedef uint32_t odp_packet_t;

#define ODP_PACKET_INVALID ODP_BUFFER_INVALID

/**
 * Initialize the packet
 *
 * Needs to be called if the user allocates a packet buffer, i.e. the packet
 * has not been received from I/O through ODP.
 *
 * @param pkt  Packet handle
 */
void odp_packet_init(odp_packet_t pkt);

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
 * Get pointer to the start of the packet buffer
 *
 * The start address of the packet buffer is not necessarily the same as the
 * start address of a received frame, e.g. an eth frame may be offset by 2 or 6
 * bytes to ensure 32 or 64-bit alignment of the IP header.
 * Use odp_packet_l2(pkt) to get the start address of a received frame.
 *
 * @param pkt  Packet handle
 *
 * @return  Pointer to the start of the packet buffer
 *
 * @see odp_packet_l2()
 */
uint8_t *odp_packet_buf_addr(odp_packet_t pkt);


/**
 * Get pointer to the start of the L2 frame
 *
 * The L2 frame header address is not necessarily the same as the address of the
 * packet buffer, see odp_packet_buf_addr()
 *
 * @param pkt  Packet handle
 *
 * @return  Pointer to L2 header
 *
 * @see odp_packet_buf_addr()
 */
uint8_t *odp_packet_l2(odp_packet_t pkt);

/**
 * Return the byte offset from the packet buffer to the L2 frame
 *
 * @param pkt  Packet handle
 *
 * @return  L2 byte offset
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
 * @return  Pointer to L3 packet
 *
 */
uint8_t *odp_packet_l3(odp_packet_t pkt);

/**
 * Return the byte offset from the packet buffer to the L3 packet
 *
 * @param pkt  Packet handle
 *
 * @return  L3 byte offset
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
 * @return  Pointer to L4 packet
 *
 */
uint8_t *odp_packet_l4(odp_packet_t pkt);

/**
 * Return the byte offset from the packet buffer to the L4 packet
 *
 * @param pkt  Packet handle
 *
 * @return  L4 byte offset
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

#ifdef __cplusplus
}
#endif

#endif







