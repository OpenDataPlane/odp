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

/** @defgroup odp_packet ODP PACKET
 *  Operations on a packet.
 *  @{
 */


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
 * Reset packet
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
 * Convert a buffer handle to a packet handle
 *
 * @param buf  Buffer handle
 *
 * @return Packet handle
 */
odp_packet_t odp_packet_from_buffer(odp_buffer_t buf);

/**
 * Convert a packet handle to a buffer handle
 *
 * @param pkt  Packet handle
 *
 * @return Buffer handle
 */
odp_buffer_t odp_packet_to_buffer(odp_packet_t pkt);


/*
 *
 * Pointers and lengths
 * ********************************************************
 *
 */

/**
 * Packet head address
 *
 * Returns start address of the first segment. Packet level headroom starts
 * from here. Use odp_packet_data() or odp_packet_l2_ptr() to return the
 * packet data start address.
 *
 * @param pkt  Packet handle
 *
 * @return Pointer to the start address of the first packet segment
 *
 * @see odp_packet_data(), odp_packet_l2_ptr(), odp_packet_headroom()
 */
void *odp_packet_head(odp_packet_t pkt);

/**
 * Total packet buffer length
 *
 * Returns sum of buffer lengths over all packet segments.
 *
 * @param pkt  Packet handle
 *
 * @return  Total packet buffer length in bytes
 *
 * @see odp_packet_reset()
 */
uint32_t odp_packet_buf_len(odp_packet_t pkt);

/**
 * Packet data pointer
 *
 * Returns the current packet data pointer. When a packet is received
 * from packet input, this points to the first byte of the received
 * packet. Packet level offsets are calculated relative to this position.
 *
 * User can adjust the data pointer with head_push/head_pull (does not modify
 * segmentation) and add_data/rem_data calls (may modify segmentation).
 *
 * @param pkt  Packet handle
 *
 * @return  Pointer to the packet data
 *
 * @see odp_packet_l2_ptr(), odp_packet_seg_len()
 */
void *odp_packet_data(odp_packet_t pkt);

/**
 * Packet segment data length
 *
 * Returns number of data bytes following the current data pointer
 * (odp_packet_data()) location in the segment.
 *
 * @param pkt  Packet handle
 *
 * @return  Segment data length in bytes (pointed by odp_packet_data())
 *
 * @see odp_packet_data()
 */
uint32_t odp_packet_seg_len(odp_packet_t pkt);

/**
 * Packet data length
 *
 * Returns sum of data lengths over all packet segments.
 *
 * @param pkt  Packet handle
 *
 * @return Packet data length
 */
uint32_t odp_packet_len(odp_packet_t pkt);

/**
 * Packet headroom length
 *
 * Returns the current packet level headroom length.
 *
 * @param pkt  Packet handle
 *
 * @return Headroom length
 */
uint32_t odp_packet_headroom(odp_packet_t pkt);

/**
 * Packet tailroom length
 *
 * Returns the current packet level tailroom length.
 *
 * @param pkt  Packet handle
 *
 * @return Tailroom length
 */
uint32_t odp_packet_tailroom(odp_packet_t pkt);

/**
 * Packet tailroom pointer
 *
 * Returns pointer to the start of the current packet level tailroom.
 *
 * User can adjust the tail pointer with tail_push/tail_pull (does not modify
 * segmentation) and add_data/rem_data calls (may modify segmentation).
 *
 * @param pkt  Packet handle
 *
 * @return  Tailroom pointer
 *
 * @see odp_packet_tailroom()
 */
void *odp_packet_tail(odp_packet_t pkt);

/**
 * Push out packet head
 *
 * Increase packet data length by moving packet head into packet headroom.
 * Packet headroom is decreased with the same amount. The packet head may be
 * pushed out up to 'headroom' bytes. Packet is not modified if there's not
 * enough headroom space.
 *
 * odp_packet_xxx:
 * seg_len  += len
 * len      += len
 * headroom -= len
 * data     -= len
 *
 * Operation does not modify packet segmentation or move data. Handles and
 * pointers remain valid. User is responsible to update packet meta-data
 * offsets when needed.
 *
 * @param pkt  Packet handle
 * @param len  Number of bytes to push the head (0 ... headroom)
 *
 * @return The new data pointer
 * @retval NULL  Requested offset exceeds available headroom
 *
 * @see odp_packet_headroom(), odp_packet_pull_head()
 */
void *odp_packet_push_head(odp_packet_t pkt, uint32_t len);

/**
 * Pull in packet head
 *
 * Decrease packet data length by removing data from the head of the packet.
 * Packet headroom is increased with the same amount. Packet head may be pulled
 * in up to seg_len - 1 bytes (i.e. packet data pointer must stay in the
 * first segment). Packet is not modified if there's not enough data.
 *
 * odp_packet_xxx:
 * seg_len  -= len
 * len      -= len
 * headroom += len
 * data     += len
 *
 * Operation does not modify packet segmentation or move data. Handles and
 * pointers remain valid. User is responsible to update packet meta-data
 * offsets when needed.
 *
 * @param pkt  Packet handle
 * @param len  Number of bytes to pull the head (0 ... seg_len - 1)
 *
 * @return The new data pointer, or NULL in case of an error.
 * @retval NULL  Requested offset exceeds packet segment length
 *
 * @see odp_packet_seg_len(), odp_packet_push_head()
 */
void *odp_packet_pull_head(odp_packet_t pkt, uint32_t len);

/**
 * Push out packet tail
 *
 * Increase packet data length by moving packet tail into packet tailroom.
 * Packet tailroom is decreased with the same amount. The packet tail may be
 * pushed out up to 'tailroom' bytes. Packet is not modified if there's not
 * enough tailroom.
 *
 * last_seg:
 * data_len += len
 *
 * odp_packet_xxx:
 * len      += len
 * tail     += len
 * tailroom -= len
 *
 * Operation does not modify packet segmentation or move data. Handles,
 * pointers and offsets remain valid.
 *
 * @param pkt  Packet handle
 * @param len  Number of bytes to push the tail (0 ... tailroom)
 *
 * @return The old tail pointer
 * @retval NULL  Requested offset exceeds available tailroom
 *
 * @see odp_packet_tailroom(), odp_packet_pull_tail()
 */
void *odp_packet_push_tail(odp_packet_t pkt, uint32_t len);

/**
 * Pull in packet tail
 *
 * Decrease packet data length by removing data from the tail of the packet.
 * Packet tailroom is increased with the same amount. Packet tail may be pulled
 * in up to last segment data_len - 1 bytes. (i.e. packet tail must stay in the
 * last segment). Packet is not modified if there's not enough data.
 *
 * last_seg:
 * data_len -= len
 *
 * odp_packet_xxx:
 * len      -= len
 * tail     -= len
 * tailroom += len
 *
 * Operation does not modify packet segmentation or move data. Handles and
 * pointers remain valid. User is responsible to update packet meta-data
 * offsets when needed.
 *
 * @param pkt  Packet handle
 * @param len  Number of bytes to pull the tail (0 ... last_seg:data_len - 1)
 *
 * @return The new tail pointer
 * @retval NULL  The specified offset exceeds allowable data length
 */
void *odp_packet_pull_tail(odp_packet_t pkt, uint32_t len);
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
 * User context pointer
 *
 * Return previously stored user context pointer.
 *
 * @param pkt  Packet handle
 *
 * @return User context pointer
 */
void *odp_packet_user_ptr(odp_packet_t pkt);

/**
 * Set user context pointer
 *
 * Each packet has room for a user defined context. The context can be stored
 * either as a pointer OR as a uint64_t value, but not both at the same time.
 * The latest context set operation determines which one has been stored.
 *
 * @param pkt  Packet handle
 * @param ctx  User context pointer
 */
void odp_packet_user_ptr_set(odp_packet_t pkt, const void *ctx);

/**
 * User context data (uint64_t)
 *
 * Return previously stored user context uint64_t value.
 *
 * @param pkt  Packet handle
 *
 * @return User context data
 */
uint64_t odp_packet_user_u64(odp_packet_t pkt);

/**
 * Set user context data (uint64_t)
 *
 * Each packet has room for a user defined context. The context can be stored
 * either as a pointer OR as a uint64_t value, but not both at the same time.
 * The latest context set operation determines which one has been stored.
 *
 * @param pkt  Packet handle
 * @param ctx  User context data
 */
void odp_packet_user_u64_set(odp_packet_t pkt, uint64_t ctx);

/**
 * Layer 2 start pointer
 *
 * Returns pointer to the start of the layer 2 header. Optionally, outputs
 * number of data bytes in the segment following the pointer.
 *
 * @param      pkt      Packet handle
 * @param[out] len      Number of data bytes remaining in the segment (output).
 *                      Ignored when NULL.
 *
 * @return  Layer 2 start pointer, or offset 0 by default
 *
 * @see odp_packet_l2_offset(), odp_packet_l2_offset_set()
 */
void *odp_packet_l2_ptr(odp_packet_t pkt, uint32_t *len);

/**
 * Layer 2 start offset
 *
 * Returns offset to the start of the layer 2 header. The offset is calculated
 * from the current odp_packet_data() position in bytes.
 *
 * User is responsible to update the offset when modifying the packet data
 * pointer position.
 *
 * @param pkt  Packet handle
 *
 * @return  Layer 2 start offset
 */
uint32_t odp_packet_l2_offset(odp_packet_t pkt);

/**
 * Set layer 2 start offset
 *
 * Set offset to the start of the layer 2 header. The offset is calculated from
 * the current odp_packet_data() position in bytes. Offset must not exceed
 * packet data length. Packet is not modified on an error.
 *
 * @param pkt     Packet handle
 * @param offset  Layer 2 start offset (0 ... odp_packet_len()-1)
 *
 * @retval 0 Success
 * @retval Non-zero Failure
 */
int odp_packet_l2_offset_set(odp_packet_t pkt, uint32_t offset);

/**
 * Layer 3 start pointer
 *
 * Returns pointer to the start of the layer 3 header. Optionally, outputs
 * number of data bytes in the segment following the pointer.
 *
 * @param      pkt      Packet handle
 * @param[out] len      Number of data bytes remaining in the segment (output).
 *                      Ignored when NULL.
 *
 * @return  Layer 3 start pointer, or NULL
 *
 * @see odp_packet_l3_offset(), odp_packet_l3_offset_set()
 */
void *odp_packet_l3_ptr(odp_packet_t pkt, uint32_t *len);

/**
 * Layer 3 start offset
 *
 * Returns offset to the start of the layer 3 header. The offset is calculated
 * from the current odp_packet_data() position in bytes.
 *
 * User is responsible to update the offset when modifying the packet data
 * pointer position.
 *
 * @param pkt  Packet handle
 *
 * @return  Layer 3 start offset or ODP_PACKET_OFFSET_INVALID if not found
 */
uint32_t odp_packet_l3_offset(odp_packet_t pkt);

/**
 * Set layer 3 start offset
 *
 * Set offset to the start of the layer 3 header. The offset is calculated from
 * the current odp_packet_data() position in bytes. Offset must not exceed
 * packet data length. Packet is not modified on an error.
 *
 * @param pkt     Packet handle
 * @param offset  Layer 3 start offset (0 ... odp_packet_len()-1)
 *
 * @retval 0 Success
 * @retval Non-zero Failure
 */
int odp_packet_l3_offset_set(odp_packet_t pkt, uint32_t offset);

/**
 * Layer 4 start pointer
 *
 * Returns pointer to the start of the layer 4 header. Optionally, outputs
 * number of data bytes in the segment following the pointer.
 *
 * @param      pkt      Packet handle
 * @param[out] len      Number of data bytes remaining in the segment (output).
 *                      Ignored when NULL.
 *
 * @return  Layer 4 start pointer, or NULL
 *
 * @see odp_packet_l4_offset(), odp_packet_l4_offset_set()
 */
void *odp_packet_l4_ptr(odp_packet_t pkt, uint32_t *len);

/**
 * Layer 4 start offset
 *
 * Returns offset to the start of the layer 4 header. The offset is calculated
 * from the current odp_packet_data() position in bytes.
 *
 * User is responsible to update the offset when modifying the packet data
 * pointer position.
 *
 * @param pkt  Packet handle
 *
 * @return  Layer 4 start offset or ODP_PACKET_OFFSET_INVALID if not found
 */
uint32_t odp_packet_l4_offset(odp_packet_t pkt);

/**
 * Set layer 4 start offset
 *
 * Set offset to the start of the layer 4 header. The offset is calculated from
 * the current odp_packet_data() position in bytes. Offset must not exceed
 * packet data length. Packet is not modified on an error.
 *
 * @param pkt     Packet handle
 * @param offset  Layer 4 start offset (0 ... odp_packet_len()-1)
 *
 * @retval 0 Success
 * @retval Non-zero Failure
 */
int odp_packet_l4_offset_set(odp_packet_t pkt, uint32_t offset);

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
 * Tests if packet is segmented (a scatter/gather list)
 *
 * @param pkt  Packet handle
 *
 * @return Non-zero if packet is segmented, otherwise 0
 */
int odp_packet_is_segmented(odp_packet_t pkt);

/**
 * Segment count
 *
 * Returns number of segments in the packet. A packet has always at least one
 * segment (the packet buffer itself).
 *
 * @param pkt  Packet handle
 *
 * @return Segment count
 */
int odp_packet_seg_count(odp_packet_t pkt);

/**
 * Get segment by index
 *
 * @param pkt   Packet handle
 * @param index Segment index (0 ... seg_count-1)
 *
 * @return Segment handle, or ODP_PACKET_SEG_INVALID on an error
 */
odp_packet_seg_t odp_packet_seg(odp_packet_t pkt, int index);

/**
 * Get next segment
 *
 * @param pkt   Packet handle
 * @param seg   Current segment handle
 *
 * @return Handle to next segment, or ODP_PACKET_SEG_INVALID on an error
 */
odp_packet_seg_t odp_packet_seg_next(odp_packet_t pkt, odp_packet_seg_t seg);

/**
 * Segment info
 *
 * Copies segment parameters into the info structure.
 *
 * @param pkt  Packet handle
 * @param seg  Segment handle
 * @param info Pointer to segment info structure
 *
 * @return 0 if successful, otherwise non-zero
 */
int odp_packet_seg_info(odp_packet_t pkt, odp_packet_seg_t seg,
			odp_packet_seg_info_t *info);

/**
 * Segment start address
 *
 * @param pkt  Packet handle
 * @param seg  Segment handle
 *
 * @return Segment start address, or NULL on an error
 */
void *odp_packet_seg_addr(odp_packet_t pkt, odp_packet_seg_t seg);

/**
 * Segment maximum data size
 *
 * @param pkt  Packet handle
 * @param seg  Segment handle
 *
 * @return Segment maximum data size
 */
size_t odp_packet_seg_size(odp_packet_t pkt, odp_packet_seg_t seg);

/**
 * Segment data address
 *
 * @param pkt  Packet handle
 * @param seg  Segment handle
 *
 * @return Segment data address
 */
void *odp_packet_seg_data(odp_packet_t pkt, odp_packet_seg_t seg);

/**
 * Segment data length
 *
 * @param pkt  Packet handle
 * @param seg  Segment handle
 *
 * @return Segment data length
 */
size_t odp_packet_seg_data_len(odp_packet_t pkt, odp_packet_seg_t seg);

/**
 * Segment headroom
 *
 * seg_headroom = seg_data - seg_addr
 *
 * @param pkt  Packet handle
 * @param seg  Segment handle
 *
 * @return Number of octets from seg_addr to seg_data
 */
size_t odp_packet_seg_headroom(odp_packet_t pkt, odp_packet_seg_t seg);

/**
 * Segment tailroom
 *
 * seg_tailroom = seg_size - seg_headroom - seg_data_len
 *
 * @param pkt  Packet handle
 * @param seg  Segment handle
 *
 * @return Number of octets from end-of-data to end-of-segment
 */
size_t odp_packet_seg_tailroom(odp_packet_t pkt, odp_packet_seg_t seg);

/**
 * Push out segment head
 *
 * Push out segment data address (away from data) and increase data length.
 * Does not modify packet in case of an error.
 *
 * seg_data     -= len
 * seg_data_len += len
 *
 * @param pkt  Packet handle
 * @param seg  Segment handle
 * @param len  Number of octets to push head (0 ... seg_headroom)
 *
 * @return New segment data address, or NULL on an error
 */
void *odp_packet_seg_push_head(odp_packet_t pkt, odp_packet_seg_t seg,
			       size_t len);

/**
 * Pull in segment head
 *
 * Pull in segment data address (towards data) and decrease data length.
 * Does not modify packet in case of an error.
 *
 * seg_data     += len
 * seg_data_len -= len
 *
 * @param pkt  Packet handle
 * @param seg  Segment handle
 * @param len  Number of octets to pull head (0 ... seg_data_len)
 *
 * @return New segment data address, or NULL on an error
 */
void *odp_packet_seg_pull_head(odp_packet_t pkt, odp_packet_seg_t seg,
			       size_t len);

/**
 * Push out segment tail
 *
 * Increase segment data length.
 * Does not modify packet in case of an error.
 *
 * seg_data_len  += len
 *
 * @param pkt  Packet handle
 * @param seg  Segment handle
 * @param len  Number of octets to push tail (0 ... seg_tailroom)
 *
 * @return New segment data length, or -1 on an error
 */
int odp_packet_seg_push_tail(odp_packet_t pkt, odp_packet_seg_t seg,
			     size_t len);

/**
 * Pull in segment tail
 *
 * Decrease segment data length.
 * Does not modify packet in case of an error.
 *
 * seg_data_len  -= len
 *
 * @param pkt  Packet handle
 * @param seg  Segment handle
 * @param len  Number of octets to pull tail (0 ... seg_data_len)
 *
 * @return New segment data length, or -1 on an error
 */
int odp_packet_seg_pull_tail(odp_packet_t pkt, odp_packet_seg_t seg,
			     size_t len);

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

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
