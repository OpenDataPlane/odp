/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */


/**
 * @file
 *
 * ODP packet descriptor
 */

#ifndef ODP_API_PACKET_H_
#define ODP_API_PACKET_H_
#include <odp/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/time.h>

/** @defgroup odp_packet ODP PACKET
 *  Operations on a packet.
 *  @{
 */

/**
 * @typedef odp_packet_t
 * ODP packet
 */

/**
 * @def ODP_PACKET_INVALID
 * Invalid packet
 */

/**
 * @def ODP_PACKET_OFFSET_INVALID
 * Invalid packet offset
 */

/**
 * @typedef odp_packet_seg_t
 * ODP packet segment
 */

/**
 * @def ODP_PACKET_SEG_INVALID
 * Invalid packet segment
 */

 /**
  * @typedef odp_packet_color_t
  * Color of packet for shaper/drop processing
  */

 /**
  * @def ODP_PACKET_GREEN
  * Packet is green
  */

 /**
  * @def ODP_PACKET_YELLOW
  * Packet is yellow
  */

 /**
  * @def ODP_PACKET_RED
  * Packet is red
  */

/*
 *
 * Alloc and free
 * ********************************************************
 *
 */

/**
 * Allocate a packet from a packet pool
 *
 * Allocates a packet of the requested length from the specified packet pool.
 * The pool must have been created with ODP_POOL_PACKET type. The
 * packet is initialized with data pointers and lengths set according to the
 * specified len, and the default headroom and tailroom length settings. All
 * other packet metadata are set to their default values. Packet length must
 * be greater than zero and not exceed packet pool parameter 'max_len' value.
 *
 * @param pool          Pool handle
 * @param len           Packet data length (1 ... pool max_len)
 *
 * @return Handle of allocated packet
 * @retval ODP_PACKET_INVALID  Packet could not be allocated
 *
 * @note The minimum headroom and tailroom used for packets is specified by
 * pool capabilities min_headroom and min_tailroom.
 */
odp_packet_t odp_packet_alloc(odp_pool_t pool, uint32_t len);

/**
 * Allocate multiple packets from a packet pool
 *
 * Otherwise like odp_packet_alloc(), but allocates multiple
 * packets from a pool.
 *
 * @param pool          Pool handle
 * @param len           Packet data length (1 ... pool max_len)
 * @param[out] pkt      Array of packet handles for output
 * @param num           Maximum number of packets to allocate
 *
 * @return Number of packets actually allocated (0 ... num)
 * @retval <0 on failure
 *
 */
int odp_packet_alloc_multi(odp_pool_t pool, uint32_t len,
			   odp_packet_t pkt[], int num);

/**
 * Free packet
 *
 * Frees the packet into the packet pool it was allocated from.
 *
 * @param pkt           Packet handle
 */
void odp_packet_free(odp_packet_t pkt);

/**
 * Free multiple packets
 *
 * Otherwise like odp_packet_free(), but frees multiple packets
 * to their originating pools.
 *
 * @param pkt           Array of packet handles
 * @param num           Number of packet handles to free
 */
void odp_packet_free_multi(const odp_packet_t pkt[], int num);

/**
 * Reset packet
 *
 * Resets all packet metadata to their default values. Packet length is used
 * to initialize pointers and lengths. It must be less than the total buffer
 * length of the packet minus the default headroom length. Packet is not
 * modified on failure.
 *
 * @param pkt           Packet handle
 * @param len           Packet data length
 *
 * @retval 0 on success
 * @retval <0 on failure
 *
 * @see odp_packet_buf_len()
 */
int odp_packet_reset(odp_packet_t pkt, uint32_t len);

/**
 * Get packet handle from event
 *
 * Converts an ODP_EVENT_PACKET type event to a packet.
 *
 * @param ev   Event handle
 *
 * @return Packet handle
 *
 * @see odp_event_type()
 */
odp_packet_t odp_packet_from_event(odp_event_t ev);

/**
 * Convert packet handle to event
 *
 * @param pkt  Packet handle
 *
 * @return Event handle
 */
odp_event_t odp_packet_to_event(odp_packet_t pkt);

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
 * Packet offset pointer
 *
 * Returns pointer to data in the packet offset. The packet level byte offset is
 * calculated from the current odp_packet_data() position. Optionally outputs
 * handle to the segment and number of data bytes in the segment following the
 * pointer.
 *
 * @param      pkt      Packet handle
 * @param      offset   Byte offset into the packet
 * @param[out] len      Number of data bytes remaining in the segment (output).
 *                      Ignored when NULL.
 * @param[out] seg      Handle to the segment containing the address (output).
 *                      Ignored when NULL.
 *
 * @return Pointer to the offset
 * @retval NULL  Requested offset exceeds packet length
 */
void *odp_packet_offset(odp_packet_t pkt, uint32_t offset, uint32_t *len,
			odp_packet_seg_t *seg);

/**
 * Packet data prefetch
 *
 * Prefetch 'len' bytes of packet data starting from 'offset' into various
 * caches close to the calling thread.
 *
 * @param      pkt      Packet handle
 * @param      offset   Byte offset into packet data
 * @param      len      Number of bytes to prefetch starting from 'offset'
 */
void odp_packet_prefetch(odp_packet_t pkt, uint32_t offset, uint32_t len);

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
 * pointers remain valid. User is responsible to update packet metadata
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
 * pointers remain valid. User is responsible to update packet metadata
 * offsets when needed.
 *
 * @param pkt  Packet handle
 * @param len  Number of bytes to pull the head (0 ... seg_len - 1)
 *
 * @return The new data pointer
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
 * pointers remain valid. User is responsible to update packet metadata
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
 * Extend packet head
 *
 * Increase packet data length at packet head. Functionality is analogous to
 * odp_packet_push_head() when data length is extended up to headroom size.
 * When data length is increased more than that, new segments are added into
 * the packet head and old segment handles become invalid.
 *
 * A successful operation overwrites the packet handle with a new handle, which
 * application must use as the reference to the packet instead of the old
 * handle. Depending on the implementation, the old and new handles may be
 * equal.
 *
 * The operation return value indicates if any packet data or metadata (e.g.
 * user_area) were moved in memory during the operation. If some memory areas
 * were moved, application must use new packet/segment handles to update
 * data pointers. Otherwise, all old pointers remain valid.
 *
 * User is responsible to update packet metadata offsets when needed. Packet
 * is not modified if operation fails.
 *
 * @param[in, out] pkt  Pointer to packet handle. A successful operation outputs
 *                      the new packet handle.
 * @param len           Number of bytes to extend the head
 * @param[out] data_ptr Pointer to output the new data pointer.
 *                      Ignored when NULL.
 * @param[out] seg_len  Pointer to output segment length at 'data_ptr' above.
 *                      Ignored when NULL.
 *
 * @retval 0   Operation successful, old pointers remain valid
 * @retval >0  Operation successful, old pointers need to be updated
 * @retval <0  Operation failed (e.g. due to an allocation failure)
 */
int odp_packet_extend_head(odp_packet_t *pkt, uint32_t len, void **data_ptr,
			   uint32_t *seg_len);

/**
 * Truncate packet head
 *
 * Decrease packet data length at packet head. Functionality is analogous to
 * odp_packet_pull_head() when data length is truncated less than the first
 * segment data length. When data length is decreased more than that, some head
 * segments are removed from the packet and old segment handles become invalid.
 *
 * A successful operation overwrites the packet handle with a new handle, which
 * application must use as the reference to the packet instead of the old
 * handle. Depending on the implementation, the old and new handles may be
 * equal.
 *
 * The operation return value indicates if any packet data or metadata (e.g.
 * user_area) were moved in memory during the operation. If some memory areas
 * were moved, application must use new packet/segment handles to update
 * data pointers. Otherwise, all old pointers remain valid.
 *
 * User is responsible to update packet metadata offsets when needed. Packet
 * is not modified if operation fails.
 *
 * @param[in, out] pkt  Pointer to packet handle. A successful operation outputs
 *                      the new packet handle.
 * @param len           Number of bytes to truncate the head (0 ... packet_len)
 * @param[out] data_ptr Pointer to output the new data pointer.
 *                      Ignored when NULL.
 * @param[out] seg_len  Pointer to output segment length at 'data_ptr' above.
 *                      Ignored when NULL.
 *
 * @retval 0   Operation successful, old pointers remain valid
 * @retval >0  Operation successful, old pointers need to be updated
 * @retval <0  Operation failed
 */
int odp_packet_trunc_head(odp_packet_t *pkt, uint32_t len, void **data_ptr,
			  uint32_t *seg_len);

/**
 * Extend packet tail
 *
 * Increase packet data length at packet tail. Functionality is analogous to
 * odp_packet_push_tail() when data length is extended up to tailroom size.
 * When data length is increased more than that, new segments are added into
 * the packet tail and old segment handles become invalid.
 *
 * A successful operation overwrites the packet handle with a new handle, which
 * application must use as the reference to the packet instead of the old
 * handle. Depending on the implementation, the old and new handles may be
 * equal.
 *
 * The operation return value indicates if any packet data or metadata (e.g.
 * user_area) were moved in memory during the operation. If some memory areas
 * were moved, application must use new packet/segment handles to update
 * data pointers. Otherwise, all old pointers remain valid.
 *
 * User is responsible to update packet metadata offsets when needed. Packet
 * is not modified if operation fails.
 *
 * @param[in, out] pkt  Pointer to packet handle. A successful operation outputs
 *                      the new packet handle.
 * @param len           Number of bytes to extend the tail
 * @param[out] data_ptr Pointer to output pointer to the last 'len' bytes
 *                      of the resulting packet (the previous tail).
 *                      Ignored when NULL.
 * @param[out] seg_len  Pointer to output segment length at 'data_ptr' above.
 *                      Ignored when NULL.
 *
 * @retval 0   Operation successful, old pointers remain valid
 * @retval >0  Operation successful, old pointers need to be updated
 * @retval <0  Operation failed (e.g. due to an allocation failure)
 */
int odp_packet_extend_tail(odp_packet_t *pkt, uint32_t len, void **data_ptr,
			   uint32_t *seg_len);

/**
 * Truncate packet tail
 *
 * Decrease packet data length at packet tail. Functionality is analogous to
 * odp_packet_pull_tail() when data length is truncated less the last segment
 * data length. When data length is decreased more than that, some tail segments
 * are removed from the packet and old segment handles become invalid.
 *
 * A successful operation overwrites the packet handle with a new handle, which
 * application must use as the reference to the packet instead of the old
 * handle. Depending on the implementation, the old and new handles may be
 * equal.
 *
 * The operation return value indicates if any packet data or metadata (e.g.
 * user_area) were moved in memory during the operation. If some memory areas
 * were moved, application must use new packet/segment handles to update
 * data pointers. Otherwise, all old pointers remain valid.
 *
 * User is responsible to update packet metadata offsets when needed. Packet
 * is not modified if operation fails.
 *
 * @param[in, out] pkt  Pointer to packet handle. A successful operation outputs
 *                      the new packet handle.
 * @param len           Number of bytes to truncate the tail (0 ... packet_len)
 * @param[out] tail_ptr Pointer to output the new tail pointer.
 *                      Ignored when NULL.
 * @param[out] tailroom Pointer to output the new tailroom. Ignored when NULL.
 *
 * @retval 0   Operation successful, old pointers remain valid
 * @retval >0  Operation successful, old pointers need to be updated
 * @retval <0  Operation failed
 */
int odp_packet_trunc_tail(odp_packet_t *pkt, uint32_t len, void **tail_ptr,
			  uint32_t *tailroom);

/**
 * Add data into an offset
 *
 * Increase packet data length by adding new data area into the specified
 * offset. The operation may modify packet segmentation and move data.
 *
 * A successful operation overwrites the packet handle with a new handle, which
 * application must use as the reference to the packet instead of the old
 * handle. Depending on the implementation, the old and new handles may be
 * equal.
 *
 * The operation return value indicates if any packet data or metadata (e.g.
 * user_area) were moved in memory during the operation. If some memory areas
 * were moved, application must use new packet/segment handles to update
 * data pointers. Otherwise, all old pointers remain valid.
 *
 * User is responsible to update packet metadata offsets when needed. Packet
 * is not modified if operation fails.
 *
 * @param[in, out] pkt  Pointer to packet handle. A successful operation outputs
 *                      the new packet handle.
 * @param offset        Byte offset into the packet
 * @param len           Number of bytes to add into the offset
 *
 * @retval 0   Operation successful, old pointers remain valid
 * @retval >0  Operation successful, old pointers need to be updated
 * @retval <0  Operation failed
 */
int odp_packet_add_data(odp_packet_t *pkt, uint32_t offset, uint32_t len);

/**
 * Remove data from an offset
 *
 * Decrease packet data length by removing data area from the specified
 * offset. The operation may modify packet segmentation and move data.
 *
 * A successful operation overwrites the packet handle with a new handle, which
 * application must use as the reference to the packet instead of the old
 * handle. Depending on the implementation, the old and new handles may be
 * equal.
 *
 * The operation return value indicates if any packet data or metadata (e.g.
 * user_area) were moved in memory during the operation. If some memory areas
 * were moved, application must use new packet/segment handles to update
 * data pointers. Otherwise, all old pointers remain valid.
 *
 * User is responsible to update packet metadata offsets when needed. Packet
 * is not modified if operation fails.
 *
 * @param[in, out] pkt  Pointer to packet handle. A successful operation outputs
 *                      the new packet handle.
 * @param offset        Byte offset into the packet
 * @param len           Number of bytes to remove from the offset
 *
 * @retval 0   Operation successful, old pointers remain valid
 * @retval >0  Operation successful, old pointers need to be updated
 * @retval <0  Operation failed */
int odp_packet_rem_data(odp_packet_t *pkt, uint32_t offset, uint32_t len);

/**
 * Align packet data
 *
 * Modify packet data alignment so that 'len' bytes between 'offset' and
 * 'offset' plus 'len' are contiguous in memory and have a minimum alignment
 * of 'align' bytes.
 *
 * A successful operation overwrites the packet handle with a new handle, which
 * the application must use as the reference to the packet instead of the old
 * handle. Depending on the implementation, the old and new handles may be
 * equal.
 *
 * The operation return value indicates if any packet data outside of the
 * requested area or metadata (e.g. user_area) were moved in memory during
 * the operation. If some other memory areas were moved, application must use
 * new packet/segment handles to update data pointers. Otherwise, old
 * pointers remain valid.
 *
 * Packet is not modified if operation fails.
 *
 * @param[in, out] pkt  Pointer to packet handle. A successful operation outputs
 *                      the new packet handle.
 * @param offset        Byte offset of the contiguous area
 * @param len           Byte length of the contiguous area (0 ... packet_len)
 * @param align         Minimum byte alignment of the contiguous area.
 *                      Valid values are powers of 2. Use 0 to indicate no
 *                      special alignment requirement. All implementations
 *                      support alignments of up to at least 32 bytes. Request
 *                      will fail if requested alignment exceeds implementation
 *                      limits.
 *
 * @retval 0   Operation successful, old pointers remain valid
 * @retval >0  Operation successful, old pointers need to be updated
 * @retval <0  Operation failed
 */
int odp_packet_align(odp_packet_t *pkt, uint32_t offset, uint32_t len,
		     uint32_t align);

/*
 *
 * Segmentation
 * ********************************************************
 *
 */

/**
 * Tests if packet is segmented
 *
 * @param pkt  Packet handle
 *
 * @retval 0 Packet is not segmented
 * @retval 1 Packet is segmented
 */
int odp_packet_is_segmented(odp_packet_t pkt);

/**
 * Number of segments
 *
 * Returns number of segments in the packet. A packet has always at least one
 * segment.
 *
 * @param pkt  Packet handle
 *
 * @return Number of segments (>0)
 */
int odp_packet_num_segs(odp_packet_t pkt);

/**
 * First segment in packet
 *
 * A packet has always the first segment (has at least one segment).
 *
 * @param pkt  Packet handle
 *
 * @return Handle to the first segment
 */
odp_packet_seg_t odp_packet_first_seg(odp_packet_t pkt);

/**
 * Last segment in packet
 *
 * A packet has always the last segment (has at least one segment).
 *
 * @param pkt  Packet handle
 *
 * @return Handle to the last segment
 */
odp_packet_seg_t odp_packet_last_seg(odp_packet_t pkt);

/**
 * Next segment in packet
 *
 * Returns handle to the next segment after the current segment, or
 * ODP_PACKET_SEG_INVALID if there are no more segments. Use
 * odp_packet_first_seg() to get handle to the first segment.
 *
 * @param pkt   Packet handle
 * @param seg   Current segment handle
 *
 * @return Handle to the next segment
 * @retval ODP_PACKET_SEG_INVALID if there are no more segments
 */
odp_packet_seg_t odp_packet_next_seg(odp_packet_t pkt, odp_packet_seg_t seg);

/**
 * Segment data pointer
 *
 * Returns pointer to the first byte of data in the segment.
 *
 * @param pkt  Packet handle
 * @param seg  Segment handle
 *
 * @return  Pointer to the segment data
 * @retval NULL on failure
 *
 * @see odp_packet_seg_data_len()
 */
void *odp_packet_seg_data(odp_packet_t pkt, odp_packet_seg_t seg);

/**
 * Segment data length
 *
 * Returns segment data length in bytes.
 *
 * @param pkt  Packet handle
 * @param seg  Segment handle
 *
 * @return  Segment data length in bytes
 *
 * @see odp_packet_seg_data()
 */
uint32_t odp_packet_seg_data_len(odp_packet_t pkt, odp_packet_seg_t seg);

/**
 * Concatenate two packets
 *
 * Concatenate all packet data from 'src' packet into tail of 'dst' packet.
 * Operation preserves 'dst' packet metadata in the resulting packet,
 * while 'src' packet handle, metadata and old segment handles for both packets
 * become invalid. Source and destination packet handles must not refer to
 * the same packet.
 *
 * A successful operation overwrites 'dst' packet handle with a new handle,
 * which application must use as the reference to the resulting packet
 * instead of the old handle. Depending on the implementation, the old and new
 * handles may be equal.
 *
 * The operation return value indicates if any packet data or metadata (e.g.
 * user_area) were moved in memory during the operation. If some memory areas
 * were moved, application must use new packet/segment handles to update
 * data pointers. Otherwise, all old pointers remain valid.
 *
 * The resulting packet is always allocated from the same pool as
 * the destination packet. The source packet may have been allocate from
 * any pool.
 *
 * On failure, both handles remain valid and packets are not modified.
 *
 * @param[in, out] dst   Pointer to destination packet handle. A successful
 *                       operation outputs the new packet handle.
 * @param src            Source packet handle
 *
 * @retval 0   Operation successful, old pointers remain valid
 * @retval >0  Operation successful, old pointers need to be updated
 * @retval <0  Operation failed
 */
int odp_packet_concat(odp_packet_t *dst, odp_packet_t src);

/**
 * Split packet into two packets
 *
 * Split the packet after 'len' bytes. The first 'len' bytes of data and
 * metadata remain in the head packet. A successful operation outputs a handle
 * for the tail packet and overwrites 'pkt' packet handle with a new
 * handle, which application must use as the reference to the resulting head
 * packet. Depending on the implementation, the old and new 'pkt' handles
 * may be equal.
 *
 * The operation return value indicates if any packet data or metadata (e.g.
 * user_area) were moved in memory during the operation. If some memory areas
 * were moved, application must use new packet/segment handles to update
 * data pointers. Otherwise, all old pointers remain valid.
 *
 * The tail packet holds the rest of the data (odp_packet_len() - 'len' bytes).
 * The packet is allocated from the same pool as the original packet and
 * metadata is initialized with default values.
 *
 * For performance reasons (zero copy), the head packet may have zero tailroom
 * and the tail packet may have zero headroom length after the operation.
 * Both packets may be extended normally.
 *
 * The original packet is not modified on failure.
 *
 * @param[in, out] pkt   Pointer to packet handle. A successful operation
 *                       outputs a new packet handle for the head packet.
 * @param len            Data length remaining in the head packet
 * @param tail           Pointer to output the tail packet handle
 *
 * @retval 0   Operation successful, old pointers remain valid
 * @retval >0  Operation successful, old pointers need to be updated
 * @retval <0  Operation failed
 */
int odp_packet_split(odp_packet_t *pkt, uint32_t len, odp_packet_t *tail);

/*
 *
 * Copy
 * ********************************************************
 *
 */

/**
 * Full copy of a packet
 *
 * Create a new copy of the packet. The new packet is exact copy of the source
 * packet (incl. data and metadata). The pool must have been created with
 * ODP_POOL_PACKET type.
 *
 * @param pkt   Packet handle
 * @param pool  Packet pool for allocation of the new packet.
 *
 * @return Handle to the copy of the packet
 * @retval ODP_PACKET_INVALID on failure
 */
odp_packet_t odp_packet_copy(odp_packet_t pkt, odp_pool_t pool);

/**
 * Partial copy of a packet
 *
 * Copy 'len' bytes of data starting from 'offset' into a new packet.
 * Metadata in the new packet is initialized with default values. Maximum number
 * of bytes to copy is packet data length minus the offset. The pool must be
 * a packet pool.
 *
 * @param pkt    Packet handle
 * @param offset Byte offset into the packet
 * @param len    Number of bytes to copy
 * @param pool   Packet pool for allocation of the new packet
 *
 * @return Handle for the new packet
 * @retval ODP_PACKET_INVALID on failure
 */
odp_packet_t odp_packet_copy_part(odp_packet_t pkt, uint32_t offset,
				  uint32_t len, odp_pool_t pool);

/**
 * Copy data from packet to memory
 *
 * Copy 'len' bytes of data starting from 'offset' to the destination
 * address. Maximum number of bytes to copy is packet data length minus the
 * offset.
 *
 * @param pkt    Packet handle
 * @param offset Byte offset into the packet
 * @param len    Number of bytes to copy
 * @param dst    Destination address
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int odp_packet_copy_to_mem(odp_packet_t pkt, uint32_t offset,
			   uint32_t len, void *dst);

/**
 * Copy data from memory to packet
 *
 * Copy 'len' bytes of data from the source address into the packet level
 * offset. Maximum number of bytes to copy is packet data length minus the
 * offset. Packet is not modified on an error.
 *
 * @param pkt    Packet handle
 * @param offset Byte offset into the packet
 * @param len    Number of bytes to copy
 * @param src    Source address
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int odp_packet_copy_from_mem(odp_packet_t pkt, uint32_t offset,
			     uint32_t len, const void *src);

/**
 * Copy data from another packet
 *
 * Copy 'len' bytes of data from 'src' packet to 'dst' packet. Copy starts from
 * the specified source and destination packet offsets. Copied areas
 * (offset ... offset + len) must not exceed their packet data lengths.
 * Source and destination packet handles must not refer to the same packet (use
 * odp_packet_copy_data() or odp_packet_move_data() for a single packet).
 *
 * Packet is not modified on an error.
 *
 * @param dst        Destination packet handle
 * @param dst_offset Byte offset into destination packet
 * @param src        Source packet handle
 * @param src_offset Byte offset into source packet
 * @param len        Number of bytes to copy
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int odp_packet_copy_from_pkt(odp_packet_t dst, uint32_t dst_offset,
			     odp_packet_t src, uint32_t src_offset,
			     uint32_t len);

/**
 * Copy data within packet
 *
 * Copy 'len' bytes of data from 'src_offset' to 'dst_offset'. Copied areas
 * (offset ... offset + len) must not overlap or exceed packet data length.
 * Packet is not modified on an error.
 *
 * @param pkt        Packet handle
 * @param dst_offset Destination byte offset
 * @param src_offset Source byte offset
 * @param len        Number of bytes to copy
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int odp_packet_copy_data(odp_packet_t pkt, uint32_t dst_offset,
			 uint32_t src_offset, uint32_t len);

/**
 * Move data within packet
 *
 * Copy 'len' bytes of data from 'src_offset' to 'dst_offset'. Copied areas
 * (offset ... offset + len) may overlap by any number of bytes, but must not
 * exceed packet data length. When areas overlap, copying takes place as if
 * source bytes are first copied into a temporary buffer, and then from there
 * to the destination. Packet is not modified on an error.
 *
 * @param pkt        Packet handle
 * @param dst_offset Destination byte offset
 * @param src_offset Source byte offset
 * @param len        Number of bytes to move
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int odp_packet_move_data(odp_packet_t pkt, uint32_t dst_offset,
			 uint32_t src_offset, uint32_t len);

/*
 *
 * Meta-data
 * ********************************************************
 *
 */

/**
 * Packet pool
 *
 * Returns handle to the packet pool where the packet was allocated from.
 *
 * @param pkt   Packet handle
 *
 * @return Packet pool handle
 */
odp_pool_t odp_packet_pool(odp_packet_t pkt);

/**
 * Packet input interface
 *
 * Returns handle to the packet IO interface which received the packet or
 * ODP_PKTIO_INVALID when the packet was allocated/reset by the application.
 *
 * @param pkt   Packet handle
 *
 * @return Packet interface handle
 * @retval ODP_PKTIO_INVALID  Packet was not received on any interface
 */
odp_pktio_t odp_packet_input(odp_packet_t pkt);

/**
 * Packet input interface index
 *
 * Returns the index of the packet I/O interface that received the packet, or
 * <0 when the packet was allocated/reset by the application.
 *
 * @param pkt   Packet handle
 *
 * @return Packet interface index (0..odp_pktio_max_index())
 * @retval <0  Packet was not received on any interface
 */
int odp_packet_input_index(odp_packet_t pkt);

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
 * Each packet has room for a user defined context pointer. The pointer value
 * does not necessarily represent a valid address - e.g. user may store any
 * value of type intptr_t. ODP may use the pointer for data prefetching, but
 * must ignore any invalid addresses.
 *
 * @param pkt  Packet handle
 * @param ctx  User context pointer
 */
void odp_packet_user_ptr_set(odp_packet_t pkt, const void *ctx);

/**
 * User area address
 *
 * Each packet has an area for user data. Size of the area is fixed and defined
 * in packet pool parameters.
 *
 * @param pkt  Packet handle
 *
 * @return       User area address associated with the packet
 * @retval NULL  The packet does not have user area
 */
void *odp_packet_user_area(odp_packet_t pkt);

/**
 * User area size
 *
 * The size is fixed and defined in packet pool parameters.
 *
 * @param pkt  Packet handle
 *
 * @return  User area size in bytes
 */
uint32_t odp_packet_user_area_size(odp_packet_t pkt);

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
 * @return  Layer 2 start pointer
 * @retval  NULL packet does not contain a valid L2 header
 *
 * @see odp_packet_l2_offset(), odp_packet_l2_offset_set(), odp_packet_has_l2()
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
 * @retval ODP_PACKET_OFFSET_INVALID packet does not contain a valid L2 header
 *
 * @see odp_packet_l2_offset_set(), odp_packet_has_l2()
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
 * @retval 0 on success
 * @retval <0 on failure
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
 * @return  Layer 3 start pointer
 * @retval NULL packet does not contain a valid L3 header
 *
 * @see odp_packet_l3_offset(), odp_packet_l3_offset_set(), odp_packet_has_l3()
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
 * @return  Layer 3 start offset, or ODP_PACKET_OFFSET_INVALID when packet does
 *          not contain a valid L3 header.
 *
 * @see odp_packet_l3_offset_set(), odp_packet_has_l3()
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
 * @retval 0 on success
 * @retval <0 on failure
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
 * @return  Layer 4 start pointer
 * @retval NULL packet does not contain a valid L4 header
 *
 * @see odp_packet_l4_offset(), odp_packet_l4_offset_set(), odp_packet_has_l4()
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
 * @return  Layer 4 start offset
 * @retval ODP_PACKET_OFFSET_INVALID packet does not contain a valid L4 header
 *
 * @see odp_packet_l4_offset_set(), odp_packet_has_l4()
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
 * @retval 0 on success
 * @retval <0 on failure
 */
int odp_packet_l4_offset_set(odp_packet_t pkt, uint32_t offset);

/**
 * Packet flow hash value
 *
 * Returns the hash generated from the packet header. Use
 * odp_packet_has_flow_hash() to check if packet contains a hash.
 *
 * @param      pkt      Packet handle
 *
 * @return  Hash value
 *
 * @note Zero can be a valid hash value.
 * @note The hash algorithm and the header fields defining the flow (therefore
 * used for hashing) is platform dependent. It is possible a platform doesn't
 * generate any hash at all.
 * @note The returned hash is either the platform generated (if any), or if
 * odp_packet_flow_hash_set() were called then the value set there.
 */
uint32_t odp_packet_flow_hash(odp_packet_t pkt);

/**
 * Set packet flow hash value
 *
 * Store the packet flow hash for the packet and sets the flow hash flag. This
 * enables (but does not require!) application to reflect packet header
 * changes in the hash.
 *
 * @param      pkt              Packet handle
 * @param      flow_hash        Hash value to set
 *
 * @note If the platform needs to keep the original hash value, it has to
 * maintain it internally. Overwriting the platform provided value doesn't
 * change how the platform handles this packet after it.
 * @note The application is not required to keep this hash valid for new or
 * modified packets.
 */
void odp_packet_flow_hash_set(odp_packet_t pkt, uint32_t flow_hash);

/**
 * Packet timestamp
 *
 * Returns packet timestamp value as odp_time_t type. Use time API for
 * additional operations on packet timestamp values or conversion into
 * nanoseconds. Use odp_packet_has_ts() to check if packet has a valid
 * timestamp. Packet input interface timestamp resolution can be checked with
 * odp_pktin_ts_res().
 *
 * @param pkt  Packet handle
 *
 * @return Timestamp value
 *
 * @see odp_pktin_ts_res(), odp_packet_has_ts(), odp_time_to_ns()
 */
odp_time_t odp_packet_ts(odp_packet_t pkt);

/**
 * Set packet timestamp
 *
 * Stores timestamp value and sets timestamp flag for the packet.
 *
 * @param pkt        Packet handle
 * @param timestamp  Timestamp value
 *
 * @see odp_packet_ts(), odp_packet_has_ts(),
 * odp_pktin_ts_from_ns()
 */
void odp_packet_ts_set(odp_packet_t pkt, odp_time_t timestamp);

/**
 * Get packet color
 *
 * @param pkt Packet handle
 * @return packet color
 */
odp_packet_color_t odp_packet_color(odp_packet_t pkt);

/**
 * Set packet color
 *
 * @param pkt Packet handle
 * @param color Color to set
 */
void odp_packet_color_set(odp_packet_t pkt, odp_packet_color_t color);

/**
 * Get drop eligible status
 *
 * @param pkt Packet handle
 * @return Packet drop eligibility status
 * @retval 0 Packet is not drop eligible
 * @retval 1 Packet is drop
 */
odp_bool_t odp_packet_drop_eligible(odp_packet_t pkt);

/**
 * Set drop eligible status
 *
 * @param pkt Packet handle
 * @param status Drop eligibility status
 */
void odp_packet_drop_eligible_set(odp_packet_t pkt, odp_bool_t status);

/**
 * Get shaper length adjustment
 *
 * @param pkt Packet handle
 * @return Shaper adjustment (-128..127)
 */
int8_t odp_packet_shaper_len_adjust(odp_packet_t pkt);

/**
 * Set shaper length adjustment
 *
 * @param pkt Packet handle
 * @param adj Signed adjustment value
 */
void odp_packet_shaper_len_adjust_set(odp_packet_t pkt, int8_t adj);

/*
 *
 * Debugging
 * ********************************************************
 *
 */

/**
 * Print packet to the console
 *
 * Print all packet debug information to the console.
 *
 * @param pkt  Packet handle
 */
void odp_packet_print(odp_packet_t pkt);

/**
 * Perform full packet validity check
 *
 * The operation may consume considerable number of cpu cycles depending on
 * the check level.
 *
 * @param pkt  Packet handle
 *
 * @retval 0 Packet is not valid
 * @retval 1 Packet is valid
 */
int odp_packet_is_valid(odp_packet_t pkt);

/**
 * Get printable value for an odp_packet_t
 *
 * @param hdl  odp_packet_t handle to be printed
 * @return     uint64_t value that can be used to print/display this
 *             handle
 *
 * @note This routine is intended to be used for diagnostic purposes
 * to enable applications to generate a printable value that represents
 * an odp_packet_t handle.
 */
uint64_t odp_packet_to_u64(odp_packet_t hdl);

/**
 * Get printable value for an odp_packet_seg_t
 *
 * @param hdl  odp_packet_seg_t handle to be printed
 * @return     uint64_t value that can be used to print/display this
 *             handle
 *
 * @note This routine is intended to be used for diagnostic purposes
 * to enable applications to generate a printable value that represents
 * an odp_packet_seg_t handle.
 */
uint64_t odp_packet_seg_to_u64(odp_packet_seg_t hdl);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
