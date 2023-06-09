/* Copyright (c) 2013-2018, Linaro Limited
 * Copyright (c) 2021-2023, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/**
 * @file
 *
 * ODP packet descriptor
 */

#ifndef ODP_API_SPEC_PACKET_H_
#define ODP_API_SPEC_PACKET_H_
#include <odp/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/event_types.h>
#include <odp/api/packet_types.h>
#include <odp/api/packet_io_types.h>
#include <odp/api/pool_types.h>
#include <odp/api/proto_stats_types.h>
#include <odp/api/std_types.h>
#include <odp/api/time_types.h>

/** @defgroup odp_packet ODP PACKET
 *  Packet event metadata and operations.
 *  @{
 */

/**
 * Event subtype of a packet
 *
 * Returns the subtype of a packet event. Subtype tells if the packet contains
 * only basic metadata (ODP_EVENT_PACKET_BASIC) or in addition to that some
 * specific metadata (e.g. ODP_EVENT_PACKET_CRYPTO or ODP_EVENT_PACKET_IPSEC).
 *
 * @param      packet   Packet handle
 *
 * @return Packet subtype
 */
odp_event_subtype_t odp_packet_subtype(odp_packet_t packet);

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
 * Free multiple packets to the same pool
 *
 * Otherwise like odp_packet_free_multi(), but all packets must be from the
 * same originating pool.
 *
 * @param pkt           Array of packet handles
 * @param num           Number of packets to free
 */
void odp_packet_free_sp(const odp_packet_t pkt[], int num);

/**
 * Reset packet
 *
 * Resets all packet metadata to their default values. Packet length is used
 * to initialize pointers and lengths. It must be less than the total buffer
 * length of the packet. Packet is not modified on failure.
 *
 * @param pkt           Packet handle
 * @param len           Packet data length (1 ... odp_packet_buf_len())
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
 * Convert multiple packet events to packet handles
 *
 * All events must be of type ODP_EVENT_PACKET.
 *
 * @param[out] pkt  Packet handle array for output
 * @param      ev   Array of event handles to convert
 * @param      num  Number of packets and events
 */
void odp_packet_from_event_multi(odp_packet_t pkt[], const odp_event_t ev[],
				 int num);

/**
 * Convert packet handle to event
 *
 * @param pkt  Packet handle
 *
 * @return Event handle
 */
odp_event_t odp_packet_to_event(odp_packet_t pkt);

/**
 * Convert multiple packet handles to events
 *
 * @param      pkt  Array of packet handles to convert
 * @param[out] ev   Event handle array for output
 * @param      num  Number of packets and events
 */
void odp_packet_to_event_multi(const odp_packet_t pkt[], odp_event_t ev[],
			       int num);

/**
 * Get information about successful reassembly offload that has happened
 *
 * This function may be called only if the reassembly status of a packet
 * is ODP_PACKET_REASS_COMPLETE.
 *
 * @param      pkt   Completely reassembled packet.
 * @param[out] info  Pointer to the info structure to be filled
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int odp_packet_reass_info(odp_packet_t pkt, odp_packet_reass_info_t *info);

/**
 * Get partial reassembly state from a packet
 *
 * In case of incomplete reassembly, a packet carries information on
 * the time already used for the reassembly attempt and one or more
 * fragments. The fragments are not necessarily the original received
 * fragments but may be partially reassembled parts of the packet.
 *
 * This function may be called only if the reassembly status of a packet
 * is ODP_PACKET_REASS_INCOMPLETE.
 *
 * @param      pkt   Incompletely reassembled packet. The packet will
 *                   be consumed if the function succeeds.
 * @param[out] frags Packet handle array for output. The size of this array must
 *                   be at least `odp_reass_config_t::max_num_frags`.
 * @param[out] res   Pointer to result structure
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int odp_packet_reass_partial_state(odp_packet_t pkt, odp_packet_t frags[],
				   odp_packet_reass_partial_state_t *res);

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
 * Returns pointer to the first byte of packet data. When packet is segmented,
 * only a portion of packet data follows the pointer. When unsure, use e.g.
 * odp_packet_seg_len() to check the data length following the pointer. Packet
 * level offsets are calculated relative to this position.
 *
 * When a packet is received from packet input, this points to the first byte
 * of the received packet. Pool configuration parameters may be used to ensure
 * that the first packet segment contains all/most of the data relevant to the
 * application.
 *
 * User can adjust the data pointer with e.g. push_head/pull_head (does not
 * modify segmentation) and extend_head/trunc_head (may modify segmentation)
 * calls.
 *
 * @param pkt  Packet handle
 *
 * @return  Pointer to the packet data
 *
 * @see odp_packet_seg_len(), odp_packet_push_head(), odp_packet_extend_head()
 */
void *odp_packet_data(odp_packet_t pkt);

/**
 * Packet data length following the data pointer
 *
 * Returns number of data bytes (in the segment) following the current data
 * pointer position. When unsure, use this function to check how many bytes
 * can be accessed linearly after data pointer (odp_packet_data()). This
 * equals to odp_packet_len() for single segment packets.
 *
 * @param pkt  Packet handle
 *
 * @return  Segment data length in bytes following odp_packet_data()
 *
 * @see odp_packet_data()
 */
uint32_t odp_packet_seg_len(odp_packet_t pkt);

/**
 * Packet data pointer with segment length
 *
 * Returns both data pointer and number of data bytes (in the segment)
 * following it. This is equivalent to calling odp_packet_data() and
 * odp_packet_seg_len().
 *
 * @param      pkt      Packet handle
 * @param[out] seg_len  Pointer to output segment length
 *
 * @return Pointer to the packet data
 *
 * @see odp_packet_data(), odp_packet_seg_len()
 */
void *odp_packet_data_seg_len(odp_packet_t pkt, uint32_t *seg_len);

/**
 * Packet data length
 *
 * Returns total data length over all packet segments. This equals the sum of
 * segment level data lengths (odp_packet_seg_data_len()).
 *
 * @param pkt  Packet handle
 *
 * @return Packet data length
 *
 * @see odp_packet_seg_len(), odp_packet_data(), odp_packet_seg_data_len()
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
 * @param len           Number of bytes to truncate the head
 *                      (0 ... packet_len - 1)
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
 * @param len           Number of bytes to truncate the tail
 *                      (0 ... packet_len - 1)
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
 * @param len           Number of bytes to remove from the offset. When offset
 *                      is zero: 0 ... packet_len - 1 bytes, otherwise
 *                      0 ... packet_len - offset bytes.
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
 * the destination packet. The source packet may have been allocated from
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
 *                       (1 ... packet_len - 1)
 * @param tail           Pointer to output the tail packet handle
 *
 * @retval 0   Operation successful, old pointers remain valid
 * @retval >0  Operation successful, old pointers need to be updated
 * @retval <0  Operation failed
 */
int odp_packet_split(odp_packet_t *pkt, uint32_t len, odp_packet_t *tail);

/**
 * Packet buffer head pointer
 *
 * Packet buffer start address. Buffer level headroom starts from here. For the first
 * packet buffer of a packet this is equivalent to odp_packet_head().
 *
 * @param      pkt_buf   Packet buffer
 *
 * @return Packet buffer head pointer
 */
void *odp_packet_buf_head(odp_packet_buf_t pkt_buf);

/**
 * Packet buffer size in bytes
 *
 * Packet buffer size is calculated from the buffer head pointer (see odp_packet_buf_head()).
 * It contains all buffer level headroom, data, and tailroom. For a single segmented packet this is
 * equivalent to odp_packet_buf_len().
 *
 * @param      pkt_buf   Packet buffer
 *
 * @return Packet buffer size
 */
uint32_t odp_packet_buf_size(odp_packet_buf_t pkt_buf);

/**
 * Packet buffer data offset
 *
 * Offset from the buffer head pointer to the first byte of packet data in the packet buffer.
 * Valid values range from 0 to buf_size - 1. For the first packet buffer of a packet
 * this is equivalent to odp_packet_headroom().
 *
 * @param      pkt_buf   Packet buffer
 *
 * @return Packet buffer data offset
 */
uint32_t odp_packet_buf_data_offset(odp_packet_buf_t pkt_buf);

/**
 * Packet buffer data length in bytes
 *
 * Packet buffer contains this many bytes of packet data. Valid values range from 1 to
 * buf_size - data_offset. For the first packet buffer of a packet this is equivalent to
 * odp_packet_seg_len().
 *
 * @param      pkt_buf   Packet buffer
 *
 * @return Packet buffer data length
 */
uint32_t odp_packet_buf_data_len(odp_packet_buf_t pkt_buf);

/**
 * Packet buffer data set
 *
 * Update packet data start offset and length in the packet buffer. Valid offset values range
 * from 0 to buf_size - 1. Valid length values range from 1 to buf_size - data_offset.
 *
 * @param      pkt_buf      Packet buffer
 * @param      data_offset  Packet buffer data offset in bytes (from the buffer head pointer)
 * @param      data_len     Packet buffer data length in bytes
 */
void odp_packet_buf_data_set(odp_packet_buf_t pkt_buf, uint32_t data_offset, uint32_t data_len);

/**
 * Convert packet buffer head pointer to handle
 *
 * Converts a packet buffer head pointer (from a previous odp_packet_buf_head() call) to a packet
 * buffer handle. This allows an application to save memory as it can store only buffer pointers
 * (instead of pointers and handles) and convert those to handles when needed. This conversion
 * may be done only for packet buffers that are not part of any packet (i.e. buffers between
 * odp_packet_disassemble() and odp_packet_reassemble() calls).
 *
 * This call can be used only for packets of an external memory pool (see odp_pool_ext_create()).
 *
 * @param      pool     Pool from which the packet buffer (disassembled packet) originate from
 * @param      head     Head pointer
 *
 * @return Packet buffer handle on success
 * @retval ODP_PACKET_BUF_INVALID on failure
 */
odp_packet_buf_t odp_packet_buf_from_head(odp_pool_t pool, void *head);

/**
 * Disassemble packet into packet buffers
 *
 * Breaks up a packet into a list of packet buffers. Outputs a packet buffer handle for each
 * segment of the packet (see odp_packet_num_segs()). After a successful operation the packet
 * handle must not be referenced anymore. Packet buffers are reassembled into a new packet (or
 * several new packets) with a later odp_packet_reassemble() call(s). All packet buffers must be
 * reassembled into a packet and freed into the originating pool before the pool is destroyed.
 *
 * This call can be used only for packets of an external memory pool (see odp_pool_ext_create()).
 *
 * @param      pkt      Packet to be disassembled
 * @param[out] pkt_buf  Packet buffer handle array for output
 * @param      num      Number of elements in packet buffer handle array. Must be equal to or
 *                      larger than number of segments in the packet.
 *
 * @return Number of handles written (equals the number of segments in the packet)
 * @retval 0 on failure
 */
uint32_t odp_packet_disassemble(odp_packet_t pkt, odp_packet_buf_t pkt_buf[], uint32_t num);

/**
 * Reassemble packet from packet buffers
 *
 * Forms a new packet from packet buffers of a previous odp_packet_disassemble() call(s). Packet
 * buffers from different disassembled packets may be used, but all buffers must be from packets of
 * the same pool. Packet pool capability 'max_segs_per_pkt' defines the maximum number of
 * packet buffers that can be reassembled to form a new packet.
 *
 * Application may use odp_packet_buf_data_set() to adjust data_offset and data_len values
 * in each packet buffer to match the current packet data placement. The operation
 * maintains packet data content and position. Each buffer becomes a segment in the new packet.
 * Packet metadata related to data length and position are set according data layout
 * in the buffers. All other packet metadata are set to their default values. After a successful
 * operation packet buffer handles must not be referenced anymore.
 *
 * This call can be used only for packets of an external memory pool (see odp_pool_ext_create()).
 *
 * @param      pool     Pool from which all packet buffers (disassembled packets) originate from
 * @param      pkt_buf  Packet buffers to form a new packet
 * @param      num      Number of packet buffers. Must not exceed max_segs_per_pkt pool capability.
 *
 * @return Handle of the newly formed packet
 * @retval ODP_PACKET_INVALID on failure
 */
odp_packet_t odp_packet_reassemble(odp_pool_t pool, odp_packet_buf_t pkt_buf[], uint32_t num);

/*
 *
 * References
 * ********************************************************
 *
 */

/**
 * Create a static reference to a packet
 *
 * A static reference is used to obtain an additional handle for referring to
 * the entire packet as it is. As long as a packet has multiple (static)
 * references, any of the references (including 'pkt') must not be used to
 * modify the packet in any way - both data and metadata must remain static.
 * The packet may be modified again when there is a single reference left.
 * Static and dynamic references must not be mixed. Results are undefined if
 * these restrictions are not observed.
 *
 * While static references are inflexible they offer efficient way to do,
 * e.g., packet retransmissions. Use odp_packet_ref() or odp_packet_ref_pkt()
 * for more flexible, dynamic references.
 *
 * Packet is not modified on failure.
 *
 * @param pkt    Handle of the packet for which a static reference is
 *               to be created.
 *
 * @return Static reference to the packet
 * @retval ODP_PACKET_INVALID  On failure
 */
odp_packet_t odp_packet_ref_static(odp_packet_t pkt);

/**
 * Create a reference to a packet
 *
 * Returns a new (dynamic) reference to a packet starting the shared part of
 * the data at a specified byte offset. Metadata and data before the offset
 * are not shared with other references of the packet. The rest of the data is
 * shared and must be treated as read only. Initially the returned reference
 * has metadata initialized to default values and does not contain unshared
 * data.  Packet (head) manipulation functions may be used normally to, e.g.,
 * add a unique header onto the shared payload. The shared part of the packet
 * may be modified again when there is a single reference left. Static and
 * dynamic references must not be mixed. Results are undefined if these
 * restrictions are not observed.
 *
 * The packet handle 'pkt' may itself be a (dynamic) reference to a packet.
 *
 * If the caller does not intend to modify either the packet or the new
 * reference to it, odp_packet_ref_static() may be used to create
 * a static reference that is more optimized for that use case.
 *
 * Packet is not modified on failure.
 *
 * @param pkt    Handle of the packet for which a reference is to be
 *               created.
 *
 * @param offset Byte offset in the packet at which the shared part is to
 *               begin. This must be in the range 0 ... odp_packet_len(pkt)-1.
 *
 * @return New reference to the packet
 * @retval ODP_PACKET_INVALID On failure
 */
odp_packet_t odp_packet_ref(odp_packet_t pkt, uint32_t offset);

/**
 * Create a reference to a packet with a header packet
 *
 * This operation is otherwise identical to odp_packet_ref(), but it prepends
 * a supplied 'hdr' packet as the head of the new reference. The resulting
 * packet consists metadata and data of the 'hdr' packet, followed by the
 * shared part of packet 'pkt'.
 *
 * The packet handle ('pkt') may itself be a (dynamic) reference to a packet,
 * but the header packet handle ('hdr') must be unique. Both packets must be
 * have been allocated from the same pool and the handles must not refer to
 * the same packet. Results are undefined if these restrictions are not
 * observed.
 *
 * Packets are not modified on failure. The header packet 'hdr' is consumed
 * on success.
 *
 * @param pkt    Handle of the packet for which a reference is to be
 *               created.
 *
 * @param offset Byte offset in 'pkt' at which the shared part is to
 *               begin. Must be in the range 0 ... odp_packet_len(pkt)-1.
 *
 * @param hdr    Handle of the header packet to be prefixed onto the new
 *               reference. Must be a unique reference.
 *
 * @return New reference the reference packet
 * @retval ODP_PACKET_INVALID On failure
 */
odp_packet_t odp_packet_ref_pkt(odp_packet_t pkt, uint32_t offset,
				odp_packet_t hdr);

/**
 * Test if packet has multiple references
 *
 * A packet that has multiple references share data with other packets. In case
 * of a static reference it also shares metadata. Shared parts must be treated
 * as read only.
 *
 * New references are created with odp_packet_ref_static(), odp_packet_ref() and
 * odp_packet_ref_pkt() calls. The intent of multiple references is to avoid
 * packet copies, however some implementations may do a packet copy for some of
 * the calls. If a copy is done, the new reference is actually a new, unique
 * packet and this function returns '0' for it. When a real reference is
 * created (instead of a copy), this function returns '1' for both packets
 * (the original packet and the new reference).
 *
 * @param pkt Packet handle
 *
 * @retval 0  This is the single reference to the packet
 * @retval 1  Packet has multiple references
 */
int odp_packet_has_ref(odp_packet_t pkt);

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
 * Parse packet
 *
 * Parse protocol headers in packet data and update layer/protocol specific
 * metadata (e.g. offsets, errors, protocols, checksum statuses, etc). Parsing
 * starts at 'offset', which is the first header byte of protocol 'param.proto'.
 * Parameter 'param.last_layer' defines the last layer application requests
 * to check. Use ODP_PROTO_LAYER_ALL for all layers. A successful operation
 * sets (or resets) packet metadata for all layers from the layer of
 * 'param.proto' to the application defined last layer. In addition, offset
 * (and pointer) to the next layer is set. Other layer/protocol specific
 * metadata have undefined values. When operation fails, all layer/protocol
 * specific metadata have undefined values.
 *
 * @param pkt     Packet handle
 * @param offset  Byte offset into the packet
 * @param param   Parse parameters. Proto and last_layer fields must be set.
 *                Clear all check bits that are not used.
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int odp_packet_parse(odp_packet_t pkt, uint32_t offset,
		     const odp_packet_parse_param_t *param);

/**
 * Parse multiple packets
 *
 * Otherwise like odp_packet_parse(), but parses multiple packets. Packets may
 * have unique offsets, but must start with the same protocol. The same
 * parse parameters are applied to all packets.
 *
 * @param pkt     Packet handle array
 * @param offset  Byte offsets into the packets
 * @param num     Number of packets and offsets
 * @param param   Parse parameters. Proto and last_layer fields must be set.
 *                Clear all check bits that are not used.
 *
 * @return Number of packets parsed successfully (0 ... num)
 * @retval <0 on failure
 */
int odp_packet_parse_multi(const odp_packet_t pkt[], const uint32_t offset[],
			   int num, const odp_packet_parse_param_t *param);

/**
 * Read parse results
 *
 * Read out the most commonly used packet parse results. The same information is
 * available through individual function calls, but this call may be more
 * efficient when reading multiple results from a packet.
 *
 * @param      pkt     Packet handle
 * @param[out] result  Pointer for parse result output
 */
void odp_packet_parse_result(odp_packet_t pkt,
			     odp_packet_parse_result_t *result);

/**
 * Read parse results from multiple packets
 *
 * Otherwise same functionality as odp_packet_parse_result() but handles
 * multiple packets.
 *
 * @param      pkt     Packet handle array
 * @param[out] result  Parse result array for output
 * @param      num     Number of packets and results
 */
void odp_packet_parse_result_multi(const odp_packet_t pkt[],
				   odp_packet_parse_result_t *result[],
				   int num);

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
 * Set packet input interface
 *
 * Set packet input interface to a valid packet IO handle or ODP_PKTIO_INVALID.
 * An application may use this for testing or other purposes, when perception
 * of the packet input interface need to be changed. The call updates both
 * input interface handle (odp_packet_input()) and index
 * (odp_packet_input_index()).
 *
 * @param pkt   Packet handle
 * @param pktio Handle to a valid packet input interface or ODP_PKTIO_INVALID.
 *              ODP_PKTIO_INVALID indicates that the packet was not received by
 *              any packet IO interface.
 */
void odp_packet_input_set(odp_packet_t pkt, odp_pktio_t pktio);

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
 * Return previously stored user context pointer. If not otherwise documented,
 * the pointer value is maintained over packet manipulating operations.
 * Implementation initializes the pointer value to NULL during new packet
 * creation (e.g. alloc and packet input) and reset.
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
 * @param pkt       Packet handle
 * @param user_ptr  User context pointer
 */
void odp_packet_user_ptr_set(odp_packet_t pkt, const void *user_ptr);

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
 * Check user flag
 *
 * Implementation clears user flag during new packet creation (e.g. alloc and packet input)
 * and reset. User may set the flag with odp_packet_user_flag_set(). Implementation never
 * sets the flag, only clears it. The flag may be useful e.g. to mark when the user area
 * content is valid.
 *
 * @param pkt   Packet handle
 *
 * @retval 0    User flag is clear
 * @retval !0   User flag is set
 */
int odp_packet_user_flag(odp_packet_t pkt);

/**
 * Set user flag
 *
 * Set (or clear) the user flag.
 *
 * @param pkt   Packet handle
 * @param val   New value for the flag. Zero clears the flag, other values set the flag.
 */
void odp_packet_user_flag_set(odp_packet_t pkt, int val);

/**
 * Layer 2 start pointer
 *
 * Returns pointer to the start of layer 2. Optionally, outputs number of data
 * bytes in the segment following the pointer. The pointer value is generated
 * from the current layer 2 offset.
 *
 * @param      pkt      Packet handle
 * @param[out] len      Number of data bytes remaining in the segment (output).
 *                      Ignored when NULL.
 *
 * @return Layer 2 start pointer
 * @retval NULL  Layer 2 offset has not been set
 *
 * @see odp_packet_l2_offset(), odp_packet_l2_offset_set(), odp_packet_has_l2()
 */
void *odp_packet_l2_ptr(odp_packet_t pkt, uint32_t *len);

/**
 * Layer 2 start offset
 *
 * Returns offset to the start of layer 2. The offset is calculated from the
 * current odp_packet_data() position in bytes. Packet parsing sets the offset
 * according to parse configuration and layers recognized in the packet. Data
 * start position updating functions (e.g. odp_packet_push_head()) do not modify
 * the offset, but user sets a new value when needed.
 *
 * @param pkt  Packet handle
 *
 * @return Layer 2 start offset
 * @retval ODP_PACKET_OFFSET_INVALID  Layer 2 offset has not been set
 *
 * @see odp_packet_l2_offset_set(), odp_packet_has_l2()
 */
uint32_t odp_packet_l2_offset(odp_packet_t pkt);

/**
 * Set layer 2 start offset
 *
 * Set offset to the start of layer 2. The offset is calculated from the current
 * odp_packet_data() position in bytes. Offset must not exceed packet data
 * length. Offset is not modified on an error.
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
 * Returns pointer to the start of layer 3. Optionally, outputs number of data
 * bytes in the segment following the pointer. The pointer value is generated
 * from the current layer 3 offset.
 *
 * @param      pkt      Packet handle
 * @param[out] len      Number of data bytes remaining in the segment (output).
 *                      Ignored when NULL.
 *
 * @return Layer 3 start pointer
 * @retval NULL  Layer 3 offset has not been set
 *
 * @see odp_packet_l3_offset(), odp_packet_l3_offset_set(), odp_packet_has_l3()
 */
void *odp_packet_l3_ptr(odp_packet_t pkt, uint32_t *len);

/**
 * Layer 3 start offset
 *
 * Returns offset to the start of layer 3. The offset is calculated from the
 * current odp_packet_data() position in bytes. Packet parsing sets the offset
 * according to parse configuration and layers recognized in the packet. Data
 * start position updating functions (e.g. odp_packet_push_head()) do not modify
 * the offset, but user sets a new value when needed.
 *
 * @param pkt  Packet handle
 *
 * @return Layer 3 start offset
 * @retval ODP_PACKET_OFFSET_INVALID  Layer 3 offset has not been set
 *
 * @see odp_packet_l3_offset_set(), odp_packet_has_l3()
 */
uint32_t odp_packet_l3_offset(odp_packet_t pkt);

/**
 * Set layer 3 start offset
 *
 * Set offset to the start of layer 3. The offset is calculated from the current
 * odp_packet_data() position in bytes. Offset must not exceed packet data
 * length. Offset is not modified on an error.
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
 * Returns pointer to the start of layer 4. Optionally, outputs number of data
 * bytes in the segment following the pointer. The pointer value is generated
 * from the current layer 4 offset.
 *
 * @param      pkt      Packet handle
 * @param[out] len      Number of data bytes remaining in the segment (output).
 *                      Ignored when NULL.
 *
 * @return Layer 4 start pointer
 * @retval NULL  Layer 4 offset has not been set
 *
 * @see odp_packet_l4_offset(), odp_packet_l4_offset_set(), odp_packet_has_l4()
 */
void *odp_packet_l4_ptr(odp_packet_t pkt, uint32_t *len);

/**
 * Layer 4 start offset
 *
 * Returns offset to the start of layer 4. The offset is calculated from the
 * current odp_packet_data() position in bytes. Packet parsing sets the offset
 * according to parse configuration and layers recognized in the packet. Data
 * start position updating functions (e.g. odp_packet_push_head()) do not modify
 * the offset, but user sets a new value when needed.
 *
 * @param pkt  Packet handle
 *
 * @return Layer 4 start offset
 * @retval ODP_PACKET_OFFSET_INVALID  Layer 4 offset has not been set
 *
 * @see odp_packet_l4_offset_set(), odp_packet_has_l4()
 */
uint32_t odp_packet_l4_offset(odp_packet_t pkt);

/**
 * Set layer 4 start offset
 *
 * Set offset to the start of layer 4. The offset is calculated from the current
 * odp_packet_data() position in bytes. Offset must not exceed packet data
 * length. Offset is not modified on an error.
 *
 * @param pkt     Packet handle
 * @param offset  Layer 4 start offset (0 ... odp_packet_len()-1)
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int odp_packet_l4_offset_set(odp_packet_t pkt, uint32_t offset);

/**
 * Layer 2 protocol type
 *
 * Returns layer 2 protocol type. Initial type value is ODP_PROTO_L2_TYPE_NONE.
 *
 * @param      pkt      Packet handle
 *
 * @return Layer 2 protocol type
 */
odp_proto_l2_type_t odp_packet_l2_type(odp_packet_t pkt);

/**
 * Layer 3 protocol type
 *
 * Returns layer 3 protocol type. Initial type value is ODP_PROTO_L3_TYPE_NONE.
 *
 * In addition to protocol types specified in ODP_PROTO_L3_TYPE_* defines,
 * the function may also return other L3 protocol types (e.g. from IEEE
 * EtherTypes list) recognized by the parser. If protocol type is not
 * recognized, ODP_PROTO_L3_TYPE_NONE is returned.
 *
 * @param      pkt      Packet handle
 *
 * @return Layer 3 protocol type
 */
odp_proto_l3_type_t odp_packet_l3_type(odp_packet_t pkt);

/**
 * Layer 4 protocol type
 *
 * Returns layer 4 protocol type. Initial type value is ODP_PROTO_L4_TYPE_NONE.
 *
 * In addition to protocol types specified in ODP_PROTO_L4_TYPE_* defines,
 * the function may also return other L4 protocol types (e.g. from IANA protocol
 * number list) recognized by the parser. If protocol type is not recognized,
 * ODP_PROTO_L4_TYPE_NONE is returned.
 *
 * @param      pkt      Packet handle
 *
 * @return Layer 4 protocol type
 */
odp_proto_l4_type_t odp_packet_l4_type(odp_packet_t pkt);

/**
 * Layer 3 checksum check status
 *
 * Returns the result of the latest layer 3 checksum check done for the packet.
 * The status tells if checksum check was attempted and the result of the
 * attempt. It depends on packet input (or IPSEC) configuration, packet content
 * and implementation capabilities if checksum check is attempted for a packet.
 *
 * @param pkt     Packet handle
 *
 * @return L3 checksum check status
 */
odp_packet_chksum_status_t odp_packet_l3_chksum_status(odp_packet_t pkt);

/**
 * Layer 4 checksum check status
 *
 * Returns the result of the latest layer 4 checksum check done for the packet.
 * The status tells if checksum check was attempted and the result of the
 * attempt. It depends on packet input (or IPSEC) configuration, packet content
 * and implementation capabilities if checksum check is attempted for a packet.
 *
 * When a UDP packet does not have a checksum (e.g. checksum field of a UDP/IPv4
 * packet is zero), checksum check result is ODP_PACKET_CHKSUM_OK.
 *
 * @param pkt     Packet handle
 *
 * @return L4 checksum check status
 */
odp_packet_chksum_status_t odp_packet_l4_chksum_status(odp_packet_t pkt);

/**
 * Layer 3 checksum insertion override
 *
 * Override checksum insertion configuration per packet. This per packet setting
 * overrides a higher level configuration for checksum insertion into a L3
 * header during packet output processing.
 *
 * Calling this function is always allowed but the checksum will not be
 * inserted if the packet is output through a pktio that does not have
 * the relevant checksum insertion enabled.
 *
 * L3 type and L3 offset in packet metadata should provide valid protocol
 * and header offset for checksum insertion purposes.
 *
 * @param pkt     Packet handle
 * @param insert  0: do not insert L3 checksum
 *                1: insert L3 checksum
 *
 * @see odp_packet_l3_offset(), odp_packet_has_ipv4(), odp_packet_has_ipv6()
 */
void odp_packet_l3_chksum_insert(odp_packet_t pkt, int insert);

/**
 * Layer 4 checksum insertion override
 *
 * Override checksum insertion configuration per packet. This per packet setting
 * overrides a higher level configuration for checksum insertion into a L4
 * header during packet output processing.
 *
 * Calling this function is always allowed but the checksum will not be
 * inserted if the packet is output through a pktio that does not have
 * the relevant checksum insertion enabled.
 *
 * L3 type, L4 type, L3 offset and L4 offset in packet metadata should provide
 * valid protocols and header offsets for checksum insertion purposes.
 *
 * @param pkt     Packet handle
 * @param insert  0: do not insert L4 checksum
 *                1: insert L4 checksum
 *
 * @see odp_packet_l3_offset(), odp_packet_has_ipv4(), odp_packet_has_ipv6()
 * @see odp_packet_l4_offset(), odp_packet_has_tcp(), odp_packet_has_udp()
 * @see odp_packet_has_sctp()
 */
void odp_packet_l4_chksum_insert(odp_packet_t pkt, int insert);

/**
 * Ones' complement sum of packet data
 *
 * Returns 16-bit ones' complement sum that was calculated over a portion of
 * packet data during a packet processing operation (e.g. packet input or
 * IPSEC offload). The data range is output with 'range' parameter, and usually
 * includes IP payload (L4 headers and payload). When 'range.length' is zero,
 * the sum has not been calculated. In case of odd number of bytes,
 * calculation uses a zero byte as padding at the end. The sum may be used as
 * part of e.g. UDP/TCP checksum checking, especially with IP fragments.
 *
 * @param      pkt    Packet handle
 * @param[out] range  Data range of the sum (output). The calculation started
 *                    from range.offset and included range.length bytes. When
 *                    range.length is zero, the sum has not been calculated.
 *
 * @return Ones' complement sum over the data range
 */
uint16_t odp_packet_ones_comp(odp_packet_t pkt, odp_packet_data_range_t *range);

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
 * odp_pktio_ts_res().
 *
 * @param pkt  Packet handle
 *
 * @return Timestamp value
 *
 * @see odp_pktio_ts_res(), odp_packet_has_ts(), odp_time_to_ns()
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
 * @see odp_packet_ts(), odp_packet_has_ts(), odp_pktio_ts_from_ns()
 */
void odp_packet_ts_set(odp_packet_t pkt, odp_time_t timestamp);

/**
 * Request Tx timestamp capture
 *
 * Control whether timestamp needs to be captured when this packet is
 * transmitted. By default, Tx timestamping is disabled. This API is allowed to
 * be called always, but the Tx timestamp is not captured if the output packet
 * IO device is not configured to enable timestamping.
 *
 * @param pkt     Packet handle
 * @param enable  0: do not capture timestamp on Tx
 *                1: capture timestamp on Tx
 *
 * @see odp_pktout_ts_read()
 */
void odp_packet_ts_request(odp_packet_t pkt, int enable);

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

/**
 * Classification mark value
 *
 * Get the value of the CLS mark of the packet. The mark value is zero by default, but may be
 * changed by the classification subsystem.
 *
 * @param pkt Packet handle
 *
 * @return mark value
 *
 * @see odp_cls_capability_t::max_mark, odp_pmr_create_opt_t::mark, odp_cls_pmr_create_opt()
 */
uint64_t odp_packet_cls_mark(odp_packet_t pkt);

/**
 * Request Large Send Offload (LSO) for a packet
 *
 * Setup packet metadata which requests LSO segmentation to be performed during packet output.
 * The selected LSO profile specifies details of the segmentation operation to be done. Depending on
 * LSO profile options, additional metadata (e.g. L3/L4 protocol header offsets) may need to be
 * set on the packet.
 *
 * @param pkt      Packet handle
 * @param lso_opt  LSO options
 *
 * @retval 0  On success
 * @retval <0 On failure
 */
int odp_packet_lso_request(odp_packet_t pkt, const odp_packet_lso_opt_t *lso_opt);

/**
 * Clear LSO request from a packet
 *
 * Clears packet metadata not to request LSO segmentation.
 *
 * @param pkt     Packet handle
 */
void odp_packet_lso_request_clr(odp_packet_t pkt);

/**
 * Check if LSO is requested for the packet
 *
 * @param pkt     Packet handle
 *
 * @retval non-zero  LSO is requested
 * @retval 0         LSO is not requested
 */
int odp_packet_has_lso_request(odp_packet_t pkt);

/**
 * Payload data offset
 *
 * Returns offset to the start of payload data. Packet data before this offset is considered as
 * protocol headers. The offset is calculated from the current odp_packet_data() position in bytes.
 * Data start position updating functions (e.g. odp_packet_push_head()) do not modify the offset,
 * but user sets a new value when needed.
 *
 * Packet parsing does not set this offset. Initial offset value is undefined. Application may
 * utilize the offset for internal purposes or when requesting LSO segmentation for the packet.
 *
 * @param pkt     Packet handle
 *
 * @return Payload data offset
 * @retval ODP_PACKET_OFFSET_INVALID  Payload data offset has not been set
 */
uint32_t odp_packet_payload_offset(odp_packet_t pkt);

/**
 * Set payload data start offset
 *
 * Set offset to the start of payload data. The offset is calculated from the current
 * odp_packet_data() position in bytes. Offset must not exceed packet data length. Offset is not
 * modified on an error.
 *
 * @param pkt     Packet handle
 * @param offset  Payload data start offset (0 ... odp_packet_len()-1) or ODP_PACKET_OFFSET_INVALID
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int odp_packet_payload_offset_set(odp_packet_t pkt, uint32_t offset);

/**
 * Enable or disable Tx packet aging
 *
 * Enable or disable Tx packet drop based on packet age. When enabled, packet will be dropped
 * if it is in Tx pktout queue or traffic shapers/schedulers for longer than timeout set.
 *
 * When tmo_ns is
 * !0: Aging is enabled
 *  0: Aging is disabled
 *
 * Aging is disabled by default. Maximum tmo value is defined by max_tx_aging_tmo_ns capa.
 *
 * @param pkt     Packet handle
 * @param tmo_ns  Packet aging drop timeout in nsec. When 0, aging drop is disabled (default).
 *
 * @see odp_pktio_capability_t::max_tx_aging_tmo_ns
 */
void odp_packet_aging_tmo_set(odp_packet_t pkt, uint64_t tmo_ns);

/**
 * Check if packet has Tx aging drop enabled
 *
 * @param pkt Packet handle
 *
 * @return Aging drop timeout if enabled.
 * @retval >0  Aging drop timeout in nano seconds and implies aging drop is enabled.
 * @retval  0  If Aging drop is disabled.
 */
uint64_t odp_packet_aging_tmo(odp_packet_t pkt);

/**
 * Request packet transmit completion
 *
 * Enables or disables packet transmit completion request for the packet. Completion may be
 * requested either in event (#ODP_PACKET_TX_COMPL_EVENT) or poll (#ODP_PACKET_TX_COMPL_POLL) mode.
 * When event mode is enabled, an event of type ODP_EVENT_PACKET_TX_COMPL will be sent to the
 * destination queue to signal transmit completion. When poll mode is enabled,
 * odp_packet_tx_compl_done() is used with the provided completion identifier to check the
 * completion. In both cases, transmit completion is reported only after pktio interface has
 * finished processing the packet.
 *
 * A previously enabled request can be disabled by setting the mode to ODP_PACKET_TX_COMPL_DISABLED.
 * Transmit completion request is disabled by default.
 *
 * @param pkt     Packet handle
 * @param opt     Packet transmit completion request options
 *
 * @retval 0  On success
 * @retval <0 On failure
 */
int odp_packet_tx_compl_request(odp_packet_t pkt, const odp_packet_tx_compl_opt_t *opt);

/**
 * Check if packet transmit completion is requested
 *
 * @param pkt     Packet handle
 *
 * @retval non-zero  Transmit completion is requested
 * @retval 0         Transmit completion is not requested
 */
int odp_packet_has_tx_compl_request(odp_packet_t pkt);

/**
 * Set packet free control option
 *
 * This option enables application to control which packets are freed/not freed back into pool
 * after ODP implementation has finished processing those. The option affects only packets that
 * are transmitted directly through a packet output interface (also with LSO), i.e. packets
 * transmitted through inline IPsec or TM are not affected.
 *
 * When the option is set to #ODP_PACKET_FREE_CTRL_DONT_FREE, packet output interface will not free
 * the packet after transmit and application may reuse the packet as soon as its transmit is
 * complete (see e.g. odp_packet_tx_compl_done()).
 *
 * The option must not be enabled on packets that have multiple references.
 *
 * Check packet IO interface capability free_ctrl.dont_free (odp_pktio_capability_t::dont_free) for
 * the option support. When an interface does not support the option, it ignores the value.
 *
 * The default value is #ODP_PACKET_FREE_CTRL_DISABLED.
 *
 * @param pkt   Packet handle
 * @param ctrl  Packet free control option value
 */
void odp_packet_free_ctrl_set(odp_packet_t pkt, odp_packet_free_ctrl_t ctrl);

/**
 * Returns packet free control option value
 *
 * @param pkt   Packet handle
 *
 * @return The current value of the packet free control option
 */
odp_packet_free_ctrl_t odp_packet_free_ctrl(odp_packet_t pkt);

/**
 * Request packet proto stats.
 *
 * The statistics enabled in the proto stats object are updated for the packet in
 * packet output when the packet is transmitted or dropped. The statistics update
 * is done as the last step of output processing after possible packet
 * transformations (e.g. fragmentation, IPsec) that may occur. If a packet is
 * fragmented or segmented to multiple packets as part of output processing, all
 * the resulting packets inherit the proto stats object association from the
 * original packet.
 *
 * The relevant octet counts will be updated with the actual packet length at
 * the time of transmission or drop plus the respective adjustment value passed
 * in the 'opt' parameter. The octet counts thus include possible additional
 * headers added by ODP during packet output (e.g. ESP header added by inline
 * outbound IPsec processing). Ethernet padding and FCS are not included in the
 * octet counts. The adjustment value is added only if the respective capability
 * field is true and otherwise ignored.
 *
 * @param pkt   Packet handle
 * @param opt   Proto stats options. If NULL, then proto stats update is
 *              disabled for this packet.
 *
 * @see odp_proto_stats_capability_t::tx
 */
void odp_packet_proto_stats_request(odp_packet_t pkt, odp_packet_proto_stats_opt_t *opt);

/**
 * Get proto stats object.
 *
 * Get the proto stats object associated with the given packet.
 *
 * @param pkt Packet handle
 *
 * @return Proto stats object handle or ODP_PROTO_STATS_INVALID if not set.
 */
odp_proto_stats_t odp_packet_proto_stats(odp_packet_t pkt);

/*
 *
 * Packet vector handling routines
 * ********************************************************
 *
 */

/**
 * Get packet vector handle from event
 *
 * Converts an ODP_EVENT_PACKET_VECTOR type event to a packet vector handle
 *
 * @param ev Event handle
 * @return Packet vector handle
 *
 * @see odp_event_type()
 */
odp_packet_vector_t odp_packet_vector_from_event(odp_event_t ev);

/**
 * Convert packet vector handle to event
 *
 * @param pktv Packet vector handle
 *
 * @return Event handle
 */
odp_event_t odp_packet_vector_to_event(odp_packet_vector_t pktv);

/**
 * Allocate a packet vector from a packet vector pool
 *
 * Allocates a packet vector from the specified packet vector pool.
 * The pool must have been created with the ODP_POOL_VECTOR type.
 *
 * @param pool Packet vector pool handle
 *
 * @return Handle of allocated packet vector
 * @retval ODP_PACKET_VECTOR_INVALID  Packet vector could not be allocated
 *
 * @note A newly allocated vector shall not contain any packets, instead, alloc
 * operation shall reserve the space for odp_pool_param_t::vector::max_size packets.
 */
odp_packet_vector_t odp_packet_vector_alloc(odp_pool_t pool);

/**
 * Free packet vector
 *
 * Frees the packet vector into the packet vector pool it was allocated from.
 *
 * @param pktv Packet vector handle
 *
 * @note This API just frees the vector, not any packets inside the vector.
 * Application can use odp_event_free() to free the vector and packets inside
 * the vector.
 */
void odp_packet_vector_free(odp_packet_vector_t pktv);

/**
 * Get packet vector table
 *
 * Packet vector table is an array of packets (odp_packet_t) stored in
 * contiguous memory location. Upon completion of this API, the implementation
 * returns the packet table pointer in pkt_tbl.
 *
 * @param      pktv    Packet vector handle
 * @param[out] pkt_tbl Points to packet vector table
 *
 * @return Number of packets available in the vector.
 *
 * @note When pktin subsystem is producing the packet vectors,
 * odp_pktin_vector_config_t::pool shall be used to configure the pool to form
 * the vector table.
 *
 * @note The maximum number of packets this vector can hold is defined by
 * odp_pool_param_t::vector::max_size. The return value of this function will not
 * be greater than odp_pool_param_t::vector::max_size
 *
 * @note The pkt_tbl points to the packet vector table. Application can edit the
 * packet handles in the table directly (up to odp_pool_param_t::vector::max_size).
 * Application must update the size of the table using odp_packet_vector_size_set()
 * when there is a change in the size of the vector.
 *
 * @note Invalid packet handles (ODP_PACKET_INVALID) are not allowed to be
 * stored in the table to allow consumers of odp_packet_vector_t handle to have
 * optimized implementation. So consumption of packets in the middle of the
 * vector would call for moving the remaining packets up to form a contiguous
 * array of packets and update the size of the new vector using
 * odp_packet_vector_size_set().
 *
 * @note The table memory is backed by a vector pool buffer. The ownership of
 * the table memory is linked to the ownership of the event. I.e. after sending
 * the event to a queue, the sender loses ownership to the table also.
 */
uint32_t odp_packet_vector_tbl(odp_packet_vector_t pktv, odp_packet_t **pkt_tbl);

/**
 * Number of packets in a vector
 *
 * @param pktv Packet vector handle
 *
 * @return The number of packets available in the vector
 */
uint32_t odp_packet_vector_size(odp_packet_vector_t pktv);

/**
 * Set the number of packets stored in a vector
 *
 * Update the number of packets stored in a vector. When the application is
 * producing a packet vector, this function shall be used by the application
 * to set the number of packets available in this vector.
 *
 * @param pktv Packet vector handle
 * @param size Number of packets in this vector
 *
 * @note The maximum number of packets this vector can hold is defined by
 * odp_pool_param_t::vector::max_size. The size value must not be greater than
 * odp_pool_param_t::vector::max_size
 *
 * @note All handles in the vector table (0 .. size - 1) need to be valid packet
 * handles.
 *
 * @see odp_packet_vector_tbl()
 *
 */
void odp_packet_vector_size_set(odp_packet_vector_t pktv, uint32_t size);

/**
 * Packet vector user area
 *
 * Returns pointer to the user area associated with the packet vector. Size of the area is fixed
 * and defined in vector pool parameters.
 *
 * @param  pktv  Packet vector handle
 *
 * @return       Pointer to the user area of the packet vector
 * @retval NULL  The packet vector does not have user area
 */
void *odp_packet_vector_user_area(odp_packet_vector_t pktv);

/**
 * Check user flag
 *
 * Implementation clears user flag during new packet vector creation (e.g. alloc and packet input)
 * and reset. User may set the flag with odp_packet_vector_user_flag_set(). Implementation never
 * sets the flag, only clears it. The flag may be useful e.g. to mark when the user area
 * content is valid.
 *
 * @param pktv  Packet vector handle
 *
 * @retval 0    User flag is clear
 * @retval !0   User flag is set
 */
int odp_packet_vector_user_flag(odp_packet_vector_t pktv);

/**
 * Set user flag
 *
 * Set (or clear) the user flag.
 *
 * @param pktv  Packet vector handle
 * @param val   New value for the flag. Zero clears the flag, other values set the flag.
 */
void odp_packet_vector_user_flag_set(odp_packet_vector_t pktv, int val);

/**
 * Check that packet vector is valid
 *
 * This function can be used for debugging purposes to check if a packet vector handle represents
 * a valid packet vector. The level of error checks depends on the implementation. Considerable
 * number of cpu cycles may be consumed depending on the level. The call should not crash if
 * the packet vector handle is corrupted.
 *
 * @param pktv Packet vector handle
 *
 * @retval 0 Packet vector is not valid
 * @retval 1 Packet vector is valid
 */
int odp_packet_vector_valid(odp_packet_vector_t pktv);

/**
 * Packet vector pool
 *
 * Returns handle to the packet vector pool where the packet vector was
 * allocated from.
 *
 * @param pktv Packet vector handle
 *
 * @return Packet vector pool handle
 */
odp_pool_t odp_packet_vector_pool(odp_packet_vector_t pktv);

/**
 * Print packet vector debug information
 *
 * Print all packet vector debug information to ODP log.
 *
 * @param pktv Packet vector handle
 */
void odp_packet_vector_print(odp_packet_vector_t pktv);

/**
 * Get printable value for an odp_packet_vector_t
 *
 * @param hdl  odp_packet_vector_t handle to be printed
 *
 * @return uint64_t value that can be used to print/display this handle
 *
 * @note This routine is intended to be used for diagnostic purposes to enable
 * applications to generate a printable value that represents an
 * odp_packet_vector_t handle.
 */
uint64_t odp_packet_vector_to_u64(odp_packet_vector_t hdl);

/**
 * Check reassembly status of the packet
 *
 * @param  pkt Packet handle
 * @return     Reassembly status
 *
 */
odp_packet_reass_status_t odp_packet_reass_status(odp_packet_t pkt);

/*
 *
 * Packet Tx completion event handling routines
 * ********************************************************
 */

/**
 * Get packet Tx completion handle from event
 *
 * Converts an ODP_EVENT_PACKET_TX_COMPL type event to packet Tx completion
 * handle.
 *
 * @param ev Event handle
 *
 * @return Packet Tx completion handle
 *
 * @see odp_event_type()
 */
odp_packet_tx_compl_t odp_packet_tx_compl_from_event(odp_event_t ev);

/** Convert packet Tx completion to event
  *
  * @param tx_compl Packet Tx completion
  *
  * @return Event handle
  */
odp_event_t odp_packet_tx_compl_to_event(odp_packet_tx_compl_t tx_compl);

/**
 * Free packet Tx completion
 *
 * Frees the packet Tx completion back to platform. It frees packet Tx
 * completion that gets allocated as part of packet Tx completion request
 * for a given packet.
 *
 * @param tx_compl Packet Tx completion handle
 *
 * @see odp_packet_tx_completion_request()
 */
void odp_packet_tx_compl_free(odp_packet_tx_compl_t tx_compl);

/**
 * User context pointer
 *
 * Return user context pointer from packet Tx completion event.
 * This is the same value set to packet using odp_packet_user_ptr_set().
 *
 * @param tx_compl  Packet Tx completion handle
 *
 * @return User context pointer
 *
 * @see odp_packet_user_ptr_set()
 */
void *odp_packet_tx_compl_user_ptr(odp_packet_tx_compl_t tx_compl);

/**
 * Check packet transmit completion
 *
 * Checks if a previously sent packet with a ODP_PACKET_TX_COMPL_POLL type transmit completion
 * request (see odp_packet_tx_compl_opt_t) has been transmitted. The packet send function call
 * clears completion identifier status, and 0 is returned while the transmit is in progress.
 * When >0 is returned, transmit of the packet is complete and the completion identifier may be
 * reused for another transmit.
 *
 * When transmit of a packet is complete, it indicates that transmit of other packets sent
 * before the packet through the same queue have also completed.
 *
 * Returns initially 0 for all configured completion identifiers.
 *
 * @param pktio          Packet IO interface that was used to send the packet
 * @param compl_id       Completion identifier that was used in the transmit completion request
 *
 * @retval >0  Packet transmit is complete
 * @retval  0  Packet transmit is not complete
 * @retval <0  Failed to read packet transmit status
 */
int odp_packet_tx_compl_done(odp_pktio_t pktio, uint32_t compl_id);

/*
 *
 * Debugging
 * ********************************************************
 *
 */

/**
 * Print packet debug information
 *
 * Print all packet debug information to the ODP log.
 *
 * @param pkt  Packet handle
 */
void odp_packet_print(odp_packet_t pkt);

/**
 * Print packet data
 *
 * Print packet debug information with packet data to the ODP log. Operation
 * prints 'len' bytes of packet data starting from 'offset' byte. Offset plus
 * length must not exceed packet length (odp_packet_len()).
 *
 * @param pkt     Packet handle
 * @param offset  Byte offset into the packet
 * @param len     Number of bytes to print
 */
void odp_packet_print_data(odp_packet_t pkt, uint32_t offset, uint32_t len);

/**
 * Check that packet is valid
 *
 * This function can be used for debugging purposes to check if a packet handle represents
 * a valid packet. The level of error checks depends on the implementation. Considerable number of
 * cpu cycles may be consumed depending on the level. The call should not crash if the packet
 * handle is corrupted.
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
