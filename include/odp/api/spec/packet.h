/* Copyright (c) 2013-2018, Linaro Limited
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

/**
 * @typedef odp_proto_l2_type_t
 * Layer 2 protocol type
 */

/**
 * @def ODP_PROTO_L2_TYPE_NONE
 * Layer 2 protocol type not defined
 *
 * @def ODP_PROTO_L2_TYPE_ETH
 * Layer 2 protocol is Ethernet
 */

/**
 * @typedef odp_proto_l3_type_t
 * Layer 3 protocol type
 */

/**
 * @def ODP_PROTO_L3_TYPE_NONE
 * Layer 3 protocol type not defined
 *
 * @def ODP_PROTO_L3_TYPE_ARP
 * Layer 3 protocol is ARP
 *
 * @def ODP_PROTO_L3_TYPE_RARP
 * Layer 3 protocol is RARP
 *
 * @def ODP_PROTO_L3_TYPE_MPLS
 * Layer 3 protocol is MPLS
 *
 * @def ODP_PROTO_L3_TYPE_IPV4
 * Layer 3 protocol type is IPv4
 *
 * @def ODP_PROTO_L3_TYPE_IPV6
 * Layer 3 protocol type is IPv6
 */

/**
 * @def ODP_PROTO_L4_TYPE_NONE
 * Layer 4 protocol type not defined
 *
 * @def ODP_PROTO_L4_TYPE_ICMPV4
 * Layer 4 protocol type is ICMPv4
 *
 * @def ODP_PROTO_L4_TYPE_IGMP
 * Layer 4 protocol type is IGMP
 *
 * @def ODP_PROTO_L4_TYPE_IPV4
 * Layer 4 protocol type is IPv4
 *
 * @def ODP_PROTO_L4_TYPE_TCP
 * Layer 4 protocol type is TCP
 *
 * @def ODP_PROTO_L4_TYPE_UDP
 * Layer 4 protocol type is UDP
 *
 * @def ODP_PROTO_L4_TYPE_IPV6
 * Layer 4 protocol type is IPv6
 *
 * @def ODP_PROTO_L4_TYPE_GRE
 * Layer 4 protocol type is GRE
 *
 * @def ODP_PROTO_L4_TYPE_ESP
 * Layer 4 protocol type is IPSEC ESP
 *
 * @def ODP_PROTO_L4_TYPE_AH
 * Layer 4 protocol type is IPSEC AH
 *
 * @def ODP_PROTO_L4_TYPE_ICMPV6
 * Layer 4 protocol type is ICMPv6
 *
 * @def ODP_PROTO_L4_TYPE_NO_NEXT
 * Layer 4 protocol type is "No Next Header".
 * Protocol / next header number is 59.
 *
 * @def ODP_PROTO_L4_TYPE_IPCOMP
 * Layer 4 protocol type is IP Payload Compression Protocol
 *
 * @def ODP_PROTO_L4_TYPE_SCTP
 * Layer 4 protocol type is SCTP
 *
 * @def ODP_PROTO_L4_TYPE_ROHC
 * Layer 4 protocol type is ROHC
 */

/**
 * Protocol
 */
typedef enum odp_proto_t {
	/** No protocol defined */
	ODP_PROTO_NONE = 0,

	/** Ethernet (including VLAN) */
	ODP_PROTO_ETH,

	/** IP version 4 */
	ODP_PROTO_IPV4,

	/** IP version 6 */
	ODP_PROTO_IPV6

} odp_proto_t;

/**
 * Protocol layer
 */
typedef enum odp_proto_layer_t {
	/** No layers */
	ODP_PROTO_LAYER_NONE = 0,

	/** Layer L2 protocols (Ethernet, VLAN, etc) */
	ODP_PROTO_LAYER_L2,

	/** Layer L3 protocols (IPv4, IPv6, ICMP, IPSEC, etc) */
	ODP_PROTO_LAYER_L3,

	/** Layer L4 protocols (UDP, TCP, SCTP) */
	ODP_PROTO_LAYER_L4,

	/** All layers */
	ODP_PROTO_LAYER_ALL

} odp_proto_layer_t;

/**
 * Packet API data range specifier
 */
typedef struct odp_packet_data_range {
	/** Offset from beginning of packet */
	uint32_t offset;

	/** Length of data to operate on */
	uint32_t length;

} odp_packet_data_range_t;

/**
 * Checksum check status in packet
 */
typedef enum odp_packet_chksum_status_t {
	/** Checksum was not checked. Checksum check was not attempted or
	  * the attempt failed. */
	ODP_PACKET_CHKSUM_UNKNOWN = 0,

	/** Checksum was checked and it was not correct */
	ODP_PACKET_CHKSUM_BAD,

	/** Checksum was checked and it was correct */
	ODP_PACKET_CHKSUM_OK

} odp_packet_chksum_status_t;

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
 * @param tail           Pointer to output the tail packet handle
 *
 * @retval 0   Operation successful, old pointers remain valid
 * @retval >0  Operation successful, old pointers need to be updated
 * @retval <0  Operation failed
 */
int odp_packet_split(odp_packet_t *pkt, uint32_t len, odp_packet_t *tail);

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
 * Flags to control packet data checksum checking
 */
typedef union odp_proto_chksums_t {
	/** Individual checksum bits. */
	struct {
		/** IPv4 header checksum */
		uint32_t ipv4   : 1;

		/** UDP checksum */
		uint32_t udp    : 1;

		/** TCP checksum */
		uint32_t tcp    : 1;

		/** SCTP checksum */
		uint32_t sctp   : 1;

	} chksum;

	/** All checksum bits. This can be used to set/clear all flags. */
	uint32_t all_chksum;

} odp_proto_chksums_t;

/**
 * Packet parse parameters
 */
typedef struct odp_packet_parse_param_t {
	/** Protocol header at parse starting point. Valid values for this
	 *  field are: ODP_PROTO_ETH, ODP_PROTO_IPV4, ODP_PROTO_IPV6. */
	odp_proto_t proto;

	/** Continue parsing until this layer. Must be the same or higher
	 *  layer than the layer of 'proto'. */
	odp_proto_layer_t last_layer;

	/** Flags to control payload data checksums checks up to the selected
	 *  parse layer. Checksum checking status can be queried for each packet
	 *  with odp_packet_l3_chksum_status() and
	 *  odp_packet_l4_chksum_status().
	 */
	odp_proto_chksums_t chksums;

} odp_packet_parse_param_t;

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

/** Packet parse results */
typedef struct odp_packet_parse_result_t {
	/** Parse result flags */
	odp_packet_parse_result_flag_t flag;

	/** @see odp_packet_len() */
	uint32_t packet_len;

	/** @see odp_packet_l2_offset() */
	uint32_t l2_offset;
	/** @see odp_packet_l3_offset() */
	uint32_t l3_offset;
	/** @see odp_packet_l4_offset() */
	uint32_t l4_offset;

	/** @see odp_packet_l3_chksum_status() */
	odp_packet_chksum_status_t l3_chksum_status;
	/** @see odp_packet_l4_chksum_status() */
	odp_packet_chksum_status_t l4_chksum_status;

	/** @see odp_packet_l2_type() */
	odp_proto_l2_type_t l2_type;
	/** @see odp_packet_l3_type() */
	odp_proto_l3_type_t l3_type;
	/** @see odp_packet_l4_type() */
	odp_proto_l4_type_t l4_type;

} odp_packet_parse_result_t;

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
 * @param pkt     Packet handle
 * @param insert  0: do not insert L3 checksum
 *                1: insert L3 checksum
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
 * @param pkt     Packet handle
 * @param insert  0: do not insert L4 checksum
 *                1: insert L4 checksum
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
