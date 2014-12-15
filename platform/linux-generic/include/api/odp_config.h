/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP configuration
 */

#ifndef ODP_CONFIG_H_
#define ODP_CONFIG_H_

#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup odp_compiler_optim
 *  Macro for maximum number of resources in ODP.
 *  @{
 */

/**
 * Maximum number of threads
 */
#define ODP_CONFIG_MAX_THREADS  128

/**
 * Maximum number of buffer pools
 */
#define ODP_CONFIG_BUFFER_POOLS 16

/**
 * Maximum number of queues
 */
#define ODP_CONFIG_QUEUES       1024

/**
 * Number of scheduling priorities
 */
#define ODP_CONFIG_SCHED_PRIOS  8

/**
 * Maximum number of packet IO resources
 */
#define ODP_CONFIG_PKTIO_ENTRIES 64

/**
 * Minimum supported buffer alignment
 * This defines the minimum buffer alignment request. Requests for
 * values below this will be rounded up to this value.
 */
#define ODP_CONFIG_BUFFER_ALIGN_MIN 8

/**
 * Maximum supported buffer alignment
 * This defines the maximum supported buffer alignment. Requests for
 * values above this will fail.
 */

#define ODP_CONFIG_BUFFER_ALIGN_MAX (4*1024)

/**
 * Default packet headroom
 * This is default headroom that will be applied to any buffer pool created
 * for packets. Note that while headroom serves to reserve space for packet
 * header expansion via the odp_packet_push_head() routine, it also serves to
 * align packets within the buffer. ODP packet buffers always have a minimum
 * of 8 byte alignment, so the headroom can be used to offset packets so that,
 * for example, a 14 byte standard Ethernet header ends on a 4 byte boundary
 * so that the following IP header begins on a 4 byte alignment. Note also
 * that this is the minimum headroom value that the application
 * requires. Implementations are free to add to whatever value is specified
 * here in multiples of 8 bytes to preserve the implied alignment
 * specification. The specific default shown here allows a 1500-byte packet
 * to be received into a single segment with Ethernet offset alignment and
 * room for some header expansion.
 */
#define ODP_CONFIG_PACKET_HEADROOM 66

/**
 * Default packet tailroom
 * This is the default tailroom that will be applied to any buffer pool
 * created for packets. This specifies the minimum tailroom value that the
 * application requires. Implementations are free to add to this as desired
 * without restriction. Note that most implementations will automatically
 * consider any unused portion of the last segment of a packet as tailroom
 */
#define ODP_CONFIG_PACKET_TAILROOM 0

/**
 * Minimum packet segment size
 * This defines the minimum allowable size for packet segments. It exists to
 * ensure that the application can have a reasonable expectation that all
 * packet headers will reside in the first packet segment. Note that this
 * value MUST be a multiple of 8.
 *
 * This is the granularity of segmented buffers/packets. Note that this is
 * currently only applicable to buffers of type ODP_BUFFER_TYPE_PACKET. It is
 * sized for now to be large enough to support 1536-byte packets with the
 * default headroom shown above, since the raw socket interface does not
 * at present support scatter/gather I/O. This is subject to the
 * ODP_CONFIG_PACKET_BUF_MIN_LEN configuration shown above and MUST be a
 * multiple of ODP_CACHE_LINE_SIZE. 1664 is used here as a default since it is
 * a multiple of both 64 and 128, which are the most common cache line sizes.
 * Adjust as needed for your platform.
 */
#define ODP_CONFIG_PACKET_BUF_LEN_MIN (1664)

/**
 * Maximum packet length supported
 * MUST be an integral number of segments and SHOULD be large enough to
 * accommodate jumbo packets (9K). Attempts to allocate or extend packets to
 * sizes larger than this limit will fail.
 */
#define ODP_CONFIG_PACKET_BUF_LEN_MAX (ODP_CONFIG_PACKET_BUF_LEN_MIN*6)

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
