/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_CONFIG_INTERNAL_H_
#define ODP_CONFIG_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Maximum number of pools
 */
#define ODP_CONFIG_POOLS 64

/*
 * Maximum number of queues
 */
#define ODP_CONFIG_QUEUES 1024

/*
 * Maximum number of ordered locks per queue
 */
#define CONFIG_QUEUE_MAX_ORD_LOCKS 4

/*
 * Maximum number of packet IO resources
 */
#define ODP_CONFIG_PKTIO_ENTRIES 64

/*
 * Minimum buffer alignment
 *
 * This defines the minimum supported buffer alignment. Requests for values
 * below this will be rounded up to this value.
 */
#define ODP_CONFIG_BUFFER_ALIGN_MIN 64

/*
 * Maximum buffer alignment
 *
 * This defines the maximum supported buffer alignment. Requests for values
 * above this will fail.
 */
#define ODP_CONFIG_BUFFER_ALIGN_MAX (4 * 1024)

/*
 * Default packet headroom
 *
 * This defines the minimum number of headroom bytes that newly created packets
 * have by default. The default apply to both ODP packet input and user
 * allocated packets. Implementations may reserve a larger than minimum headroom
 * size e.g. due to HW or a protocol specific alignment requirement.
 *
 * @internal In odp-linux implementation:
 * The default value (66) allows a 1500-byte packet to be received into a single
 * segment with Ethernet offset alignment and room for some header expansion.
 */
#define CONFIG_PACKET_HEADROOM 66

/*
 * Default packet tailroom
 *
 * This defines the minimum number of tailroom bytes that newly created packets
 * have by default. The default apply to both ODP packet input and user
 * allocated packets. Implementations are free to add to this as desired
 * without restriction. Note that most implementations will automatically
 * consider any unused portion of the last segment of a packet as tailroom
 */
#define CONFIG_PACKET_TAILROOM 0

/*
 * Maximum number of segments per packet
 */
#define CONFIG_PACKET_MAX_SEGS 6

/*
 * Maximum packet segment size including head- and tailrooms
 */
#define CONFIG_PACKET_SEG_SIZE (8 * 1024)

/* Maximum data length in a segment
 *
 * The user defined segment length (seg_len in odp_pool_param_t) must not
 * be larger than this.
*/
#define CONFIG_PACKET_MAX_SEG_LEN  (CONFIG_PACKET_SEG_SIZE - \
				    CONFIG_PACKET_HEADROOM - \
				    CONFIG_PACKET_TAILROOM)

/*
 * Minimum packet segment length
 *
 * This defines the minimum packet segment buffer length in bytes. The user
 * defined segment length (seg_len in odp_pool_param_t) will be rounded up into
 * this value.
 */
#define CONFIG_PACKET_SEG_LEN_MIN CONFIG_PACKET_MAX_SEG_LEN

/* Maximum number of shared memory blocks.
 *
 * This the the number of separate SHM areas that can be reserved concurrently
 */
#define ODP_CONFIG_SHM_BLOCKS (ODP_CONFIG_POOLS + 48)

/*
 * Size of the virtual address space pre-reserver for ISHM
 *
 * This is just virtual space preallocation size, not memory allocation.
 * This address space is used by ISHM to map things at a common address in
 * all ODP threads (when the _ODP_ISHM_SINGLE_VA flag is used).
 * In bytes.
 */
#define ODP_CONFIG_ISHM_VA_PREALLOC_SZ (536870912L)

/* Maximum number of shared memory blocks available on the driver interface.
 *
 * This the the number of separate SHM areas that can be reserved concurrently
 */
#define ODPDRV_CONFIG_SHM_BLOCKS 48

/* Maximum event burst size
 *
 * This controls the burst size on various enqueue, dequeue, etc calls. Large
 * burst size improves throughput, but may degrade QoS (increase latency).
 */
#define CONFIG_BURST_SIZE 16

/*
 * Maximum number of events in a pool
 */
#define CONFIG_POOL_MAX_NUM (1 * 1024 * 1024)

/*
 * Maximum number of events in a thread local pool cache
 */
#define CONFIG_POOL_CACHE_SIZE 256

#ifdef __cplusplus
}
#endif

#endif
