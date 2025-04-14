/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2018 Linaro Limited
 * Copyright (c) 2019-2023 Nokia
 */

#ifndef ODP_CONFIG_INTERNAL_H_
#define ODP_CONFIG_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Maximum number of supported CPU identifiers. The maximum supported CPU ID is
 * CONFIG_NUM_CPU_IDS - 1. Note that the maximum number of ODP threads is
 * defined by ODP_THREAD_COUNT_MAX.
 */
#define CONFIG_NUM_CPU_IDS 256

/*
 * Maximum number of packet IO resources
 */
#define CONFIG_PKTIO_ENTRIES 64

/*
 * Pools reserved for internal usage, 1 for IPsec status events and one per packet
 * I/O for TX completion
 */
#define CONFIG_INTERNAL_POOLS (1 + CONFIG_PKTIO_ENTRIES)

/*
 * Maximum number of pools.
 */
#define CONFIG_POOLS 128

/*
 * Queues reserved for ODP internal use
 */
#define CONFIG_INTERNAL_QUEUES 64

/*
 * Maximum number of plain ODP queues
 */
#define CONFIG_MAX_PLAIN_QUEUES 1024

/*
 * Maximum number of scheduled ODP queues
 *
 * Must be a power of two.
 */
#define CONFIG_MAX_SCHED_QUEUES 1024

/*
 * Maximum number of queues
 */
#define CONFIG_MAX_QUEUES (CONFIG_INTERNAL_QUEUES + \
			   CONFIG_MAX_PLAIN_QUEUES + \
			   CONFIG_MAX_SCHED_QUEUES)

/*
 * Maximum number of ordered locks per queue
 */
#define CONFIG_QUEUE_MAX_ORD_LOCKS 2

/*
 * Maximum number of DMA sessions
 */
#define CONFIG_MAX_DMA_SESSIONS 32

/*
 * Stashes reserved for internal usage
 */
#define CONFIG_INTERNAL_STASHES CONFIG_MAX_DMA_SESSIONS

/*
 * Maximum number of stashes
 */
#define CONFIG_MAX_STASHES 2048

/*
 * Maximum buffer alignment
 *
 * This defines the maximum supported buffer alignment. Requests for values
 * above this will fail.
 */
#define CONFIG_BUFFER_ALIGN_MAX (4 * 1024)

/*
 * Default packet headroom
 *
 * This defines the minimum number of headroom bytes that newly created packets
 * have by default. The default apply to both ODP packet input and user
 * allocated packets. Implementations may reserve a larger than minimum headroom
 * size e.g. due to HW or a protocol specific alignment requirement.
 *
 * @internal In odp-linux implementation:
 * The default value (128) allows a 1500-byte packet to be received into a
 * single segment with room for some header expansion.
 */
#define CONFIG_PACKET_HEADROOM 128

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
 * Maximum packet segment size including head- and tailrooms
 */
#define CONFIG_PACKET_SEG_SIZE (60 * 1024)

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
#define CONFIG_PACKET_SEG_LEN_MIN ((2 * 1024) + \
				   CONFIG_PACKET_HEADROOM + \
				   CONFIG_PACKET_TAILROOM)

/*
 * Number of shared memory blocks reserved for implementation internal use.
 *
 * Each pool requires three blocks (buffers, ring, user area), 20 blocks
 * are reserved for per ODP module global data and one block per packet I/O is
 * reserved for TX completion usage.
 */
#define CONFIG_INTERNAL_SHM_BLOCKS ((CONFIG_POOLS * 3) + 20 + CONFIG_PKTIO_ENTRIES)

/*
 * Maximum number of shared memory blocks.
 *
 * This is the number of separate SHM blocks that an application can reserve
 * concurrently.
 */
#define CONFIG_SHM_BLOCKS 64

/*
 * Maximum event burst size
 *
 * This controls the burst size on various enqueue, dequeue, etc calls. Large
 * burst size improves throughput, but may degrade QoS (increase latency).
 */
#define CONFIG_BURST_SIZE 32

/*
 * Maximum number of events in a pool. Power of two minus one results optimal
 * memory usage for the ring.
 */
#define CONFIG_POOL_MAX_NUM ((1024 * 1024) - 1)

/*
 * Maximum number of events in a thread local pool cache
 */
#define CONFIG_POOL_CACHE_MAX_SIZE 256

/* Maximum packet vector size */
#define CONFIG_PACKET_VECTOR_MAX_SIZE 256

/* Maximum event vector size */
#define CONFIG_EVENT_VECTOR_MAX_SIZE 256

/* Enable pool statistics collection */
#define CONFIG_POOL_STATISTICS 1

/*
 * Maximum number of IPsec SAs. The actual maximum number can be further
 * limited by the number of sessions supported by the crypto subsystem and
 * is reported by odp_ipsec_capability().
 */
#define CONFIG_IPSEC_MAX_NUM_SA 4000

/*
 * Use 128-bit atomics for timer implementation (if available)
 *
 * On some platforms 128-bit atomic operations may be available, but the
 * implementation of used 128-bit GCC built-in functions (e.g.
 * __atomic_compare_exchange_n) utilizes expensive locking. Set to zero to use
 * ODP lock based implementation instead.
 */
#define CONFIG_TIMER_128BIT_ATOMICS 1

/* Enable timer scan performance benchmark. This works with inline enabled. */
#define CONFIG_TIMER_PROFILE_INLINE 0

/* Maximum number of ML models that can be created or loaded. */
#define CONFIG_ML_MAX_MODELS 4

/* Maximum number of inputs for a ML model. */
#define CONFIG_ML_MAX_INPUTS 4

/* Maximum number of outputs for a ML model. */
#define CONFIG_ML_MAX_OUTPUTS 4

#ifdef __cplusplus
}
#endif

#endif
