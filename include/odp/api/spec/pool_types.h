/* Copyright (c) 2021-2022, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * Type definitions for pools
 */

#ifndef ODP_API_SPEC_POOL_TYPES_H_
#define ODP_API_SPEC_POOL_TYPES_H_
#include <odp/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/std_types.h>
#include <odp/api/dma_types.h>

/** @addtogroup odp_pool
 *  @{
 */

/**
 * @typedef odp_pool_t
 * ODP pool
 */

/**
 * @def ODP_POOL_INVALID
 * Invalid pool
 */

/**
 * @def ODP_POOL_NAME_LEN
 * Maximum pool name length in chars including null char
 */

/**
 * @def ODP_POOL_MAX_THREAD_STATS
 * Maximum number of per thread statistics a single odp_pool_stats() call can read
 */

/** Maximum number of packet pool subparameters */
#define ODP_POOL_MAX_SUBPARAMS  7

/**
 * Pool statistics counters options
 *
 * Pool statistics counters listed in a bit field structure.
 */
typedef union odp_pool_stats_opt_t {
	/** Option flags */
	struct {
		/** @see odp_pool_stats_t::available */
		uint64_t available          : 1;

		/** @see odp_pool_stats_t::alloc_ops */
		uint64_t alloc_ops          : 1;

		/** @see odp_pool_stats_t::alloc_fails */
		uint64_t alloc_fails        : 1;

		/** @see odp_pool_stats_t::free_ops */
		uint64_t free_ops           : 1;

		/** @see odp_pool_stats_t::total_ops */
		uint64_t total_ops          : 1;

		/** @see odp_pool_stats_t::cache_available */
		uint64_t cache_available    : 1;

		/** @see odp_pool_stats_t::cache_alloc_ops */
		uint64_t cache_alloc_ops    : 1;

		/** @see odp_pool_stats_t::cache_free_ops */
		uint64_t cache_free_ops     : 1;

		/** @see odp_pool_stats_t::thread::cache_available */
		uint64_t thread_cache_available : 1;
	} bit;

	/** All bits of the bit field structure
	 *
	 *  This field can be used to set/clear all flags, or for bitwise
	 *  operations over the entire structure. */
	uint64_t all;

} odp_pool_stats_opt_t;

/**
 * Pool statistics counters
 *
 * In addition to API alloc and free calls, statistics counters may be updated
 * by alloc/free operations from implementation internal software or hardware
 * components.
 */
typedef struct odp_pool_stats_t {
	/** The number of available events in the pool */
	uint64_t available;

	/** The number of alloc operations from the pool. Includes both
	 *  successful and failed operations (pool empty). */
	uint64_t alloc_ops;

	/** The number of failed alloc operations (pool empty) */
	uint64_t alloc_fails;

	/** The number of free operations to the pool */
	uint64_t free_ops;

	/** The total number of alloc and free operations. Includes both
	 *  successful and failed operations (pool empty). */
	uint64_t total_ops;

	/** The number of available events in the local caches of all threads */
	uint64_t cache_available;

	/** The number of successful alloc operations from pool caches (returned
	 *  at least one event). */
	uint64_t cache_alloc_ops;

	/** The number of free operations, which stored events to pool caches. */
	uint64_t cache_free_ops;

	/** Per thread counters */
	struct {
		/** First thread identifier to read counters from. Ignored when
		 *  'thread.cache_available' is not enabled. */
		uint16_t first;

		/** Last thread identifier to read counters from. Ignored when
		 *  'thread.cache_available' is not enabled. */
		uint16_t last;

		/** The number of available events in each thread local cache
		 *
		 *  If 'first' and 'last' include all threads of the instance,
		 *  the sum of 'thread.cache_available' matches
		 *  'cache_available'. */
		uint64_t cache_available[ODP_POOL_MAX_THREAD_STATS];
	} thread;

} odp_pool_stats_t;

/**
 * Pool capabilities
 */
typedef struct odp_pool_capability_t {
	/** Maximum number of pools of any type */
	uint32_t max_pools;

	/** Buffer pool capabilities  */
	struct {
		/** Maximum number of buffer pools */
		uint32_t max_pools;

		/** Maximum buffer data alignment in bytes */
		uint32_t max_align;

		/** Maximum buffer data size in bytes
		 *
		 * The value of zero means that size is limited only by the
		 * available memory size for the pool. */
		uint32_t max_size;

		/** Maximum number of buffers of any size
		 *
		 * The value of zero means that limited only by the available
		 * memory size for the pool. */
		uint32_t max_num;

		/** Minimum size of thread local cache */
		uint32_t min_cache_size;

		/** Maximum size of thread local cache */
		uint32_t max_cache_size;

		/** Supported statistics counters */
		odp_pool_stats_opt_t stats;
	} buf;

	/** Packet pool capabilities  */
	struct {
		/** Maximum number of packet pools */
		uint32_t max_pools;

		/** Maximum packet data length in bytes
		 *
		 * This defines the maximum packet data length that can be
		 * stored into a packet. Attempts to allocate or extend packets
		 * to sizes larger than this limit will fail.
		 *
		 * The value of zero means that limited only by the available
		 * memory size for the pool. */
		uint32_t max_len;

		/** Maximum number of packets of any length
		 *
		 * The value of zero means that limited only by the available
		 * memory size for the pool. */
		uint32_t max_num;

		/** Maximum packet data alignment in bytes
		 *
		 * This is the maximum value of packet pool alignment
		 * (pkt.align) parameter. */
		uint32_t max_align;

		/** Minimum packet level headroom length in bytes
		 *
		 * The minimum number of headroom bytes that newly created
		 * packets have by default. The default apply to both ODP
		 * packet input and user allocated packets.*/
		uint32_t min_headroom;

		/** Maximum packet level headroom length in bytes
		 *
		 * The maximum value of packet pool headroom parameter
		 * that can be configured. This value applies to both ODP
		 * packet input and user allocated packets.*/
		uint32_t max_headroom;

		/** Minimum packet level tailroom length in bytes
		 *
		 * The minimum number of tailroom bytes that newly created
		 * packets have by default. The default apply to both ODP
		 * packet input and user allocated packets.*/
		uint32_t min_tailroom;

		/** Maximum number of segments per packet */
		uint32_t max_segs_per_pkt;

		/** Minimum packet segment data length in bytes
		 *
		 * The user defined segment length (seg_len in
		 * odp_pool_param_t) will be rounded up into this value. */
		uint32_t min_seg_len;

		/** Maximum packet segment data length in bytes
		 *
		 * The user defined segment length (seg_len in odp_pool_param_t)
		 * must not be larger than this.
		 *
		 * The value of zero means that limited only by the available
		 * memory size for the pool. */
		uint32_t max_seg_len;

		/** Maximum user area size in bytes
		 *
		 * The value of zero means that limited only by the available
		 * memory size for the pool. */
		uint32_t max_uarea_size;

		/** Maximum number of subparameters
		 *
		 *  Maximum number of packet pool subparameters. Valid range is
		 *  0 ... ODP_POOL_MAX_SUBPARAMS. */
		uint8_t max_num_subparam;

		/** Minimum size of thread local cache */
		uint32_t min_cache_size;

		/** Maximum size of thread local cache */
		uint32_t max_cache_size;

		/** Supported statistics counters */
		odp_pool_stats_opt_t stats;
	} pkt;

	/** Timeout pool capabilities  */
	struct {
		/** Maximum number of timeout pools */
		uint32_t max_pools;

		/** Maximum number of timeout events in a pool
		 *
		 * The value of zero means that limited only by the available
		 * memory size for the pool. */
		uint32_t max_num;

		/** Minimum size of thread local cache */
		uint32_t min_cache_size;

		/** Maximum size of thread local cache */
		uint32_t max_cache_size;

		/** Supported statistics counters */
		odp_pool_stats_opt_t stats;
	} tmo;

	/** Vector pool capabilities */
	struct {
		/** Maximum number of vector pools */
		uint32_t max_pools;

		/** Maximum number of vector events in a pool
		 *
		 * The value of zero means that limited only by the available
		 * memory size for the pool. */
		uint32_t max_num;

		/** Maximum number of general types, such as odp_packet_t, in a vector. */
		uint32_t max_size;

		/** Minimum size of thread local cache */
		uint32_t min_cache_size;

		/** Maximum size of thread local cache */
		uint32_t max_cache_size;

		/** Supported statistics counters */
		odp_pool_stats_opt_t stats;
	} vector;

} odp_pool_capability_t;

/**
 * Packet pool subparameters
 */
typedef struct odp_pool_pkt_subparam_t {
	/** Number of 'len' byte packets. */
	uint32_t num;

	/** Packet length in bytes */
	uint32_t len;

} odp_pool_pkt_subparam_t;

/**
 * Pool types
 */
typedef enum odp_pool_type_t {
	/** Packet pool*/
	ODP_POOL_PACKET = ODP_EVENT_PACKET,

	/** Buffer pool */
	ODP_POOL_BUFFER = ODP_EVENT_BUFFER,

	/** Timeout pool */
	ODP_POOL_TIMEOUT = ODP_EVENT_TIMEOUT,

	/** Vector pool
	 *
	 * The pool to hold a vector of general type such as odp_packet_t.
	 * Each vector holds an array of generic types of the same type.
	 * @see ODP_EVENT_PACKET_VECTOR
	 */
	ODP_POOL_VECTOR,

	/** DMA completion event pool */
	ODP_POOL_DMA_COMPL

} odp_pool_type_t;

/**
 * Pool parameters
 */
typedef struct odp_pool_param_t {
	/** Pool type */
	odp_pool_type_t type;

	/** Parameters for buffer pools */
	struct {
		/** Number of buffers in the pool */
		uint32_t num;

		/** Buffer size in bytes. The maximum number of bytes
		 *  application will store in each buffer.
		 */
		uint32_t size;

		/** Minimum buffer alignment in bytes. Valid values are
		 *  powers of two. Use 0 for default alignment.
		 *  Default will always be a multiple of 8.
		 */
		uint32_t align;

		/** Maximum number of buffers cached locally per thread
		 *
		 *  A non-zero value allows implementation to cache buffers
		 *  locally per each thread. Thread local caching may improve
		 *  performance, but requires application to take account that
		 *  some buffers may be stored locally per thread and thus are
		 *  not available for allocation from other threads.
		 *
		 *  This is the maximum number of buffers to be cached per
		 *  thread. The actual cache size is implementation specific.
		 *  The value must not be less than 'min_cache_size' or exceed
		 *  'max_cache_size' capability. The default value is
		 *  implementation specific and set by odp_pool_param_init().
		 */
		uint32_t cache_size;
	} buf;

	/** Parameters for packet pools */
	struct {
		/** Minimum number of 'len' byte packets.
		 *
		 *  The pool must contain at least this many packets that are
		 *  'len' bytes or smaller. An implementation may round up the
		 *  value, as long as the 'max_num' parameter below is not
		 *  violated. The maximum value for this field is defined by
		 *  pool capability pkt.max_num.
		 */
		uint32_t num;

		/** Maximum number of packets.
		 *
		 *  This is the maximum number of packets of any length that can
		 *  be allocated from the pool. The maximum value is defined by
		 *  pool capability pkt.max_num. Use 0 when there's no
		 *  requirement for the maximum number of packets. The default
		 *  value is 0.
		 */
		uint32_t max_num;

		/** Minimum length of 'num' packets.
		 *
		 *  The pool must contain at least 'num' packets up to this
		 *  packet length (1 ... 'len' bytes). The maximum value for
		 *  this field is defined by pool capability pkt.max_len.
		 *  Use 0 for default.
		 */
		uint32_t len;

		/** Maximum packet length that will be allocated from
		 *  the pool. The maximum value is defined by pool capability
		 *  pkt.max_len. Use 0 for default.
		 */
		uint32_t max_len;

		/** Minimum packet data alignment in bytes.
		 *
		 *  Valid values are powers of two. User allocated packets have
		 *  start of data (@see odp_packet_data()) aligned to this or
		 *  a higher alignment (power of two value). This parameter
		 *  does not apply to packets that ODP allocates internally
		 *  (e.g. packets from packet input).
		 *
		 *  The maximum value is defined by pool capability
		 *  pkt.max_align. Use 0 for default alignment.
		 */
		uint32_t align;

		/** Minimum number of packet data bytes that can be stored in
		 *  the first segment of a newly allocated packet (starting from
		 *  odp_packet_data()). The maximum value is defined by
		 *  pool capability pkt.max_seg_len. Use 0 for default.
		 */
		uint32_t seg_len;

		/** User area size in bytes. The maximum value is defined by
		 *  pool capability pkt.max_uarea_size. Specify as 0 if no user
		 *  area is needed.
		 */
		uint32_t uarea_size;

		/** Minimum headroom size in bytes. Each newly allocated
		 *  packet from the pool must have at least this much headroom.
		 *  The maximum value is defined by pool capability
		 *  pkt.max_headroom. Use zero if headroom is not needed.
		 */
		uint32_t headroom;

		/** Number of subparameters
		 *
		 *  The number of subparameter table entries used. The maximum
		 *  value is defined by pool capability pkt.max_num_subparam.
		 *  The default value is 0.
		 */
		uint8_t num_subparam;

		/** Subparameter table
		 *
		 *  Subparameters continue pool configuration with additional
		 *  packet length requirements. The first table entry follows
		 *  the num/len specification above. So that, sub[0].len > 'len'
		 *  and sub[0].num refers to packet lengths between 'len' + 1
		 *  and sub[0].len. Similarly, sub[1] follows sub[0]
		 *  specification, and so on.
		 *
		 *  Each requirement is supported separately and may be rounded
		 *  up, as long as the 'max_num' parameter is not violated. It's
		 *  implementation specific if some requirements are supported
		 *  simultaneously (e.g. due to subpool design).
		 */
		odp_pool_pkt_subparam_t sub[ODP_POOL_MAX_SUBPARAMS];

		/** Maximum number of packets cached locally per thread
		 *
		 *  See buf.cache_size documentation for details.
		 */
		uint32_t cache_size;
	} pkt;

	/** Parameters for timeout pools */
	struct {
		/** Number of timeouts in the pool */
		uint32_t num;

		/** Maximum number of timeouts cached locally per thread
		 *
		 *  See buf.cache_size documentation for details.
		 */
		uint32_t cache_size;
	} tmo;

	/** Parameters for vector pools */
	struct {
		/** Number of vectors in the pool */
		uint32_t num;

		/** Maximum number of general types, such as odp_packet_t, in a vector. */
		uint32_t max_size;

		/** Maximum number of vectors cached locally per thread
		 *
		 *  See buf.cache_size documentation for details.
		 */
		uint32_t cache_size;
	} vector;

	/**
	 * Configure statistics counters
	 *
	 * An application can read the enabled statistics counters using
	 * odp_pool_stats(). For optimal performance an application should
	 * enable only the required counters.
	 */
	odp_pool_stats_opt_t stats;

} odp_pool_param_t;

/**
 * External memory pool population done
 *
 * Application uses this flag to mark the last odp_pool_ext_populate() call, which completes
 * external memory pool population phase.
 */
#define ODP_POOL_POPULATE_DONE 0x1

/**
 * External memory pool capabilities
 *
 * Generic fields (not specific to a pool type) contain capabilities
 * of the requested pool type.
 */
typedef struct odp_pool_ext_capability_t {
	/** Requested pool type
	 *
	 *  Pool type from the odp_pool_ext_capability() call is recorded here for reference. */
	odp_pool_type_t type;

	/** Maximum number of pools
	 *
	 *  Maximum number of external memory pools of the requested type. */
	uint32_t max_pools;

	/** Minimum size of thread local cache */
	uint32_t min_cache_size;

	/** Maximum size of thread local cache */
	uint32_t max_cache_size;

	/** Supported statistics counters */
	odp_pool_stats_opt_t stats;

	/** Packet pool capabilities  */
	struct {
		/** Maximum number of packet buffers */
		uint32_t max_num_buf;

		/** Maximum packet buffer size in bytes */
		uint32_t max_buf_size;

		/** ODP header size in bytes
		 *
		 *  Application must reserve this many bytes from the start of a packet buffer
		 *  for ODP implementation usage. When the value is zero, ODP implementation does
		 *  not need header space to be reserved for it. Application will not modify this
		 *  memory area (after buffer populate call).
		 */
		uint32_t odp_header_size;

		/** ODP trailer size in bytes
		 *
		 *  Application must reserve this many bytes from the end of a packet buffer
		 *  for ODP implementation usage. When the value is zero, ODP implementation does
		 *  not need trailer space to be reserved for it. Application will not modify this
		 *  memory area (after buffer populate call).
		 */
		uint32_t odp_trailer_size;

		/** Minimum packet pool memory area alignment in bytes
		 *
		 *  The memory area used for a packet pool, starting from (or before) the lowest
		 *  addressed buffer and extending to the end (or after) of the highest addressed
		 *  buffer, must have at least this (power of two) alignment. The value is 1 when
		 *  there is no alignment requirement.
		 */
		uint32_t min_mem_align;

		/** Minimum packet buffer pointer alignment in bytes
		 *
		 *  Packet buffer pointers populated into a pool must be evenly divisible with
		 *  this value. The value is 1 when there is no alignment requirement.
		 */
		uint32_t min_buf_align;

		/** Minimum packet headroom alignment in bytes
		 *
		 *  Packet buffers populated into a pool must have their headroom start address
		 *  evenly divisible with this value. The value is 1 when there is no alignment
		 *  requirement.
		 */
		uint32_t min_head_align;

		/** Packet buffer alignment flags
		 *
		 *  These flags specify additional alignment requirements for packet buffers.
		 *  If not stated otherwise, min_buf_align and min_head_align alignment
		 *  requirements apply also.
		 */
		struct {
			/** Packet buffers are size aligned
			 *
			 *  When set, packet buffer pointers must be aligned to the buffer size.
			 *  For example, if the buffer size would be 2304 bytes (0x900),
			 *  each buffer start address must be a multiple of 0x900
			 *  (e.g. 0x12000900, 0x12001200, 0x12004800, etc). */
			uint16_t buf_size_aligned : 1;

		};

		/** Maximum headroom parameter value
		 *
		 *  The packet pool headroom parameter may not exceed this value.
		 */
		uint32_t max_headroom;

		/** Maximum headroom size in bytes
		 *
		 *  Any newly allocated packet will have at most this much headroom. Application
		 *  may use this to ensure that packet buffer size is large enough to fit both
		 *  buffer headers, headroom and data.
		 */
		uint32_t max_headroom_size;

		/** Maximum number of segments per packet */
		uint32_t max_segs_per_pkt;

		/** Maximum user area size in bytes */
		uint32_t max_uarea_size;

	} pkt;

} odp_pool_ext_capability_t;

/**
 * External memory pool parameters
 */
typedef struct odp_pool_ext_param_t {
	/** Pool type */
	odp_pool_type_t type;

	/** Maximum thread local cache size for the pool
	 *
	 *  Valid value range is from min_cache_size to max_cache_size capability.
	 *  The default value is implementation specific. See odp_pool_param_t (buf.cache_size)
	 *  for more detailed documentation.
	 */
	uint32_t cache_size;

	/**
	 * Pool statistics configuration
	 *
	 * All pool statistics are disabled by default. For optimal performance, enable only those
	 * counters that are actually used. Counters may be read with odp_pool_stats().
	 */
	odp_pool_stats_opt_t stats;

	/** Parameters for packet pools */
	struct {
		/** Number of packet buffers
		 *
		 *  The number of packet buffers application will populate into the pool.
		 *  The maximum value is defined by pool capability pkt.max_num_buf.
		 */
		uint32_t num_buf;

		/** Packet buffer size
		 *
		 *  Total buffer size in bytes including all headers, trailer, head-/tailroom
		 *  and data. This is calculated from buffer start pointer to the end of buffer
		 *  data area (including tailroom) or ODP trailer (see odp_trailer_size capability).
		 *  All packet buffers application populates into the pool are of this size.
		 */
		uint32_t buf_size;

		/** Application header size
		 *
		 *  Application reserves this many bytes for its own buffer header usage.
		 *  The application header follows immediately the ODP buffer header
		 *  (see odp_header_size capability). ODP implementation will not modify this
		 *  memory area. The default value is 0.
		 */
		uint32_t app_header_size;

		/** User area size
		 *
		 *  Per packet user area size in bytes. As with normal pools, user area location
		 *  is ODP implementation specific. Use zero if no user area is needed.
		 *  The maximum value is defined by pool capability pkt.max_uarea_size.
		 *  The default value is 0.
		 */
		uint32_t uarea_size;

		/** Minimum headroom size
		 *
		 *  Each newly allocated packet from the pool must have at least this much
		 *  headroom in bytes. The configuration applies to both ODP packet input and
		 *  application allocated packets. Use zero if headroom is not needed. The maximum
		 *  value is defined by pool capability pkt.max_headroom. Implementation may
		 *  round up the initial headroom size up to pool capability pkt.max_headroom_size.
		 */
		uint32_t headroom;

	} pkt;

} odp_pool_ext_param_t;

/**
 * Pool information struct
 * Used to get information about a pool.
 */
typedef struct odp_pool_info_t {
	/** Pool type */
	odp_pool_type_t type;

	/** Pool name */
	const char *name;

	/** External memory pool
	 *
	 *  0: Pool is a normal pool
	 *  1: Pool is an external memory pool
	 */
	odp_bool_t pool_ext;

	/** Pool parameters union */
	union {
		/** Copy of pool parameters. This is set when pool_ext is 0. */
		odp_pool_param_t params;

		/** Copy of external memory pool parameters. This is set when pool_ext is 1. */
		odp_pool_ext_param_t pool_ext_param;

		/** Copy of pool parameters when pool type is ODP_POOL_DMA_COMPL. */
		odp_dma_pool_param_t dma_pool_param;
	};

	/** Additional info for packet pools */
	struct {
		/** Maximum number of packets of any length
		 *
		 *  This is the maximum number of packets that can be allocated
		 *  from the pool at anytime. Application can use this e.g.
		 *  to prepare enough per packet contexts.
		 */
		uint32_t max_num;

	} pkt;

	/** Minimum data address.
	 *
	 *  This is the minimum address that application accessible
	 *  data of any object (event) allocated from the pool may
	 *  locate. When there's no application accessible data
	 *  (e.g. ODP_POOL_TIMEOUT pools), the value may be zero.
	 */
	uintptr_t min_data_addr;

	/** Maximum data address.
	 *
	 *  This is the maximum address that application accessible
	 *  data of any object (event) allocated from the pool may
	 *  locate. When there's no application accessible data
	 *  (e.g. ODP_POOL_TIMEOUT pools), the value may be zero.
	 */
	uintptr_t max_data_addr;

} odp_pool_info_t;

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
