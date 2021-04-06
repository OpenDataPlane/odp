/* Copyright (c) 2015-2018, Linaro Limited
 * Copyright (c) 2020, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP pool
 */

#ifndef ODP_API_SPEC_POOL_H_
#define ODP_API_SPEC_POOL_H_
#include <odp/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/std_types.h>

/** @defgroup odp_pool ODP POOL
 *  Packet and buffer (event) pools.
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

	/** The number of available events in the local caches of all threads
	 *  using the pool */
	uint64_t cache_available;

	/** The number of successful alloc operations from pool caches (returned
	 *  at least one event). */
	uint64_t cache_alloc_ops;

	/** The number of free operations, which stored events to pool caches. */
	uint64_t cache_free_ops;

} odp_pool_stats_t;

/**
 * Pool capabilities
 */
typedef struct odp_pool_capability_t {
	/** Maximum number of pools of any type */
	unsigned int max_pools;

	/** Buffer pool capabilities  */
	struct {
		/** Maximum number of buffer pools */
		unsigned int max_pools;

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
		unsigned int max_pools;

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
		unsigned int max_pools;

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
		/** odp_pool_param_t::vector::max_size should be power of two. */
		odp_bool_t size_is_pow2;

		/** Maximum number of vector pools */
		unsigned int max_pools;

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
 * Query pool capabilities
 *
 * Outputs pool capabilities on success.
 *
 * @param[out] capa   Pointer to capability structure for output
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int odp_pool_capability(odp_pool_capability_t *capa);

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
 * Pool parameters
 */
typedef struct odp_pool_param_t {
	/** Pool type */
	int type;

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

		/** Minimum number of packet data bytes that are stored in the
		 *  first segment of a packet. The maximum value is defined by
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

/** Packet pool*/
#define ODP_POOL_PACKET       ODP_EVENT_PACKET
/** Buffer pool */
#define ODP_POOL_BUFFER       ODP_EVENT_BUFFER
/** Timeout pool */
#define ODP_POOL_TIMEOUT      ODP_EVENT_TIMEOUT
/** Vector pool
 *
 * The pool to hold a vector of general type such as odp_packet_t.
 * Each vector holds an array of generic types of the same type.
 * @see ODP_EVENT_PACKET_VECTOR
 */
#define ODP_POOL_VECTOR	      (ODP_POOL_TIMEOUT + 1)

/**
 * Create a pool
 *
 * This routine is used to create a pool. The use of pool name is optional.
 * Unique names are not required. However, odp_pool_lookup() returns only a
 * single matching pool. Use odp_pool_param_init() to initialize parameters
 * into their default values.
 *
 * @param name     Name of the pool or NULL. Maximum string length is
 *                 ODP_POOL_NAME_LEN.
 * @param param    Pool parameters.
 *
 * @return Handle of the created pool
 * @retval ODP_POOL_INVALID  Pool could not be created
 */
odp_pool_t odp_pool_create(const char *name, const odp_pool_param_t *param);

/**
 * Destroy a pool previously created by odp_pool_create()
 *
 * @param pool    Handle of the pool to be destroyed
 *
 * @retval 0 Success
 * @retval -1 Failure
 *
 * @note This routine destroys a previously created pool, and will destroy any
 * internal shared memory objects associated with the pool. Results are
 * undefined if an attempt is made to destroy a pool that contains allocated
 * or otherwise active buffers.
 */
int odp_pool_destroy(odp_pool_t pool);

/**
 * Find a pool by name
 *
 * @param name      Name of the pool
 *
 * @return Handle of the first matching pool
 * @retval ODP_POOL_INVALID  Pool could not be found
 */
odp_pool_t odp_pool_lookup(const char *name);

/**
 * Pool information struct
 * Used to get information about a pool.
 */
typedef struct odp_pool_info_t {
	/** Pool name */
	const char *name;

	/** Copy of pool parameters */
	odp_pool_param_t params;

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
 * Retrieve information about a pool
 *
 * @param pool         Pool handle
 *
 * @param[out] info    Receives an odp_pool_info_t object
 *                     that describes the pool.
 *
 * @retval 0 Success
 * @retval -1 Failure.  Info could not be retrieved.
 */
int odp_pool_info(odp_pool_t pool, odp_pool_info_t *info);

/**
 * Print pool info
 *
 * @param pool      Pool handle
 *
 * @note This routine writes implementation-defined information about the
 * specified pool to the ODP log. The intended use is for debugging.
 */
void odp_pool_print(odp_pool_t pool);

/**
 * Get printable value for an odp_pool_t
 *
 * @param hdl  odp_pool_t handle to be printed
 * @return     uint64_t value that can be used to print/display this
 *             handle
 *
 * @note This routine is intended to be used for diagnostic purposes
 * to enable applications to generate a printable value that represents
 * an odp_pool_t handle.
 */
uint64_t odp_pool_to_u64(odp_pool_t hdl);

/**
 * Initialize pool params
 *
 * Initialize an odp_pool_param_t to its default values for all fields
 *
 * @param param   Address of the odp_pool_param_t to be initialized
 */
void odp_pool_param_init(odp_pool_param_t *param);

/**
 * Maximum pool index
 *
 * Return the maximum pool index. Pool indexes (e.g. returned by odp_pool_index())
 * range from zero to this maximum value.
 *
 * @return Maximum pool index
 */
unsigned int odp_pool_max_index(void);

/**
 * Get pool index
 *
 * @param pool    Pool handle
 *
 * @return Pool index (0..odp_pool_max_index())
 * @retval <0 on failure
 */
int odp_pool_index(odp_pool_t pool);

/**
 * Get statistics for pool handle
 *
 * Read the statistics counters enabled using odp_pool_stats_opt_t during pool
 * creation. The inactive counters are set to zero by the implementation.
 *
 * @param      pool   Pool handle
 * @param[out] stats  Output buffer for counters
 *
 * @retval  0 on success
 * @retval <0 on failure
 */
int odp_pool_stats(odp_pool_t pool, odp_pool_stats_t *stats);

/**
 * Reset statistics for pool handle
 *
 * Reset all statistics counters to zero except: odp_pool_stats_t::available,
 * odp_pool_stats_t::cache_available
 *
 * @param pool    Pool handle
 *
 * @retval  0 on success
 * @retval <0 on failure
 */
int odp_pool_stats_reset(odp_pool_t pool);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
