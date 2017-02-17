/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP pool
 */

#ifndef ODP_API_POOL_H_
#define ODP_API_POOL_H_
#include <odp/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/std_types.h>

/** @defgroup odp_pool ODP POOL
 *  Operations on a pool.
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
 * Pool capabilities
 */
typedef struct odp_pool_capability_t {
	/** Maximum number of pools of any type */
	unsigned max_pools;

	/** Buffer pool capabilities  */
	struct {
		/** Maximum number of buffer pools */
		unsigned max_pools;

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
	} buf;

	/** Packet pool capabilities  */
	struct {
		/** Maximum number of packet pools */
		unsigned max_pools;

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

		/** Minimum packet level headroom length in bytes
		 *
		 * The minimum number of headroom bytes that newly created
		 * packets have by default. The default apply to both ODP
		 * packet input and user allocated packets.*/
		uint32_t min_headroom;

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
	} pkt;

	/** Timeout pool capabilities  */
	struct {
		/** Maximum number of timeout pools */
		unsigned max_pools;

		/** Maximum number of timeout events in a pool
		 *
		 * The value of zero means that limited only by the available
		 * memory size for the pool. */
		uint32_t max_num;
	} tmo;

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
 * Pool parameters
 * Used to communicate pool creation options.
 * @note A single thread may not be able to allocate all 'num' elements
 * from the pool at any particular time, as other threads or hardware
 * blocks are allowed to keep some for caching purposes.
 */
typedef struct odp_pool_param_t {
	/** Pool type */
	int type;

	union {
		struct {
			/** Number of buffers in the pool */
			uint32_t num;

			/** Buffer size in bytes. The maximum number of bytes
			    application will store in each buffer. */
			uint32_t size;

			/** Minimum buffer alignment in bytes. Valid values are
			    powers of two. Use 0 for default alignment.
			    Default will always be a multiple of 8. */
			uint32_t align;
		} buf;
		struct {
			/** The number of packets that the pool must provide
			    that are packet length 'len' bytes or smaller.
			    The maximum value is defined by pool capability
			    pkt.max_num. */
			uint32_t num;

			/** Minimum packet length that the pool must provide
			    'num' packets. The number of packets may be less
			    than 'num' when packets are larger than 'len'.
			    The maximum value is defined by pool capability
			    pkt.max_len. Use 0 for default. */
			uint32_t len;

			/** Maximum packet length that will be allocated from
			    the pool. The maximum value is defined by pool
			    capability pkt.max_len. Use 0 for default (the
			    pool maximum). */
			uint32_t max_len;

			/** Minimum number of packet data bytes that are stored
			    in the first segment of a packet. The maximum value
			    is defined by pool capability pkt.max_seg_len.
			    Use 0 for default. */
			uint32_t seg_len;

			/** User area size in bytes. The maximum value is
			    defined by pool capability pkt.max_uarea_size.
			    Specify as 0 if no user area is needed. */
			uint32_t uarea_size;
		} pkt;
		struct {
			/** Number of timeouts in the pool */
			uint32_t num;
		} tmo;
	};
} odp_pool_param_t;

/** Packet pool*/
#define ODP_POOL_PACKET       ODP_EVENT_PACKET
/** Buffer pool */
#define ODP_POOL_BUFFER       ODP_EVENT_BUFFER
/** Timeout pool */
#define ODP_POOL_TIMEOUT      ODP_EVENT_TIMEOUT

/**
 * Create a pool
 *
 * This routine is used to create a pool. The use of pool name is optional.
 * Unique names are not required. However, odp_pool_lookup() returns only a
 * single matching pool.
 *
 * @param name     Name of the pool or NULL. Maximum string length is
 *                 ODP_POOL_NAME_LEN.
 * @param params   Pool parameters.
 *
 * @return Handle of the created pool
 * @retval ODP_POOL_INVALID  Pool could not be created
 */

odp_pool_t odp_pool_create(const char *name, odp_pool_param_t *params);

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
	const char *name;          /**< pool name */
	odp_pool_param_t params;   /**< pool parameters */
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
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
