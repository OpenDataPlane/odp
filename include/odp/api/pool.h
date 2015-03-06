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

#ifdef __cplusplus
extern "C" {
#endif



#include <odp/std_types.h>

/** @addtogroup odp_buffer
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

/** Maximum queue name lenght in chars */
#define ODP_POOL_NAME_LEN  32

/**
 * Pool parameters
 * Used to communicate pool creation options.
 */
typedef struct odp_pool_param_t {
	union {
		struct {
			uint32_t num;   /**< Number of buffers in the pool */
			uint32_t size;  /**< Buffer size in bytes.  The
					     maximum number of bytes
					     application will store in each
					     buffer. */
			uint32_t align; /**< Minimum buffer alignment in bytes.
					     Valid values are powers of two.
					     Use 0 for default alignment.
					     Default will always be a multiple
					     of 8. */
		} buf;
		struct {
			uint32_t num;       /**< The number of packets that the
						 pool must provide that are
						 packet length 'len' bytes or
						 smaller. */
			uint32_t len;       /**< Minimum packet length that the
						 pool must provide 'num'
						 packets. The number of packets
						 may be less than 'num' when
						 packets are larger than 'len'.
						 Use 0 for default.
					     */
			uint32_t seg_len;   /**< Minimum number of packet data
						 bytes that are stored in the
						 first segment of a packet.
						 The maximum value is defined by
						 ODP_CONFIG_PACKET_SEG_LEN_MAX.
						 Use 0 for default. */
		} pkt;
		struct {
			uint32_t num;    /**< Number of timeouts in the pool */
		} tmo;
	};

	int type;  /**< Pool type */
} odp_pool_param_t;

/** Packet pool*/
#define ODP_POOL_PACKET       ODP_EVENT_PACKET
/** Buffer pool */
#define ODP_POOL_BUFFER       ODP_EVENT_BUFFER
/** Timeout pool */
#define ODP_POOL_TIMEOUT      ODP_EVENT_TIMEOUT

/**
 * Create a pool
 * This routine is used to create a pool. It take three
 * arguments: the optional name of the pool to be created, an optional shared
 * memory handle, and a parameter struct that describes the pool to be
 * created. If a name is not specified the result is an anonymous pool that
 * cannot be referenced by odp_pool_lookup().
 *
 * @param name     Name of the pool, max ODP_POOL_NAME_LEN-1 chars.
 *                 May be specified as NULL for anonymous pools.
 *
 * @param shm      The shared memory object in which to create the pool.
 *                 Use ODP_SHM_NULL to reserve default memory type
 *                 for the pool type.
 *
 * @param params   Pool parameters.
 *
 * @return Handle of the created pool
 * @retval ODP_POOL_INVALID  Pool could not be created
 */

odp_pool_t odp_pool_create(const char *name,
			   odp_shm_t shm,
			   odp_pool_param_t *params);

/**
 * Destroy a pool previously created by odp_pool_create()
 *
 * @param pool    Handle of the pool to be destroyed
 *
 * @retval 0 Success
 * @retval -1 Failure
 *
 * @note This routine destroys a previously created pool. This call
 * does not destroy any shared memory object passed to
 * odp_pool_create() used to store the pool contents. The caller
 * takes responsibility for that. If no shared memory object was passed as
 * part of the create call, then this routine will destroy any internal shared
 * memory objects associated with the pool. Results are undefined if
 * an attempt is made to destroy a pool that contains allocated or
 * otherwise active buffers.
 */
int odp_pool_destroy(odp_pool_t pool);

/**
 * Find a pool by name
 *
 * @param name      Name of the pool
 *
 * @return Handle of found pool
 * @retval ODP_POOL_INVALID  Pool could not be found
 *
 * @note This routine cannot be used to look up an anonymous pool (one created
 * with no name).
 */
odp_pool_t odp_pool_lookup(const char *name);

/**
 * Pool information struct
 * Used to get information about a pool.
 */
typedef struct odp_pool_info_t {
	const char *name;          /**< pool name */
	odp_shm_t shm;             /**< handle of shared memory area
					supplied by application to
					contain pool, or
					ODP_SHM_INVALID if this pool is
					managed by ODP */
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
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
