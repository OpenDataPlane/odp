/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP buffer pool
 */

#ifndef ODP_BUFFER_POOL_H_
#define ODP_BUFFER_POOL_H_

#ifdef __cplusplus
extern "C" {
#endif



#include <odp_std_types.h>
#include <odp_platform_types.h>
#include <odp_buffer.h>

/** @addtogroup odp_buffer
 *  Operations on a buffer pool.
 *  @{
 */

/** Maximum queue name lenght in chars */
#define ODP_BUFFER_POOL_NAME_LEN  32

/**
 * Buffer pool parameters
 * Used to communicate buffer pool creation options.
 */
typedef struct odp_buffer_pool_param_t {
	uint32_t buf_size;  /**< Buffer size in bytes.  The maximum
			       number of bytes application will
			       store in each buffer. For packets, this
			       is the maximum packet data length, and
			       configured headroom and tailroom will be
			       added to this number */
	uint32_t buf_align; /**< Minimum buffer alignment in bytes.
			       Valid values are powers of two.  Use 0
			       for default alignment.  Default will
			       always be a multiple of 8. */
	uint32_t num_bufs;  /**< Number of buffers in the pool */
	int      buf_type;  /**< Buffer type */
} odp_buffer_pool_param_t;

/**
 * Create a buffer pool
 * This routine is used to create a buffer pool. It take three
 * arguments: the optional name of the pool to be created, an optional shared
 * memory handle, and a parameter struct that describes the pool to be
 * created. If a name is not specified the result is an anonymous pool that
 * cannot be referenced by odp_buffer_pool_lookup().
 *
 * @param name     Name of the pool, max ODP_BUFFER_POOL_NAME_LEN-1 chars.
 *                 May be specified as NULL for anonymous pools.
 *
 * @param shm      The shared memory object in which to create the pool.
 *                 Use ODP_SHM_NULL to reserve default memory type
 *                 for the buffer type.
 *
 * @param params   Buffer pool parameters.
 *
 * @return Handle of the created buffer pool
 * @retval ODP_BUFFER_POOL_INVALID  Buffer pool could not be created
 */

odp_buffer_pool_t odp_buffer_pool_create(const char *name,
					 odp_shm_t shm,
					 odp_buffer_pool_param_t *params);

/**
 * Destroy a buffer pool previously created by odp_buffer_pool_create()
 *
 * @param pool    Handle of the buffer pool to be destroyed
 *
 * @retval 0 Success
 * @retval -1 Failure
 *
 * @note This routine destroys a previously created buffer pool. This call
 * does not destroy any shared memory object passed to
 * odp_buffer_pool_create() used to store the buffer pool contents. The caller
 * takes responsibility for that. If no shared memory object was passed as
 * part of the create call, then this routine will destroy any internal shared
 * memory objects associated with the buffer pool. Results are undefined if
 * an attempt is made to destroy a buffer pool that contains allocated or
 * otherwise active buffers.
 */
int odp_buffer_pool_destroy(odp_buffer_pool_t pool);

/**
 * Find a buffer pool by name
 *
 * @param name      Name of the pool
 *
 * @return Handle of found buffer pool
 * @retval ODP_BUFFER_POOL_INVALID  Buffer pool could not be found
 *
 * @note This routine cannot be used to look up an anonymous pool (one created
 * with no name).
 */
odp_buffer_pool_t odp_buffer_pool_lookup(const char *name);

/**
 * Buffer pool information struct
 * Used to get information about a buffer pool.
 */
typedef struct odp_buffer_pool_info_t {
	const char *name;                 /**< pool name */
	odp_shm_t shm;                    /**< handle of shared memory area
					     supplied by application to
					     contain buffer pool, or
					     ODP_SHM_INVALID if this pool is
					     managed by ODP */
	odp_buffer_pool_param_t params;   /**< pool parameters */
} odp_buffer_pool_info_t;

/**
 * Retrieve information about a buffer pool
 *
 * @param pool         Buffer pool handle
 *
 * @param[out] info    Receives an odp_buffer_pool_info_t object
 *                     that describes the pool.
 *
 * @retval 0 Success
 * @retval -1 Failure.  Info could not be retrieved.
 */

int odp_buffer_pool_info(odp_buffer_pool_t pool,
			 odp_buffer_pool_info_t *info);

/**
 * Print buffer pool info
 *
 * @param pool      Pool handle
 *
 * @note This routine writes implementation-defined information about the
 * specified buffer pool to the ODP log. The intended use is for debugging.
 */
void odp_buffer_pool_print(odp_buffer_pool_t pool);

/**
 * Buffer alloc
 *
 * The validity of a buffer can be cheked at any time with odp_buffer_is_valid()
 * @param pool      Pool handle
 *
 * @return Handle of allocated buffer
 * @retval ODP_BUFFER_INVALID  Buffer could not be allocated
 */
odp_buffer_t odp_buffer_alloc(odp_buffer_pool_t pool);

/**
 * Buffer free
 *
 * @param buf       Buffer handle
 *
 */
void odp_buffer_free(odp_buffer_t buf);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
