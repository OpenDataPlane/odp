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
 * Find a buffer pool by name
 *
 * @param name      Name of the pool
 *
 * @return Buffer pool handle, or ODP_BUFFER_POOL_INVALID if not found.
 */
odp_buffer_pool_t odp_buffer_pool_lookup(const char *name);


/**
 * Print buffer pool info
 *
 * @param pool      Pool handle
 *
 */
void odp_buffer_pool_print(odp_buffer_pool_t pool);


/**
 * Buffer alloc
 *
 * The validity of a buffer can be cheked at any time with odp_buffer_is_valid()
 * @param pool      Pool handle
 *
 * @return Buffer handle or ODP_BUFFER_INVALID
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
