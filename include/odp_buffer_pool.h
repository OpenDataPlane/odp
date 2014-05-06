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
#include <odp_buffer.h>

/** Maximum queue name lenght in chars */
#define ODP_BUFFER_POOL_NAME_LEN  32

/** Invalid buffer pool */
#define ODP_BUFFER_POOL_INVALID  (0xffffffff)

/** ODP buffer pool */
typedef uint32_t odp_buffer_pool_t;


/**
 * Create a buffer pool
 *
 * @param name      Name of the pool (max ODP_BUFFER_POOL_NAME_LEN - 1 chars)
 * @param base_addr Pool base address
 * @param size      Pool size in bytes
 * @param buf_size  Buffer size in bytes
 * @param buf_align Minimum buffer alignment
 * @param buf_type  Buffer type
 *
 * @return Buffer pool handle
 */
odp_buffer_pool_t odp_buffer_pool_create(const char *name,
					 void *base_addr, uint64_t size,
					 size_t buf_size, size_t buf_align,
					 int buf_type);


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




#ifdef __cplusplus
}
#endif

#endif
