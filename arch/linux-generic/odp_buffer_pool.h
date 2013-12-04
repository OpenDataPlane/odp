/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *    * Redistributions of source code must retain the above copyright notice,
 *      this list of conditions and the following disclaimer.
 *
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *
 *    * Neither the name of Linaro Limited nor the names of its contributors
 *      may be used to endorse or promote products derived from this software
 *      without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIALDAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
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


#define ODP_BUFFER_POOL_NAME_LEN  32
#define ODP_BUFFER_POOL_INVALID  (0xffffffff)
#define ODP_BUFFER_TYPE_RAW       0
#define ODP_BUFFER_TYPE_PACKET    1

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




odp_buffer_t odp_buffer_alloc(odp_buffer_pool_t pool);



#ifdef __cplusplus
}
#endif

#endif







