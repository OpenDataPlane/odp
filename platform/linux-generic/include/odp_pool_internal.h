/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP buffer pool - internal header
 */

#ifndef ODP_POOL_INTERNAL_H_
#define ODP_POOL_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/shared_memory.h>
#include <odp/api/ticketlock.h>

#include <odp_buffer_internal.h>
#include <odp_config_internal.h>
#include <odp_ring_internal.h>
#include <odp/api/plat/strong_types.h>

typedef struct pool_cache_t {
	uint32_t num;

	odp_buffer_t buf[CONFIG_POOL_CACHE_SIZE];

} pool_cache_t ODP_ALIGNED_CACHE;

/* Buffer header ring */
typedef struct {
	/* Ring header */
	ring_t   hdr;

	/* Ring data: buffer handles */
	uint32_t buf[CONFIG_POOL_MAX_NUM];

} pool_ring_t ODP_ALIGNED_CACHE;

typedef struct pool_t {
	odp_ticketlock_t lock ODP_ALIGNED_CACHE;

	char             name[ODP_POOL_NAME_LEN];
	odp_pool_param_t params;
	odp_pool_t       pool_hdl;
	uint32_t         pool_idx;
	uint32_t         ring_mask;
	odp_shm_t        shm;
	odp_shm_t        uarea_shm;
	int              reserved;
	uint32_t         num;
	uint32_t         align;
	uint32_t         headroom;
	uint32_t         tailroom;
	uint32_t         data_size;
	uint32_t         max_len;
	uint32_t         max_seg_len;
	uint32_t         uarea_size;
	uint32_t         block_size;
	uint32_t         shm_size;
	uint32_t         uarea_shm_size;
	uint8_t         *base_addr;
	uint8_t         *uarea_base_addr;

	pool_cache_t     local_cache[ODP_THREAD_COUNT_MAX];

	odp_shm_t        ring_shm;
	pool_ring_t     *ring;

} pool_t;

typedef struct pool_table_t {
	pool_t    pool[ODP_CONFIG_POOLS];
	odp_shm_t shm;
} pool_table_t;

extern pool_table_t *pool_tbl;

static inline pool_t *pool_entry(uint32_t pool_idx)
{
	return &pool_tbl->pool[pool_idx];
}

static inline pool_t *pool_entry_from_hdl(odp_pool_t pool_hdl)
{
	return &pool_tbl->pool[_odp_typeval(pool_hdl)];
}

static inline odp_buffer_hdr_t *pool_buf_hdl_to_hdr(pool_t *pool,
						    odp_buffer_t buf)
{
	odp_buffer_bits_t handle;
	uint32_t index, block_offset;
	odp_buffer_hdr_t *buf_hdr;

	handle.handle = buf;
	index         = handle.index;
	block_offset  = index * pool->block_size;

	/* clang requires cast to uintptr_t */
	buf_hdr = (odp_buffer_hdr_t *)(uintptr_t)&pool->base_addr[block_offset];

	return buf_hdr;
}

static inline odp_buffer_hdr_t *buf_hdl_to_hdr(odp_buffer_t buf)
{
	odp_buffer_bits_t handle;
	uint32_t pool_id;
	pool_t *pool;

	handle.handle = buf;
	pool_id       = handle.pool_id;
	pool          = pool_entry(pool_id);

	return pool_buf_hdl_to_hdr(pool, buf);
}

int buffer_alloc_multi(pool_t *pool, odp_buffer_t buf[],
		       odp_buffer_hdr_t *buf_hdr[], int num);
void buffer_free_multi(const odp_buffer_t buf[], int num_free);

#ifdef __cplusplus
}
#endif

#endif
