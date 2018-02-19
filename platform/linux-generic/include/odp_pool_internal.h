/* Copyright (c) 2013-2018, Linaro Limited
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

typedef struct ODP_ALIGNED_CACHE pool_cache_t {
	uint32_t num;
	uint32_t buf_index[CONFIG_POOL_CACHE_SIZE];

} pool_cache_t;

/* Buffer header ring */
typedef struct ODP_ALIGNED_CACHE {
	/* Ring header */
	ring_t   hdr;

	/* Ring data: buffer handles */
	uint32_t buf[CONFIG_POOL_MAX_NUM];

} pool_ring_t;

/* Callback function for pool destroy */
typedef void (*pool_destroy_cb_fn)(void *pool);

typedef struct pool_t {
	odp_ticketlock_t ODP_ALIGNED_CACHE lock;

	char             name[ODP_POOL_NAME_LEN];
	odp_pool_param_t params;
	odp_pool_t       pool_hdl;
	uint32_t         pool_idx;
	uint32_t         ring_mask;
	odp_shm_t        shm;
	odp_shm_t        uarea_shm;
	uint64_t         shm_size;
	uint64_t         uarea_shm_size;
	int              reserved;
	uint32_t         num;
	uint32_t         align;
	uint32_t         headroom;
	uint32_t         tailroom;
	uint32_t         seg_len;
	uint32_t         max_seg_len;
	uint32_t         max_len;
	uint32_t         uarea_size;
	uint32_t         block_size;
	uint8_t         *base_addr;
	uint8_t         *uarea_base_addr;

	/* Used by DPDK zero-copy pktio */
	uint8_t		mem_from_huge_pages;
	pool_destroy_cb_fn ext_destroy;
	void            *ext_desc;

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

static inline odp_buffer_hdr_t *buf_hdl_to_hdr(odp_buffer_t buf)
{
	return (odp_buffer_hdr_t *)(uintptr_t)buf;
}

int buffer_alloc_multi(pool_t *pool, odp_buffer_hdr_t *buf_hdr[], int num);
void buffer_free_multi(odp_buffer_hdr_t *buf_hdr[], int num_free);

#ifdef __cplusplus
}
#endif

#endif
