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

	pool_ring_t      ring;

} pool_t;

pool_t *pool_entry(uint32_t pool_idx);

static inline pool_t *odp_pool_to_entry(odp_pool_t pool_hdl)
{
	return pool_entry(_odp_typeval(pool_hdl));
}

static inline uint32_t odp_buffer_pool_headroom(odp_pool_t pool)
{
	return odp_pool_to_entry(pool)->headroom;
}

static inline uint32_t odp_buffer_pool_tailroom(odp_pool_t pool)
{
	return odp_pool_to_entry(pool)->tailroom;
}

#ifdef __cplusplus
}
#endif

#endif
