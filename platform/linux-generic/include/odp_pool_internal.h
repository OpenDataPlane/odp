/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2013-2018 Linaro Limited
 * Copyright (c) 2019-2025 Nokia
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

#include <odp/api/atomic.h>
#include <odp/api/shared_memory.h>
#include <odp/api/ticketlock.h>
#include <odp/api/align.h>

#include <odp_event_internal.h>
#include <odp_config_internal.h>
#include <odp_ring_mpmc_rst_ptr_internal.h>
#include <odp/api/plat/strong_types.h>

#define _ODP_POOL_MEM_SRC_DATA_SIZE 128

typedef struct ODP_ALIGNED_CACHE pool_cache_t {
	/* Number of buffers in cache */
	odp_atomic_u32_t cache_num;
	/* Cached buffers */
	_odp_event_hdr_t *event_hdr[CONFIG_POOL_CACHE_MAX_SIZE];

} pool_cache_t;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
/* Event header ring */
typedef struct ODP_ALIGNED_CACHE {
	/* Ring header */
	ring_mpmc_rst_ptr_t hdr;

	/* Ring data: buffer handles */
	_odp_event_hdr_t *event_hdr[CONFIG_POOL_MAX_NUM + 1];

	/* Index to pointer look-up table for external memory pool */
	_odp_event_hdr_t *event_hdr_by_index[];

} pool_ring_t;
#pragma GCC diagnostic pop

struct _odp_pool_mem_src_ops_t;

typedef struct pool_t {
	odp_ticketlock_t lock ODP_ALIGNED_CACHE;
	uint32_t         pool_idx;
	uint8_t          reserved;

	/* Everything under this mark are memset() to zero on pool create */
	uint8_t          memset_mark;
	uint8_t          type;
	uint8_t          pool_ext;
	pool_ring_t     *ring;
	uint32_t         ring_mask;
	uint32_t         cache_size;
	uint32_t         burst_size;
	uint32_t         num;
	uint32_t         headroom;
	uint32_t         tailroom;
	uint32_t         seg_len;
	uint32_t         max_seg_len;
	uint32_t         max_len;
	uint32_t         param_uarea_size;

	/* --- 64-byte cache line boundary --- */

	uint32_t         uarea_size;
	uint32_t         block_size;
	uint32_t         block_offset;
	uint32_t         trailer_size;
	uint8_t         *base_addr;
	uint8_t         *max_addr;
	uint32_t         ext_head_offset;
	uint32_t         skipped_blocks;
	odp_pool_param_t params;
	odp_pool_ext_param_t ext_param;

	const struct _odp_pool_mem_src_ops_t *mem_src_ops;
	/* Private area for memory source operations */
	uint8_t mem_src_data[_ODP_POOL_MEM_SRC_DATA_SIZE] ODP_ALIGNED_CACHE;

	struct ODP_ALIGNED_CACHE {
		odp_atomic_u64_t alloc_ops;
		odp_atomic_u64_t alloc_fails;
		odp_atomic_u64_t free_ops;
		odp_atomic_u64_t cache_alloc_ops;
		odp_atomic_u64_t cache_free_ops;
	} stats;

	pool_cache_t     local_cache[ODP_THREAD_COUNT_MAX];

	/* --- Control path data --- */

	odp_shm_t        shm;
	uint64_t         shm_size;
	odp_shm_t        ring_shm;
	odp_shm_t        uarea_shm;
	uint64_t         uarea_shm_size;
	uint8_t         *uarea_base_addr;
	uint32_t         align;
	uint32_t         num_populated;
	odp_pool_type_t  type_2; /* Pool type from application PoV */
	uint8_t          mem_from_huge_pages;
	char             name[ODP_POOL_NAME_LEN];

} pool_t;

typedef struct pool_global_t {
	pool_t    pool[CONFIG_POOLS];
	odp_shm_t shm;

	struct {
		uint32_t pkt_max_len;
		uint32_t pkt_max_num;
		uint32_t local_cache_size;
		uint32_t burst_size;
		uint32_t pkt_base_align;
		uint32_t buf_min_align;
	} config;

} pool_global_t;

/* Operations for when ODP packet pool is used as a memory source for e.g. zero-copy packet IO
 * purposes */
typedef struct _odp_pool_mem_src_ops_t {
	/* Name of the ops provider */
	const char *name;
	/* Signal if ops provider is an active user for the pool as a memory source */
	odp_bool_t (*is_active)(void);
	/* Force disable for the ops provider (for now, if one active memory source user is found,
	 * others are disabled) */
	void (*force_disable)(void);
	/* Adjust pool block sizes as required by memory consumer */
	void (*adjust_size)(uint8_t *data, uint32_t *block_size, uint32_t *block_offset,
			    uint32_t *flags);
	/* Bind the pool as a memory source */
	int (*bind)(uint8_t *data, pool_t *pool);
	/* Unbind the pool as a memory source */
	void (*unbind)(uint8_t *data);
} _odp_pool_mem_src_ops_t;

extern pool_global_t *_odp_pool_glb;

static inline pool_t *_odp_pool_entry_from_idx(uint32_t pool_idx)
{
	return &_odp_pool_glb->pool[pool_idx];
}

static inline pool_t *_odp_pool_entry(odp_pool_t pool_hdl)
{
	return (pool_t *)(uintptr_t)pool_hdl;
}

static inline odp_pool_t _odp_pool_handle(pool_t *pool)
{
	return (odp_pool_t)(uintptr_t)pool;
}

static inline odp_pool_type_t _odp_pool_type(odp_pool_t pool_hdl)
{
	return _odp_pool_entry(pool_hdl)->type_2;
}

static inline _odp_event_hdr_t *event_hdr_from_index(pool_t *pool,
						     uint32_t event_idx)
{
	uint64_t block_offset;
	_odp_event_hdr_t *event_hdr;

	block_offset = (event_idx * (uint64_t)pool->block_size) +
			pool->block_offset;

	/* clang requires cast to uintptr_t */
	event_hdr = (_odp_event_hdr_t *)(uintptr_t)&pool->base_addr[block_offset];

	return event_hdr;
}

odp_event_t _odp_event_alloc(pool_t *pool);
int _odp_event_alloc_multi(pool_t *pool, _odp_event_hdr_t *event_hdr[], int num);
void _odp_event_free_multi(_odp_event_hdr_t *event_hdr[], int num_free);
void _odp_event_free_sp(_odp_event_hdr_t *event_hdr[], int num);
int _odp_event_is_valid(odp_event_t event);

static inline void _odp_event_free(odp_event_t event)
{
	_odp_event_free_sp((_odp_event_hdr_t **)&event, 1);
}

odp_pool_t _odp_pool_create(const char *name, const odp_pool_param_t *params,
			    odp_pool_type_t type_2);

#ifdef __cplusplus
}
#endif

#endif
