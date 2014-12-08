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

#ifndef ODP_BUFFER_POOL_INTERNAL_H_
#define ODP_BUFFER_POOL_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp_std_types.h>
#include <odp_buffer_pool.h>
#include <odp_buffer_internal.h>
#include <odp_align.h>
#include <odp_align_internal.h>
#include <odp_hints.h>
#include <odp_config.h>
#include <odp_debug.h>

/* Use ticketlock instead of spinlock */
#define POOL_USE_TICKETLOCK

/* Extra error checks */
/* #define POOL_ERROR_CHECK */


#ifdef POOL_USE_TICKETLOCK
#include <odp_ticketlock.h>
#else
#include <odp_spinlock.h>
#endif


struct pool_entry_s {
#ifdef POOL_USE_TICKETLOCK
	odp_ticketlock_t        lock ODP_ALIGNED_CACHE;
#else
	odp_spinlock_t          lock ODP_ALIGNED_CACHE;
#endif

	odp_buffer_chunk_hdr_t *head;
	uint64_t                free_bufs;
	char                    name[ODP_BUFFER_POOL_NAME_LEN];

	odp_buffer_pool_t       pool_hdl ODP_ALIGNED_CACHE;
	uintptr_t               buf_base;
	size_t                  buf_size;
	size_t                  buf_offset;
	uint64_t                num_bufs;
	void                   *pool_base_addr;
	uint64_t                pool_size;
	size_t                  user_size;
	size_t                  user_align;
	int                     buf_type;
	size_t                  hdr_size;
};

typedef union pool_entry_u {
	struct pool_entry_s s;
	uint8_t pad[ODP_CACHE_LINE_SIZE_ROUNDUP(sizeof(struct pool_entry_s))];
} pool_entry_t;

extern void *pool_entry_ptr[];


static inline void *get_pool_entry(uint32_t pool_id)
{
	return pool_entry_ptr[pool_id];
}

static inline uint32_t pool_handle_to_index(odp_buffer_pool_t pool_hdl)
{
	return pool_hdl - 1;
}

static inline odp_buffer_hdr_t *odp_buf_to_hdr(odp_buffer_t buf)
{
	odp_buffer_bits_t handle;
	uint32_t pool_id;
	uint32_t index;
	struct pool_entry_s *pool;
	odp_buffer_hdr_t *hdr;

	handle.u32 = buf;
	pool_id    = handle.pool_id;
	index      = handle.index;

#ifdef POOL_ERROR_CHECK
	if (odp_unlikely(pool_id > ODP_CONFIG_BUFFER_POOLS)) {
		ODP_ERR("odp_buf_to_hdr: Bad pool id\n");
		return NULL;
	}
#endif

	pool = get_pool_entry(pool_id);

#ifdef POOL_ERROR_CHECK
	if (odp_unlikely(index > pool->num_bufs - 1)) {
		ODP_ERR("odp_buf_to_hdr: Bad buffer index\n");
		return NULL;
	}
#endif

	hdr = (odp_buffer_hdr_t *)(pool->buf_base + index * pool->buf_size);

	return hdr;
}


#ifdef __cplusplus
}
#endif

#endif
