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

#include <odp/api/std_types.h>
#include <odp/api/align.h>
#include <odp_align_internal.h>
#include <odp/api/pool.h>
#include <odp_buffer_internal.h>
#include <odp/api/hints.h>
#include <odp_config_internal.h>
#include <odp/api/debug.h>
#include <odp/api/shared_memory.h>
#include <odp/api/atomic.h>
#include <odp/api/thread.h>
#include <string.h>

/**
 * Buffer initialization routine prototype
 *
 * @note Routines of this type MAY be passed as part of the
 * _odp_buffer_pool_init_t structure to be called whenever a
 * buffer is allocated to initialize the user metadata
 * associated with that buffer.
 */
typedef void (_odp_buf_init_t)(odp_buffer_t buf, void *buf_init_arg);

/**
 * Buffer pool initialization parameters
 * Used to communicate buffer pool initialization options. Internal for now.
 */
typedef struct _odp_buffer_pool_init_t {
	size_t udata_size;         /**< Size of user metadata for each buffer */
	_odp_buf_init_t *buf_init; /**< Buffer initialization routine to use */
	void *buf_init_arg;        /**< Argument to be passed to buf_init() */
} _odp_buffer_pool_init_t;         /**< Type of buffer initialization struct */

#define POOL_MAX_LOCAL_CHUNKS 4
#define POOL_CHUNK_SIZE       32
#define POOL_MAX_LOCAL_BUFS   (POOL_MAX_LOCAL_CHUNKS * POOL_CHUNK_SIZE)

struct local_cache_s {
	uint64_t bufallocs;  /* Local buffer alloc count */
	uint64_t buffrees;   /* Local buffer free count */

	uint32_t num_buf;
	odp_buffer_hdr_t *buf[POOL_MAX_LOCAL_BUFS];
};

/* Local cache for buffer alloc/free acceleration */
typedef struct local_cache_t {
	union {
		struct local_cache_s s;

		uint8_t pad[ODP_CACHE_LINE_SIZE_ROUNDUP(
			    sizeof(struct local_cache_s))];
	};
} local_cache_t;

#include <odp/api/plat/ticketlock_inlines.h>
#define POOL_LOCK(a)      _odp_ticketlock_lock(a)
#define POOL_UNLOCK(a)    _odp_ticketlock_unlock(a)
#define POOL_LOCK_INIT(a) odp_ticketlock_init(a)

/**
 * ODP Pool stats - Maintain some useful stats regarding pool utilization
 */
typedef struct {
	odp_atomic_u64_t bufallocs;     /**< Count of successful buf allocs */
	odp_atomic_u64_t buffrees;      /**< Count of successful buf frees */
	odp_atomic_u64_t blkallocs;     /**< Count of successful blk allocs */
	odp_atomic_u64_t blkfrees;      /**< Count of successful blk frees */
	odp_atomic_u64_t bufempty;      /**< Count of unsuccessful buf allocs */
	odp_atomic_u64_t blkempty;      /**< Count of unsuccessful blk allocs */
	odp_atomic_u64_t buf_high_wm_count; /**< Count of high buf wm conditions */
	odp_atomic_u64_t buf_low_wm_count;  /**< Count of low buf wm conditions */
	odp_atomic_u64_t blk_high_wm_count;  /**< Count of high blk wm conditions */
	odp_atomic_u64_t blk_low_wm_count;   /**< Count of low blk wm conditions */
} _odp_pool_stats_t;

struct pool_entry_s {
	odp_ticketlock_t        lock ODP_ALIGNED_CACHE;
	odp_ticketlock_t        buf_lock;
	odp_ticketlock_t        blk_lock;

	char                    name[ODP_POOL_NAME_LEN];
	odp_pool_param_t        params;
	uint32_t                udata_size;
	odp_pool_t              pool_hdl;
	uint32_t                pool_id;
	odp_shm_t               pool_shm;
	union {
		uint32_t all;
		struct {
			uint32_t has_name:1;
			uint32_t user_supplied_shm:1;
			uint32_t unsegmented:1;
			uint32_t zeroized:1;
			uint32_t predefined:1;
		};
	} flags;
	uint32_t                quiesced;
	uint32_t                buf_low_wm_assert;
	uint32_t                blk_low_wm_assert;
	uint8_t                *pool_base_addr;
	uint8_t                *pool_mdata_addr;
	size_t                  pool_size;
	uint32_t                buf_align;
	uint32_t                buf_stride;
	odp_buffer_hdr_t       *buf_freelist;
	void                   *blk_freelist;
	odp_atomic_u32_t        bufcount;
	odp_atomic_u32_t        blkcount;
	_odp_pool_stats_t       poolstats;
	uint32_t                buf_num;
	uint32_t                seg_size;
	uint32_t                blk_size;
	uint32_t                buf_high_wm;
	uint32_t                buf_low_wm;
	uint32_t                blk_high_wm;
	uint32_t                blk_low_wm;
	uint32_t                headroom;
	uint32_t                tailroom;

	local_cache_t local_cache[ODP_THREAD_COUNT_MAX] ODP_ALIGNED_CACHE;
};

typedef union pool_entry_u {
	struct pool_entry_s s;

	uint8_t pad[ODP_CACHE_LINE_SIZE_ROUNDUP(sizeof(struct pool_entry_s))];
} pool_entry_t;

extern void *pool_entry_ptr[];

#if defined(ODP_CONFIG_SECURE_POOLS) && (ODP_CONFIG_SECURE_POOLS == 1)
#define buffer_is_secure(buf) (buf->flags.zeroized)
#define pool_is_secure(pool) (pool->flags.zeroized)
#else
#define buffer_is_secure(buf) 0
#define pool_is_secure(pool) 0
#endif

static inline void *get_blk(struct pool_entry_s *pool)
{
	void *myhead;
	uint64_t blkcount;

	POOL_LOCK(&pool->blk_lock);

	myhead = pool->blk_freelist;

	if (odp_unlikely(myhead == NULL)) {
		POOL_UNLOCK(&pool->blk_lock);
		odp_atomic_inc_u64(&pool->poolstats.blkempty);
	} else {
		pool->blk_freelist = ((odp_buf_blk_t *)myhead)->next;
		POOL_UNLOCK(&pool->blk_lock);
		blkcount = odp_atomic_fetch_sub_u32(&pool->blkcount, 1) - 1;

		/* Check for low watermark condition */
		if (blkcount == pool->blk_low_wm && !pool->blk_low_wm_assert) {
			pool->blk_low_wm_assert = 1;
			odp_atomic_inc_u64(&pool->poolstats.blk_low_wm_count);
		}

		odp_atomic_inc_u64(&pool->poolstats.blkallocs);
	}

	return myhead;
}

static inline void ret_blk(struct pool_entry_s *pool, void *block)
{
	uint64_t blkcount;

	POOL_LOCK(&pool->blk_lock);

	((odp_buf_blk_t *)block)->next = pool->blk_freelist;
	pool->blk_freelist = block;

	POOL_UNLOCK(&pool->blk_lock);

	blkcount = odp_atomic_fetch_add_u32(&pool->blkcount, 1);

	/* Check if low watermark condition should be deasserted */
	if (blkcount == pool->blk_high_wm && pool->blk_low_wm_assert) {
		pool->blk_low_wm_assert = 0;
		odp_atomic_inc_u64(&pool->poolstats.blk_high_wm_count);
	}

	odp_atomic_inc_u64(&pool->poolstats.blkfrees);
}

static inline odp_pool_t pool_index_to_handle(uint32_t pool_id)
{
	return _odp_cast_scalar(odp_pool_t, pool_id);
}

static inline uint32_t pool_handle_to_index(odp_pool_t pool_hdl)
{
	return _odp_typeval(pool_hdl);
}

static inline void *get_pool_entry(uint32_t pool_id)
{
	return pool_entry_ptr[pool_id];
}

static inline pool_entry_t *odp_pool_to_entry(odp_pool_t pool)
{
	return (pool_entry_t *)get_pool_entry(pool_handle_to_index(pool));
}

static inline pool_entry_t *odp_buf_to_pool(odp_buffer_hdr_t *buf)
{
	return odp_pool_to_entry(buf->pool_hdl);
}

static inline uint32_t odp_buffer_pool_segment_size(odp_pool_t pool)
{
	return odp_pool_to_entry(pool)->s.seg_size;
}

static inline uint32_t odp_buffer_pool_headroom(odp_pool_t pool)
{
	return odp_pool_to_entry(pool)->s.headroom;
}

static inline uint32_t odp_buffer_pool_tailroom(odp_pool_t pool)
{
	return odp_pool_to_entry(pool)->s.tailroom;
}

odp_pool_t _pool_create(const char *name,
			odp_pool_param_t *params,
			uint32_t shmflags);

#ifdef __cplusplus
}
#endif

#endif
