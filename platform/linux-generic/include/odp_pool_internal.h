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

#include <odp/std_types.h>
#include <odp/align.h>
#include <odp_align_internal.h>
#include <odp/pool.h>
#include <odp_buffer_internal.h>
#include <odp/hints.h>
#include <odp/config.h>
#include <odp/debug.h>
#include <odp/shared_memory.h>
#include <odp/atomic.h>
#include <odp_atomic_internal.h>
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

/* Local cache for buffer alloc/free acceleration */
typedef struct local_cache_t {
	odp_buffer_hdr_t *buf_freelist;  /* The local cache */
	uint64_t bufallocs;              /* Local buffer alloc count */
	uint64_t buffrees;               /* Local buffer free count */
} local_cache_t;

/* Use ticketlock instead of spinlock */
#define POOL_USE_TICKETLOCK

/* Extra error checks */
/* #define POOL_ERROR_CHECK */


#ifdef POOL_USE_TICKETLOCK
#include <odp/ticketlock.h>
#define POOL_LOCK(a)      odp_ticketlock_lock(a)
#define POOL_UNLOCK(a)    odp_ticketlock_unlock(a)
#define POOL_LOCK_INIT(a) odp_ticketlock_init(a)
#else
#include <odp/spinlock.h>
#define POOL_LOCK(a)      odp_spinlock_lock(a)
#define POOL_UNLOCK(a)    odp_spinlock_unlock(a)
#define POOL_LOCK_INIT(a) odp_spinlock_init(a)
#endif

struct pool_entry_s {
#ifdef POOL_USE_TICKETLOCK
	odp_ticketlock_t        lock ODP_ALIGNED_CACHE;
#else
	odp_spinlock_t          lock ODP_ALIGNED_CACHE;
#endif

	char                    name[ODP_POOL_NAME_LEN];
	odp_pool_param_t        params;
	_odp_buffer_pool_init_t init_params;
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
	uint32_t                low_wm_assert;
	uint8_t                *pool_base_addr;
	uint8_t                *pool_mdata_addr;
	size_t                  pool_size;
	uint32_t                buf_align;
	uint32_t                buf_stride;
	_odp_atomic_ptr_t       buf_freelist;
	_odp_atomic_ptr_t       blk_freelist;
	odp_atomic_u32_t        bufcount;
	odp_atomic_u32_t        blkcount;
	odp_atomic_u64_t        bufallocs;
	odp_atomic_u64_t        buffrees;
	odp_atomic_u64_t        blkallocs;
	odp_atomic_u64_t        blkfrees;
	odp_atomic_u64_t        bufempty;
	odp_atomic_u64_t        blkempty;
	odp_atomic_u64_t        high_wm_count;
	odp_atomic_u64_t        low_wm_count;
	uint32_t                seg_size;
	uint32_t                high_wm;
	uint32_t                low_wm;
	uint32_t                headroom;
	uint32_t                tailroom;
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

#define TAG_ALIGN ((size_t)16)

#define odp_cs(ptr, old, new) \
	_odp_atomic_ptr_cmp_xchg_strong(&ptr, (void **)&old, (void *)new, \
					_ODP_MEMMODEL_SC, \
					_ODP_MEMMODEL_SC)

/* Helper functions for pointer tagging to avoid ABA race conditions */
#define odp_tag(ptr) \
	(((size_t)ptr) & (TAG_ALIGN - 1))

#define odp_detag(ptr) \
	((void *)(((size_t)ptr) & -TAG_ALIGN))

#define odp_retag(ptr, tag) \
	((void *)(((size_t)ptr) | odp_tag(tag)))


static inline void *get_blk(struct pool_entry_s *pool)
{
	void *oldhead, *myhead, *newhead;

	oldhead = _odp_atomic_ptr_load(&pool->blk_freelist, _ODP_MEMMODEL_ACQ);

	do {
		size_t tag = odp_tag(oldhead);
		myhead = odp_detag(oldhead);
		if (odp_unlikely(myhead == NULL))
			break;
		newhead = odp_retag(((odp_buf_blk_t *)myhead)->next, tag + 1);
	} while (odp_cs(pool->blk_freelist, oldhead, newhead) == 0);

	if (odp_unlikely(myhead == NULL))
		odp_atomic_inc_u64(&pool->blkempty);
	else
		odp_atomic_dec_u32(&pool->blkcount);

	return (void *)myhead;
}

static inline void ret_blk(struct pool_entry_s *pool, void *block)
{
	void *oldhead, *myhead, *myblock;

	oldhead = _odp_atomic_ptr_load(&pool->blk_freelist, _ODP_MEMMODEL_ACQ);

	do {
		size_t tag = odp_tag(oldhead);
		myhead = odp_detag(oldhead);
		((odp_buf_blk_t *)block)->next = myhead;
		myblock = odp_retag(block, tag + 1);
	} while (odp_cs(pool->blk_freelist, oldhead, myblock) == 0);

	odp_atomic_inc_u32(&pool->blkcount);
	odp_atomic_inc_u64(&pool->blkfrees);
}

static inline odp_buffer_hdr_t *get_buf(struct pool_entry_s *pool)
{
	odp_buffer_hdr_t *oldhead, *myhead, *newhead;

	oldhead = _odp_atomic_ptr_load(&pool->buf_freelist, _ODP_MEMMODEL_ACQ);

	do {
		size_t tag = odp_tag(oldhead);
		myhead = odp_detag(oldhead);
		if (odp_unlikely(myhead == NULL))
			break;
		newhead = odp_retag(myhead->next, tag + 1);
	} while (odp_cs(pool->buf_freelist, oldhead, newhead) == 0);

	if (odp_unlikely(myhead == NULL)) {
		odp_atomic_inc_u64(&pool->bufempty);
	} else {
		uint64_t bufcount =
			odp_atomic_fetch_sub_u32(&pool->bufcount, 1) - 1;

		/* Check for low watermark condition */
		if (bufcount == pool->low_wm && !pool->low_wm_assert) {
			pool->low_wm_assert = 1;
			odp_atomic_inc_u64(&pool->low_wm_count);
		}

		odp_atomic_inc_u64(&pool->bufallocs);
		myhead->next = myhead;  /* Mark buffer allocated */
		myhead->allocator = odp_thread_id();
	}

	return (void *)myhead;
}

static inline void ret_buf(struct pool_entry_s *pool, odp_buffer_hdr_t *buf)
{
	odp_buffer_hdr_t *oldhead, *myhead, *mybuf;

	buf->allocator = ODP_FREEBUF;  /* Mark buffer free */

	if (!buf->flags.hdrdata && buf->type != ODP_EVENT_BUFFER) {
		while (buf->segcount > 0) {
			if (buffer_is_secure(buf) || pool_is_secure(pool))
				memset(buf->addr[buf->segcount - 1],
				       0, buf->segsize);
			ret_blk(pool, buf->addr[--buf->segcount]);
		}
		buf->size = 0;
	}

	oldhead = _odp_atomic_ptr_load(&pool->buf_freelist, _ODP_MEMMODEL_ACQ);

	do {
		size_t tag = odp_tag(oldhead);
		myhead = odp_detag(oldhead);
		buf->next = myhead;
		mybuf = odp_retag(buf, tag + 1);
	} while (odp_cs(pool->buf_freelist, oldhead, mybuf) == 0);

	uint64_t bufcount = odp_atomic_fetch_add_u32(&pool->bufcount, 1) + 1;

	/* Check if low watermark condition should be deasserted */
	if (bufcount == pool->high_wm && pool->low_wm_assert) {
		pool->low_wm_assert = 0;
		odp_atomic_inc_u64(&pool->high_wm_count);
	}

	odp_atomic_inc_u64(&pool->buffrees);
}

static inline void *get_local_buf(local_cache_t *buf_cache,
				  struct pool_entry_s *pool,
				  size_t totsize)
{
	odp_buffer_hdr_t *buf = buf_cache->buf_freelist;

	if (odp_likely(buf != NULL)) {
		buf_cache->buf_freelist = buf->next;

		if (odp_unlikely(buf->size < totsize)) {
			intmax_t needed = totsize - buf->size;

			do {
				void *blk = get_blk(pool);
				if (odp_unlikely(blk == NULL)) {
					ret_buf(pool, buf);
					buf_cache->buffrees--;
					return NULL;
				}
				buf->addr[buf->segcount++] = blk;
				needed -= pool->seg_size;
			} while (needed > 0);

			buf->size = buf->segcount * pool->seg_size;
		}

		buf_cache->bufallocs++;
		buf->allocator = odp_thread_id();  /* Mark buffer allocated */
	}

	return buf;
}

static inline void ret_local_buf(local_cache_t *buf_cache,
				odp_buffer_hdr_t *buf)
{
	buf->allocator = ODP_FREEBUF;
	buf->next = buf_cache->buf_freelist;
	buf_cache->buf_freelist = buf;

	buf_cache->buffrees++;
}

static inline void flush_cache(local_cache_t *buf_cache,
			       struct pool_entry_s *pool)
{
	odp_buffer_hdr_t *buf = buf_cache->buf_freelist;
	uint32_t flush_count = 0;

	while (buf != NULL) {
		odp_buffer_hdr_t *next = buf->next;
		ret_buf(pool, buf);
		buf = next;
		flush_count++;
	}

	odp_atomic_add_u64(&pool->bufallocs, buf_cache->bufallocs);
	odp_atomic_add_u64(&pool->buffrees, buf_cache->buffrees - flush_count);

	buf_cache->buf_freelist = NULL;
	buf_cache->bufallocs = 0;
	buf_cache->buffrees = 0;
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

#ifdef __cplusplus
}
#endif

#endif
