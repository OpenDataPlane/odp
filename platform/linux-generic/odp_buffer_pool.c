/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_std_types.h>
#include <odp_pool.h>
#include <odp_buffer_internal.h>
#include <odp_buffer_pool_internal.h>
#include <odp_buffer_inlines.h>
#include <odp_packet_internal.h>
#include <odp_timer_internal.h>
#include <odp_align_internal.h>
#include <odp_shared_memory.h>
#include <odp_align.h>
#include <odp_internal.h>
#include <odp_config.h>
#include <odp_hints.h>
#include <odp_debug_internal.h>
#include <odp_atomic_internal.h>

#include <string.h>
#include <stdlib.h>


#if ODP_CONFIG_POOLS > ODP_BUFFER_MAX_POOLS
#error ODP_CONFIG_POOLS > ODP_BUFFER_MAX_POOLS
#endif


typedef union buffer_type_any_u {
	odp_buffer_hdr_t  buf;
	odp_packet_hdr_t  pkt;
	odp_timeout_hdr_t tmo;
} odp_anybuf_t;

_ODP_STATIC_ASSERT((sizeof(union buffer_type_any_u) % 8) == 0,
		   "BUFFER_TYPE_ANY_U__SIZE_ERR");

/* Any buffer type header */
typedef struct {
	union buffer_type_any_u any_hdr;    /* any buffer type */
} odp_any_buffer_hdr_t;

typedef struct odp_any_hdr_stride {
	uint8_t pad[ODP_CACHE_LINE_SIZE_ROUNDUP(sizeof(odp_any_buffer_hdr_t))];
} odp_any_hdr_stride;


typedef struct pool_table_t {
	pool_entry_t pool[ODP_CONFIG_POOLS];
} pool_table_t;


/* The pool table */
static pool_table_t *pool_tbl;

/* Pool entry pointers (for inlining) */
void *pool_entry_ptr[ODP_CONFIG_POOLS];

/* Local cache for buffer alloc/free acceleration */
static __thread local_cache_t local_cache[ODP_CONFIG_POOLS];

int odp_buffer_pool_init_global(void)
{
	uint32_t i;
	odp_shm_t shm;

	shm = odp_shm_reserve("odp_buffer_pools",
			      sizeof(pool_table_t),
			      sizeof(pool_entry_t), 0);

	pool_tbl = odp_shm_addr(shm);

	if (pool_tbl == NULL)
		return -1;

	memset(pool_tbl, 0, sizeof(pool_table_t));

	for (i = 0; i < ODP_CONFIG_POOLS; i++) {
		/* init locks */
		pool_entry_t *pool = &pool_tbl->pool[i];
		POOL_LOCK_INIT(&pool->s.lock);
		pool->s.pool_hdl = pool_index_to_handle(i);
		pool->s.pool_id = i;
		pool_entry_ptr[i] = pool;
	}

	ODP_DBG("\nBuffer pool init global\n");
	ODP_DBG("  pool_entry_s size     %zu\n", sizeof(struct pool_entry_s));
	ODP_DBG("  pool_entry_t size     %zu\n", sizeof(pool_entry_t));
	ODP_DBG("  odp_buffer_hdr_t size %zu\n", sizeof(odp_buffer_hdr_t));
	ODP_DBG("\n");
	return 0;
}

/**
 * Pool creation
 */

odp_pool_t odp_pool_create(const char *name,
			   odp_shm_t shm,
			   odp_pool_param_t *params)
{
	odp_pool_t pool_hdl = ODP_POOL_INVALID;
	pool_entry_t *pool;
	uint32_t i, headroom = 0, tailroom = 0;

	/* Default size and align for timeouts */
	if (params->type == ODP_POOL_TIMEOUT) {
		params->buf.size  = 0; /* tmo.__res1 */
		params->buf.align = 0; /* tmo.__res2 */
	}

	/* Default initialization paramters */
	static _odp_buffer_pool_init_t default_init_params = {
		.udata_size = 0,
		.buf_init = NULL,
		.buf_init_arg = NULL,
	};

	_odp_buffer_pool_init_t *init_params = &default_init_params;

	if (params == NULL)
		return ODP_POOL_INVALID;

	/* Restriction for v1.0: All non-packet buffers are unsegmented */
	int unsegmented = 1;

	/* Restriction for v1.0: No zeroization support */
	const int zeroized = 0;

	/* Restriction for v1.0: No udata support */
	uint32_t udata_stride = (init_params->udata_size > sizeof(void *)) ?
		ODP_CACHE_LINE_SIZE_ROUNDUP(init_params->udata_size) :
		0;

	uint32_t blk_size, buf_stride;
	uint32_t buf_align = params->buf.align;

	/* Validate requested buffer alignment */
	if (buf_align > ODP_CONFIG_BUFFER_ALIGN_MAX ||
	    buf_align != ODP_ALIGN_ROUNDDOWN_POWER_2(buf_align, buf_align))
		return ODP_POOL_INVALID;

	/* Set correct alignment based on input request */
	if (buf_align == 0)
		buf_align = ODP_CACHE_LINE_SIZE;
	else if (buf_align < ODP_CONFIG_BUFFER_ALIGN_MIN)
		buf_align = ODP_CONFIG_BUFFER_ALIGN_MIN;

	/* Calculate space needed for buffer blocks and metadata */
	switch (params->type) {
	case ODP_POOL_BUFFER:
	case ODP_POOL_TIMEOUT:
		blk_size = params->buf.size;

		/* Optimize small raw buffers */
		if (blk_size > ODP_MAX_INLINE_BUF || params->buf.align != 0)
			blk_size = ODP_ALIGN_ROUNDUP(blk_size, buf_align);

		buf_stride = params->type == ODP_POOL_BUFFER ?
			sizeof(odp_buffer_hdr_stride) :
			sizeof(odp_timeout_hdr_stride);
		break;

	case ODP_POOL_PACKET:
		headroom = ODP_CONFIG_PACKET_HEADROOM;
		tailroom = ODP_CONFIG_PACKET_TAILROOM;
		unsegmented = params->buf.size > ODP_CONFIG_PACKET_BUF_LEN_MAX;

		if (unsegmented)
			blk_size = ODP_ALIGN_ROUNDUP(
				headroom + params->buf.size + tailroom,
				buf_align);
		else
			blk_size = ODP_ALIGN_ROUNDUP(
				headroom + params->buf.size + tailroom,
				ODP_CONFIG_PACKET_BUF_LEN_MIN);

		buf_stride = params->type == ODP_POOL_PACKET ?
			sizeof(odp_packet_hdr_stride) :
			sizeof(odp_any_hdr_stride);
		break;

	default:
		return ODP_POOL_INVALID;
	}

	/* Validate requested number of buffers against addressable limits */
	if (params->buf.num >
	    (ODP_BUFFER_MAX_BUFFERS / (buf_stride / ODP_CACHE_LINE_SIZE)))
		return ODP_POOL_INVALID;

	/* Find an unused buffer pool slot and iniitalize it as requested */
	for (i = 0; i < ODP_CONFIG_POOLS; i++) {
		pool = get_pool_entry(i);

		POOL_LOCK(&pool->s.lock);
		if (pool->s.pool_shm != ODP_SHM_INVALID) {
			POOL_UNLOCK(&pool->s.lock);
			continue;
		}

		/* found free pool */
		size_t block_size, pad_size, mdata_size, udata_size;

		pool->s.flags.all = 0;

		if (name == NULL) {
			pool->s.name[0] = 0;
		} else {
			strncpy(pool->s.name, name,
				ODP_POOL_NAME_LEN - 1);
			pool->s.name[ODP_POOL_NAME_LEN - 1] = 0;
			pool->s.flags.has_name = 1;
		}

		pool->s.params = *params;
		pool->s.init_params = *init_params;
		pool->s.buf_align = buf_align;

		/* Optimize for short buffers: Data stored in buffer hdr */
		if (blk_size <= ODP_MAX_INLINE_BUF) {
			block_size = 0;
			pool->s.buf_align = blk_size == 0 ? 0 : sizeof(void *);
		} else {
			block_size = params->buf.num * blk_size;
			pool->s.buf_align = buf_align;
		}

		pad_size = ODP_CACHE_LINE_SIZE_ROUNDUP(block_size) - block_size;
		mdata_size = params->buf.num * buf_stride;
		udata_size = params->buf.num * udata_stride;

		pool->s.pool_size = ODP_PAGE_SIZE_ROUNDUP(block_size +
							  pad_size +
							  mdata_size +
							  udata_size);

		if (shm == ODP_SHM_NULL) {
			shm = odp_shm_reserve(pool->s.name,
					      pool->s.pool_size,
					      ODP_PAGE_SIZE, 0);
			if (shm == ODP_SHM_INVALID) {
				POOL_UNLOCK(&pool->s.lock);
				return ODP_POOL_INVALID;
			}
			pool->s.pool_base_addr = odp_shm_addr(shm);
		} else {
			odp_shm_info_t info;
			if (odp_shm_info(shm, &info) != 0 ||
			    info.size < pool->s.pool_size) {
				POOL_UNLOCK(&pool->s.lock);
				return ODP_POOL_INVALID;
			}
			pool->s.pool_base_addr = odp_shm_addr(shm);
			void *page_addr =
				ODP_ALIGN_ROUNDUP_PTR(pool->s.pool_base_addr,
						      ODP_PAGE_SIZE);
			if (pool->s.pool_base_addr != page_addr) {
				if (info.size < pool->s.pool_size +
				    ((size_t)page_addr -
				     (size_t)pool->s.pool_base_addr)) {
					POOL_UNLOCK(&pool->s.lock);
					return ODP_POOL_INVALID;
				}
				pool->s.pool_base_addr = page_addr;
			}
			pool->s.flags.user_supplied_shm = 1;
		}

		pool->s.pool_shm = shm;

		/* Now safe to unlock since pool entry has been allocated */
		POOL_UNLOCK(&pool->s.lock);

		pool->s.flags.unsegmented = unsegmented;
		pool->s.flags.zeroized = zeroized;
		pool->s.seg_size = unsegmented ?
			blk_size : ODP_CONFIG_PACKET_BUF_LEN_MIN;


		uint8_t *block_base_addr = pool->s.pool_base_addr;
		uint8_t *mdata_base_addr =
			block_base_addr + block_size + pad_size;
		uint8_t *udata_base_addr = mdata_base_addr + mdata_size;

		/* Pool mdata addr is used for indexing buffer metadata */
		pool->s.pool_mdata_addr = mdata_base_addr;

		pool->s.buf_stride = buf_stride;
		_odp_atomic_ptr_store(&pool->s.buf_freelist, NULL,
				      _ODP_MEMMODEL_RLX);
		_odp_atomic_ptr_store(&pool->s.blk_freelist, NULL,
				      _ODP_MEMMODEL_RLX);

		/* Initialization will increment these to their target vals */
		odp_atomic_store_u32(&pool->s.bufcount, 0);
		odp_atomic_store_u32(&pool->s.blkcount, 0);

		uint8_t *buf = udata_base_addr - buf_stride;
		uint8_t *udat = udata_stride == 0 ? NULL :
			block_base_addr - udata_stride;

		/* Init buffer common header and add to pool buffer freelist */
		do {
			odp_buffer_hdr_t *tmp =
				(odp_buffer_hdr_t *)(void *)buf;

			/* Iniitalize buffer metadata */
			tmp->allocator = ODP_FREEBUF;
			tmp->flags.all = 0;
			tmp->flags.zeroized = zeroized;
			tmp->size = 0;
			odp_atomic_store_u32(&tmp->ref_count, 0);
			tmp->type = params->type;
			tmp->pool_hdl = pool->s.pool_hdl;
			tmp->udata_addr = (void *)udat;
			tmp->udata_size = init_params->udata_size;
			tmp->segcount = 0;
			tmp->segsize = pool->s.seg_size;
			tmp->handle.handle = odp_buffer_encode_handle(tmp);

			/* Set 1st seg addr for zero-len buffers */
			tmp->addr[0] = NULL;

			/* Special case for short buffer data */
			if (blk_size <= ODP_MAX_INLINE_BUF) {
				tmp->flags.hdrdata = 1;
				if (blk_size > 0) {
					tmp->segcount = 1;
					tmp->addr[0] = &tmp->addr[1];
					tmp->size = blk_size;
				}
			}

			/* Push buffer onto pool's freelist */
			ret_buf(&pool->s, tmp);
			buf  -= buf_stride;
			udat -= udata_stride;
		} while (buf >= mdata_base_addr);

		/* Form block freelist for pool */
		uint8_t *blk =
			block_base_addr + block_size - pool->s.seg_size;

		if (blk_size > ODP_MAX_INLINE_BUF)
			do {
				ret_blk(&pool->s, blk);
				blk -= pool->s.seg_size;
			} while (blk >= block_base_addr);

		/* Initialize pool statistics counters */
		odp_atomic_store_u64(&pool->s.bufallocs, 0);
		odp_atomic_store_u64(&pool->s.buffrees, 0);
		odp_atomic_store_u64(&pool->s.blkallocs, 0);
		odp_atomic_store_u64(&pool->s.blkfrees, 0);
		odp_atomic_store_u64(&pool->s.bufempty, 0);
		odp_atomic_store_u64(&pool->s.blkempty, 0);
		odp_atomic_store_u64(&pool->s.high_wm_count, 0);
		odp_atomic_store_u64(&pool->s.low_wm_count, 0);

		/* Reset other pool globals to initial state */
		pool->s.low_wm_assert = 0;
		pool->s.quiesced = 0;
		pool->s.low_wm_assert = 0;
		pool->s.headroom = headroom;
		pool->s.tailroom = tailroom;

		/* Watermarks are hard-coded for now to control caching */
		pool->s.high_wm = params->buf.num / 2;
		pool->s.low_wm = params->buf.num / 4;

		pool_hdl = pool->s.pool_hdl;
		break;
	}

	return pool_hdl;
}


odp_pool_t odp_pool_lookup(const char *name)
{
	uint32_t i;
	pool_entry_t *pool;

	for (i = 0; i < ODP_CONFIG_POOLS; i++) {
		pool = get_pool_entry(i);

		POOL_LOCK(&pool->s.lock);
		if (strcmp(name, pool->s.name) == 0) {
			/* found it */
			POOL_UNLOCK(&pool->s.lock);
			return pool->s.pool_hdl;
		}
		POOL_UNLOCK(&pool->s.lock);
	}

	return ODP_POOL_INVALID;
}

int odp_pool_info(odp_pool_t pool_hdl, odp_pool_info_t *info)
{
	uint32_t pool_id = pool_handle_to_index(pool_hdl);
	pool_entry_t *pool = get_pool_entry(pool_id);

	if (pool == NULL || info == NULL)
		return -1;

	info->name = pool->s.name;
	info->shm  = pool->s.flags.user_supplied_shm ?
		pool->s.pool_shm : ODP_SHM_INVALID;
	info->params.buf.size  = pool->s.params.buf.size;
	info->params.buf.align = pool->s.params.buf.align;
	info->params.buf.num   = pool->s.params.buf.num;
	info->params.type      = pool->s.params.type;

	return 0;
}

int odp_pool_destroy(odp_pool_t pool_hdl)
{
	uint32_t pool_id = pool_handle_to_index(pool_hdl);
	pool_entry_t *pool = get_pool_entry(pool_id);

	if (pool == NULL)
		return -1;

	POOL_LOCK(&pool->s.lock);

	/* Call fails if pool is not allocated or predefined*/
	if (pool->s.pool_shm == ODP_SHM_INVALID ||
	    pool->s.flags.predefined) {
		POOL_UNLOCK(&pool->s.lock);
		return -1;
	}

	/* Make sure local cache is empty */
	flush_cache(&local_cache[pool_id], &pool->s);

	/* Call fails if pool has allocated buffers */
	if (odp_atomic_load_u32(&pool->s.bufcount) < pool->s.params.buf.num) {
		POOL_UNLOCK(&pool->s.lock);
		return -1;
	}

	if (!pool->s.flags.user_supplied_shm)
		odp_shm_free(pool->s.pool_shm);

	pool->s.pool_shm = ODP_SHM_INVALID;
	POOL_UNLOCK(&pool->s.lock);

	return 0;
}

odp_buffer_t buffer_alloc(odp_pool_t pool_hdl, size_t size)
{
	uint32_t pool_id = pool_handle_to_index(pool_hdl);
	pool_entry_t *pool = get_pool_entry(pool_id);
	uintmax_t totsize = pool->s.headroom + size + pool->s.tailroom;
	odp_anybuf_t *buf;

	/* Reject oversized allocation requests */
	if ((pool->s.flags.unsegmented && totsize > pool->s.seg_size) ||
	    (!pool->s.flags.unsegmented &&
	     totsize > ODP_CONFIG_PACKET_BUF_LEN_MAX))
		return ODP_BUFFER_INVALID;

	/* Try to satisfy request from the local cache */
	buf = (odp_anybuf_t *)(void *)get_local_buf(&local_cache[pool_id],
						    &pool->s, totsize);

	/* If cache is empty, satisfy request from the pool */
	if (odp_unlikely(buf == NULL)) {
		buf = (odp_anybuf_t *)(void *)get_buf(&pool->s);

		if (odp_unlikely(buf == NULL))
			return ODP_BUFFER_INVALID;

		/* Get blocks for this buffer, if pool uses application data */
		if (buf->buf.size < totsize) {
			intmax_t needed = totsize - buf->buf.size;
			do {
				uint8_t *blk = get_blk(&pool->s);
				if (blk == NULL) {
					ret_buf(&pool->s, &buf->buf);
					return ODP_BUFFER_INVALID;
				}
				buf->buf.addr[buf->buf.segcount++] = blk;
				needed -= pool->s.seg_size;
			} while (needed > 0);
			buf->buf.size = buf->buf.segcount * pool->s.seg_size;
		}
	}

	/* By default, buffers inherit their pool's zeroization setting */
	buf->buf.flags.zeroized = pool->s.flags.zeroized;

	if (buf->buf.type == ODP_EVENT_PACKET) {
		packet_init(pool, &buf->pkt, size);

		if (pool->s.init_params.buf_init != NULL)
			(*pool->s.init_params.buf_init)
				(buf->buf.handle.handle,
				 pool->s.init_params.buf_init_arg);
	}

	return odp_hdr_to_buf(&buf->buf);
}

odp_buffer_t odp_buffer_alloc(odp_pool_t pool_hdl)
{
	return buffer_alloc(pool_hdl,
			    odp_pool_to_entry(pool_hdl)->s.params.buf.size);
}

void odp_buffer_free(odp_buffer_t buf)
{
	odp_buffer_hdr_t *buf_hdr = odp_buf_to_hdr(buf);
	pool_entry_t *pool = odp_buf_to_pool(buf_hdr);

	if (odp_unlikely(pool->s.low_wm_assert))
		ret_buf(&pool->s, buf_hdr);
	else
		ret_local_buf(&local_cache[pool->s.pool_id], buf_hdr);
}

void _odp_flush_caches(void)
{
	int i;

	for (i = 0; i < ODP_CONFIG_POOLS; i++) {
		pool_entry_t *pool = get_pool_entry(i);
		flush_cache(&local_cache[i], &pool->s);
	}
}

void odp_pool_print(odp_pool_t pool_hdl)
{
	pool_entry_t *pool;
	uint32_t pool_id;

	pool_id = pool_handle_to_index(pool_hdl);
	pool    = get_pool_entry(pool_id);

	uint32_t bufcount  = odp_atomic_load_u32(&pool->s.bufcount);
	uint32_t blkcount  = odp_atomic_load_u32(&pool->s.blkcount);
	uint64_t bufallocs = odp_atomic_load_u64(&pool->s.bufallocs);
	uint64_t buffrees  = odp_atomic_load_u64(&pool->s.buffrees);
	uint64_t blkallocs = odp_atomic_load_u64(&pool->s.blkallocs);
	uint64_t blkfrees  = odp_atomic_load_u64(&pool->s.blkfrees);
	uint64_t bufempty  = odp_atomic_load_u64(&pool->s.bufempty);
	uint64_t blkempty  = odp_atomic_load_u64(&pool->s.blkempty);
	uint64_t hiwmct    = odp_atomic_load_u64(&pool->s.high_wm_count);
	uint64_t lowmct    = odp_atomic_load_u64(&pool->s.low_wm_count);

	ODP_DBG("Pool info\n");
	ODP_DBG("---------\n");
	ODP_DBG(" pool            %i\n", pool->s.pool_hdl);
	ODP_DBG(" name            %s\n",
		pool->s.flags.has_name ? pool->s.name : "Unnamed Pool");
	ODP_DBG(" pool type       %s\n",
		pool->s.params.type == ODP_POOL_BUFFER ? "buffer" :
	       (pool->s.params.type == ODP_POOL_PACKET ? "packet" :
	       (pool->s.params.type == ODP_POOL_TIMEOUT ? "timeout" :
		"unknown")));
	ODP_DBG(" pool storage    %sODP managed\n",
		pool->s.flags.user_supplied_shm ?
		"application provided, " : "");
	ODP_DBG(" pool status     %s\n",
		pool->s.quiesced ? "quiesced" : "active");
	ODP_DBG(" pool opts       %s, %s, %s\n",
		pool->s.flags.unsegmented ? "unsegmented" : "segmented",
		pool->s.flags.zeroized ? "zeroized" : "non-zeroized",
		pool->s.flags.predefined  ? "predefined" : "created");
	ODP_DBG(" pool base       %p\n",  pool->s.pool_base_addr);
	ODP_DBG(" pool size       %zu (%zu pages)\n",
		pool->s.pool_size, pool->s.pool_size / ODP_PAGE_SIZE);
	ODP_DBG(" pool mdata base %p\n",  pool->s.pool_mdata_addr);
	ODP_DBG(" udata size      %zu\n", pool->s.init_params.udata_size);
	ODP_DBG(" headroom        %u\n",  pool->s.headroom);
	ODP_DBG(" buf size        %zu\n", pool->s.params.buf.size);
	ODP_DBG(" tailroom        %u\n",  pool->s.tailroom);
	ODP_DBG(" buf align       %u requested, %u used\n",
		pool->s.params.buf.align, pool->s.buf_align);
	ODP_DBG(" num bufs        %u\n",  pool->s.params.buf.num);
	ODP_DBG(" bufs available  %u %s\n", bufcount,
		pool->s.low_wm_assert ? " **low wm asserted**" : "");
	ODP_DBG(" bufs in use     %u\n",  pool->s.params.buf.num - bufcount);
	ODP_DBG(" buf allocs      %lu\n", bufallocs);
	ODP_DBG(" buf frees       %lu\n", buffrees);
	ODP_DBG(" buf empty       %lu\n", bufempty);
	ODP_DBG(" blk size        %zu\n",
		pool->s.seg_size > ODP_MAX_INLINE_BUF ? pool->s.seg_size : 0);
	ODP_DBG(" blks available  %u\n",  blkcount);
	ODP_DBG(" blk allocs      %lu\n", blkallocs);
	ODP_DBG(" blk frees       %lu\n", blkfrees);
	ODP_DBG(" blk empty       %lu\n", blkempty);
	ODP_DBG(" high wm value   %lu\n", pool->s.high_wm);
	ODP_DBG(" high wm count   %lu\n", hiwmct);
	ODP_DBG(" low wm value    %lu\n", pool->s.low_wm);
	ODP_DBG(" low wm count    %lu\n", lowmct);
}


odp_pool_t odp_buffer_pool(odp_buffer_t buf)
{
	return odp_buf_to_hdr(buf)->pool_hdl;
}
