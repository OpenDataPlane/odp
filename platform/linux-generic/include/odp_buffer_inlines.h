/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * Inline functions for ODP buffer mgmt routines - implementation internal
 */

#ifndef ODP_BUFFER_INLINES_H_
#define ODP_BUFFER_INLINES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp_buffer_internal.h>
#include <odp_buffer_pool_internal.h>

static inline odp_buffer_t odp_buffer_encode_handle(odp_buffer_hdr_t *hdr)
{
	odp_buffer_bits_t handle;
	uint32_t pool_id = pool_handle_to_index(hdr->pool_hdl);
	struct pool_entry_s *pool = get_pool_entry(pool_id);

	handle.pool_id = pool_id;
	handle.index = ((uint8_t *)hdr - pool->pool_mdata_addr) /
		ODP_CACHE_LINE_SIZE;
	handle.seg = 0;

	return handle.u32;
}

static inline odp_buffer_t odp_hdr_to_buf(odp_buffer_hdr_t *hdr)
{
	return hdr->handle.handle;
}

static inline odp_buffer_hdr_t *odp_buf_to_hdr(odp_buffer_t buf)
{
	odp_buffer_bits_t handle;
	uint32_t pool_id;
	uint32_t index;
	struct pool_entry_s *pool;

	handle.u32 = buf;
	pool_id    = handle.pool_id;
	index      = handle.index;

#ifdef POOL_ERROR_CHECK
	if (odp_unlikely(pool_id > ODP_CONFIG_POOLS)) {
		ODP_ERR("odp_buf_to_hdr: Bad pool id\n");
		return NULL;
	}
#endif

	pool = get_pool_entry(pool_id);

#ifdef POOL_ERROR_CHECK
	if (odp_unlikely(index > pool->params.num_bufs - 1)) {
		ODP_ERR("odp_buf_to_hdr: Bad buffer index\n");
		return NULL;
	}
#endif

	return (odp_buffer_hdr_t *)(void *)
		(pool->pool_mdata_addr + (index * ODP_CACHE_LINE_SIZE));
}

static inline uint32_t odp_buffer_refcount(odp_buffer_hdr_t *buf)
{
	return odp_atomic_load_u32(&buf->ref_count);
}

static inline uint32_t odp_buffer_incr_refcount(odp_buffer_hdr_t *buf,
						uint32_t val)
{
	return odp_atomic_fetch_add_u32(&buf->ref_count, val) + val;
}

static inline uint32_t odp_buffer_decr_refcount(odp_buffer_hdr_t *buf,
						uint32_t val)
{
	uint32_t tmp;

	tmp = odp_atomic_fetch_sub_u32(&buf->ref_count, val);

	if (tmp < val) {
		odp_atomic_fetch_add_u32(&buf->ref_count, val - tmp);
		return 0;
	} else {
		return tmp - val;
	}
}

static inline odp_buffer_hdr_t *validate_buf(odp_buffer_t buf)
{
	odp_buffer_bits_t handle;
	odp_buffer_hdr_t *buf_hdr;
	handle.u32 = buf;

	/* For buffer handles, segment index must be 0 and pool id in range */
	if (handle.seg != 0 || handle.pool_id >= ODP_CONFIG_POOLS)
		return NULL;

	pool_entry_t *pool = odp_pool_to_entry(handle.pool_id);

	/* If pool not created, handle is invalid */
	if (pool->s.pool_shm == ODP_SHM_INVALID)
		return NULL;

	uint32_t buf_stride = pool->s.buf_stride / ODP_CACHE_LINE_SIZE;

	/* A valid buffer index must be on stride, and must be in range */
	if ((handle.index % buf_stride != 0) ||
	    ((uint32_t)(handle.index / buf_stride) >= pool->s.params.buf.num))
		return NULL;

	buf_hdr = (odp_buffer_hdr_t *)(void *)
		(pool->s.pool_mdata_addr +
		 (handle.index * ODP_CACHE_LINE_SIZE));

	/* Handle is valid, so buffer is valid if it is allocated */
	return buf_hdr->allocator == ODP_FREEBUF ? NULL : buf_hdr;
}

int odp_buffer_snprint(char *str, uint32_t n, odp_buffer_t buf);

static inline void *buffer_map(odp_buffer_hdr_t *buf,
			       uint32_t offset,
			       uint32_t *seglen,
			       uint32_t limit)
{
	int seg_index  = offset / buf->segsize;
	int seg_offset = offset % buf->segsize;

	if (seglen != NULL) {
		uint32_t buf_left = limit - offset;
		*seglen = seg_offset + buf_left <= buf->segsize ?
			buf_left : buf->segsize - seg_offset;
	}

	return (void *)(seg_offset + (uint8_t *)buf->addr[seg_index]);
}

static inline odp_buffer_seg_t segment_next(odp_buffer_hdr_t *buf,
					    odp_buffer_seg_t seg)
{
	odp_buffer_bits_t seghandle;
	seghandle.u32 = seg;

	if (seg == ODP_SEGMENT_INVALID ||
	    seghandle.prefix != buf->handle.prefix ||
	    seghandle.seg >= buf->segcount - 1)
		return ODP_SEGMENT_INVALID;
	else {
		seghandle.seg++;
		return (odp_buffer_seg_t)seghandle.u32;
	}
}

static inline void *segment_map(odp_buffer_hdr_t *buf,
				odp_buffer_seg_t seg,
				uint32_t *seglen,
				uint32_t limit,
				uint32_t hr)
{
	uint32_t seg_offset, buf_left;
	odp_buffer_bits_t seghandle;
	uint8_t *seg_addr;
	seghandle.u32 = seg;

	if (seghandle.prefix != buf->handle.prefix ||
	    seghandle.seg >= buf->segcount)
		return NULL;

	seg_addr   = (uint8_t *)buf->addr[seghandle.seg];
	seg_offset = seghandle.seg * buf->segsize;
	limit     += hr;

	/* Can't map this segment if it's nothing but headroom or tailroom */
	if (hr >= seg_offset + buf->segsize || seg_offset > limit)
		return NULL;

	/* Adjust address & offset if this segment contains any headroom */
	if (hr > seg_offset) {
		seg_addr   += hr % buf->segsize;
		seg_offset += hr % buf->segsize;
	}

	/* Set seglen if caller is asking for it */
	if (seglen != NULL) {
		buf_left = limit - seg_offset;
		*seglen = buf_left < buf->segsize ? buf_left : buf->segsize;
	}

	return (void *)seg_addr;
}


#ifdef __cplusplus
}
#endif

#endif
