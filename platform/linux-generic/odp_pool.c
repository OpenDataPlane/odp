/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/pool.h>
#include <odp/api/shared_memory.h>
#include <odp/api/align.h>
#include <odp/api/ticketlock.h>

#include <odp_pool_internal.h>
#include <odp_internal.h>
#include <odp_buffer_inlines.h>
#include <odp_packet_internal.h>
#include <odp_config_internal.h>
#include <odp_debug_internal.h>
#include <odp_ring_internal.h>

#include <string.h>
#include <stdio.h>
#include <inttypes.h>

#include <odp/api/plat/ticketlock_inlines.h>
#define LOCK(a)      _odp_ticketlock_lock(a)
#define UNLOCK(a)    _odp_ticketlock_unlock(a)
#define LOCK_INIT(a) odp_ticketlock_init(a)

#define CACHE_BURST    32
#define RING_SIZE_MIN  (2 * CACHE_BURST)

/* Define a practical limit for contiguous memory allocations */
#define MAX_SIZE   (10 * 1024 * 1024)

ODP_STATIC_ASSERT(CONFIG_POOL_CACHE_SIZE > (2 * CACHE_BURST),
		  "cache_burst_size_too_large_compared_to_cache_size");

ODP_STATIC_ASSERT(CONFIG_PACKET_SEG_LEN_MIN >= 256,
		  "ODP Segment size must be a minimum of 256 bytes");

/* Thread local variables */
typedef struct pool_local_t {
	pool_cache_t *cache[ODP_CONFIG_POOLS];
	int thr_id;
} pool_local_t;

pool_table_t *pool_tbl;
static __thread pool_local_t local;

static inline odp_pool_t pool_index_to_handle(uint32_t pool_idx)
{
	return _odp_cast_scalar(odp_pool_t, pool_idx);
}

static inline uint32_t pool_id_from_buf(odp_buffer_t buf)
{
	odp_buffer_bits_t handle;

	handle.handle = buf;
	return handle.pool_id;
}

int odp_pool_init_global(void)
{
	uint32_t i;
	odp_shm_t shm;

	shm = odp_shm_reserve("_odp_pool_table",
			      sizeof(pool_table_t),
			      ODP_CACHE_LINE_SIZE, 0);

	pool_tbl = odp_shm_addr(shm);

	if (pool_tbl == NULL)
		return -1;

	memset(pool_tbl, 0, sizeof(pool_table_t));
	pool_tbl->shm = shm;

	for (i = 0; i < ODP_CONFIG_POOLS; i++) {
		pool_t *pool = pool_entry(i);

		LOCK_INIT(&pool->lock);
		pool->pool_hdl = pool_index_to_handle(i);
		pool->pool_idx = i;
	}

	ODP_DBG("\nPool init global\n");
	ODP_DBG("  odp_buffer_hdr_t size %zu\n", sizeof(odp_buffer_hdr_t));
	ODP_DBG("  odp_packet_hdr_t size %zu\n", sizeof(odp_packet_hdr_t));
	ODP_DBG("\n");
	return 0;
}

int odp_pool_term_global(void)
{
	int i;
	pool_t *pool;
	int ret = 0;
	int rc = 0;

	for (i = 0; i < ODP_CONFIG_POOLS; i++) {
		pool = pool_entry(i);

		LOCK(&pool->lock);
		if (pool->reserved) {
			ODP_ERR("Not destroyed pool: %s\n", pool->name);
			rc = -1;
		}
		UNLOCK(&pool->lock);
	}

	ret = odp_shm_free(pool_tbl->shm);
	if (ret < 0) {
		ODP_ERR("shm free failed");
		rc = -1;
	}

	return rc;
}

int odp_pool_init_local(void)
{
	pool_t *pool;
	int i;
	int thr_id = odp_thread_id();

	memset(&local, 0, sizeof(pool_local_t));

	for (i = 0; i < ODP_CONFIG_POOLS; i++) {
		pool           = pool_entry(i);
		local.cache[i] = &pool->local_cache[thr_id];
		local.cache[i]->num = 0;
	}

	local.thr_id = thr_id;
	return 0;
}

static void flush_cache(pool_cache_t *cache, pool_t *pool)
{
	ring_t *ring;
	uint32_t mask;
	uint32_t cache_num, i, data;

	ring = &pool->ring.hdr;
	mask = pool->ring_mask;
	cache_num = cache->num;

	for (i = 0; i < cache_num; i++) {
		data = (uint32_t)(uintptr_t)cache->buf[i];
		ring_enq(ring, mask, data);
	}

	cache->num = 0;
}

int odp_pool_term_local(void)
{
	int i;

	for (i = 0; i < ODP_CONFIG_POOLS; i++) {
		pool_t *pool = pool_entry(i);

		flush_cache(local.cache[i], pool);
	}

	return 0;
}

static pool_t *reserve_pool(void)
{
	int i;
	pool_t *pool;

	for (i = 0; i < ODP_CONFIG_POOLS; i++) {
		pool = pool_entry(i);

		LOCK(&pool->lock);
		if (pool->reserved == 0) {
			pool->reserved = 1;
			UNLOCK(&pool->lock);
			return pool;
		}
		UNLOCK(&pool->lock);
	}

	return NULL;
}

static odp_buffer_t form_buffer_handle(uint32_t pool_idx, uint32_t buffer_idx)
{
	odp_buffer_bits_t bits;

	bits.handle  = 0;
	bits.pool_id = pool_idx;
	bits.index   = buffer_idx;

	return bits.handle;
}

static void init_buffers(pool_t *pool)
{
	uint32_t i;
	odp_buffer_hdr_t *buf_hdr;
	odp_packet_hdr_t *pkt_hdr;
	odp_buffer_t buf_hdl;
	void *addr;
	void *uarea = NULL;
	uint8_t *data;
	uint32_t offset;
	ring_t *ring;
	uint32_t mask;
	int type;
	uint32_t seg_size;

	ring = &pool->ring.hdr;
	mask = pool->ring_mask;
	type = pool->params.type;

	for (i = 0; i < pool->num; i++) {
		addr    = &pool->base_addr[i * pool->block_size];
		buf_hdr = addr;
		pkt_hdr = addr;

		if (pool->uarea_size)
			uarea = &pool->uarea_base_addr[i * pool->uarea_size];

		data = buf_hdr->data;

		if (type == ODP_POOL_PACKET)
			data = pkt_hdr->data;

		offset = pool->headroom;

		/* move to correct align */
		while (((uintptr_t)&data[offset]) % pool->align != 0)
			offset++;

		memset(buf_hdr, 0, (uintptr_t)data - (uintptr_t)buf_hdr);

		seg_size = pool->headroom + pool->data_size + pool->tailroom;

		/* Initialize buffer metadata */
		buf_hdr->size = seg_size;
		buf_hdr->type = type;
		buf_hdr->event_type = type;
		buf_hdr->pool_hdl = pool->pool_hdl;
		buf_hdr->uarea_addr = uarea;
		/* Show user requested size through API */
		buf_hdr->uarea_size = pool->params.pkt.uarea_size;
		buf_hdr->segcount = 1;
		buf_hdr->segsize = seg_size;

		/* Pointer to data start (of the first segment) */
		buf_hdr->seg[0].hdr       = buf_hdr;
		buf_hdr->seg[0].data      = &data[offset];
		buf_hdr->seg[0].len       = pool->data_size;

		/* Store base values for fast init */
		buf_hdr->base_data = buf_hdr->seg[0].data;
		buf_hdr->base_len  = buf_hdr->seg[0].len;
		buf_hdr->buf_end   = &data[offset + pool->data_size +
				     pool->tailroom];

		buf_hdl = form_buffer_handle(pool->pool_idx, i);
		buf_hdr->handle.handle = buf_hdl;

		/* Store buffer into the global pool */
		ring_enq(ring, mask, (uint32_t)(uintptr_t)buf_hdl);
	}
}

static odp_pool_t pool_create(const char *name, odp_pool_param_t *params,
			      uint32_t shmflags)
{
	pool_t *pool;
	uint32_t uarea_size, headroom, tailroom;
	odp_shm_t shm;
	uint32_t data_size, align, num, hdr_size, block_size;
	uint32_t max_len, max_seg_len;
	uint32_t ring_size;
	int name_len;
	const char *postfix = "_uarea";
	char uarea_name[ODP_POOL_NAME_LEN + sizeof(postfix)];

	if (params == NULL) {
		ODP_ERR("No params");
		return ODP_POOL_INVALID;
	}

	align = 0;

	if (params->type == ODP_POOL_BUFFER)
		align = params->buf.align;

	if (align < ODP_CONFIG_BUFFER_ALIGN_MIN)
		align = ODP_CONFIG_BUFFER_ALIGN_MIN;

	/* Validate requested buffer alignment */
	if (align > ODP_CONFIG_BUFFER_ALIGN_MAX ||
	    align != ODP_ALIGN_ROUNDDOWN_POWER_2(align, align)) {
		ODP_ERR("Bad align requirement");
		return ODP_POOL_INVALID;
	}

	headroom    = 0;
	tailroom    = 0;
	data_size   = 0;
	max_len     = 0;
	max_seg_len = 0;
	uarea_size  = 0;

	switch (params->type) {
	case ODP_POOL_BUFFER:
		num  = params->buf.num;
		data_size = params->buf.size;
		break;

	case ODP_POOL_PACKET:
		headroom    = CONFIG_PACKET_HEADROOM;
		tailroom    = CONFIG_PACKET_TAILROOM;
		num         = params->pkt.num;
		uarea_size  = params->pkt.uarea_size;
		data_size   = CONFIG_PACKET_MAX_SEG_LEN;
		max_seg_len = CONFIG_PACKET_MAX_SEG_LEN;
		max_len     = CONFIG_PACKET_MAX_SEGS * max_seg_len;
		break;

	case ODP_POOL_TIMEOUT:
		num = params->tmo.num;
		break;

	default:
		ODP_ERR("Bad pool type");
		return ODP_POOL_INVALID;
	}

	if (uarea_size)
		uarea_size = ODP_CACHE_LINE_SIZE_ROUNDUP(uarea_size);

	pool = reserve_pool();

	if (pool == NULL) {
		ODP_ERR("No more free pools");
		return ODP_POOL_INVALID;
	}

	if (name == NULL) {
		pool->name[0] = 0;
	} else {
		strncpy(pool->name, name,
			ODP_POOL_NAME_LEN - 1);
		pool->name[ODP_POOL_NAME_LEN - 1] = 0;
	}

	name_len = strlen(pool->name);
	memcpy(uarea_name, pool->name, name_len);
	strcpy(&uarea_name[name_len], postfix);

	pool->params = *params;

	hdr_size = sizeof(odp_packet_hdr_t);
	hdr_size = ODP_CACHE_LINE_SIZE_ROUNDUP(hdr_size);

	block_size = ODP_CACHE_LINE_SIZE_ROUNDUP(hdr_size + align + headroom +
						 data_size + tailroom);

	if (num <= RING_SIZE_MIN)
		ring_size = RING_SIZE_MIN;
	else
		ring_size = ODP_ROUNDUP_POWER_2(num);

	pool->ring_mask      = ring_size - 1;
	pool->num            = num;
	pool->align          = align;
	pool->headroom       = headroom;
	pool->data_size      = data_size;
	pool->max_len        = max_len;
	pool->max_seg_len    = max_seg_len;
	pool->tailroom       = tailroom;
	pool->block_size     = block_size;
	pool->uarea_size     = uarea_size;
	pool->shm_size       = num * block_size;
	pool->uarea_shm_size = num * uarea_size;

	shm = odp_shm_reserve(pool->name, pool->shm_size,
			      ODP_PAGE_SIZE, shmflags);

	pool->shm = shm;

	if (shm == ODP_SHM_INVALID) {
		ODP_ERR("Shm reserve failed");
		goto error;
	}

	pool->base_addr = odp_shm_addr(pool->shm);

	pool->uarea_shm = ODP_SHM_INVALID;
	if (uarea_size) {
		shm = odp_shm_reserve(uarea_name, pool->uarea_shm_size,
				      ODP_PAGE_SIZE, shmflags);

		pool->uarea_shm = shm;

		if (shm == ODP_SHM_INVALID) {
			ODP_ERR("Shm reserve failed (uarea)");
			goto error;
		}

		pool->uarea_base_addr = odp_shm_addr(pool->uarea_shm);
	}

	ring_init(&pool->ring.hdr);
	init_buffers(pool);

	return pool->pool_hdl;

error:
	if (pool->shm != ODP_SHM_INVALID)
		odp_shm_free(pool->shm);

	if (pool->uarea_shm != ODP_SHM_INVALID)
		odp_shm_free(pool->uarea_shm);

	LOCK(&pool->lock);
	pool->reserved = 0;
	UNLOCK(&pool->lock);
	return ODP_POOL_INVALID;
}

static int check_params(odp_pool_param_t *params)
{
	odp_pool_capability_t capa;

	odp_pool_capability(&capa);

	switch (params->type) {
	case ODP_POOL_BUFFER:
		if (params->buf.num > capa.buf.max_num) {
			printf("buf.num too large %u\n", params->buf.num);
			return -1;
		}

		if (params->buf.size > capa.buf.max_size) {
			printf("buf.size too large %u\n", params->buf.size);
			return -1;
		}

		if (params->buf.align > capa.buf.max_align) {
			printf("buf.align too large %u\n", params->buf.align);
			return -1;
		}

		break;

	case ODP_POOL_PACKET:
		if (params->pkt.len > capa.pkt.max_len) {
			printf("pkt.len too large %u\n", params->pkt.len);
			return -1;
		}

		if (params->pkt.max_len > capa.pkt.max_len) {
			printf("pkt.max_len too large %u\n",
			       params->pkt.max_len);
			return -1;
		}

		if (params->pkt.seg_len > capa.pkt.max_seg_len) {
			printf("pkt.seg_len too large %u\n",
			       params->pkt.seg_len);
			return -1;
		}

		if (params->pkt.uarea_size > capa.pkt.max_uarea_size) {
			printf("pkt.uarea_size too large %u\n",
			       params->pkt.uarea_size);
			return -1;
		}

		break;

	case ODP_POOL_TIMEOUT:
		if (params->tmo.num > capa.tmo.max_num) {
			printf("tmo.num too large %u\n", params->tmo.num);
			return -1;
		}
		break;

	default:
		printf("bad pool type %i\n", params->type);
		return -1;
	}

	return 0;
}

odp_pool_t odp_pool_create(const char *name, odp_pool_param_t *params)
{
	uint32_t shm_flags = 0;

	if (check_params(params))
		return ODP_POOL_INVALID;

#ifdef _ODP_PKTIO_IPC
	if (params && (params->type == ODP_POOL_PACKET))
		shm_flags = ODP_SHM_PROC;
#endif

	return pool_create(name, params, shm_flags);
}

int odp_pool_destroy(odp_pool_t pool_hdl)
{
	pool_t *pool = pool_entry_from_hdl(pool_hdl);
	int i;

	if (pool == NULL)
		return -1;

	LOCK(&pool->lock);

	if (pool->reserved == 0) {
		UNLOCK(&pool->lock);
		ODP_ERR("Pool not created\n");
		return -1;
	}

	/* Make sure local caches are empty */
	for (i = 0; i < ODP_THREAD_COUNT_MAX; i++)
		flush_cache(&pool->local_cache[i], pool);

	odp_shm_free(pool->shm);

	if (pool->uarea_shm != ODP_SHM_INVALID)
		odp_shm_free(pool->uarea_shm);

	pool->reserved = 0;
	UNLOCK(&pool->lock);

	return 0;
}

odp_event_type_t _odp_buffer_event_type(odp_buffer_t buf)
{
	return buf_hdl_to_hdr(buf)->event_type;
}

void _odp_buffer_event_type_set(odp_buffer_t buf, int ev)
{
	buf_hdl_to_hdr(buf)->event_type = ev;
}

odp_pool_t odp_pool_lookup(const char *name)
{
	uint32_t i;
	pool_t *pool;

	for (i = 0; i < ODP_CONFIG_POOLS; i++) {
		pool = pool_entry(i);

		LOCK(&pool->lock);
		if (strcmp(name, pool->name) == 0) {
			/* found it */
			UNLOCK(&pool->lock);
			return pool->pool_hdl;
		}
		UNLOCK(&pool->lock);
	}

	return ODP_POOL_INVALID;
}

int odp_pool_info(odp_pool_t pool_hdl, odp_pool_info_t *info)
{
	pool_t *pool = pool_entry_from_hdl(pool_hdl);

	if (pool == NULL || info == NULL)
		return -1;

	info->name = pool->name;
	info->params = pool->params;

	return 0;
}

int buffer_alloc_multi(pool_t *pool, odp_buffer_t buf[],
		       odp_buffer_hdr_t *buf_hdr[], int max_num)
{
	ring_t *ring;
	uint32_t mask, i;
	pool_cache_t *cache;
	uint32_t cache_num, num_ch, num_deq, burst;

	ring  = &pool->ring.hdr;
	mask  = pool->ring_mask;
	cache = local.cache[pool->pool_idx];

	cache_num = cache->num;
	num_ch    = max_num;
	num_deq   = 0;
	burst     = CACHE_BURST;

	if (odp_unlikely(cache_num < (uint32_t)max_num)) {
		/* Cache does not have enough buffers */
		num_ch  = cache_num;
		num_deq = max_num - cache_num;

		if (odp_unlikely(num_deq > CACHE_BURST))
			burst = num_deq;
	}

	/* Get buffers from the cache */
	for (i = 0; i < num_ch; i++)
		buf[i] = cache->buf[cache_num - num_ch + i];

	/* If needed, get more from the global pool */
	if (odp_unlikely(num_deq)) {
		/* Temporary copy needed since odp_buffer_t is uintptr_t
		 * and not uint32_t. */
		uint32_t data[burst];

		burst     = ring_deq_multi(ring, mask, data, burst);
		cache_num = burst - num_deq;

		if (odp_unlikely(burst < num_deq)) {
			num_deq   = burst;
			cache_num = 0;
		}

		for (i = 0; i < num_deq; i++) {
			uint32_t idx = num_ch + i;

			buf[idx] = (odp_buffer_t)(uintptr_t)data[i];

			if (buf_hdr) {
				buf_hdr[idx] = buf_hdl_to_hdr(buf[idx]);
				/* Prefetch newly allocated and soon to be used
				 * buffer headers. */
				odp_prefetch(buf_hdr[idx]);
			}
		}

		/* Cache extra buffers. Cache is currently empty. */
		for (i = 0; i < cache_num; i++)
			cache->buf[i] = (odp_buffer_t)
					(uintptr_t)data[num_deq + i];

		cache->num = cache_num;
	} else {
		cache->num = cache_num - num_ch;
	}

	if (buf_hdr) {
		for (i = 0; i < num_ch; i++)
			buf_hdr[i] = buf_hdl_to_hdr(buf[i]);
	}

	return num_ch + num_deq;
}

static inline void buffer_free_to_pool(uint32_t pool_id,
				       const odp_buffer_t buf[], int num)
{
	pool_t *pool;
	int i;
	ring_t *ring;
	uint32_t mask;
	pool_cache_t *cache;
	uint32_t cache_num;

	cache = local.cache[pool_id];
	pool  = pool_entry(pool_id);
	ring  = &pool->ring.hdr;
	mask  = pool->ring_mask;

	/* Special case of a very large free. Move directly to
	 * the global pool. */
	if (odp_unlikely(num > CONFIG_POOL_CACHE_SIZE)) {
		for (i = 0; i < num; i++)
			ring_enq(ring, mask, (uint32_t)(uintptr_t)buf[i]);

		return;
	}

	/* Make room into local cache if needed. Do at least burst size
	 * transfer. */
	cache_num = cache->num;

	if (odp_unlikely((int)(CONFIG_POOL_CACHE_SIZE - cache_num) < num)) {
		uint32_t index;
		int burst = CACHE_BURST;

		if (odp_unlikely(num > CACHE_BURST))
			burst = num;

		{
			/* Temporary copy needed since odp_buffer_t is
			 * uintptr_t and not uint32_t. */
			uint32_t data[burst];

			index = cache_num - burst;

			for (i = 0; i < burst; i++)
				data[i] = (uint32_t)
					  (uintptr_t)cache->buf[index + i];

			ring_enq_multi(ring, mask, data, burst);
		}

		cache_num -= burst;
	}

	for (i = 0; i < num; i++)
		cache->buf[cache_num + i] = buf[i];

	cache->num = cache_num + num;
}

void buffer_free_multi(const odp_buffer_t buf[], int num_total)
{
	uint32_t pool_id;
	int num;
	int i;
	int first = 0;

	while (1) {
		num = 1;
		i   = 1;
		pool_id = pool_id_from_buf(buf[first]);

		/* 'num' buffers are from the same pool */
		if (num_total > 1) {
			for (i = first; i < num_total; i++)
				if (pool_id != pool_id_from_buf(buf[i]))
					break;

			num = i - first;
		}

		buffer_free_to_pool(pool_id, &buf[first], num);

		if (i == num_total)
			return;

		first = i;
	}
}

odp_buffer_t odp_buffer_alloc(odp_pool_t pool_hdl)
{
	odp_buffer_t buf;
	pool_t *pool;
	int ret;

	pool = pool_entry_from_hdl(pool_hdl);
	ret = buffer_alloc_multi(pool, &buf, NULL, 1);

	if (odp_likely(ret == 1))
		return buf;

	return ODP_BUFFER_INVALID;
}

int odp_buffer_alloc_multi(odp_pool_t pool_hdl, odp_buffer_t buf[], int num)
{
	pool_t *pool;

	pool = pool_entry_from_hdl(pool_hdl);

	return buffer_alloc_multi(pool, buf, NULL, num);
}

void odp_buffer_free(odp_buffer_t buf)
{
	buffer_free_multi(&buf, 1);
}

void odp_buffer_free_multi(const odp_buffer_t buf[], int num)
{
	buffer_free_multi(buf, num);
}

int odp_pool_capability(odp_pool_capability_t *capa)
{
	uint32_t max_seg_len = CONFIG_PACKET_MAX_SEG_LEN;

	memset(capa, 0, sizeof(odp_pool_capability_t));

	capa->max_pools = ODP_CONFIG_POOLS;

	/* Buffer pools */
	capa->buf.max_pools = ODP_CONFIG_POOLS;
	capa->buf.max_align = ODP_CONFIG_BUFFER_ALIGN_MAX;
	capa->buf.max_size  = MAX_SIZE;
	capa->buf.max_num   = CONFIG_POOL_MAX_NUM;

	/* Packet pools */
	capa->pkt.max_pools        = ODP_CONFIG_POOLS;
	capa->pkt.max_len          = CONFIG_PACKET_MAX_SEGS * max_seg_len;
	capa->pkt.max_num	   = CONFIG_POOL_MAX_NUM;
	capa->pkt.min_headroom     = CONFIG_PACKET_HEADROOM;
	capa->pkt.min_tailroom     = CONFIG_PACKET_TAILROOM;
	capa->pkt.max_segs_per_pkt = CONFIG_PACKET_MAX_SEGS;
	capa->pkt.min_seg_len      = max_seg_len;
	capa->pkt.max_seg_len      = max_seg_len;
	capa->pkt.max_uarea_size   = MAX_SIZE;

	/* Timeout pools */
	capa->tmo.max_pools = ODP_CONFIG_POOLS;
	capa->tmo.max_num   = CONFIG_POOL_MAX_NUM;

	return 0;
}

void odp_pool_print(odp_pool_t pool_hdl)
{
	pool_t *pool;

	pool = pool_entry_from_hdl(pool_hdl);

	printf("\nPool info\n");
	printf("---------\n");
	printf("  pool            %" PRIu64 "\n",
	       odp_pool_to_u64(pool->pool_hdl));
	printf("  name            %s\n", pool->name);
	printf("  pool type       %s\n",
	       pool->params.type == ODP_POOL_BUFFER ? "buffer" :
	       (pool->params.type == ODP_POOL_PACKET ? "packet" :
	       (pool->params.type == ODP_POOL_TIMEOUT ? "timeout" :
		"unknown")));
	printf("  pool shm        %" PRIu64 "\n",
	       odp_shm_to_u64(pool->shm));
	printf("  user area shm   %" PRIu64 "\n",
	       odp_shm_to_u64(pool->uarea_shm));
	printf("  num             %u\n", pool->num);
	printf("  align           %u\n", pool->align);
	printf("  headroom        %u\n", pool->headroom);
	printf("  data size       %u\n", pool->data_size);
	printf("  max data len    %u\n", pool->max_len);
	printf("  max seg len     %u\n", pool->max_seg_len);
	printf("  tailroom        %u\n", pool->tailroom);
	printf("  block size      %u\n", pool->block_size);
	printf("  uarea size      %u\n", pool->uarea_size);
	printf("  shm size        %u\n", pool->shm_size);
	printf("  base addr       %p\n", pool->base_addr);
	printf("  uarea shm size  %u\n", pool->uarea_shm_size);
	printf("  uarea base addr %p\n", pool->uarea_base_addr);
	printf("\n");
}

odp_pool_t odp_buffer_pool(odp_buffer_t buf)
{
	uint32_t pool_id = pool_id_from_buf(buf);

	return pool_index_to_handle(pool_id);
}

void odp_pool_param_init(odp_pool_param_t *params)
{
	memset(params, 0, sizeof(odp_pool_param_t));
}

uint64_t odp_pool_to_u64(odp_pool_t hdl)
{
	return _odp_pri(hdl);
}

int seg_alloc_tail(odp_buffer_hdr_t *buf_hdr,  int segcount)
{
	(void)buf_hdr;
	(void)segcount;
	return 0;
}

void seg_free_tail(odp_buffer_hdr_t *buf_hdr, int segcount)
{
	(void)buf_hdr;
	(void)segcount;
}

int odp_buffer_is_valid(odp_buffer_t buf)
{
	odp_buffer_bits_t handle;
	pool_t *pool;

	handle.handle = buf;

	if (handle.pool_id >= ODP_CONFIG_POOLS)
		return 0;

	pool = pool_entry(handle.pool_id);

	if (pool->reserved == 0)
		return 0;

	return 1;
}
