/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_buffer_pool.h>
#include <odp_buffer_internal.h>
#include <odp_packet_internal.h>
#include <odp_shared_memory.h>
#include <odp_align.h>
#include <odp_internal.h>
#include <odp_config.h>
#include <odp_hints.h>
#include <odp_debug.h>

#include <string.h>
#include <stdlib.h>


#define USE_TICKETLOCK

#ifdef USE_TICKETLOCK
#include <odp_ticketlock.h>
#define LOCK(a)      odp_ticketlock_lock(a)
#define UNLOCK(a)    odp_ticketlock_unlock(a)
#define LOCK_INIT(a) odp_ticketlock_init(a)
#else
#include <odp_spinlock.h>
#define LOCK(a)      odp_spinlock_lock(a)
#define UNLOCK(a)    odp_spinlock_unlock(a)
#define LOCK_INIT(a) odp_spinlock_init(a)
#endif


#if ODP_CONFIG_BUFFER_POOLS > ODP_BUFFER_MAX_POOLS
#error ODP_CONFIG_BUFFER_POOLS > ODP_BUFFER_MAX_POOLS
#endif

#define NULL_INDEX ((uint32_t)-1)

struct pool_entry_s {
#ifdef USE_TICKETLOCK
	odp_ticketlock_t        lock ODP_ALIGNED_CACHE;
#else
	odp_spinlock_t          lock ODP_ALIGNED_CACHE;
#endif

	odp_buffer_chunk_hdr_t *head;
	uint64_t                free_bufs;
	char                    name[ODP_BUFFER_POOL_NAME_LEN];


	odp_buffer_pool_t       pool ODP_ALIGNED_CACHE;
	uintptr_t               buf_base;
	size_t                  buf_size;
	size_t                  buf_offset;
	uint64_t                num_bufs;
	void                   *pool_base_addr;
	uint64_t                pool_size;
	size_t                  payload_size;
	size_t                  payload_align;
	int                     buf_type;
	size_t                  hdr_size;
};


typedef union pool_entry_u {
	struct pool_entry_s s;

	uint8_t pad[ODP_CACHE_LINE_SIZE_ROUNDUP(sizeof(struct pool_entry_s))];

} pool_entry_t;


typedef struct pool_table_t {
	pool_entry_t pool[ODP_CONFIG_BUFFER_POOLS];

} pool_table_t;


static pool_table_t *pool_tbl;


static __thread odp_buffer_chunk_hdr_t *local_chunk[ODP_CONFIG_BUFFER_POOLS];


static inline pool_entry_t *get_pool(odp_buffer_pool_t pool_id)
{
	return &pool_tbl->pool[pool_id];
}


static inline void set_handle(odp_buffer_hdr_t *hdr,
			      pool_entry_t *pool, uint32_t index)
{
	uint32_t pool_id = (uint32_t) pool->s.pool;

	if (pool_id > ODP_CONFIG_BUFFER_POOLS)
		ODP_ERR("set_handle: Bad pool id\n");

	if (index > ODP_BUFFER_MAX_INDEX)
		ODP_ERR("set_handle: Bad buffer index\n");

	hdr->handle.pool  = pool_id;
	hdr->handle.index = index;
}


odp_buffer_hdr_t *odp_buf_to_hdr(odp_buffer_t buf)
{
	odp_buffer_bits_t handle;
	uint32_t pool_id;
	uint32_t index;
	pool_entry_t *pool;
	odp_buffer_hdr_t *hdr;

	handle.u32 = buf;
	pool_id    = handle.pool;
	index      = handle.index;

	if (odp_unlikely(pool_id > ODP_CONFIG_BUFFER_POOLS)) {
		ODP_ERR("odp_buf_to_hdr: Bad pool id\n");
		return NULL;
	}

	pool = get_pool(pool_id);

	if (odp_unlikely(index > pool->s.num_bufs - 1)) {
		ODP_ERR("odp_buf_to_hdr: Bad buffer index\n");
		return NULL;
	}

	hdr = (odp_buffer_hdr_t *)(pool->s.buf_base + index * pool->s.buf_size);

	return hdr;
}


int odp_buffer_pool_init_global(void)
{
	odp_buffer_pool_t i;

	pool_tbl = odp_shm_reserve("odp_buffer_pools",
				   sizeof(pool_table_t),
				   sizeof(pool_entry_t));

	if (pool_tbl == NULL)
		return -1;

	memset(pool_tbl, 0, sizeof(pool_table_t));


	for (i = 0; i < ODP_CONFIG_BUFFER_POOLS; i++) {
		/* init locks */
		pool_entry_t *pool = get_pool(i);
		LOCK_INIT(&pool->s.lock);
		pool->s.pool = i;
	}

	ODP_DBG("\nBuffer pool init global\n");
	ODP_DBG("  pool_entry_s size     %zu\n", sizeof(struct pool_entry_s));
	ODP_DBG("  pool_entry_t size     %zu\n", sizeof(pool_entry_t));
	ODP_DBG("  odp_buffer_hdr_t size %zu\n", sizeof(odp_buffer_hdr_t));
	ODP_DBG("\n");

	return 0;
}


static odp_buffer_hdr_t *index_to_hdr(pool_entry_t *pool, uint32_t index)
{
	odp_buffer_hdr_t *hdr;

	hdr = (odp_buffer_hdr_t *)(pool->s.buf_base + index * pool->s.buf_size);

	return hdr;
}


static void add_buf_index(odp_buffer_chunk_hdr_t *chunk_hdr, uint32_t index)
{
	uint32_t i = chunk_hdr->chunk.num_bufs;
	chunk_hdr->chunk.buf_index[i] = index;
	chunk_hdr->chunk.num_bufs++;
}


static uint32_t rem_buf_index(odp_buffer_chunk_hdr_t *chunk_hdr)
{
	uint32_t index;
	uint32_t i;

	i = chunk_hdr->chunk.num_bufs - 1;
	index = chunk_hdr->chunk.buf_index[i];
	chunk_hdr->chunk.num_bufs--;

	return index;
}


static odp_buffer_chunk_hdr_t *next_chunk(pool_entry_t *pool,
					  odp_buffer_chunk_hdr_t *chunk_hdr)
{
	uint32_t index;

	index = chunk_hdr->chunk.buf_index[ODP_BUFS_PER_CHUNK-1];

	if (index == NULL_INDEX)
		return NULL;
	else
		return (odp_buffer_chunk_hdr_t *)index_to_hdr(pool, index);
}


static odp_buffer_chunk_hdr_t *rem_chunk(pool_entry_t *pool)
{
	odp_buffer_chunk_hdr_t *chunk_hdr;

	chunk_hdr = pool->s.head;

	if (chunk_hdr == NULL) {
		/* Pool is empty */
		return NULL;
	}

	pool->s.head = next_chunk(pool, chunk_hdr);

	pool->s.free_bufs -= ODP_BUFS_PER_CHUNK;

	/* unlink */
	rem_buf_index(chunk_hdr);

	return chunk_hdr;
}


static void add_chunk(pool_entry_t *pool, odp_buffer_chunk_hdr_t *chunk_hdr)
{
	if (pool->s.head) {
		/* link pool head to the chunk */
		add_buf_index(chunk_hdr, pool->s.head->buf_hdr.index);
	} else {
		add_buf_index(chunk_hdr, NULL_INDEX);
	}

	pool->s.head = chunk_hdr;

	pool->s.free_bufs += ODP_BUFS_PER_CHUNK;
}


static void check_align(pool_entry_t *pool, odp_buffer_hdr_t *hdr)
{
	if (!ODP_ALIGNED_CHECK_POWER_2(hdr->addr, pool->s.payload_align)) {
		ODP_ERR("check_align: payload align error %p, align %zu\n",
			hdr->addr, pool->s.payload_align);
		exit(0);
	}

	if (!ODP_ALIGNED_CHECK_POWER_2(hdr, ODP_CACHE_LINE_SIZE)) {
		ODP_ERR("check_align: hdr align error %p, align %i\n",
			hdr, ODP_CACHE_LINE_SIZE);
		exit(0);
	}
}


static void fill_hdr(void *ptr, pool_entry_t *pool, uint32_t index,
		     int buf_type)
{
	odp_buffer_hdr_t *hdr = (odp_buffer_hdr_t *)ptr;
	size_t size = pool->s.hdr_size;
	uint8_t *payload = hdr->payload;

	if (buf_type == ODP_BUFFER_TYPE_CHUNK)
		size = sizeof(odp_buffer_chunk_hdr_t);

	if (pool->s.buf_type == ODP_BUFFER_TYPE_PACKET) {
		odp_packet_hdr_t *packet_hdr = ptr;
		payload = packet_hdr->payload;
	}

	memset(hdr, 0, size);

	set_handle(hdr, pool, index);

	hdr->addr  = &payload[pool->s.buf_offset - pool->s.hdr_size];
	hdr->index = index;
	hdr->size  = pool->s.payload_size;
	hdr->pool  = pool->s.pool;
	hdr->type  = buf_type;

	check_align(pool, hdr);
}


static void link_bufs(pool_entry_t *pool)
{
	odp_buffer_chunk_hdr_t *chunk_hdr;
	size_t hdr_size;
	size_t payload_size;
	size_t payload_align;
	size_t size;
	size_t offset;
	size_t min_size;
	uint64_t pool_size;
	uintptr_t buf_base;
	uint32_t index;
	uintptr_t pool_base;
	int buf_type;


	buf_type      = pool->s.buf_type;
	payload_size  = pool->s.payload_size;
	payload_align = pool->s.payload_align;
	pool_size     = pool->s.pool_size;
	pool_base     = (uintptr_t) pool->s.pool_base_addr;

	if (buf_type == ODP_BUFFER_TYPE_RAW) {
		hdr_size = sizeof(odp_buffer_hdr_t);
	} else if (buf_type == ODP_BUFFER_TYPE_PACKET) {
		hdr_size = sizeof(odp_packet_hdr_t);
	} else {
		ODP_ERR("odp_buffer_pool_create: Bad type %i\n",
			buf_type);
		exit(0);
	}


	/* Chunk must fit into buffer payload.*/
	min_size = sizeof(odp_buffer_chunk_hdr_t) - hdr_size;
	if (payload_size < min_size)
		payload_size = min_size;

	/* Roundup payload size to full cachelines */
	payload_size = ODP_CACHE_LINE_SIZE_ROUNDUP(payload_size);

	/* Min cacheline alignment for buffer header and payload */
	payload_align = ODP_CACHE_LINE_SIZE_ROUNDUP(payload_align);
	offset        = ODP_CACHE_LINE_SIZE_ROUNDUP(hdr_size);

	/* Multiples of cacheline size */
	if (payload_size > payload_align)
		size = payload_size + offset;
	else
		size = payload_align + offset;


	/* First buffer */
	buf_base = ODP_ALIGN_ROUNDUP(pool_base + offset, payload_align)
		   - offset;

	pool->s.hdr_size   = hdr_size;
	pool->s.buf_base   = buf_base;
	pool->s.buf_size   = size;
	pool->s.buf_offset = offset;
	index = 0;

	chunk_hdr = (odp_buffer_chunk_hdr_t *)index_to_hdr(pool, index);
	pool->s.head   = NULL;
	pool_size     -= buf_base - pool_base;

	while (pool_size > ODP_BUFS_PER_CHUNK * size) {
		int i;

		fill_hdr(chunk_hdr, pool, index, ODP_BUFFER_TYPE_CHUNK);

		index++;

		for (i = 0; i < ODP_BUFS_PER_CHUNK - 1; i++) {
			odp_buffer_hdr_t *hdr = index_to_hdr(pool, index);

			fill_hdr(hdr, pool, index, buf_type);

			add_buf_index(chunk_hdr, index);
			index++;
		}

		add_chunk(pool, chunk_hdr);

		chunk_hdr = (odp_buffer_chunk_hdr_t *)index_to_hdr(pool,
								   index);
		pool->s.num_bufs += ODP_BUFS_PER_CHUNK;
		pool_size -=  ODP_BUFS_PER_CHUNK * size;
	}
}


odp_buffer_pool_t odp_buffer_pool_create(const char *name,
					 void *base_addr, uint64_t size,
					 size_t buf_size, size_t buf_align,
					 int buf_type)
{
	odp_buffer_pool_t i;
	pool_entry_t *pool;
	odp_buffer_pool_t pool_id = ODP_BUFFER_POOL_INVALID;

	for (i = 0; i < ODP_CONFIG_BUFFER_POOLS; i++) {
		pool = get_pool(i);

		LOCK(&pool->s.lock);

		if (pool->s.buf_base == 0) {
			/* found free pool */

			strncpy(pool->s.name, name,
				ODP_BUFFER_POOL_NAME_LEN - 1);
			pool->s.name[ODP_BUFFER_POOL_NAME_LEN - 1] = 0;
			pool->s.pool_base_addr = base_addr;
			pool->s.pool_size      = size;
			pool->s.payload_size   = buf_size;
			pool->s.payload_align  = buf_align;
			pool->s.buf_type       = buf_type;

			link_bufs(pool);

			UNLOCK(&pool->s.lock);

			pool_id = i;
			break;
		}

		UNLOCK(&pool->s.lock);
	}

	return pool_id;
}


odp_buffer_pool_t odp_buffer_pool_lookup(const char *name)
{
	odp_buffer_pool_t i;
	pool_entry_t *pool;

	for (i = 0; i < ODP_CONFIG_BUFFER_POOLS; i++) {
		pool = get_pool(i);

		LOCK(&pool->s.lock);

		if (strcmp(name, pool->s.name) == 0) {
			/* found it */
			UNLOCK(&pool->s.lock);
			return i;
		}

		UNLOCK(&pool->s.lock);
	}


	return ODP_BUFFER_POOL_INVALID;
}


odp_buffer_t odp_buffer_alloc(odp_buffer_pool_t pool_id)
{
	pool_entry_t *pool;
	odp_buffer_chunk_hdr_t *chunk;
	odp_buffer_bits_t handle;

	pool  = get_pool(pool_id);
	chunk = local_chunk[pool_id];

	if (chunk == NULL) {
		LOCK(&pool->s.lock);
		chunk = rem_chunk(pool);
		UNLOCK(&pool->s.lock);

		if (chunk == NULL)
			return ODP_BUFFER_INVALID;

		local_chunk[pool_id] = chunk;
	}

	if (chunk->chunk.num_bufs == 0) {
		/* give the chunk buffer */
		local_chunk[pool_id] = NULL;
		chunk->buf_hdr.type = pool->s.buf_type;

		handle = chunk->buf_hdr.handle;
	} else {
		odp_buffer_hdr_t *hdr;
		uint32_t index;
		index = rem_buf_index(chunk);
		hdr = index_to_hdr(pool, index);

		handle = hdr->handle;
	}



	return handle.u32;
}


void odp_buffer_free(odp_buffer_t buf)
{
	odp_buffer_hdr_t *hdr;
	odp_buffer_pool_t pool_id;
	pool_entry_t *pool;
	odp_buffer_chunk_hdr_t *chunk_hdr;

	hdr       = odp_buf_to_hdr(buf);
	pool_id   = hdr->pool;
	pool      = get_pool(pool_id);
	chunk_hdr = local_chunk[pool_id];


	if (chunk_hdr && chunk_hdr->chunk.num_bufs == ODP_BUFS_PER_CHUNK - 1) {
		/* Current chunk is full. Push back to the pool */
		LOCK(&pool->s.lock);
		add_chunk(pool, chunk_hdr);
		UNLOCK(&pool->s.lock);
		chunk_hdr = NULL;
	}

	if (chunk_hdr == NULL) {
		/* Use this buffer */
		chunk_hdr = (odp_buffer_chunk_hdr_t *)hdr;
		local_chunk[pool_id] = chunk_hdr;
		chunk_hdr->chunk.num_bufs = 0;
	} else {
		/* Add to current chunk */
		add_buf_index(chunk_hdr, hdr->index);
	}
}


void odp_buffer_pool_print(odp_buffer_pool_t pool_id)
{
	pool_entry_t *pool;
	odp_buffer_chunk_hdr_t *chunk_hdr;
	uint32_t i;

	pool = get_pool(pool_id);

	printf("Pool info\n");
	printf("---------\n");
	printf("  pool          %i\n",           pool->s.pool);
	printf("  name          %s\n",           pool->s.name);
	printf("  pool base     %p\n",           pool->s.pool_base_addr);
	printf("  buf base      0x%"PRIxPTR"\n", pool->s.buf_base);
	printf("  pool size     0x%"PRIx64"\n",  pool->s.pool_size);
	printf("  buf size      %zu\n",          pool->s.payload_size);
	printf("  buf align     %zu\n",          pool->s.payload_align);
	printf("  hdr size      %zu\n",          pool->s.hdr_size);
	printf("  alloc size    %zu\n",          pool->s.buf_size);
	printf("  offset to hdr %zu\n",          pool->s.buf_offset);
	printf("  num bufs      %"PRIu64"\n",    pool->s.num_bufs);
	printf("  free bufs     %"PRIu64"\n",    pool->s.free_bufs);

	/* first chunk */
	chunk_hdr = pool->s.head;

	if (chunk_hdr == NULL) {
		ODP_ERR("  POOL EMPTY\n");
		return;
	}

	printf("\n  First chunk\n");

	for (i = 0; i < chunk_hdr->chunk.num_bufs - 1; i++) {
		uint32_t index;
		odp_buffer_hdr_t *hdr;

		index = chunk_hdr->chunk.buf_index[i];
		hdr   = index_to_hdr(pool, index);

		printf("  [%i] addr %p, id %"PRIu32"\n", i, hdr->addr, index);
	}

	printf("  [%i] addr %p, id %"PRIu32"\n", i, chunk_hdr->buf_hdr.addr,
	       chunk_hdr->buf_hdr.index);

	/* next chunk */
	chunk_hdr = next_chunk(pool, chunk_hdr);

	if (chunk_hdr) {
		printf("  Next chunk\n");
		printf("  addr %p, id %"PRIu32"\n", chunk_hdr->buf_hdr.addr,
		       chunk_hdr->buf_hdr.index);
	}

	printf("\n");
}
