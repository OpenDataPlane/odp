/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_std_types.h>
#include <odp_buffer_pool.h>
#include <odp_buffer_pool_internal.h>
#include <odp_buffer_internal.h>
#include <odp_packet_internal.h>
#include <odp_shared_memory.h>
#include <odp_shared_memory_internal.h>
#include <odp_align.h>
#include <odp_internal.h>
#include <odp_config.h>
#include <configs/odp_config_platform.h>
#include <odp_hints.h>
#include <odp_debug.h>
#include <odp_sync.h>
#include <odp_queue_internal.h>

#include <string.h>
#include <stdlib.h>
#include <ti_em_rh.h>

#ifdef POOL_USE_TICKETLOCK
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


#define NULL_INDEX ((uint32_t)-1)




typedef union pool_entry_u {
	struct pool_entry_s s;

	uint8_t pad[ODP_CACHE_LINE_SIZE_ROUNDUP(sizeof(struct pool_entry_s))];

} pool_entry_t;


typedef struct pool_table_t {
	pool_entry_t pool[ODP_CONFIG_BUFFER_POOLS];

} pool_table_t;

typedef struct {
	uintptr_t p;
	uintptr_t v;
} pvaddr_t;

/* The pool table */
static pool_table_t *pool_tbl;

/* Pool entry pointers (for inlining) */
void *pool_entry_ptr[ODP_CONFIG_BUFFER_POOLS];

static uint32_t ti_odp_alloc_public_desc(uint32_t num)
{
	static uint32_t free_desc_id;
	uint32_t tmp;

	if (free_desc_id + num > TI_ODP_PUBLIC_DESC_NUM)
		return -1;

	tmp = __sync_fetch_and_add(&free_desc_id, num);

	if (tmp + num > TI_ODP_PUBLIC_DESC_NUM) {
		__sync_fetch_and_sub(&free_desc_id, num);
		return -1;
	}
	return tmp;
}

odp_buffer_pool_t odp_buf_to_pool(odp_buffer_t buf)
{
	odp_buffer_hdr_t *hdr = odp_buf_to_hdr(buf);
	pool_entry_t *pool = get_pool_entry(0);
	return hdr->free_queue - pool->s.free_queue;
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
		pool_entry_t *pool = &pool_tbl->pool[i];
		LOCK_INIT(&pool->s.lock);
		pool->s.pool = i;
		pool_entry_ptr[i] = pool;
		pool->s.free_queue = TI_ODP_FREE_QUEUE_BASE_IDX + i;
	}

	ODP_DBG("\nBuffer pool init global\n");
	ODP_DBG("  pool_entry_s size     %zu\n", sizeof(struct pool_entry_s));
	ODP_DBG("  pool_entry_t size     %zu\n", sizeof(pool_entry_t));
	ODP_DBG("\n");
	return 0;
}

#define MAX_BUFS_PER_POOL	2000

static int link_bufs(pool_entry_t *pool)
{
	size_t buf_size, buf_align;
	uint64_t pool_size;
	uintptr_t pool_base;
	pvaddr_t buf_addr, desc_addr;
	uint32_t desc_index;
	uint32_t num_bufs, i;

	buf_align  = pool->s.payload_align;
	buf_size   = ODP_ALIGN_ROUNDUP(pool->s.payload_size, buf_align);
	pool_size  = pool->s.pool_size;
	pool_base  = (uintptr_t) pool->s.pool_base_addr;
	/* First buffer */
	buf_addr.v = ODP_ALIGN_ROUNDUP(pool_base, buf_align);
	buf_addr.p = _odp_shm_get_paddr((void *)buf_addr.v);
	pool->s.buf_base = buf_addr.v;

	num_bufs   = (pool_size - (buf_addr.v - pool_base)) / buf_size;
	/*
	 * FIXME: Currently a number of HW descriptors is limited,
	 *        so temporary limit max number of buffers per pool
	 *        to be albe to run ODP example apps.
	 *        Descriptor management have to be made more intelligent
	 *        To remove this limitation.
	 */
	if (num_bufs > MAX_BUFS_PER_POOL) {
		ODP_DBG("Limiting number of buffer in %s from %d to %d\n",
			pool->s.name, num_bufs, MAX_BUFS_PER_POOL);
		num_bufs = MAX_BUFS_PER_POOL;
	}

	desc_index = ti_odp_alloc_public_desc(num_bufs);

	ODP_DBG("%s: buf_size: %zu, buf_align: %zu\n", __func__,
		buf_size, buf_align);
	ODP_DBG("%s: pool_size: %llu, pool_base: 0x%p\n", __func__,
		pool_size, (void *)pool_base);
	ODP_DBG("%s: buf_addr.v: 0x%p, buf_addr.p: 0x%p\n", __func__,
		(void *)buf_addr.v, (void *)buf_addr.p);
	ODP_DBG("%s: num_bufs: %u, desc_index: %u\n", __func__,
		num_bufs, desc_index);

	/* FIXME: Need to define error codes somewhere */
	if (desc_index == (uint32_t)-1) {
		ODP_ERR("Failed to allocate %u descriptors for pool %s\n",
			num_bufs, pool->s.name);
		return -1;
	}

	if (ti_em_osal_hw_queue_open(pool->s.free_queue) != EM_OK) {
		ODP_ERR("Failed to open HW queue %u\n", pool->s.free_queue);
		return -1;
	}

	for (i = 0; i < num_bufs; i++) {
		Cppi_DescTag     tag;
		odp_buffer_hdr_t *hdr;

		/*
		 * TODO: Need to get descriptor size here and shift
		 * descriptor address, but not query it on every iteration.
		 */
		desc_addr.v = (uintptr_t)ti_em_rh_public_desc_addr(desc_index,
				&desc_addr.p);
		hdr = (odp_buffer_hdr_t *)desc_addr.v;
		memset((void *)hdr, 0, sizeof(*hdr));

		hdr->free_queue = pool->s.free_queue;
		hdr->buf_vaddr  = (void *)buf_addr.v;

		/* Set defaults in descriptor */
		hdr->desc.descInfo = (Cppi_DescType_HOST << 30) |
				     (Cppi_PSLoc_PS_IN_DESC << 22) |
				     (buf_size & 0xFFFF);
		hdr->desc.packetInfo =
			(((uint32_t) Cppi_EPIB_EPIB_PRESENT) << 31) |
			(0x2 << 16) |
			(((uint32_t) Cppi_ReturnPolicy_RETURN_BUFFER) << 15) |
			(pool->s.free_queue & 0x3FFF);
		hdr->desc.origBuffPtr   = buf_addr.p;
		hdr->desc.buffPtr       = buf_addr.p;
		hdr->desc.origBufferLen = buf_size;
		hdr->desc.buffLen       = buf_size;

		/* TODO: pslen is set to 0, but should be configurable */
		ti_em_cppi_set_pslen(Cppi_DescType_HOST,
				     (Cppi_Desc *)(hdr), 0);

		tag.srcTagHi  = 0x00;
		tag.srcTagLo  = 0xFF;
		tag.destTagHi = 0x00;
		tag.destTagLo = 0x00;
		ti_em_cppi_set_tag(Cppi_DescType_HOST,
				   (Cppi_Desc *)(hdr),
				   &tag);

		odp_sync_stores();
		_ti_hw_queue_push_desc(pool->s.free_queue, hdr);
		buf_addr.v += buf_size;
		buf_addr.p += buf_size;
		desc_index++;
	}

	return 0;
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
		pool = get_pool_entry(i);

		LOCK(&pool->s.lock);

		if (pool->s.buf_base == 0) {
			/* found free pool */
			ODP_DBG("%s: found free pool id: %u for %s\n", __func__,
				i, name);
			strncpy(pool->s.name, name,
				ODP_BUFFER_POOL_NAME_LEN - 1);
			pool->s.name[ODP_BUFFER_POOL_NAME_LEN - 1] = 0;
			pool->s.pool_base_addr = base_addr;
			pool->s.pool_size      = size;
			pool->s.payload_size   = buf_size;
			pool->s.payload_align  = buf_align;
			pool->s.buf_type       = buf_type;
			pool->s.buf_base = (uintptr_t)ODP_ALIGN_ROUNDUP_PTR(
						   base_addr, buf_align);

			if (link_bufs(pool) != -1)
				pool_id = i;
			UNLOCK(&pool->s.lock);
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
		pool = get_pool_entry(i);

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
	pool_entry_t *pool = get_pool_entry(pool_id);
	return (odp_buffer_t)ti_em_osal_hw_queue_pop(pool->s.free_queue,
			TI_EM_MEM_PUBLIC_DESC);
}


void odp_buffer_free(odp_buffer_t buf)
{
	odp_buffer_hdr_t *hdr = odp_buf_to_hdr(buf);
	_ti_hw_queue_push_desc(hdr->free_queue, hdr);
}

void odp_buffer_pool_print(odp_buffer_pool_t pool_id)
{
	(void)pool_id;
}
