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
#include <odp_align.h>
#include <odp_internal.h>
#include <odp_config.h>
#include <odp_hints.h>
#include <odp_debug.h>

#include <string.h>
#include <stdlib.h>

/* for DPDK */
#include <odp_packet_dpdk.h>

#define MBUF_SIZE (2048 + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)
#define NB_MBUF   32768

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


#if ODP_CONFIG_BUFFER_POOLS > ODP_BUFFER_MAX_POOLS
#error ODP_CONFIG_BUFFER_POOLS > ODP_BUFFER_MAX_POOLS
#endif

#define NULL_INDEX ((uint32_t)-1)


typedef union pool_entry_u {
	struct pool_entry_s s;

	uint8_t pad[ODP_CACHE_LINE_SIZE_ROUNDUP(sizeof(struct pool_entry_s))];

} pool_entry_t;


typedef struct pool_table_t {
	pool_entry_t pool[ODP_CONFIG_BUFFER_POOLS];

} pool_table_t;


/* The pool table */
static pool_table_t *pool_tbl;

/* Pool entry pointers (for inlining) */
void *pool_entry_ptr[ODP_CONFIG_BUFFER_POOLS];


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
	}

	ODP_DBG("\nBuffer pool init global\n");
	ODP_DBG("  pool_entry_s size     %zu\n", sizeof(struct pool_entry_s));
	ODP_DBG("  pool_entry_t size     %zu\n", sizeof(pool_entry_t));
	ODP_DBG("  odp_buffer_hdr_t size %zu\n", sizeof(odp_buffer_hdr_t));
	ODP_DBG("\n");

	return 0;
}


odp_buffer_pool_t odp_buffer_pool_create(const char *name,
					 void *base_addr, uint64_t size,
					 size_t buf_size, size_t buf_align,
					 int buf_type)
{
	struct rte_mempool *pktmbuf_pool = NULL;
	ODP_DBG("odp_buffer_pool_create: %s, %lx, %u, %u, %u, %d\n", name,
		(uint64_t) base_addr, (unsigned) size,
		(unsigned) buf_size, (unsigned) buf_align,
		buf_type);

	pktmbuf_pool =
		rte_mempool_create(name, NB_MBUF,
				   MBUF_SIZE, MAX_PKT_BURST,
				   sizeof(struct rte_pktmbuf_pool_private),
				   rte_pktmbuf_pool_init, NULL,
				   rte_pktmbuf_init, NULL,
				   rte_socket_id(), 0);
	if (pktmbuf_pool == NULL) {
		ODP_ERR("Cannot init DPDK mbuf pool\n");
		return -1;
	}

	return (odp_buffer_pool_t) pktmbuf_pool;
}


odp_buffer_pool_t odp_buffer_pool_lookup(const char *name)
{
	struct rte_mempool *mp = NULL;

	mp = rte_mempool_lookup(name);
	if (mp == NULL)
		return ODP_BUFFER_POOL_INVALID;

	return (odp_buffer_pool_t)mp;
}


odp_buffer_t odp_buffer_alloc(odp_buffer_pool_t pool_id)
{
	return (odp_buffer_t)rte_pktmbuf_alloc((struct rte_mempool *)pool_id);
}


void odp_buffer_free(odp_buffer_t buf)
{
	rte_pktmbuf_free((struct rte_mbuf *)buf);
}


void odp_buffer_pool_print(odp_buffer_pool_t pool_id)
{
	rte_mempool_dump((const struct rte_mempool *)pool_id);
}
