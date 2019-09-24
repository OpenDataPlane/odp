/* Copyright (c) 2017-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/* This file gathers the buddy and slab allocation functionality provided
 * by _ishm.
 * _odp_ishmpool_create() can be used to create a pool for buddy/slab
 * allocation. _odp_ishmpool_create() will allocate a memory area using
 * ishm_reserve() for both the control part (needed for tracking
 * allocation/free...) and the user memory itself (part of which will be given
 * at each ishmpool_alloc()).
 * The element size provided at pool creation time determines whether
 * to pool will of type buddy or slab.
 * For buddy, all allocations are rounded to the nearest power of 2.
 *
 * The implementation of the buddy allocator is very traditional: it
 * maintains N lists of free buffers.
 * The control part actually contains these N queue heads, (N-M are actually
 * used), the free buffers themselves being used for chaining (the chaining info
 * is in the buffers: as they are "free" they should not be touched by the
 * user). The control part also contains a array of bytes for remembering
 * the size (actually the order) of the allocated buffers:
 * There are 2^(N-M) such bytes, this number being the maximum number of
 * allocated buffers (when all allocation are <= 2^M bytes)
 * Buddy allocators handle fragmentation by splitting or merging blocks by 2.
 * They guarantee a minimum efficiency of 50%, at worse case fragmentation.
 *
 * Slab implementation is even simpler, all free elements being queued in
 * one single queue at init, taken from this queue when allocated and
 * returned to this same queue when freed.
 *
 * The reason for not using malloc() is that malloc does not guarantee
 * memory sharability between ODP threads (regardless of their implememtation)
 * which ishm_reserve() can do. see the comments around
 * _odp_ishmbud_pool_create() and ishm_reserve() for more details.
 *
 * This file is divided in 3 sections: the first one regroups functions
 * needed by the buddy allocation.
 * The second one regroups the functions needed by the slab allocator.
 * The third section regroups the common functions exported externally.
 */

#include <odp_posix_extensions.h>
#include <odp/api/spinlock.h>
#include <odp/api/align.h>
#include <odp/api/debug.h>
#include <odp_shm_internal.h>
#include <odp_debug_internal.h>
#include <odp_align_internal.h>
#include <odp_shm_internal.h>
#include <odp_ishmpool_internal.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <inttypes.h>

#define BUDDY_MIN_SIZE 32 /* minimal buddy allocation size */

typedef _odp_ishm_pool_t pool_t; /* for shorter writing             */

/* array of ishm block index used for pools. only used for pool
 * lookup by name */
#define MAX_NB_POOL 100
static int pool_blk_idx[MAX_NB_POOL];

/* section 1: functions for buddy allocation:                                 */

/* free buddy blocks contains the following structure, used to link the
 * free blocks together.
 */
typedef struct bblock_t {
	struct bblock_t *next;
	uint32_t order;
} bblock_t;

/* value set in the 'order' table when the block is not allocated:   */
#define BBLOCK_FREE 0

/* compute ceil(log2(size)) */
static uint8_t clog2(uint64_t size)
{
	uint64_t sz;
	uint32_t bit;
	uint8_t res;

	sz = size;	/* we start by computing res = log2(sz)...   */
	res = 0;
	for (bit = 32; bit ; bit >>= 1) {
		if (sz >= ((uint64_t)1 << bit)) {
			sz >>= bit;
			res += bit;
		}
	}
	if (((uint64_t)1 << res) < size) /* ...and then ceil(x)      */
		res++;

	return res;
}

/*
 * given a bblock address, and an order value, returns the address
 * of the buddy bblock (the other "half")
 */
static inline bblock_t *get_bblock_buddy(pool_t *bpool, bblock_t *addr,
					 uint8_t order)
{
	uintptr_t b;

	b = ((uintptr_t)addr - (uintptr_t)bpool->ctrl.user_addr);
	b ^= 1 << order;
	return (void *)(b + (uintptr_t)bpool->ctrl.user_addr);
}

/*
 * given a buddy block address, return its number (used for busy flags):
 */
static inline uintptr_t get_bblock_nr(pool_t *bpool, void *addr)
{
	uintptr_t b;
	uint8_t min_order;

	min_order = bpool->ctrl.min_order;
	b = ((uintptr_t)addr - (uintptr_t)bpool->ctrl.user_addr) >> min_order;
	return b;
}

/* remove bblock from the list for bblocks of rank order. The bblock to be
 * removed is really expected to be on the list: not finding it is an error */
static inline void remove_from_list(pool_t *bpool, uint8_t order,
				    bblock_t *bblock)
{
	bblock_t *curr;       /* current bblock (when parsing list) */
	bblock_t *prev;       /* previous bblock (when parsing list) */

	curr = bpool->ctrl.free_heads[order];
	if (!curr)
		goto remove_from_list_error;

	if (curr == bblock) {
		bpool->ctrl.free_heads[order] = curr->next;
		return;
	}

	while (curr) {
		if (curr == bblock) {
			prev->next = curr->next;
			return;
		}
		prev = curr;
		curr = curr->next;
	}

remove_from_list_error:
	ODP_ERR("List corrupted\n");
}

/*
 * create a buddy memory pool of given size (actually nearest power of 2),
 * where allocation will never be smaller than min_alloc.
 * returns a pointer to the created buddy_pool
 * The allocated area contains:
 * - The _odp_ishm_pool_ctrl_t structure
 * - The array of ((order - min_order) of free list heads
 * - The array of 'order' values, remembering sizes of allocated bblocks
 * - alignment to cache line
 * - The user memory
 */
static pool_t *_odp_ishmbud_pool_create(const char *pool_name, int store_idx,
					uint64_t size,
					uint64_t min_alloc, int flags)
{
	uint8_t  order;          /* pool order = ceil(log2(size))         */
	uint8_t  min_order;      /* pool min_order = ceil(log2(min_alloc))*/
	uint32_t max_nb_bblock;  /* max number of bblock, when smallest   */
	uint32_t control_sz;     /* size of control area                  */
	uint32_t free_head_sz;   /* mem area needed for list heads        */
	uint32_t saved_order_sz; /* mem area to remember given sizes      */
	uint64_t user_sz;        /* 2^order bytes		          */
	uint64_t total_sz;	 /* total size to request                 */
	int	 blk_idx;	 /* as returned by _ishm_resrve()         */
	pool_t *bpool;
	int i;
	bblock_t *first_block;

	/* a bblock_t must fit in the buffers for linked chain! */
	if (min_alloc < sizeof(bblock_t))
		min_alloc = sizeof(bblock_t);

	/* pool order is such that 2^order = size. same for min_order   */
	order = clog2(size);
	min_order = clog2(min_alloc);

	/* check parameters obvious wishes: */
	if (order >= 64)
		return NULL;
	if (order < min_order)
		return NULL;

	/* at worst case, all bblocks have smallest (2^min_order) size  */
	max_nb_bblock = (1 << (order - min_order));

	/* space needed for the control area (padded to cache line size)*/
	control_sz = ROUNDUP_CACHE_LINE(sizeof(_odp_ishm_pool_ctrl_t));

	/* space needed for 'order' free bblock list heads:             */
	/* Note that only lists from min_order to order are really used.*/
	free_head_sz = ROUNDUP_CACHE_LINE(sizeof(void *) * (order + 1));

	/* space needed for order -i.e. size- storage of alloc'd bblock:*/
	saved_order_sz = ROUNDUP_CACHE_LINE(max_nb_bblock * sizeof(uint8_t));

	/* space needed for user area is 2^order bytes: */
	user_sz = 1 << order;

	total_sz = control_sz +
		   free_head_sz +
		   saved_order_sz +
		   user_sz;

	/* allocate required memory: */
	blk_idx = _odp_ishm_reserve(pool_name, total_sz, -1,
				    ODP_CACHE_LINE_SIZE, 0, flags, 0);
	if (blk_idx < 0) {
		ODP_ERR("_odp_ishm_reserve failed.");
		return NULL;
	}

	bpool = _odp_ishm_address(blk_idx);
	if (bpool == NULL) {
		ODP_ERR("_odp_ishm_address failed.");
		return NULL;
	}

	/* store in pool array (needed for look up): */
	pool_blk_idx[store_idx] = blk_idx;

	/* remember block index, needed when pool is destroyed */
	bpool->ctrl.ishm_blk_idx = blk_idx;

	/* remember element size: 0 means unknown size, i.e. buddy alloation*/
	bpool->ctrl.element_sz = 0;

	/* prepare mutex: */
	odp_spinlock_init(&bpool->ctrl.lock);

	/* initialise pointers and things... */
	bpool->ctrl.order = order;
	bpool->ctrl.min_order = min_order;
	bpool->ctrl.free_heads =
		(void *)((uintptr_t)bpool + control_sz);
	bpool->ctrl.alloced_order =
		(uint8_t *)((uintptr_t)bpool->ctrl.free_heads + free_head_sz);
	bpool->ctrl.user_addr =
		(void *)((uintptr_t)bpool->ctrl.alloced_order + saved_order_sz);

	/* initialize all free list to NULL, except the top biggest element:*/
	for (i = 0; i < (order - min_order); i++)
		bpool->ctrl.free_heads[i] = NULL;
	bpool->ctrl.free_heads[order] = bpool->ctrl.user_addr;
	first_block = (bblock_t *)bpool->ctrl.user_addr;
	first_block->next = NULL;
	first_block->order = order;

	/* set all 'order' of allocated bblocks to free: */
	memset(bpool->ctrl.alloced_order, BBLOCK_FREE, saved_order_sz);

	return bpool;
}

/* allocated memory from the given buddy pool */
static void *_odp_ishmbud_alloc(pool_t *bpool, uint64_t size)
{
	uint32_t rq_order; /* requested order */
	uint32_t try_order;
	bblock_t *bblock;
	bblock_t *buddy;
	uintptr_t nr;

	/* if size is zero or too big reject: */
	if ((!size) && (size > (1U << bpool->ctrl.order))) {
		ODP_ERR("Invalid alloc size (0 or larger than whole pool)\n");
		return NULL;
	}

	/* compute ceil(log2(size)), to get the requested block order:    */
	rq_order = clog2(size);

	/* make sure the requested order is bigger (or same) as minimum!  */
	if (rq_order < bpool->ctrl.min_order)
		rq_order = bpool->ctrl.min_order;

	/* mutex from here: */
	odp_spinlock_lock(&bpool->ctrl.lock);

	/* now, start trying to allocate a bblock of rq_order. If that
	 * fails keep trying larger orders until pool order is reached    */
	bblock = NULL;
	for (try_order = rq_order; try_order <= bpool->ctrl.order;
	     try_order++) {
		if (bpool->ctrl.free_heads[try_order]) {
			/* remove from list: */
			bblock =
				(bblock_t *)(bpool->ctrl.free_heads[try_order]);
			bpool->ctrl.free_heads[try_order] = bblock->next;
			break;
		}
	}

	if (!bblock) {
		odp_spinlock_unlock(&bpool->ctrl.lock);
		ODP_ERR("Out of memory. (Buddy pool full)\n");
		return NULL;
	}

	/* OK: we got a block, but possibbly too large (if try_order>rq_order)
	 * return the extra halves to the pool hence splitting the bblock at
	 * each 'extra' order: */
	while (try_order-- > rq_order) {
		/* split: */
		buddy = (bblock_t *)((uintptr_t)bblock + (1 << try_order));
		buddy->order = try_order;
		/* add to list: */
		buddy->next = bpool->ctrl.free_heads[try_order];
		bpool->ctrl.free_heads[try_order] = buddy;
		/* mark as free (non allocated block get size 0): */
		nr = get_bblock_nr(bpool, buddy);
		bpool->ctrl.alloced_order[nr] = BBLOCK_FREE;
	}

	/* remember the size if the allocated block: */
	nr = get_bblock_nr(bpool, bblock);
	bpool->ctrl.alloced_order[nr] = rq_order;

	/* and return the allocated block! */
	odp_spinlock_unlock(&bpool->ctrl.lock);
	return (void *)bblock;
}

/* free a previously allocated buffer from a given buddy pool */
static int _odp_ishmbud_free(pool_t *bpool, void *addr)
{
	uintptr_t user_start; /* start of user area */
	uintptr_t user_stop;  /* stop  of user area */
	uintptr_t mask;	      /* 2^min_order - 1    */
	bblock_t *bblock;     /* bblock being freed */
	bblock_t *buddy;      /* buddy bblock of bblock being freed */
	uint8_t order;	      /* order of block being freed */
	uintptr_t nr;	      /* block number */

	/* freeing NULL is regarded as OK, though without any effect:   */
	if (!addr)
		return 0;

	user_start = (uintptr_t)bpool->ctrl.user_addr;
	user_stop  = user_start + ((uintptr_t)1 << bpool->ctrl.order);
	mask = ((uintptr_t)1 << bpool->ctrl.min_order) - 1;

	/* some sanity checks: check that given address is within pool and
	 * that relative address has 2^min_order granularity:           */
	if (((uintptr_t)addr < user_start) ||
	    ((uintptr_t)addr > user_stop)  ||
	    (((uintptr_t)addr - user_start) & mask)) {
		ODP_ERR("Invalid address to be freed\n");
		return -1;
	}

	/* mutex from here: */
	odp_spinlock_lock(&bpool->ctrl.lock);

	/* collect saved block order and make sure bblock was allocated */
	bblock = (bblock_t *)addr;
	nr = get_bblock_nr(bpool, bblock);
	order = bpool->ctrl.alloced_order[nr];
	if (order == BBLOCK_FREE) {
		ODP_ERR("Double free error\n");
		odp_spinlock_unlock(&bpool->ctrl.lock);
		return -1;
	}

	/* this looks like a valid free, mark at least this as free:   */
	bpool->ctrl.alloced_order[nr] = BBLOCK_FREE;

	/* go up in orders, trying to merge buddies... */
	while (order < bpool->ctrl.order) {
		buddy = get_bblock_buddy(bpool, bblock, order);
		/*if buddy is not free: no further merge possible */
		nr = get_bblock_nr(bpool, buddy);
		if (bpool->ctrl.alloced_order[nr] != BBLOCK_FREE)
			break;
		/*merge only bblock of same order:*/
		if (buddy->order != order)
			break;
		/*merge: remove buddy from free list: */
		remove_from_list(bpool, order, buddy);
		/*merge: make sure we point at start of block: */
		if (bblock > buddy)
			bblock = buddy;
		/*merge: size of bloack has dubbled: increse order: */
		order++;
	}

	/* insert the bblock into its correct free block list: */
	bblock->next = bpool->ctrl.free_heads[order];
	bpool->ctrl.free_heads[order] = bblock;

	/* remember the (possibly now merged) block order: */
	bblock->order = order;

	odp_spinlock_unlock(&bpool->ctrl.lock);
	return 0;
}

/* print buddy pool status and performs sanity checks */
static int _odp_ishmbud_pool_status(const char *title, pool_t *bpool)
{
	uint8_t order, pool_order, pool_min_order;
	uint64_t free_q_nb_bblocks[64];
	uint64_t allocated_nb_bblocks[64];
	uint64_t free_q_nb_bblocks_bytes[64];
	uint64_t allocated_nb_bblocks_bytes[64];
	uint64_t total_bytes_free;
	uint64_t total_bytes_allocated;
	uint64_t nr;
	bblock_t *bblock;
	int res = 0;

	odp_spinlock_lock(&bpool->ctrl.lock);

	pool_order = bpool->ctrl.order;
	pool_min_order = bpool->ctrl.min_order;

	ODP_DBG("\n%s\n", title);
	ODP_DBG("Pool Type: BUDDY\n");
	ODP_DBG("pool size: %" PRIu64 " (bytes)\n", (1UL << pool_order));
	ODP_DBG("pool order: %d\n", (int)pool_order);
	ODP_DBG("pool min_order: %d\n", (int)pool_min_order);

	/* a pool wholse order is more than 64 cannot even be reached on 64
	 * bit machines! */
	if (pool_order > 64) {
		odp_spinlock_unlock(&bpool->ctrl.lock);
		return -1;
	}

	total_bytes_free = 0;
	total_bytes_allocated = 0;

	/* for each queue */
	for (order = pool_min_order; order <= pool_order; order++) {
		free_q_nb_bblocks[order] = 0;
		free_q_nb_bblocks_bytes[order] = 0;
		allocated_nb_bblocks[order] = 0;
		allocated_nb_bblocks_bytes[order] = 0;

		/* get the number of buffs in the free queue for this order: */
		bblock = bpool->ctrl.free_heads[order];
		while (bblock) {
			free_q_nb_bblocks[order]++;
			free_q_nb_bblocks_bytes[order] += (1 << order);
			bblock = bblock->next;
		}

		total_bytes_free += free_q_nb_bblocks_bytes[order];

		/* get the number of allocated buffers of this order */
		for (nr = 0;
		     nr < (1U << (pool_order - pool_min_order)); nr++) {
			if (bpool->ctrl.alloced_order[nr] == order)
				allocated_nb_bblocks[order]++;
		}

		allocated_nb_bblocks_bytes[order] =
			allocated_nb_bblocks[order] * (1 << order);

		total_bytes_allocated += allocated_nb_bblocks_bytes[order];

		ODP_DBG("Order %d => Free: %" PRIu64 " buffers "
			"(%" PRIu64" bytes)   "
			"Allocated %" PRIu64 " buffers (%" PRIu64 "  bytes)   "
			"Total: %" PRIu64 "  bytes\n",
			(int)order, free_q_nb_bblocks[order],
			free_q_nb_bblocks_bytes[order],
			allocated_nb_bblocks[order],
			allocated_nb_bblocks_bytes[order],
			free_q_nb_bblocks_bytes[order] +
			allocated_nb_bblocks_bytes[order]);
	}

	ODP_DBG("Allocated space: %" PRIu64 " (bytes)\n",
		total_bytes_allocated);
	ODP_DBG("Free space: %" PRIu64 " (bytes)\n", total_bytes_free);

	if (total_bytes_free + total_bytes_allocated != (1U << pool_order)) {
		ODP_DBG("Lost bytes on this pool!\n");
		res = -1;
	}

	if (res)
		ODP_DBG("Pool inconsistent!\n");

	odp_spinlock_unlock(&bpool->ctrl.lock);
	return res;
}

/* section 2: functions for slab allocation:                                  */

/* free slab blocks contains the following structure, used to link the
 * free blocks together.
 */
typedef struct sblock_t {
	struct sblock_t *next;
} sblock_t;

/*
 * create a slab memory pool of given size (rounded up to the nearest integer
 * number of element, where each element has size 'elt_size').
 * returns a pointer to the created slab pool.
 * The allocated area contains:
 * - The _odp_ishm_pool_ctrl_t structure
 * - alignment to cache line
 * - The user memory
 */
static pool_t *_odp_ishmslab_pool_create(const char *pool_name, int store_idx,
					 uint64_t size,
					 uint64_t elt_size, int flags)
{
	uint32_t nb_sblock;      /* number of elements in the pool        */
	uint32_t control_sz;     /* size of control area                  */
	uint64_t total_sz;	 /* total size to request                 */
	uint64_t user_sz;        /* 2^order bytes		          */
	int	 blk_idx;	 /* as returned by _ishm_reserve()        */
	pool_t *spool;
	unsigned int i;
	sblock_t *block;

	/* a sblock_t must fit in the buffers for linked chain! */
	if (elt_size < sizeof(bblock_t)) {
		elt_size = sizeof(bblock_t);
		size = size * (sizeof(bblock_t) / elt_size +
			       ((sizeof(bblock_t) % elt_size) ? 1 : 0));
	}

	/* nb of element fitting in the pool is just ceil(size/elt_size)*/
	nb_sblock = (size / elt_size) + ((size % elt_size) ? 1 : 0);

	/* space needed for the control area (padded to cache line size)*/
	control_sz = ROUNDUP_CACHE_LINE(sizeof(_odp_ishm_pool_ctrl_t));

	/* space needed for user area is : */
	user_sz = nb_sblock * elt_size;

	total_sz = control_sz +
		   user_sz;

	/* allocate required memory: */
	blk_idx = _odp_ishm_reserve(pool_name, total_sz, -1,
				    ODP_CACHE_LINE_SIZE, 0, flags, 0);
	if (blk_idx < 0) {
		ODP_ERR("_odp_ishm_reserve failed.");
		return NULL;
	}

	spool = _odp_ishm_address(blk_idx);
	if (spool == NULL) {
		ODP_ERR("_odp_ishm_address failed.");
		return NULL;
	}

	/* store in pool array (needed for look up): */
	pool_blk_idx[store_idx] = blk_idx;

	/* remember block index, needed when pool is destroyed */
	spool->ctrl.ishm_blk_idx = blk_idx;

	/* remember element (sblock) size and their number: */
	spool->ctrl.element_sz = elt_size;
	spool->ctrl.nb_elem = nb_sblock;

	/* prepare mutex: */
	odp_spinlock_init(&spool->ctrl.lock);

	/* initialise pointers and things... */
	spool->ctrl.user_addr =
		(void *)((uintptr_t)spool + control_sz);

	/* initialise the free list with the list of all elements:*/
	spool->ctrl.free_head = spool->ctrl.user_addr;
	for (i = 0; i < nb_sblock - 1; i++) {
		block = (sblock_t *)((uintptr_t)spool->ctrl.user_addr +
				     i * (uintptr_t)elt_size);
		block->next = (sblock_t *)((uintptr_t)block +
					   (uintptr_t)elt_size);
	}
	block = (sblock_t *)((uintptr_t)spool->ctrl.user_addr +
			     (nb_sblock - 1) * (uintptr_t)elt_size);
	block->next = NULL;

	return spool;
}

/* allocated memory from the given slab pool */
static void *_odp_ishmslab_alloc(pool_t *spool, uint64_t size)
{
	void *ret;
	sblock_t *block;

	if (size > spool->ctrl.element_sz)
		return NULL;

	odp_spinlock_lock(&spool->ctrl.lock);
	ret = spool->ctrl.free_head;
	if (!ret) {
		odp_spinlock_unlock(&spool->ctrl.lock);
		ODP_ERR("Out of memory. (Slab pool full)\n");
		return NULL;
	}

	block = (sblock_t *)ret;
	spool->ctrl.free_head = block->next;

	odp_spinlock_unlock(&spool->ctrl.lock);
	return ret;
}

/* free a previously allocated buffer from a given slab pool */
static int _odp_ishmslab_free(pool_t *spool, void *addr)
{
	uintptr_t user_start; /* start of user area */
	uintptr_t user_stop;  /* stop  of user area */
	sblock_t *block;

	/* freeing NULL is regarded as OK, though without any effect:   */
	if (!addr)
		return 0;

	user_start = (uintptr_t)spool->ctrl.user_addr;
	user_stop  = user_start + spool->ctrl.element_sz * spool->ctrl.nb_elem;

	/* some sanity checks: check that given address is within pool and
	 * that relative address has element_sz granularity:           */
	if (((uintptr_t)addr < user_start) ||
	    ((uintptr_t)addr > user_stop)  ||
	    (((uintptr_t)addr - user_start) % spool->ctrl.element_sz)) {
		ODP_ERR("Invalid address to be freed\n");
		return -1;
	}

	odp_spinlock_lock(&spool->ctrl.lock);
	block = (sblock_t *)addr;
	block->next = (sblock_t *)spool->ctrl.free_head;
	spool->ctrl.free_head = addr;
	odp_spinlock_unlock(&spool->ctrl.lock);

	return 0;
}

/* print slab pool status and performs sanity checks */
static int _odp_ishmslab_pool_status(const char *title, pool_t *spool)
{
	sblock_t *sblock;
	uint64_t nb_free_elts; /* number of free elements */

	odp_spinlock_lock(&spool->ctrl.lock);

	ODP_DBG("\n%s\n", title);
	ODP_DBG("Pool Type: FIXED SIZE\n");
	ODP_DBG("pool size: %" PRIu64 " (bytes)\n",
		spool->ctrl.nb_elem * spool->ctrl.element_sz);

	/* count the number of free elements in the free list: */
	nb_free_elts = 0;
	sblock = (sblock_t *)spool->ctrl.free_head;
	while (sblock) {
		nb_free_elts++;
		sblock = sblock->next;
	}

	ODP_DBG("%" PRIu64 "/%" PRIu64 " available elements.\n",
		nb_free_elts, spool->ctrl.nb_elem);

	odp_spinlock_unlock(&spool->ctrl.lock);
	return 0;
}

/* section 3: common, external functions:                                     */

/* create a pool: either with fixed alloc size (if max_alloc/min_alloc<2) or
 * of variable block size (if max_alloc == 0) */
pool_t *_odp_ishm_pool_create(const char *pool_name, uint64_t size,
			      uint64_t min_alloc, uint64_t max_alloc, int flags)
{
	int store_idx;
	uint64_t real_pool_sz;

	if (min_alloc > max_alloc) {
		ODP_ERR("invalid parameter: min_alloc > max_alloc");
		return NULL;
	}

	/* search for a free index in pool_blk_idx for the pool */
	for (store_idx = 0; store_idx < MAX_NB_POOL; store_idx++) {
		if (pool_blk_idx[store_idx] < 0)
			break;
	}
	if (store_idx == MAX_NB_POOL) {
		ODP_ERR("Max number of pool reached (MAX_NB_POOL)");
		return NULL;
	}

	if ((min_alloc == 0) || ((max_alloc / min_alloc) > 2)) {
		/* alloc variation is not constant enough: we go for a buddy
		 * allocator. The pool efficiency may go as low as 50%
		 * so we double the required size to make sure we can satisfy
		 * the user request */
		real_pool_sz = 2 * size;
		return _odp_ishmbud_pool_create(pool_name, store_idx,
						real_pool_sz,
						BUDDY_MIN_SIZE, flags);
	} else {
		/* min and max are close enough so we go for constant size
		 * allocator:
		 * make sure the pool can fit the required size, even when
		 * only min_alloc allocation are performed: */
		real_pool_sz = ((size / min_alloc) +
				((size % min_alloc) ? 1 : 0))
			       * max_alloc;
		return _odp_ishmslab_pool_create(pool_name, store_idx,
						 real_pool_sz,
						 max_alloc, flags);
	}
}

/* destroy a pool. everything goes away. no operation on the pool should
 * follow. */
int _odp_ishm_pool_destroy(pool_t *pool)
{
	int store_idx;

	for (store_idx = 0; store_idx < MAX_NB_POOL; store_idx++) {
		if (pool_blk_idx[store_idx] == pool->ctrl.ishm_blk_idx) {
			pool_blk_idx[store_idx] = -1;
			break;
		}
	}

	return _odp_ishm_free_by_index(pool->ctrl.ishm_blk_idx);
}

/* allocated a buffer from a pool */
void *_odp_ishm_pool_alloc(_odp_ishm_pool_t *pool, uint64_t size)
{
	if (!pool->ctrl.element_sz)
		return _odp_ishmbud_alloc(pool, size);
	else
		return _odp_ishmslab_alloc(pool, size);
}

/* free a previously allocated buffer from a pool */
int _odp_ishm_pool_free(_odp_ishm_pool_t *pool, void *addr)
{
	if (!pool->ctrl.element_sz)
		return _odp_ishmbud_free(pool, addr);
	else
		return _odp_ishmslab_free(pool, addr);
}

/* Print a pool status */
int _odp_ishm_pool_status(const char *title, _odp_ishm_pool_t *pool)
{
	if (!pool->ctrl.element_sz)
		return _odp_ishmbud_pool_status(title, pool);
	else
		return _odp_ishmslab_pool_status(title, pool);
}

void _odp_ishm_pool_init(void)
{
	int i;

	for (i = 0; i < MAX_NB_POOL; i++)
		pool_blk_idx[i] = -1;
}
