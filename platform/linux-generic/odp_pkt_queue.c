/* Copyright 2015 EZchip Semiconductor Ltd. All Rights Reserved.

 * Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdint.h>
#include <string.h>
#include <malloc.h>
#include <stdio.h>
#include <odp.h>
#include <odp_pkt_queue_internal.h>
#include <odp_debug_internal.h>

#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#define MIN(a, b) (((a) < (b)) ? (a) : (b))

#define INVALID_PKT  0

typedef struct /* Must be exactly 64 bytes long AND cacheline aligned! */ {
	uint32_t next_queue_blk_idx;
	uint32_t tail_queue_blk_idx;
	odp_packet_t pkts[7];
} ODP_ALIGNED_CACHE queue_blk_t;

typedef struct {
	queue_blk_t blks[0];
} ODP_ALIGNED_CACHE queue_blks_t;

/* The queue_num_tbl is used to map from a queue_num to a queue_num_desc.
 * The reason is based on the assumption that usually only a small fraction
 * of the max_num_queues will have more than 1 pkt associated with it.  This
 * way the active queue_desc's can be dynamically allocated and freed according
 * to the actual usage pattern.
 */
typedef struct {
	uint32_t queue_num_to_blk_idx[0];
} queue_num_tbl_t;

typedef struct {
	uint32_t num_blks;
	uint32_t next_blk_idx; /* blk_idx of queue_blks not yet added. */
	queue_blks_t *queue_blks;
} queue_region_desc_t;

typedef struct {
	uint64_t total_pkt_appends;
	uint64_t total_pkt_removes;
	uint64_t total_bad_removes;
	uint32_t free_list_size;
	uint32_t min_free_list_size;
	uint32_t peak_free_list_size;
	uint32_t free_list_head_idx;
	uint32_t max_queue_num;
	uint32_t max_queued_pkts;
	uint32_t next_queue_num;
	queue_region_desc_t queue_region_descs[16];
	uint32_t *queue_num_tbl;
	uint8_t current_region;
	uint8_t all_regions_used;
} queue_pool_t;

static queue_blk_t *blk_idx_to_queue_blk(queue_pool_t *queue_pool,
					 uint32_t queue_blk_idx)
{
	queue_region_desc_t *queue_region_desc;
	uint32_t which_region, blk_tbl_idx;

	which_region = queue_blk_idx >> 28;
	blk_tbl_idx = queue_blk_idx & ((1 << 28) - 1);
	queue_region_desc = &queue_pool->queue_region_descs[which_region];
	return &queue_region_desc->queue_blks->blks[blk_tbl_idx];
}

static int pkt_queue_free_list_add(queue_pool_t *pool,
				   uint32_t num_queue_blks)
{
	queue_region_desc_t *region_desc;
	queue_blks_t *queue_blks;
	queue_blk_t *queue_blk;
	uint32_t which_region, blks_added, num_blks, start_idx;
	uint32_t malloc_len, blks_to_add, cnt;

	which_region = pool->current_region;
	blks_added = 0;
	while ((blks_added < num_queue_blks) && (pool->all_regions_used == 0)) {
		region_desc = &pool->queue_region_descs[which_region];
		start_idx = region_desc->next_blk_idx;
		num_blks = region_desc->num_blks;
		queue_blks = region_desc->queue_blks;
		if (!queue_blks) {
			malloc_len = num_blks * sizeof(queue_blk_t);
			queue_blks = malloc(malloc_len);
			memset(queue_blks, 0, malloc_len);
			region_desc->queue_blks = queue_blks;
		}

		/* Now add as many queue_blks to the free list as... */
		blks_to_add = MIN(num_blks - start_idx, num_queue_blks);
		queue_blk = &queue_blks->blks[start_idx];
		for (cnt = 1; cnt <= blks_to_add; cnt++) {
			queue_blk->next_queue_blk_idx = start_idx + cnt;
			queue_blk++;
		}

		blks_added += blks_to_add;
		pool->free_list_size += blks_to_add;
		region_desc->next_blk_idx += blks_to_add;
		if (blks_to_add == (num_blks - start_idx)) {
			/* Advance to the next region */
			pool->current_region++;
			if (16 <= pool->current_region) {
				pool->all_regions_used = 1;
				return blks_added;
			}

			which_region = pool->current_region;
		}
	}

	return blks_added;
}

static queue_blk_t *queue_blk_alloc(queue_pool_t *pool,
				    uint32_t *queue_blk_idx)
{
	queue_blk_t *head_queue_blk;
	uint32_t head_queue_blk_idx;
	int rc;

	if (pool->free_list_size <= 1) {
		/* Replenish the queue_blk_t free list. */
		pool->min_free_list_size = pool->free_list_size;
		rc = pkt_queue_free_list_add(pool, 64);
		if (rc <= 0)
			return NULL;
	}

	head_queue_blk_idx = pool->free_list_head_idx;
	head_queue_blk = blk_idx_to_queue_blk(pool, head_queue_blk_idx);
	pool->free_list_size--;
	pool->free_list_head_idx = head_queue_blk->next_queue_blk_idx;
	*queue_blk_idx = head_queue_blk_idx;
	if (pool->free_list_size < pool->min_free_list_size)
		pool->min_free_list_size = pool->free_list_size;

	memset(head_queue_blk, 0, sizeof(queue_blk_t));
	return head_queue_blk;
}

static void queue_blk_free(queue_pool_t *pool, queue_blk_t *queue_blk,
			   uint32_t queue_blk_idx)
{
	if ((!queue_blk) || (queue_blk_idx == 0))
		return;

	queue_blk->next_queue_blk_idx = pool->free_list_head_idx;
	pool->free_list_head_idx = queue_blk_idx;
	pool->free_list_size++;
	if (pool->peak_free_list_size < pool->free_list_size)
		pool->peak_free_list_size = pool->free_list_size;
}

static void queue_region_desc_init(queue_pool_t *pool, uint32_t which_region,
				   uint32_t num_blks)
{
	queue_region_desc_t *queue_region_desc;

	queue_region_desc = &pool->queue_region_descs[which_region];
	queue_region_desc->num_blks = num_blks;
}

_odp_int_queue_pool_t _odp_queue_pool_create(uint32_t max_num_queues,
					     uint32_t max_queued_pkts)
{
	queue_pool_t *pool;
	uint32_t idx, initial_free_list_size, malloc_len, first_queue_blk_idx;
	int rc;

	pool = malloc(sizeof(queue_pool_t));
	memset(pool, 0, sizeof(queue_pool_t));

       /* Initialize the queue_blk_tbl_sizes array based upon the
	* max_queued_pkts.
	*/
	max_queued_pkts = MAX(max_queued_pkts, 64 * 1024);
	queue_region_desc_init(pool, 0, max_queued_pkts / 4);
	queue_region_desc_init(pool, 1, max_queued_pkts / 64);
	queue_region_desc_init(pool, 2, max_queued_pkts / 64);
	queue_region_desc_init(pool, 3, max_queued_pkts / 64);
	queue_region_desc_init(pool, 4, max_queued_pkts / 64);
	for (idx = 5; idx < 16; idx++)
		queue_region_desc_init(pool, idx, max_queued_pkts / 16);

       /* Now allocate the first queue_blk_tbl and add its blks to the free
	* list.  Replenish the queue_blk_t free list.
	*/
	initial_free_list_size = MIN(64 * 1024, max_queued_pkts / 4);
	rc = pkt_queue_free_list_add(pool, initial_free_list_size);
	if (rc < 0)
		return _ODP_INT_QUEUE_POOL_INVALID;

	/* Discard the first queue blk with idx 0 */
	queue_blk_alloc(pool, &first_queue_blk_idx);

	pool->max_queue_num = max_num_queues;
	pool->max_queued_pkts = max_queued_pkts;
	pool->next_queue_num = 1;

	malloc_len = max_num_queues * sizeof(uint32_t);
	pool->queue_num_tbl = malloc(malloc_len);
	memset(pool->queue_num_tbl, 0, malloc_len);

	pool->min_free_list_size = pool->free_list_size;
	pool->peak_free_list_size = pool->free_list_size;
	return (_odp_int_queue_pool_t)pool;
}

_odp_int_pkt_queue_t _odp_pkt_queue_create(_odp_int_queue_pool_t queue_pool)
{
	queue_pool_t *pool;
	uint32_t queue_num;

	pool = (queue_pool_t *)queue_pool;
	queue_num = pool->next_queue_num++;
	if (pool->max_queue_num < queue_num)
		return _ODP_INT_PKT_QUEUE_INVALID;

	return (_odp_int_pkt_queue_t)queue_num;
}

int _odp_pkt_queue_append(_odp_int_queue_pool_t queue_pool,
			  _odp_int_pkt_queue_t pkt_queue, odp_packet_t pkt)
{
	queue_pool_t *pool;
	queue_blk_t *first_blk, *tail_blk, *new_tail_blk;
	uint32_t queue_num, first_blk_idx, tail_blk_idx, new_tail_blk_idx;
	uint32_t idx;

	pool = (queue_pool_t *)queue_pool;
	queue_num = (uint32_t)pkt_queue;
	if ((queue_num == 0) || (pool->max_queue_num < queue_num))
		return -2;

	if (pkt == INVALID_PKT)
		return -3;

	pool->total_pkt_appends++;
	first_blk_idx = pool->queue_num_tbl[queue_num];
	if (first_blk_idx == 0) {
		first_blk = queue_blk_alloc(pool, &first_blk_idx);
		if (!first_blk)
			return -1;

		pool->queue_num_tbl[queue_num] = first_blk_idx;
		memset(first_blk, 0, sizeof(queue_blk_t));
		first_blk->pkts[0] = pkt;
		return 0;
	}

	first_blk = blk_idx_to_queue_blk(pool, first_blk_idx);
	tail_blk_idx = first_blk->tail_queue_blk_idx;
	if (tail_blk_idx == 0)
		tail_blk = first_blk;
	else
		tail_blk = blk_idx_to_queue_blk(pool, tail_blk_idx);

	/* Find first empty slot and insert pkt there. */
	for (idx = 0; idx < 7; idx++) {
		if (tail_blk->pkts[idx] == INVALID_PKT) {
			tail_blk->pkts[idx] = pkt;
			return 0;
		}
	}

       /* If we reach here, the tai_blk was full, so we need to allocate a new
	* one and link it in.
	*/
	new_tail_blk = queue_blk_alloc(pool, &new_tail_blk_idx);
	if (!new_tail_blk)
		return -1;

	memset(new_tail_blk, 0, sizeof(queue_blk_t));
	new_tail_blk->pkts[0] = pkt;
	tail_blk->next_queue_blk_idx = new_tail_blk_idx;
	first_blk->tail_queue_blk_idx = new_tail_blk_idx;
	return 0;
}

int _odp_pkt_queue_remove(_odp_int_queue_pool_t queue_pool,
			  _odp_int_pkt_queue_t pkt_queue, odp_packet_t *pkt)
{
	queue_pool_t *pool;
	queue_blk_t *first_blk, *second_blk;
	uint32_t queue_num, first_blk_idx, next_blk_idx, idx;

	pool = (queue_pool_t *)queue_pool;
	queue_num = (uint32_t)pkt_queue;
	if ((queue_num == 0) || (pool->max_queue_num < queue_num))
		return -2;

	first_blk_idx = pool->queue_num_tbl[queue_num];
	if (first_blk_idx == 0)
		return 0; /* pkt queue is empty. */

	/* Now remove the first valid odp_packet_t handle value we find. */
	first_blk = blk_idx_to_queue_blk(pool, first_blk_idx);
	for (idx = 0; idx < 7; idx++) {
		if (first_blk->pkts[idx] != INVALID_PKT) {
			*pkt = first_blk->pkts[idx];
			first_blk->pkts[idx] = INVALID_PKT;

			/* Now see if there are any more pkts in this queue. */
			if ((idx == 6) ||
			    (first_blk->pkts[idx + 1] == INVALID_PKT)) {
				/* We have reached the end of this queue_blk.
				 * Check to see if there is a following block
				 * or not
				 */
				next_blk_idx = first_blk->next_queue_blk_idx;
				if (next_blk_idx != 0) {
					second_blk =
						blk_idx_to_queue_blk
						(pool,
						 next_blk_idx);
					second_blk->tail_queue_blk_idx =
						first_blk->tail_queue_blk_idx;
				}

				pool->queue_num_tbl[queue_num] = next_blk_idx;
				queue_blk_free(pool, first_blk, first_blk_idx);
			}

			pool->total_pkt_removes++;
			return 1;
		}
	}

	/* It is an error to not find at least one pkt in the first_blk! */
	pool->total_bad_removes++;
	return -1;
}

void _odp_pkt_queue_stats_print(_odp_int_queue_pool_t queue_pool)
{
	queue_pool_t *pool;

	pool = (queue_pool_t *)queue_pool;
	ODP_DBG("pkt_queue_stats - queue_pool=0x%lX\n", queue_pool);
	ODP_DBG("  max_queue_num=%u max_queued_pkts=%u next_queue_num=%u\n",
		pool->max_queue_num, pool->max_queued_pkts,
		pool->next_queue_num);
	ODP_DBG("  total pkt appends=%lu total pkt removes=%lu "
		"bad removes=%lu\n",
		pool->total_pkt_appends, pool->total_pkt_removes,
		pool->total_bad_removes);
	ODP_DBG("  free_list size=%u  min size=%u peak size=%u\n",
		pool->free_list_size, pool->min_free_list_size,
		pool->peak_free_list_size);
}

void _odp_queue_pool_destroy(_odp_int_queue_pool_t queue_pool)
{
	queue_region_desc_t *queue_region_desc;
	queue_pool_t *pool;
	uint32_t idx;

	pool = (queue_pool_t *)queue_pool;
	for (idx = 0; idx < 16; idx++) {
		queue_region_desc = &pool->queue_region_descs[idx];
		if (queue_region_desc->queue_blks)
			free(queue_region_desc->queue_blks);
	}

	free(pool->queue_num_tbl);
	free(pool);
}
