/* Copyright 2015 EZchip Semiconductor Ltd. All Rights Reserved.
 *
 * Copyright (c) 2015-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdint.h>
#include <string.h>
#include <malloc.h>
#include <stdio.h>
#include <inttypes.h>
#include <odp_debug_internal.h>
#include <odp_sorted_list_internal.h>

typedef struct sorted_list_item_s sorted_list_item_t;

struct sorted_list_item_s {
	sorted_list_item_t *next_item;
	uint64_t            sort_key;
	uint64_t            user_data;
};

typedef struct {
	sorted_list_item_t *first_item;
	uint32_t            sorted_list_len;
	uint32_t            pad;
} sorted_list_desc_t;

typedef struct {
	sorted_list_desc_t descs[0];
} sorted_list_descs_t;

typedef struct {
	uint64_t             total_inserts;
	uint64_t             total_deletes;
	uint64_t             total_removes;
	uint32_t             max_sorted_lists;
	uint32_t             next_list_idx;
	sorted_list_descs_t *list_descs;
} sorted_pool_t;

_odp_int_sorted_pool_t _odp_sorted_pool_create(uint32_t max_sorted_lists)
{
	sorted_list_descs_t *list_descs;
	sorted_pool_t       *pool;
	uint32_t             malloc_len;

	pool = malloc(sizeof(sorted_pool_t));
	memset(pool, 0, sizeof(sorted_pool_t));
	pool->max_sorted_lists = max_sorted_lists;
	pool->next_list_idx    = 1;

	malloc_len = max_sorted_lists * sizeof(sorted_list_desc_t);
	list_descs = malloc(malloc_len);
	memset(list_descs, 0, malloc_len);
	pool->list_descs = list_descs;
	return (_odp_int_sorted_pool_t)(uintptr_t)pool;
}

_odp_int_sorted_list_t
_odp_sorted_list_create(_odp_int_sorted_pool_t sorted_pool,
			uint32_t max_entries ODP_UNUSED)
{
	sorted_pool_t *pool;
	uint32_t       list_idx;

	pool     = (sorted_pool_t *)(uintptr_t)sorted_pool;
	list_idx = pool->next_list_idx++;
	return (_odp_int_sorted_list_t)list_idx;
}

int _odp_sorted_list_insert(_odp_int_sorted_pool_t sorted_pool,
			    _odp_int_sorted_list_t sorted_list,
			    uint64_t              sort_key,
			    uint64_t              user_data)
{
	sorted_list_desc_t *list_desc;
	sorted_list_item_t *new_list_item, *list_item, *prev_list_item;
	sorted_pool_t      *pool;
	uint32_t            list_idx;

	pool     = (sorted_pool_t *)(uintptr_t)sorted_pool;
	list_idx = (uint32_t)sorted_list;
	if ((pool->next_list_idx    <= list_idx) ||
	    (pool->max_sorted_lists <= list_idx))
		return -1;

	list_desc     = &pool->list_descs->descs[list_idx];
	new_list_item = malloc(sizeof(sorted_list_item_t));
	memset(new_list_item, 0, sizeof(sorted_list_item_t));
	new_list_item->next_item = NULL;
	new_list_item->sort_key  = sort_key;
	new_list_item->user_data = user_data;

       /* Now insert the new_list_item according to the sort_key (lowest
	* value first).
	*/
	list_item      = list_desc->first_item;
	prev_list_item = NULL;
	while ((list_item) && (list_item->sort_key <= sort_key)) {
		prev_list_item = list_item;
		list_item      = list_item->next_item;
	}

	new_list_item->next_item = list_item;
	if (!prev_list_item)
		list_desc->first_item = new_list_item;
	else
		prev_list_item->next_item = new_list_item;

	list_desc->sorted_list_len++;
	pool->total_inserts++;
	return 0;
}

int _odp_sorted_list_find(_odp_int_sorted_pool_t sorted_pool,
			  _odp_int_sorted_list_t sorted_list,
			  uint64_t              user_data,
			  uint64_t             *sort_key_ptr)
{
	sorted_list_desc_t *list_desc;
	sorted_list_item_t *list_item;
	sorted_pool_t      *pool;
	uint32_t            list_idx;

	pool     = (sorted_pool_t *)(uintptr_t)sorted_pool;
	list_idx = (uint32_t)sorted_list;
	if ((pool->next_list_idx    <= list_idx) ||
	    (pool->max_sorted_lists <= list_idx))
		return -1;

	list_desc = &pool->list_descs->descs[list_idx];

       /* Now search the sorted linked list - as described by list_desc -
	* until an entry is found whose user_data field matches the supplied
	* user_data or the end of the list is reached.
	*/
	list_item = list_desc->first_item;
	while (list_item) {
		if (list_item->user_data == user_data) {
			if (sort_key_ptr)
				*sort_key_ptr = list_item->sort_key;

			return 1;
		}

		list_item = list_item->next_item;
	}

	return 0;
}

int _odp_sorted_list_delete(_odp_int_sorted_pool_t sorted_pool,
			    _odp_int_sorted_list_t sorted_list,
			    uint64_t              user_data)
{
	sorted_list_desc_t *list_desc;
	sorted_list_item_t *next_list_item, *list_item, *prev_list_item;
	sorted_pool_t      *pool;
	uint32_t            list_idx;

	pool     = (sorted_pool_t *)(uintptr_t)sorted_pool;
	list_idx = (uint32_t)sorted_list;
	if ((pool->next_list_idx    <= list_idx) ||
	    (pool->max_sorted_lists <= list_idx))
		return -1;

	list_desc = &pool->list_descs->descs[list_idx];

       /* Now search the sorted linked list - as described by list_desc -
	* until an entry is found whose user_data field matches the supplied
	* user_data or the end of the list is reached.
	*/
	list_item      = list_desc->first_item;
	prev_list_item = NULL;
	while (list_item) {
		next_list_item = list_item->next_item;

		if (list_item->user_data == user_data) {
			if (!prev_list_item)
				list_desc->first_item = next_list_item;
			else
				prev_list_item->next_item = next_list_item;

			list_desc->sorted_list_len--;
			free(list_item);
			pool->total_deletes++;
			return 0;
		}

		prev_list_item = list_item;
		list_item      = next_list_item;
	}

	return -1;
}

int _odp_sorted_list_remove(_odp_int_sorted_pool_t sorted_pool,
			    _odp_int_sorted_list_t sorted_list,
			    uint64_t              *sort_key_ptr,
			    uint64_t              *user_data_ptr)
{
	sorted_list_desc_t *list_desc;
	sorted_list_item_t *list_item;
	sorted_pool_t      *pool;
	uint32_t            list_idx;

	pool     = (sorted_pool_t *)(uintptr_t)sorted_pool;
	list_idx = (uint32_t)sorted_list;
	if ((pool->next_list_idx    <= list_idx) ||
	    (pool->max_sorted_lists <= list_idx))
		return -1;

	list_desc = &pool->list_descs->descs[list_idx];
	if ((list_desc->sorted_list_len == 0) ||
	    (!list_desc->first_item))
		return -1;

	list_item             = list_desc->first_item;
	list_desc->first_item = list_item->next_item;
	list_desc->sorted_list_len--;

	if (sort_key_ptr)
		*sort_key_ptr = list_item->sort_key;

	if (user_data_ptr)
		*user_data_ptr = list_item->user_data;

	free(list_item);
	pool->total_removes++;
	return 1;
}

int _odp_sorted_list_destroy(_odp_int_sorted_pool_t sorted_pool,
			     _odp_int_sorted_list_t sorted_list)
{
	sorted_list_desc_t *list_desc;
	sorted_pool_t      *pool;
	uint32_t            list_idx;

	pool     = (sorted_pool_t *)(uintptr_t)sorted_pool;
	list_idx = (uint32_t)sorted_list;
	if ((pool->next_list_idx    <= list_idx) ||
	    (pool->max_sorted_lists <= list_idx))
		return -1;

	list_desc = &pool->list_descs->descs[list_idx];
	if (list_desc->sorted_list_len != 0)
		return -2;

	/* TBD Mark the list as free. */
	return 0;
}

void _odp_sorted_list_stats_print(_odp_int_sorted_pool_t sorted_pool)
{
	sorted_pool_t *pool;

	pool = (sorted_pool_t *)(uintptr_t)sorted_pool;
	ODP_PRINT("sorted_pool=0x%" PRIX64 "\n", sorted_pool);
	ODP_PRINT("  max_sorted_lists=%u next_list_idx=%u\n",
		  pool->max_sorted_lists, pool->next_list_idx);
	ODP_PRINT("  total_inserts=%" PRIu64 " total_deletes=%" PRIu64
		  " total_removes=%" PRIu64 "\n", pool->total_inserts,
		  pool->total_deletes, pool->total_removes);
}

void _odp_sorted_pool_destroy(_odp_int_sorted_pool_t sorted_pool)
{
	sorted_list_descs_t *list_descs;
	sorted_list_desc_t  *list_desc;
	sorted_list_item_t  *list_item, *next_list_item;
	sorted_pool_t       *pool;
	uint32_t             list_idx;

	pool       = (sorted_pool_t *)(uintptr_t)sorted_pool;
	list_descs = pool->list_descs;

	for (list_idx = 0; list_idx < pool->next_list_idx; list_idx++) {
		list_desc = &list_descs->descs[list_idx];
		list_item = list_desc->first_item;
		while (list_item) {
			next_list_item = list_item->next_item;
			free(list_item);
			list_item = next_list_item;
		}
	}

	free(list_descs);
	free(pool);
}
