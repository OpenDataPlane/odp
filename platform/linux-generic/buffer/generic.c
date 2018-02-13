/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "config.h"

#include <odp/api/buffer.h>
#include <odp_pool_internal.h>
#include <odp_buffer_internal.h>
#include <odp_buffer_inlines.h>
#include <odp_debug_internal.h>
#include <subsystem/spec/buffer_subsystem.h>

#include <string.h>
#include <stdio.h>
#include <inttypes.h>

static odp_buffer_t generic_buffer_from_event(odp_event_t ev)
{
	return (odp_buffer_t)ev;
}

static odp_event_t generic_buffer_to_event(odp_buffer_t buf)
{
	return (odp_event_t)buf;
}

static void *generic_buffer_addr(odp_buffer_t buf)
{
	odp_buffer_hdr_t *hdr = buf_hdl_to_hdr(buf);

	return hdr->seg[0].data;
}

static uint32_t generic_buffer_size(odp_buffer_t buf)
{
	odp_buffer_hdr_t *hdr = buf_hdl_to_hdr(buf);
	pool_t *pool = hdr->pool_ptr;

	return pool->seg_len;
}

int odp_buffer_snprint(char *str, uint32_t n, odp_buffer_t buf)
{
	odp_buffer_hdr_t *hdr;
	pool_t *pool;
	int len = 0;

	if (!odp_buffer_is_valid(buf)) {
		ODP_PRINT("Buffer is not valid.\n");
		return len;
	}

	hdr = buf_hdl_to_hdr(buf);
	pool = hdr->pool_ptr;

	len += snprintf(&str[len], n-len,
			"Buffer\n");
	len += snprintf(&str[len], n-len,
			"  pool         %" PRIu64 "\n",
			odp_pool_to_u64(pool->pool_hdl));
	len += snprintf(&str[len], n-len,
			"  addr         %p\n",          hdr->seg[0].data);
	len += snprintf(&str[len], n-len,
			"  size         %" PRIu32 "\n", odp_buffer_size(buf));
	len += snprintf(&str[len], n-len,
			"  type         %i\n",          hdr->type);

	return len;
}

static void generic_buffer_print(odp_buffer_t buf)
{
	int max_len = 512;
	char str[max_len];
	int len;

	len = odp_buffer_snprint(str, max_len-1, buf);
	str[len] = 0;

	ODP_PRINT("\n%s\n", str);
}

static uint64_t generic_buffer_to_u64(odp_buffer_t hdl)
{
	return _odp_pri(hdl);
}

odp_event_type_t _odp_buffer_event_type(odp_buffer_t buf)
{
	return buf_hdl_to_hdr(buf)->event_type;
}

void _odp_buffer_event_type_set(odp_buffer_t buf, int ev)
{
	buf_hdl_to_hdr(buf)->event_type = ev;
}

int buffer_alloc_multi(pool_t *pool, odp_buffer_hdr_t *buf_hdr[], int max_num)
{
	ring_t *ring;
	uint32_t mask, i;
	pool_cache_t *cache;
	uint32_t cache_num, num_ch, num_deq, burst;
	odp_buffer_hdr_t *hdr;

	cache = _pool_local_data.cache[pool->pool_idx];

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
	for (i = 0; i < num_ch; i++) {
		uint32_t j = cache_num - num_ch + i;

		buf_hdr[i] = buf_hdr_from_index(pool, cache->buf_index[j]);
	}

	/* If needed, get more from the global pool */
	if (odp_unlikely(num_deq)) {
		/* Temporary copy needed since odp_buffer_t is uintptr_t
		 * and not uint32_t. */
		uint32_t data[burst];

		ring      = &pool->ring->hdr;
		mask      = pool->ring_mask;
		burst     = ring_deq_multi(ring, mask, data, burst);
		cache_num = burst - num_deq;

		if (odp_unlikely(burst < num_deq)) {
			num_deq   = burst;
			cache_num = 0;
		}

		for (i = 0; i < num_deq; i++) {
			uint32_t idx = num_ch + i;

			hdr = buf_hdr_from_index(pool, data[i]);
			odp_prefetch(hdr);
			buf_hdr[idx] = hdr;
		}

		/* Cache extra buffers. Cache is currently empty. */
		for (i = 0; i < cache_num; i++)
			cache->buf_index[i] = data[num_deq + i];

		cache->num = cache_num;
	} else {
		cache->num = cache_num - num_ch;
	}

	return num_ch + num_deq;
}

static inline void buffer_free_to_pool(pool_t *pool,
				       odp_buffer_hdr_t *buf_hdr[], int num)
{
	int i;
	ring_t *ring;
	uint32_t mask;
	pool_cache_t *cache;
	uint32_t cache_num;

	cache = _pool_local_data.cache[pool->pool_idx];

	/* Special case of a very large free. Move directly to
	 * the global pool. */
	if (odp_unlikely(num > CONFIG_POOL_CACHE_SIZE)) {
		uint32_t buf_index[num];

		ring  = &pool->ring->hdr;
		mask  = pool->ring_mask;
		for (i = 0; i < num; i++)
			buf_index[i] = buf_hdr_to_index(buf_hdr[i]);

		ring_enq_multi(ring, mask, buf_index, num);

		return;
	}

	/* Make room into local cache if needed. Do at least burst size
	 * transfer. */
	cache_num = cache->num;

	if (odp_unlikely((int)(CONFIG_POOL_CACHE_SIZE - cache_num) < num)) {
		uint32_t index;
		int burst = CACHE_BURST;

		ring  = &pool->ring->hdr;
		mask  = pool->ring_mask;

		if (odp_unlikely(num > CACHE_BURST))
			burst = num;
		if (odp_unlikely((uint32_t)num > cache_num))
			burst = cache_num;

		{
			/* Temporary copy needed since odp_buffer_t is
			 * uintptr_t and not uint32_t. */
			uint32_t data[burst];

			index = cache_num - burst;

			for (i = 0; i < burst; i++)
				data[i] = cache->buf_index[index + i];

			ring_enq_multi(ring, mask, data, burst);
		}

		cache_num -= burst;
	}

	for (i = 0; i < num; i++)
		cache->buf_index[cache_num + i] = buf_hdr_to_index(buf_hdr[i]);

	cache->num = cache_num + num;
}

void buffer_free_multi(odp_buffer_hdr_t *buf_hdr[], int num_total)
{
	pool_t *pool;
	int num;
	int i;
	int first = 0;

	while (1) {
		num  = 1;
		i    = 1;
		pool = buf_hdr[first]->pool_ptr;

		/* 'num' buffers are from the same pool */
		if (num_total > 1) {
			for (i = first; i < num_total; i++)
				if (pool != buf_hdr[i]->pool_ptr)
					break;

			num = i - first;
		}

		buffer_free_to_pool(pool, &buf_hdr[first], num);

		if (i == num_total)
			return;

		first = i;
	}
}

static odp_buffer_t generic_buffer_alloc(odp_pool_t pool_hdl)
{
	odp_buffer_t buf;
	pool_t *pool;
	int ret;

	ODP_ASSERT(ODP_POOL_INVALID != pool_hdl);

	pool = pool_entry_from_hdl(pool_hdl);
	ret  = buffer_alloc_multi(pool, (odp_buffer_hdr_t **)&buf, 1);

	if (odp_likely(ret == 1))
		return buf;

	return ODP_BUFFER_INVALID;
}

static int generic_buffer_alloc_multi(odp_pool_t pool_hdl,
				      odp_buffer_t buf[], int num)
{
	pool_t *pool;

	ODP_ASSERT(ODP_POOL_INVALID != pool_hdl);

	pool = pool_entry_from_hdl(pool_hdl);

	return buffer_alloc_multi(pool, (odp_buffer_hdr_t **)buf, num);
}

static void generic_buffer_free(odp_buffer_t buf)
{
	buffer_free_multi((odp_buffer_hdr_t **)&buf, 1);
}

static void generic_buffer_free_multi(const odp_buffer_t buf[], int num)
{
	buffer_free_multi((odp_buffer_hdr_t **)(uintptr_t)buf, num);
}

static odp_pool_t generic_buffer_pool(odp_buffer_t buf)
{
	pool_t *pool = pool_from_buf(buf);

	return pool->pool_hdl;
}

static int generic_buffer_is_valid(odp_buffer_t buf)
{
	pool_t *pool;

	if (buf == ODP_BUFFER_INVALID)
		return 0;

	pool = pool_from_buf(buf);

	if (pool->pool_idx >= ODP_CONFIG_POOLS)
		return 0;

	if (pool->reserved == 0)
		return 0;

	return 1;
}

odp_buffer_module_t generic_buffer = {
	.base = {
		.name = "generic_buffer",
		.init_local = NULL,
		.term_local = NULL,
		.init_global = NULL,
		.term_global = NULL,
		},
	.buffer_from_event = generic_buffer_from_event,
	.buffer_to_event = generic_buffer_to_event,
	.buffer_addr = generic_buffer_addr,
	.buffer_alloc_multi = generic_buffer_alloc_multi,
	.buffer_free_multi = generic_buffer_free_multi,
	.buffer_alloc = generic_buffer_alloc,
	.buffer_free = generic_buffer_free,
	.buffer_size = generic_buffer_size,
	.buffer_is_valid = generic_buffer_is_valid,
	.buffer_pool = generic_buffer_pool,
	.buffer_print = generic_buffer_print,
	.buffer_to_u64 = generic_buffer_to_u64,
};

ODP_MODULE_CONSTRUCTOR(generic_buffer)
{
	odp_module_constructor(&generic_buffer);
	odp_subsystem_register_module(buffer, &generic_buffer);
}

