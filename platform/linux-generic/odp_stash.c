/* Copyright (c) 2020-2023, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/shared_memory.h>
#include <odp/api/stash.h>
#include <odp/api/std_types.h>
#include <odp/api/ticketlock.h>

#include <odp/api/plat/strong_types.h>

#include <odp_config_internal.h>
#include <odp_debug_internal.h>
#include <odp_global_data.h>
#include <odp_init_internal.h>
#include <odp_libconfig_internal.h>
#include <odp_macros_internal.h>
#include <odp_ring_u32_internal.h>
#include <odp_ring_u64_internal.h>

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>

ODP_STATIC_ASSERT(CONFIG_INTERNAL_STASHES < CONFIG_MAX_STASHES, "TOO_MANY_INTERNAL_STASHES");

#define MIN_RING_SIZE 64

enum {
	STASH_FREE = 0,
	STASH_RESERVED,
	STASH_ACTIVE
};

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
typedef struct stash_t {
	char      name[ODP_STASH_NAME_LEN];
	int       index;
	uint32_t  ring_mask;
	uint32_t  obj_size;

	/* Ring header followed by variable sized data (object handles) */
	union {
		struct ODP_ALIGNED_CACHE {
			ring_u32_t hdr;
			uint32_t   data[];
		} ring_u32;

		struct ODP_ALIGNED_CACHE {
			ring_u64_t hdr;
			uint64_t   data[];
		} ring_u64;
	};

} stash_t;
#pragma GCC diagnostic pop

typedef struct stash_global_t {
	odp_ticketlock_t  lock;
	odp_shm_t         shm;
	uint32_t          max_num;
	uint32_t          max_num_obj;
	uint32_t          num_internal;
	uint8_t           stash_state[CONFIG_MAX_STASHES];
	stash_t           *stash[CONFIG_MAX_STASHES];
	uint8_t           data[] ODP_ALIGNED_CACHE;

} stash_global_t;

static stash_global_t *stash_global;

int _odp_stash_init_global(void)
{
	odp_shm_t shm;
	uint32_t max_num, max_num_obj;
	const char *str;
	uint64_t ring_max_size, stash_max_size, stash_data_size, offset;
	const uint32_t internal_stashes = odp_global_ro.disable.dma ? 0 : CONFIG_INTERNAL_STASHES;
	uint8_t *stash_data;
	int val = 0;

	if (odp_global_ro.disable.stash && odp_global_ro.disable.dma) {
		_ODP_PRINT("Stash is DISABLED\n");
		return 0;
	}

	_ODP_PRINT("Stash config:\n");

	str = "stash.max_num";
	if (!_odp_libconfig_lookup_int(str, &val)) {
		_ODP_ERR("Config option '%s' not found.\n", str);
		return -1;
	}
	_ODP_PRINT("  %s: %i\n", str, val);
	max_num = val;

	str = "stash.max_num_obj";
	if (!_odp_libconfig_lookup_int(str, &val)) {
		_ODP_ERR("Config option '%s' not found.\n", str);
		return -1;
	}
	_ODP_PRINT("  %s: %i\n", str, val);
	max_num_obj = val;

	_ODP_PRINT("\n");

	/* Reserve resources for implementation internal stashes */
	if (max_num > CONFIG_MAX_STASHES - internal_stashes) {
		_ODP_ERR("Maximum supported number of stashes: %d\n",
			 CONFIG_MAX_STASHES - internal_stashes);
		return -1;
	}
	max_num += internal_stashes;

	/* Must have room for minimum sized ring */
	if (max_num_obj < MIN_RING_SIZE)
		max_num_obj = MIN_RING_SIZE - 1;

	/* Ring size must be larger than the number of items stored */
	ring_max_size = _ODP_ROUNDUP_POWER2_U32(max_num_obj + 1);

	stash_max_size = _ODP_ROUNDUP_CACHE_LINE(sizeof(stash_t) +
						 (ring_max_size * sizeof(uint64_t)));
	stash_data_size = max_num * stash_max_size;

	shm = odp_shm_reserve("_odp_stash_global", sizeof(stash_global_t) + stash_data_size,
			      ODP_CACHE_LINE_SIZE, 0);

	stash_global = odp_shm_addr(shm);

	if (stash_global == NULL) {
		_ODP_ERR("SHM reserve of stash global data failed\n");
		return -1;
	}

	memset(stash_global, 0, sizeof(stash_global_t));
	stash_global->shm = shm;
	stash_global->max_num = max_num;
	stash_global->max_num_obj = max_num_obj;
	stash_global->num_internal = internal_stashes;
	odp_ticketlock_init(&stash_global->lock);

	/* Initialize stash pointers */
	stash_data = stash_global->data;
	offset = 0;

	for (uint32_t i = 0; i < max_num; i++) {
		stash_global->stash[i] = (stash_t *)(uintptr_t)(stash_data + offset);
		offset += stash_max_size;
	}

	return 0;
}

int _odp_stash_term_global(void)
{
	if (odp_global_ro.disable.stash)
		return 0;

	if (stash_global == NULL)
		return 0;

	if (odp_shm_free(stash_global->shm)) {
		_ODP_ERR("SHM free failed\n");
		return -1;
	}

	return 0;
}

int odp_stash_capability(odp_stash_capability_t *capa, odp_stash_type_t type)
{
	uint32_t max_stashes;

	if (odp_global_ro.disable.stash) {
		_ODP_ERR("Stash is disabled\n");
		return -1;
	}

	(void)type;
	max_stashes = stash_global->max_num - stash_global->num_internal;

	memset(capa, 0, sizeof(odp_stash_capability_t));

	capa->max_stashes_any_type = max_stashes;
	capa->max_stashes          = max_stashes;
	capa->max_num_obj          = stash_global->max_num_obj;
	capa->max_obj_size         = sizeof(uint64_t);
	capa->max_get_batch        = MIN_RING_SIZE;
	capa->max_put_batch        = MIN_RING_SIZE;
	capa->stats.bit.count      = 1;

	return 0;
}

void odp_stash_param_init(odp_stash_param_t *param)
{
	memset(param, 0, sizeof(odp_stash_param_t));
	param->type     = ODP_STASH_TYPE_DEFAULT;
	param->put_mode = ODP_STASH_OP_MT;
	param->get_mode = ODP_STASH_OP_MT;
}

static int reserve_index(void)
{
	int index = -1;

	odp_ticketlock_lock(&stash_global->lock);

	for (uint32_t i = 0; i < stash_global->max_num; i++) {
		if (stash_global->stash_state[i] == STASH_FREE) {
			index = i;
			stash_global->stash_state[i] = STASH_RESERVED;
			break;
		}
	}

	odp_ticketlock_unlock(&stash_global->lock);

	return index;
}

static void free_index(int i)
{
	odp_ticketlock_lock(&stash_global->lock);

	stash_global->stash_state[i] = STASH_FREE;

	odp_ticketlock_unlock(&stash_global->lock);
}

odp_stash_t odp_stash_create(const char *name, const odp_stash_param_t *param)
{
	stash_t *stash;
	uint64_t i, ring_size;
	int ring_u64, index;

	if (odp_global_ro.disable.stash) {
		_ODP_ERR("Stash is disabled\n");
		return ODP_STASH_INVALID;
	}

	if (param->obj_size > sizeof(uint64_t)) {
		_ODP_ERR("Too large object handle.\n");
		return ODP_STASH_INVALID;
	}

	if (param->num_obj > stash_global->max_num_obj) {
		_ODP_ERR("Too many objects.\n");
		return ODP_STASH_INVALID;
	}

	if (name && strlen(name) >= ODP_STASH_NAME_LEN) {
		_ODP_ERR("Too long name.\n");
		return ODP_STASH_INVALID;
	}

	index = reserve_index();

	if (index < 0) {
		_ODP_ERR("Maximum number of stashes created already.\n");
		return ODP_STASH_INVALID;
	}

	ring_u64 = 0;
	if (param->obj_size > sizeof(uint32_t))
		ring_u64 = 1;

	ring_size = param->num_obj;

	/* Ring size must be larger than the number of items stored */
	if (ring_size + 1 <= MIN_RING_SIZE)
		ring_size = MIN_RING_SIZE;
	else
		ring_size = _ODP_ROUNDUP_POWER2_U32(ring_size + 1);

	stash = stash_global->stash[index];
	memset(stash, 0, sizeof(stash_t));

	if (ring_u64) {
		ring_u64_init(&stash->ring_u64.hdr);

		for (i = 0; i < ring_size; i++)
			stash->ring_u64.data[i] = 0;
	} else {
		ring_u32_init(&stash->ring_u32.hdr);

		for (i = 0; i < ring_size; i++)
			stash->ring_u32.data[i] = 0;
	}

	if (name)
		strcpy(stash->name, name);

	stash->index        = index;
	stash->obj_size     = param->obj_size;
	stash->ring_mask    = ring_size - 1;

	/* This makes stash visible to lookups */
	odp_ticketlock_lock(&stash_global->lock);
	stash_global->stash_state[index] = STASH_ACTIVE;
	odp_ticketlock_unlock(&stash_global->lock);

	return (odp_stash_t)stash;
}

int odp_stash_destroy(odp_stash_t st)
{
	stash_t *stash;

	if (st == ODP_STASH_INVALID)
		return -1;

	stash = (stash_t *)(uintptr_t)st;

	free_index(stash->index);

	return 0;
}

uint64_t odp_stash_to_u64(odp_stash_t st)
{
	return _odp_pri(st);
}

odp_stash_t odp_stash_lookup(const char *name)
{
	stash_t *stash;

	if (name == NULL)
		return ODP_STASH_INVALID;

	odp_ticketlock_lock(&stash_global->lock);

	for (uint32_t i = 0; i < stash_global->max_num; i++) {
		stash = stash_global->stash[i];

		if (stash_global->stash_state[i] == STASH_ACTIVE &&
		    strcmp(stash->name, name) == 0) {
			odp_ticketlock_unlock(&stash_global->lock);
			return (odp_stash_t)stash;
		}
	}

	odp_ticketlock_unlock(&stash_global->lock);

	return ODP_STASH_INVALID;
}

static inline int32_t stash_put(odp_stash_t st, const void *obj, int32_t num)
{
	stash_t *stash;
	uint32_t obj_size;
	int32_t i;

	stash = (stash_t *)(uintptr_t)st;

	if (odp_unlikely(st == ODP_STASH_INVALID))
		return -1;

	obj_size = stash->obj_size;

	if (obj_size == sizeof(uint64_t)) {
		ring_u64_t *ring_u64 = &stash->ring_u64.hdr;

		ring_u64_enq_multi(ring_u64, stash->ring_mask,
				   (uint64_t *)(uintptr_t)obj, num);
		return num;
	}

	if (obj_size == sizeof(uint32_t)) {
		ring_u32_t *ring_u32 = &stash->ring_u32.hdr;

		ring_u32_enq_multi(ring_u32, stash->ring_mask,
				   (uint32_t *)(uintptr_t)obj, num);
		return num;
	}

	if (obj_size == sizeof(uint16_t)) {
		const uint16_t *u16_ptr = obj;
		ring_u32_t *ring_u32 = &stash->ring_u32.hdr;
		uint32_t u32[num];

		for (i = 0; i < num; i++)
			u32[i] = u16_ptr[i];

		ring_u32_enq_multi(ring_u32, stash->ring_mask, u32, num);
		return num;
	}

	if (obj_size == sizeof(uint8_t)) {
		const uint8_t *u8_ptr = obj;
		ring_u32_t *ring_u32 = &stash->ring_u32.hdr;
		uint32_t u32[num];

		for (i = 0; i < num; i++)
			u32[i] = u8_ptr[i];

		ring_u32_enq_multi(ring_u32, stash->ring_mask, u32, num);
		return num;
	}

	return -1;
}

int32_t odp_stash_put(odp_stash_t st, const void *obj, int32_t num)
{
	return stash_put(st, obj, num);
}

int32_t odp_stash_put_batch(odp_stash_t st, const void *obj, int32_t num)
{
	/* Returns always 'num', or -1 on failure. */
	return stash_put(st, obj, num);
}

static inline int32_t stash_put_u32(odp_stash_t st, const uint32_t val[],
				    int32_t num)
{
	stash_t *stash = (stash_t *)(uintptr_t)st;

	if (odp_unlikely(st == ODP_STASH_INVALID))
		return -1;

	_ODP_ASSERT(stash->obj_size == sizeof(uint32_t));

	ring_u32_enq_multi(&stash->ring_u32.hdr, stash->ring_mask,
			   (uint32_t *)(uintptr_t)val, num);
	return num;
}

int32_t odp_stash_put_u32(odp_stash_t st, const uint32_t val[], int32_t num)
{
	return stash_put_u32(st, val, num);
}

int32_t odp_stash_put_u32_batch(odp_stash_t st, const uint32_t val[],
				int32_t num)
{
	/* Returns always 'num', or -1 on failure. */
	return stash_put_u32(st, val, num);
}

static inline int32_t stash_put_u64(odp_stash_t st, const uint64_t val[],
				    int32_t num)
{
	stash_t *stash = (stash_t *)(uintptr_t)st;

	if (odp_unlikely(st == ODP_STASH_INVALID))
		return -1;

	_ODP_ASSERT(stash->obj_size == sizeof(uint64_t));

	ring_u64_enq_multi(&stash->ring_u64.hdr, stash->ring_mask,
			   (uint64_t *)(uintptr_t)val, num);
	return num;
}

int32_t odp_stash_put_u64(odp_stash_t st, const uint64_t val[], int32_t num)
{
	return stash_put_u64(st, val, num);
}

int32_t odp_stash_put_u64_batch(odp_stash_t st, const uint64_t val[],
				int32_t num)
{
	/* Returns always 'num', or -1 on failure. */
	return stash_put_u64(st, val, num);
}

static inline int32_t stash_put_ptr(odp_stash_t st, const uintptr_t ptr[],
				    int32_t num)
{
	stash_t *stash = (stash_t *)(uintptr_t)st;

	if (odp_unlikely(st == ODP_STASH_INVALID))
		return -1;

	_ODP_ASSERT(stash->obj_size == sizeof(uintptr_t));

	if (sizeof(uintptr_t) == sizeof(uint32_t))
		ring_u32_enq_multi(&stash->ring_u32.hdr, stash->ring_mask,
				   (uint32_t *)(uintptr_t)ptr, num);
	else if (sizeof(uintptr_t) == sizeof(uint64_t))
		ring_u64_enq_multi(&stash->ring_u64.hdr, stash->ring_mask,
				   (uint64_t *)(uintptr_t)ptr, num);
	else
		return -1;

	return num;
}

int32_t odp_stash_put_ptr(odp_stash_t st, const uintptr_t ptr[], int32_t num)
{
	return stash_put_ptr(st, ptr, num);
}

int32_t odp_stash_put_ptr_batch(odp_stash_t st,	const uintptr_t ptr[],
				int32_t num)
{
	/* Returns always 'num', or -1 on failure. */
	return stash_put_ptr(st, ptr, num);
}

static inline int32_t stash_get(odp_stash_t st, void *obj, int32_t num, odp_bool_t batch)
{
	stash_t *stash;
	uint32_t obj_size;
	uint32_t i, num_deq;

	stash = (stash_t *)(uintptr_t)st;

	if (odp_unlikely(st == ODP_STASH_INVALID))
		return -1;

	obj_size = stash->obj_size;

	if (obj_size == sizeof(uint64_t)) {
		ring_u64_t *ring_u64 = &stash->ring_u64.hdr;

		if (batch)
			return ring_u64_deq_batch(ring_u64, stash->ring_mask, obj, num);
		else
			return ring_u64_deq_multi(ring_u64, stash->ring_mask, obj, num);
	}

	if (obj_size == sizeof(uint32_t)) {
		ring_u32_t *ring_u32 = &stash->ring_u32.hdr;

		if (batch)
			return ring_u32_deq_batch(ring_u32, stash->ring_mask, obj, num);
		else
			return ring_u32_deq_multi(ring_u32, stash->ring_mask, obj, num);
	}

	if (obj_size == sizeof(uint16_t)) {
		uint16_t *u16_ptr = obj;
		ring_u32_t *ring_u32 = &stash->ring_u32.hdr;
		uint32_t u32[num];

		if (batch)
			num_deq = ring_u32_deq_batch(ring_u32, stash->ring_mask, u32, num);
		else
			num_deq = ring_u32_deq_multi(ring_u32, stash->ring_mask, u32, num);

		for (i = 0; i < num_deq; i++)
			u16_ptr[i] = u32[i];

		return num_deq;
	}

	if (obj_size == sizeof(uint8_t)) {
		uint8_t *u8_ptr = obj;
		ring_u32_t *ring_u32 = &stash->ring_u32.hdr;
		uint32_t u32[num];

		if (batch)
			num_deq = ring_u32_deq_batch(ring_u32, stash->ring_mask, u32, num);
		else
			num_deq = ring_u32_deq_multi(ring_u32, stash->ring_mask, u32, num);

		for (i = 0; i < num_deq; i++)
			u8_ptr[i] = u32[i];

		return num_deq;
	}

	return -1;
}

int32_t odp_stash_get(odp_stash_t st, void *obj, int32_t num)
{
	return stash_get(st, obj, num, 0);
}

int32_t odp_stash_get_batch(odp_stash_t st, void *obj, int32_t num)
{
	return stash_get(st, obj, num, 1);
}

int32_t odp_stash_get_u32(odp_stash_t st, uint32_t val[], int32_t num)
{
	stash_t *stash = (stash_t *)(uintptr_t)st;

	if (odp_unlikely(st == ODP_STASH_INVALID))
		return -1;

	_ODP_ASSERT(stash->obj_size == sizeof(uint32_t));

	return ring_u32_deq_multi(&stash->ring_u32.hdr, stash->ring_mask, val,
				  num);
}

int32_t odp_stash_get_u32_batch(odp_stash_t st, uint32_t val[], int32_t num)
{
	stash_t *stash = (stash_t *)(uintptr_t)st;

	if (odp_unlikely(st == ODP_STASH_INVALID))
		return -1;

	_ODP_ASSERT(stash->obj_size == sizeof(uint32_t));

	return ring_u32_deq_batch(&stash->ring_u32.hdr, stash->ring_mask, val, num);
}

int32_t odp_stash_get_u64(odp_stash_t st, uint64_t val[], int32_t num)
{
	stash_t *stash = (stash_t *)(uintptr_t)st;

	if (odp_unlikely(st == ODP_STASH_INVALID))
		return -1;

	_ODP_ASSERT(stash->obj_size == sizeof(uint64_t));

	return ring_u64_deq_multi(&stash->ring_u64.hdr, stash->ring_mask, val,
				  num);
}

int32_t odp_stash_get_u64_batch(odp_stash_t st, uint64_t val[], int32_t num)
{
	stash_t *stash = (stash_t *)(uintptr_t)st;

	if (odp_unlikely(st == ODP_STASH_INVALID))
		return -1;

	_ODP_ASSERT(stash->obj_size == sizeof(uint64_t));

	return ring_u64_deq_batch(&stash->ring_u64.hdr, stash->ring_mask, val, num);
}

int32_t odp_stash_get_ptr(odp_stash_t st, uintptr_t ptr[], int32_t num)
{
	stash_t *stash = (stash_t *)(uintptr_t)st;

	if (odp_unlikely(st == ODP_STASH_INVALID))
		return -1;

	_ODP_ASSERT(stash->obj_size == sizeof(uintptr_t));

	if (sizeof(uintptr_t) == sizeof(uint32_t))
		return ring_u32_deq_multi(&stash->ring_u32.hdr,
					  stash->ring_mask,
					  (uint32_t *)(uintptr_t)ptr, num);
	else if (sizeof(uintptr_t) == sizeof(uint64_t))
		return ring_u64_deq_multi(&stash->ring_u64.hdr,
					  stash->ring_mask,
					  (uint64_t *)(uintptr_t)ptr, num);
	return -1;
}

int32_t odp_stash_get_ptr_batch(odp_stash_t st, uintptr_t ptr[], int32_t num)
{
	stash_t *stash = (stash_t *)(uintptr_t)st;

	if (odp_unlikely(st == ODP_STASH_INVALID))
		return -1;

	_ODP_ASSERT(stash->obj_size == sizeof(uintptr_t));

	if (sizeof(uintptr_t) == sizeof(uint32_t))
		return ring_u32_deq_batch(&stash->ring_u32.hdr, stash->ring_mask,
					  (uint32_t *)(uintptr_t)ptr, num);
	else if (sizeof(uintptr_t) == sizeof(uint64_t))
		return ring_u64_deq_batch(&stash->ring_u64.hdr, stash->ring_mask,
					  (uint64_t *)(uintptr_t)ptr, num);
	return -1;
}

int odp_stash_flush_cache(odp_stash_t st)
{
	if (odp_unlikely(st == ODP_STASH_INVALID))
		return -1;

	return 0;
}

static uint32_t stash_obj_count(stash_t *stash)
{
	ring_u32_t *ring_u32;
	uint32_t obj_size = stash->obj_size;

	if (obj_size == sizeof(uint64_t)) {
		ring_u64_t *ring_u64 = &stash->ring_u64.hdr;

		return ring_u64_len(ring_u64);
	}

	ring_u32 = &stash->ring_u32.hdr;

	return ring_u32_len(ring_u32);
}

void odp_stash_print(odp_stash_t st)
{
	stash_t *stash = (stash_t *)(uintptr_t)st;

	if (st == ODP_STASH_INVALID) {
		_ODP_ERR("Bad stash handle\n");
		return;
	}

	_ODP_PRINT("\nStash info\n");
	_ODP_PRINT("----------\n");
	_ODP_PRINT("  handle          0x%" PRIx64 "\n", odp_stash_to_u64(st));
	_ODP_PRINT("  name            %s\n", stash->name);
	_ODP_PRINT("  index           %i\n", stash->index);
	_ODP_PRINT("  obj size        %u\n", stash->obj_size);
	_ODP_PRINT("  obj count       %u\n", stash_obj_count(stash));
	_ODP_PRINT("  ring size       %u\n", stash->ring_mask + 1);
	_ODP_PRINT("\n");
}

int odp_stash_stats(odp_stash_t st, odp_stash_stats_t *stats)
{
	stash_t *stash = (stash_t *)(uintptr_t)st;

	if (st == ODP_STASH_INVALID) {
		_ODP_ERR("Bad stash handle\n");
		return -1;
	}

	stats->count       = stash_obj_count(stash);
	stats->cache_count = 0;

	return 0;
}
