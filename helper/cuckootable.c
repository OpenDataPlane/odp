/* Copyright (c) 2016-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2016 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <stdio.h>

#include <odp/helper/odph_cuckootable.h>
#include <odp/helper/odph_debug.h>
#include <odp_api.h>

/* More efficient access to a map of single ullong */
#define ULLONG_FOR_EACH_1(IDX, MAP)	\
	for (; MAP && (((IDX) = __builtin_ctzll(MAP)), true); \
		 MAP = (MAP & (MAP - 1)))

/** @magic word, write to the first byte of the memory block
 *   to indicate this block is used by a cuckoo hash table
 */
#define ODPH_CUCKOO_TABLE_MAGIC_WORD 0xDFDFFDFD

/** Number of items per bucket. */
#define HASH_BUCKET_ENTRIES		4

#define NULL_SIGNATURE			0
#define KEY_ALIGNMENT			16

/** Maximum size of hash table that can be created. */
#define HASH_ENTRIES_MAX        1048576

/** @internal signature struct
 *   Structure storing both primary and secondary hashes
 */
struct cuckoo_table_signatures {
	union {
		struct {
			uint32_t current;
			uint32_t alt;
		};
		uint64_t sig;
	};
};

/** @internal kay-value struct
 *   Structure that stores key-value pair
 */
struct cuckoo_table_key_value {
	uint8_t *key;
	uint8_t *value;
};

/** @internal bucket structure
 *  Put the elements with defferent keys but a same signature
 *  into a bucket, and each bucket has at most HASH_BUCKET_ENTRIES
 *  elements.
 */
struct ODP_ALIGNED_CACHE cuckoo_table_bucket {
	struct cuckoo_table_signatures signatures[HASH_BUCKET_ENTRIES];
	/* Includes dummy key index that always contains index 0 */
	odp_buffer_t key_buf[HASH_BUCKET_ENTRIES + 1];
	uint8_t flag[HASH_BUCKET_ENTRIES];
};

/* More efficient access to a map of single ullong */
#define ULLONG_FOR_EACH_1(IDX, MAP)	\
	for (; MAP && (((IDX) = __builtin_ctzll(MAP)), true); \
		 MAP = (MAP & (MAP - 1)))

/** A hash table structure. */
typedef struct ODP_ALIGNED_CACHE {
	/**< for check */
	uint32_t magicword;
	/**< Name of the hash. */
	char name[ODPH_TABLE_NAME_LEN];
	/**< Total table entries. */
	uint32_t entries;
	/**< Number of buckets in table. */
	uint32_t num_buckets;
	/**< Length of hash key. */
	uint32_t key_len;
	/**< Length of value. */
	uint32_t value_len;
	/**< Bitmask for getting bucket index from hash signature. */
	uint32_t bucket_bitmask;
	/**< Queue that stores all free key-value slots*/
	odp_queue_t free_slots;
	/** Table with buckets storing all the hash values and key indexes
	  to the key table*/
	struct cuckoo_table_bucket *buckets;
} odph_cuckoo_table_impl;

/**
 * Aligns input parameter to the next power of 2
 *
 * @param x
 *   The integer value to algin
 *
 * @return
 *   Input parameter aligned to the next power of 2
 */
static inline uint32_t
align32pow2(uint32_t x)
{
	x--;
	x |= x >> 1;
	x |= x >> 2;
	x |= x >> 4;
	x |= x >> 8;
	x |= x >> 16;

	return x + 1;
}

odph_table_t
odph_cuckoo_table_lookup(const char *name)
{
	odph_cuckoo_table_impl *tbl = NULL;
	odp_shm_t shm;

	if (name == NULL || strlen(name) >= ODPH_TABLE_NAME_LEN)
		return NULL;

	shm = odp_shm_lookup(name);
	if (shm != ODP_SHM_INVALID)
		tbl = (odph_cuckoo_table_impl *)odp_shm_addr(shm);
	if (!tbl || tbl->magicword != ODPH_CUCKOO_TABLE_MAGIC_WORD)
		return NULL;

	if (strcmp(tbl->name, name))
		return NULL;

	return (odph_table_t)tbl;
}

odph_table_t
odph_cuckoo_table_create(
		const char *name, uint32_t capacity, uint32_t key_size,
		uint32_t value_size)
{
	odph_cuckoo_table_impl *tbl;
	odp_shm_t shm_tbl;

	odp_pool_t pool;
	odp_pool_param_t param;

	odp_queue_t queue;
	odp_queue_param_t qparam;
	odp_queue_capability_t qcapa;
	odp_pool_capability_t pcapa;

	char pool_name[ODPH_TABLE_NAME_LEN + 3],
		 queue_name[ODPH_TABLE_NAME_LEN + 3];
	unsigned i;
	uint32_t impl_size, kv_entry_size,
			 bucket_num, bucket_size;

	if (odp_queue_capability(&qcapa)) {
		ODPH_DBG("queue capa failed\n");
		return NULL;
	}

	if (qcapa.plain.max_size && qcapa.plain.max_size < capacity) {
		ODPH_DBG("queue max_size too small\n");
		return NULL;
	}

	if (odp_pool_capability(&pcapa)) {
		ODPH_DBG("pool capa failed\n");
		return NULL;
	}

	if (pcapa.buf.max_num && pcapa.buf.max_num < capacity) {
		ODPH_DBG("pool max_num too small\n");
		return NULL;
	}

	/* Check for valid parameters */
	if (
	    (capacity > HASH_ENTRIES_MAX) ||
	    (capacity < HASH_BUCKET_ENTRIES) ||
	    (key_size == 0) ||
	    (strlen(name) == 0)) {
		ODPH_DBG("invalid parameters\n");
		return NULL;
	}

	/* Guarantee there's no existing */
	tbl = (odph_cuckoo_table_impl *)(void *)odph_cuckoo_table_lookup(name);
	if (tbl != NULL) {
		ODPH_DBG("cuckoo hash table %s already exists\n", name);
		return NULL;
	}

	/* Calculate the sizes of different parts of cuckoo hash table */
	impl_size = sizeof(odph_cuckoo_table_impl);
	kv_entry_size = sizeof(struct cuckoo_table_key_value)
					+ key_size + value_size;

	bucket_num = align32pow2(capacity) / HASH_BUCKET_ENTRIES;
	bucket_size = bucket_num * sizeof(struct cuckoo_table_bucket);

	shm_tbl = odp_shm_reserve(
				name, impl_size + bucket_size,
				ODP_CACHE_LINE_SIZE, ODP_SHM_SW_ONLY);

	if (shm_tbl == ODP_SHM_INVALID) {
		ODPH_DBG(
			"shm allocation failed for odph_cuckoo_table_impl %s\n",
			name);
		return NULL;
	}

	tbl = (odph_cuckoo_table_impl *)odp_shm_addr(shm_tbl);
	memset(tbl, 0, impl_size + bucket_size);

	/* header of this mem block is the table impl struct,
	 * then the bucket pool.
	 */
	tbl->buckets = (void *)((char *)tbl + impl_size);

	/* initialize key-value buffer pool */
	snprintf(pool_name, sizeof(pool_name), "kv_%s", name);
	pool = odp_pool_lookup(pool_name);

	if (pool != ODP_POOL_INVALID)
		odp_pool_destroy(pool);

	odp_pool_param_init(&param);
	param.type = ODP_POOL_BUFFER;
	param.buf.size = kv_entry_size;
	param.buf.align = ODP_CACHE_LINE_SIZE;
	param.buf.num = capacity;

	pool = odp_pool_create(pool_name, &param);

	if (pool == ODP_POOL_INVALID) {
		ODPH_DBG("failed to create key-value pool\n");
		odp_shm_free(shm_tbl);
		return NULL;
	}

	/* initialize free_slots queue */
	odp_queue_param_init(&qparam);
	qparam.type = ODP_QUEUE_TYPE_PLAIN;
	qparam.size = capacity;

	snprintf(queue_name, sizeof(queue_name), "fs_%s", name);
	queue = odp_queue_create(queue_name, &qparam);
	if (queue == ODP_QUEUE_INVALID) {
		ODPH_DBG("failed to create free_slots queue\n");
		odp_pool_destroy(pool);
		odp_shm_free(shm_tbl);
		return NULL;
	}

	/* Setup hash context */
	snprintf(tbl->name, sizeof(tbl->name), "%s", name);
	tbl->magicword = ODPH_CUCKOO_TABLE_MAGIC_WORD;
	tbl->entries = capacity;
	tbl->key_len = key_size;
	tbl->value_len = value_size;
	tbl->num_buckets = bucket_num;
	tbl->bucket_bitmask = bucket_num - 1;
	tbl->free_slots = queue;

	/* generate all free buffers, and put into queue */
	for (i = 0; i < capacity; i++) {
		odp_event_t ev = odp_buffer_to_event(
				odp_buffer_alloc(pool));
		if (ev == ODP_EVENT_INVALID) {
			ODPH_DBG("failed to generate free slots\n");
			odph_cuckoo_table_destroy((odph_table_t)tbl);
			return NULL;
		}

		if (odp_queue_enq(queue, ev) < 0) {
			ODPH_DBG("failed to enqueue free slots\n");
			odph_cuckoo_table_destroy((odph_table_t)tbl);
			return NULL;
		}
	}

	return (odph_table_t)tbl;
}

int
odph_cuckoo_table_destroy(odph_table_t tbl)
{
	int ret;
	odph_cuckoo_table_impl *impl = NULL;
	char pool_name[ODPH_TABLE_NAME_LEN + 3];
	odp_event_t ev;
	odp_shm_t shm;
	odp_pool_t pool;
	uint32_t i, j;

	if (tbl == NULL)
		return -1;

	impl = (odph_cuckoo_table_impl *)(void *)tbl;

	/* check magic word */
	if (impl->magicword != ODPH_CUCKOO_TABLE_MAGIC_WORD) {
		ODPH_DBG("wrong magicword for cuckoo table\n");
		return -1;
	}

	/* free all used buffers*/
	for (i = 0; i < impl->num_buckets; i++) {
		for (j = 0; j < HASH_BUCKET_ENTRIES; j++) {
			if (impl->buckets[i].signatures[j].current
					!= NULL_SIGNATURE)
				odp_buffer_free(impl->buckets[i].key_buf[j]);
		}
	}

	/* free all free buffers */
	while ((ev = odp_queue_deq(impl->free_slots))
			!= ODP_EVENT_INVALID) {
		odp_buffer_free(odp_buffer_from_event(ev));
	}

	/* destroy free_slots queue */
	ret = odp_queue_destroy(impl->free_slots);
	if (ret < 0)
		ODPH_DBG("failed to destroy free_slots queue\n");

	/* destroy key-value pool */
	snprintf(pool_name, sizeof(pool_name), "kv_%s", impl->name);
	pool = odp_pool_lookup(pool_name);
	if (pool == ODP_POOL_INVALID) {
		ODPH_DBG("invalid pool\n");
		return -1;
	}

	ret = odp_pool_destroy(pool);
	if (ret != 0) {
		ODPH_DBG("failed to destroy key-value buffer pool\n");
		return -1;
	}

	/* free impl */
	shm = odp_shm_lookup(impl->name);
	if (shm == ODP_SHM_INVALID) {
		ODPH_DBG("unable look up shm\n");
		return -1;
	}

	return odp_shm_free(shm);
}

static uint32_t hash(const odph_cuckoo_table_impl *h, const void *key)
{
	/* calc hash result by key */
	return odp_hash_crc32c(key, h->key_len, 0);
}

/* Calc the secondary hash value from the primary hash value of a given key */
static inline uint32_t
hash_secondary(const uint32_t primary_hash)
{
	static const unsigned all_bits_shift = 12;
	static const unsigned alt_bits_xor = 0x5bd1e995;

	uint32_t tag = primary_hash >> all_bits_shift;

	return (primary_hash ^ ((tag + 1) * alt_bits_xor));
}

/* Search for an entry that can be pushed to its alternative location */
static inline int
make_space_bucket(
	const odph_cuckoo_table_impl *impl,
	struct cuckoo_table_bucket *bkt)
{
	unsigned i, j;
	int ret;
	uint32_t next_bucket_idx;
	struct cuckoo_table_bucket *next_bkt[HASH_BUCKET_ENTRIES];

	/*
	 * Push existing item (search for bucket with space in
	 * alternative locations) to its alternative location
	 */
	for (i = 0; i < HASH_BUCKET_ENTRIES; i++) {
		/* Search for space in alternative locations */
		next_bucket_idx = bkt->signatures[i].alt & impl->bucket_bitmask;
		next_bkt[i] = &impl->buckets[next_bucket_idx];
		for (j = 0; j < HASH_BUCKET_ENTRIES; j++) {
			if (next_bkt[i]->signatures[j].sig == NULL_SIGNATURE)
				break;
		}

		if (j != HASH_BUCKET_ENTRIES)
			break;
	}

	/* Alternative location has spare room (end of recursive function) */
	if (i != HASH_BUCKET_ENTRIES) {
		next_bkt[i]->signatures[j].alt = bkt->signatures[i].current;
		next_bkt[i]->signatures[j].current = bkt->signatures[i].alt;
		next_bkt[i]->key_buf[j] = bkt->key_buf[i];
		return i;
	}

	/* Pick entry that has not been pushed yet */
	for (i = 0; i < HASH_BUCKET_ENTRIES; i++)
		if (bkt->flag[i] == 0)
			break;

	/* All entries have been pushed, so entry cannot be added */
	if (i == HASH_BUCKET_ENTRIES)
		return -ENOSPC;

	/* Set flag to indicate that this entry is going to be pushed */
	bkt->flag[i] = 1;
	/* Need room in alternative bucket to insert the pushed entry */
	ret = make_space_bucket(impl, next_bkt[i]);
	/*
	 * After recursive function.
	 * Clear flags and insert the pushed entry
	 * in its alternative location if successful,
	 * or return error
	 */
	bkt->flag[i] = 0;
	if (ret >= 0) {
		next_bkt[i]->signatures[ret].alt = bkt->signatures[i].current;
		next_bkt[i]->signatures[ret].current = bkt->signatures[i].alt;
		next_bkt[i]->key_buf[ret] = bkt->key_buf[i];
		return i;
	}

	return ret;
}

static inline int32_t
cuckoo_table_add_key_with_hash(
	const odph_cuckoo_table_impl *h, const void *key,
	uint32_t sig, void *data)
{
	uint32_t alt_hash;
	uint32_t prim_bucket_idx, sec_bucket_idx;
	unsigned i;
	struct cuckoo_table_bucket *prim_bkt, *sec_bkt;
	struct cuckoo_table_key_value *new_kv, *kv;

	odp_buffer_t new_buf;
	int ret;

	prim_bucket_idx = sig & h->bucket_bitmask;
	prim_bkt = &h->buckets[prim_bucket_idx];
	__builtin_prefetch((const void *)(uintptr_t)prim_bkt, 0, 3);

	alt_hash = hash_secondary(sig);
	sec_bucket_idx = alt_hash & h->bucket_bitmask;
	sec_bkt = &h->buckets[sec_bucket_idx];
	__builtin_prefetch((const void *)(uintptr_t)sec_bkt, 0, 3);

	/* Get a new slot for storing the new key */
	new_buf = odp_buffer_from_event(odp_queue_deq(h->free_slots));
	if (new_buf == ODP_BUFFER_INVALID)
		return -ENOSPC;

	/* Check if key is already inserted in primary location */
	for (i = 0; i < HASH_BUCKET_ENTRIES; i++) {
		if (
			prim_bkt->signatures[i].current == sig &&
			prim_bkt->signatures[i].alt == alt_hash)  {
			kv = (struct cuckoo_table_key_value *)odp_buffer_addr(
					prim_bkt->key_buf[i]);
			if (memcmp(key, kv->key, h->key_len) == 0) {
				odp_queue_enq(
						h->free_slots,
						odp_buffer_to_event(new_buf));
				/* Update data */
				if (kv->value != NULL)
					memcpy(kv->value, data, h->value_len);

				/* Return bucket index */
				return prim_bucket_idx;
			}
		}
	}

	/* Check if key is already inserted in secondary location */
	for (i = 0; i < HASH_BUCKET_ENTRIES; i++) {
		if (
			sec_bkt->signatures[i].alt == sig &&
			sec_bkt->signatures[i].current == alt_hash)  {
			kv = (struct cuckoo_table_key_value *)odp_buffer_addr(
					sec_bkt->key_buf[i]);
			if (memcmp(key, kv->key, h->key_len) == 0) {
				odp_queue_enq(
						h->free_slots,
						odp_buffer_to_event(new_buf));
				/* Update data */
				if (kv->value != NULL)
					memcpy(kv->value, data, h->value_len);

				/* Return bucket index */
				return sec_bucket_idx;
			}
		}
	}

	new_kv = (struct cuckoo_table_key_value *)odp_buffer_addr(new_buf);
	__builtin_prefetch((const void *)(uintptr_t)new_kv, 0, 3);

	/* Copy key and value.
	 * key-value mem block : struct cuckoo_table_key_value
	 *		+ key (key_len) + value (value_len)
	 */
	new_kv->key = (uint8_t *)new_kv
					+ sizeof(struct cuckoo_table_key_value);
	memcpy(new_kv->key, key, h->key_len);

	if (h->value_len > 0) {
		new_kv->value = new_kv->key + h->key_len;
		memcpy(new_kv->value, data, h->value_len);
	} else {
		new_kv->value = NULL;
	}

	/* Insert new entry is there is room in the primary bucket */
	for (i = 0; i < HASH_BUCKET_ENTRIES; i++) {
		/* Check if slot is available */
		if (odp_likely(prim_bkt->signatures[i].sig == NULL_SIGNATURE)) {
			prim_bkt->signatures[i].current = sig;
			prim_bkt->signatures[i].alt = alt_hash;
			prim_bkt->key_buf[i] = new_buf;
			return prim_bucket_idx;
		}
	}

	/* Primary bucket is full, so we need to make space for new entry */
	ret = make_space_bucket(h, prim_bkt);

	/*
	 * After recursive function.
	 * Insert the new entry in the position of the pushed entry
	 * if successful or return error and
	 * store the new slot back in the pool
	 */
	if (ret >= 0) {
		prim_bkt->signatures[ret].current = sig;
		prim_bkt->signatures[ret].alt = alt_hash;
		prim_bkt->key_buf[ret] = new_buf;
		return prim_bucket_idx;
	}

	/* Error in addition, store new slot back in the free_slots */
	odp_queue_enq(h->free_slots, odp_buffer_to_event(new_buf));
	return ret;
}

int
odph_cuckoo_table_put_value(odph_table_t tbl, void *key, void *value)
{
	odph_cuckoo_table_impl *impl;
	int ret;

	if ((tbl == NULL) || (key == NULL))
		return -EINVAL;

	impl = (odph_cuckoo_table_impl *)(void *)tbl;
	ret = cuckoo_table_add_key_with_hash(
			impl, key, hash(impl, key), value);

	if (ret < 0)
		return -1;

	return 0;
}

static inline int32_t
cuckoo_table_lookup_with_hash(
	const odph_cuckoo_table_impl *h, const void *key,
	uint32_t sig, void **data_ptr)
{
	uint32_t bucket_idx;
	uint32_t alt_hash;
	unsigned i;
	struct cuckoo_table_bucket *bkt;
	struct cuckoo_table_key_value *kv;

	bucket_idx = sig & h->bucket_bitmask;
	bkt = &h->buckets[bucket_idx];

	/* Check if key is in primary location */
	for (i = 0; i < HASH_BUCKET_ENTRIES; i++) {
		if (
			bkt->signatures[i].current == sig &&
			bkt->signatures[i].sig != NULL_SIGNATURE) {
			kv = (struct cuckoo_table_key_value *)odp_buffer_addr(
					bkt->key_buf[i]);
			if (memcmp(key, kv->key, h->key_len) == 0) {
				if (data_ptr != NULL)
					*data_ptr = kv->value;
				/*
				 * Return index where key is stored,
				 * subtracting the first dummy index
				 */
				return bucket_idx;
			}
		}
	}

	/* Calculate secondary hash */
	alt_hash = hash_secondary(sig);
	bucket_idx = alt_hash & h->bucket_bitmask;
	bkt = &h->buckets[bucket_idx];

	/* Check if key is in secondary location */
	for (i = 0; i < HASH_BUCKET_ENTRIES; i++) {
		if (
			bkt->signatures[i].current == alt_hash &&
			bkt->signatures[i].alt == sig) {
			kv = (struct cuckoo_table_key_value *)odp_buffer_addr(
					bkt->key_buf[i]);
			if (memcmp(key, kv->key, h->key_len) == 0) {
				if (data_ptr != NULL)
					*data_ptr = kv->value;
				/*
				 * Return index where key is stored,
				 * subtracting the first dummy index
				 */
				return bucket_idx;
			}
		}
	}

	return -ENOENT;
}

int odph_cuckoo_table_get_value(odph_table_t tbl, void *key,
				void *buffer, uint32_t buffer_size ODP_UNUSED)
{
	odph_cuckoo_table_impl *impl = (odph_cuckoo_table_impl *)(void *)tbl;
	void *tmp = NULL;
	int ret;

	if ((tbl == NULL) || (key == NULL))
		return -EINVAL;

	ret = cuckoo_table_lookup_with_hash(impl, key, hash(impl, key), &tmp);

	if (ret < 0)
		return -1;

	if (impl->value_len > 0)
		memcpy(buffer, tmp, impl->value_len);

	return 0;
}

static inline int32_t
cuckoo_table_del_key_with_hash(
	const odph_cuckoo_table_impl *h,
	const void *key, uint32_t sig)
{
	uint32_t bucket_idx;
	uint32_t alt_hash;
	unsigned i;
	struct cuckoo_table_bucket *bkt;
	struct cuckoo_table_key_value *kv;

	bucket_idx = sig & h->bucket_bitmask;
	bkt = &h->buckets[bucket_idx];

	/* Check if key is in primary location */
	for (i = 0; i < HASH_BUCKET_ENTRIES; i++) {
		if (
			bkt->signatures[i].current == sig &&
			bkt->signatures[i].sig != NULL_SIGNATURE) {
			kv = (struct cuckoo_table_key_value *)odp_buffer_addr(
					bkt->key_buf[i]);
			if (memcmp(key, kv->key, h->key_len) == 0) {
				bkt->signatures[i].sig = NULL_SIGNATURE;
				odp_queue_enq(
						h->free_slots,
						odp_buffer_to_event(
							bkt->key_buf[i]));
				return bucket_idx;
			}
		}
	}

	/* Calculate secondary hash */
	alt_hash = hash_secondary(sig);
	bucket_idx = alt_hash & h->bucket_bitmask;
	bkt = &h->buckets[bucket_idx];

	/* Check if key is in secondary location */
	for (i = 0; i < HASH_BUCKET_ENTRIES; i++) {
		if (
			bkt->signatures[i].current == alt_hash &&
			bkt->signatures[i].sig != NULL_SIGNATURE) {
			kv = (struct cuckoo_table_key_value *)odp_buffer_addr(
					bkt->key_buf[i]);
			if (memcmp(key, kv->key, h->key_len) == 0) {
				bkt->signatures[i].sig = NULL_SIGNATURE;
				odp_queue_enq(
						h->free_slots,
						odp_buffer_to_event(
							bkt->key_buf[i]));
				return bucket_idx;
			}
		}
	}

	return -ENOENT;
}

int
odph_cuckoo_table_remove_value(odph_table_t tbl, void *key)
{
	odph_cuckoo_table_impl *impl = (void *)tbl;
	int ret;

	if ((tbl == NULL) || (key == NULL))
		return -EINVAL;

	ret = cuckoo_table_del_key_with_hash(impl, key, hash(impl, key));
	if (ret < 0)
		return -1;

	return 0;
}

odph_table_ops_t odph_cuckoo_table_ops = {
	odph_cuckoo_table_create,
	odph_cuckoo_table_lookup,
	odph_cuckoo_table_destroy,
	odph_cuckoo_table_put_value,
	odph_cuckoo_table_get_value,
	odph_cuckoo_table_remove_value
};
