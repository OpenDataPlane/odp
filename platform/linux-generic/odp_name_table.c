 /* Copyright 2015 EZchip Semiconductor Ltd. All Rights Reserved.

 * Copyright (c) 2015-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdint.h>
#include <string.h>
#include <malloc.h>
#include <stdlib.h>
#include <odp_name_table_internal.h>
#include <odp_debug_internal.h>
#include <odp_macros_internal.h>

 /* The following constants define some tunable parameters of this module.
 * They are set to fairly reasonable values (perhaps somewhat biased toward
 * handling a number of names in the range of one thousand to one million).
 * Change these values ONLY if your needs are outside of this range AND you
 * have a complete understanding of how this code works.
 *
 * The primary hash table size should be a power of 2 in the range 256 to 64K.
 * The size of the secondary hash tables should be a power of 2 in the range
 * 64 to 256.
 */
#define PRIMARY_HASH_TBL_SIZE    (16 * 1024)
#define SECONDARY_HASH_TBL_SIZE  128

 /* The following thresholds set the number of primary table hash collisions
 * before either replacing the name_table entry linked list with a secondary
 * hash table (in the case of MAX_PRIMARY_LIST_SIZE) when adding OR
 * replacing a secondary hash table with a linked list (MIN_SECONDARY_TBL_SIZE)
 * when deleting.  It is important to make sure these values are sufficiently
 * different in value so as to exhibit meaningful hysteresis.
 */
#define MAX_PRIMARY_LIST_SIZE   12
#define MAX_SECONDARY_LIST_SIZE 12
#define MIN_SECONDARY_TBL_SIZE  4

 /* Still to be documented.*/
#define INITIAL_NAME_TBL_SIZE   1024

 /* The number of name tables should not be changed. */
#define NUM_NAME_TBLS  16

#define SECONDARY_HASH_HISTO_PRINT  1
#define SECONDARY_HASH_DUMP         0

typedef struct name_tbl_entry_s name_tbl_entry_t;

 /* It is important for most platforms that the following struct fit within
 * one cacheline.
 */
struct ODP_ALIGNED_CACHE name_tbl_entry_s {
	name_tbl_entry_t *next_entry;
	uint64_t          user_data;
	_odp_int_name_t   name_tbl_id;
	uint32_t          hash_value;
	uint8_t           name_kind;
	uint8_t           name_len;
	char              name[_ODP_INT_NAME_LEN + 1];
};

typedef struct ODP_ALIGNED_CACHE {
	uint32_t          num_allocd;
	uint32_t          num_used;
	uint32_t          num_added_to_free_list;
	uint32_t          num_avail_to_add;
	uint32_t          base_id;
	name_tbl_entry_t *free_list_head;
	name_tbl_entry_t  entries[0];
} name_tbl_t;

typedef struct {
	name_tbl_t *tbls[NUM_NAME_TBLS];
	uint64_t    avail_space_bit_mask;
	uint64_t    num_adds;
	uint64_t    num_deletes;
	uint32_t    current_num_names;
	uint8_t     num_name_tbls;
} name_tbls_t;

 /* A hash table entry is LOGICALLY either empty, a pointer to a 64-byte
 * aligned name_tbl_entry_t OR a pointer to a 64-byte aligned secondary hash
 * table.  Since the bottom 6-bits of this value are not needed to hold the
 * address, these 6 bits are used to indicate the what type of object this
 * address refers to AND in one case the maximum number of hash "collisions"
 * at this level.  Specifically, if the entire value is 0 then this entry is
 * empty, else if the bottom 6 bits are 0, then this hash_tbl_entry_t value is
 * a pointer to a secondary hash table.  Otherwise if the bottom 6 bits are
 * NOT zero then this values points to a (linked list of) name_table_entry_t
 * records AND the bottom 6 bits are the length of this list.
 */
typedef uint64_t hash_tbl_entry_t;

typedef struct {
	hash_tbl_entry_t hash_entries[SECONDARY_HASH_TBL_SIZE];
} secondary_hash_tbl_t;

typedef struct {
	hash_tbl_entry_t hash_entries[PRIMARY_HASH_TBL_SIZE];
	uint32_t         hash_collisions[PRIMARY_HASH_TBL_SIZE];
	uint32_t         num_secondary_tbls[2];
} primary_hash_tbl_t;

static uint8_t            name_tbls_initialized;
static name_tbls_t        name_tbls;
static odp_ticketlock_t   name_table_lock;
static primary_hash_tbl_t name_hash_tbl;

static void *aligned_malloc(uint32_t length, uint32_t align)
{
	uintptr_t malloc_addr, mem_addr, alignment, total_length;
	uint32_t  pad_len, *pad_len_ptr;

       /* This code assumes that malloc always uses at least 4-byte
	* alignment.
	*/
	alignment    = (uintptr_t)align;
	total_length = ((uintptr_t)length) + alignment;
	malloc_addr  = (uintptr_t)malloc(total_length);
	mem_addr     = (malloc_addr + alignment) & ~(alignment - 1);
	pad_len      = (uint32_t)(mem_addr - malloc_addr);
	pad_len_ptr  = (uint32_t *)(mem_addr - 4);
	*pad_len_ptr = pad_len;
	return (void *)mem_addr;
}

static void aligned_free(void *mem_ptr)
{
	uintptr_t mem_addr, malloc_addr;
	uint32_t *pad_len_ptr;

	mem_addr    = (uintptr_t)mem_ptr;
	pad_len_ptr = (uint32_t *)(mem_addr - 4);
	malloc_addr = mem_addr - *pad_len_ptr;
	free((void *)malloc_addr);
}

static uint32_t hash_name_and_kind(const char *name, uint8_t name_kind)
{
	return odp_hash_crc32c(name, strlen(name), name_kind);
}

static uint32_t linked_list_len(name_tbl_entry_t *name_tbl_entry)
{
	uint32_t count;

	count = 0;
	while (name_tbl_entry) {
		count++;
		name_tbl_entry = name_tbl_entry->next_entry;
	}

	return count;
}

static secondary_hash_tbl_t *secondary_hash_tbl_alloc(void)
{
	secondary_hash_tbl_t *secondary_hash_tbl;

	secondary_hash_tbl = aligned_malloc(sizeof(secondary_hash_tbl_t),
					    ODP_CACHE_LINE_SIZE);
	memset(secondary_hash_tbl, 0, sizeof(secondary_hash_tbl_t));
	return secondary_hash_tbl;
}

static void secondary_hash_tbl_free(secondary_hash_tbl_t *secondary_hash_tbl)
{
	aligned_free(secondary_hash_tbl);
}

static void check_secondary_hash(secondary_hash_tbl_t *secondary_hash_tbl)
{
	hash_tbl_entry_t hash_tbl_entry, hash_tbl_entry2;
	uint64_t         tbn1, tbn2;
	uint32_t         idx, idx2;

	for (idx = 0; idx < SECONDARY_HASH_TBL_SIZE; idx++) {
		hash_tbl_entry = secondary_hash_tbl->hash_entries[idx];
		tbn1           = hash_tbl_entry & ~0x3F;

		if (hash_tbl_entry != 0) {
			if ((hash_tbl_entry >> 48) == 0x7FFF)
				;
			else if ((hash_tbl_entry >> 48) == 0)
				;
			else
				abort();

			for (idx2 = 0; idx2 < idx; idx2++) {
				hash_tbl_entry2 =
					secondary_hash_tbl->hash_entries[idx2];
				if (hash_tbl_entry2 != 0) {
					tbn2 = hash_tbl_entry2 & ~0x3F;
					if (tbn1 == tbn2)
						abort();
				}
			}
		}
	}
}

static void secondary_hash_dump(secondary_hash_tbl_t *secondary_hash_tbl)
{
	name_tbl_entry_t *name_tbl_entry;
	hash_tbl_entry_t  hash_tbl_entry;
	uint32_t          count, idx, entry_cnt, list_cnt;

	count = 0;
	for (idx = 0; idx < SECONDARY_HASH_TBL_SIZE; idx++) {
		hash_tbl_entry = secondary_hash_tbl->hash_entries[idx];
		if (hash_tbl_entry != 0) {
			if ((hash_tbl_entry & 0x3F) != 0) {
				name_tbl_entry = (name_tbl_entry_t *)
				  (uintptr_t)(hash_tbl_entry & ~0x3F);
				entry_cnt = hash_tbl_entry & 0x3F;
				list_cnt  = linked_list_len(name_tbl_entry);
				if (entry_cnt != list_cnt)
					ODP_DBG("%s idx=%u entry_cnt=%u "
						"list_cnt=%u\n",
						__func__,
						idx, entry_cnt, list_cnt);

				count += entry_cnt;
			} else {
				ODP_DBG("%s inner secondary tbl\n",
					__func__);
			}
		}
	}

	ODP_DBG("%s count=%u\n", __func__, count);
}

static uint32_t name_tbl_free_list_add(name_tbl_t *name_tbl,
				       uint32_t    num_to_add)
{
	uint32_t first_idx, name_tbl_id, entry_idx, num_added, cnt;

	first_idx   = name_tbl->num_added_to_free_list;
	name_tbl_id = name_tbl->base_id | first_idx;
	entry_idx   = first_idx;

	num_added = MIN(num_to_add, name_tbl->num_avail_to_add);
	if (num_added == 0)
		return 0;

	for (cnt = 1; cnt < num_added; cnt++) {
		name_tbl->entries[entry_idx].name_tbl_id = name_tbl_id;
		name_tbl->entries[entry_idx].next_entry  =
			&name_tbl->entries[entry_idx + 1];
		name_tbl_id++;
		entry_idx++;
	}

	name_tbl->entries[entry_idx].name_tbl_id = name_tbl_id;
	name_tbl->entries[entry_idx].next_entry  = name_tbl->free_list_head;

	name_tbl->free_list_head          = &name_tbl->entries[first_idx];
	name_tbl->num_added_to_free_list += num_added;
	name_tbl->num_avail_to_add       -= num_added;
	return num_added;
}

static name_tbl_t *name_tbl_alloc(uint32_t name_tbls_idx, uint32_t num_entries)
{
	name_tbl_t *name_tbl;
	uint32_t    name_tbl_size;

	name_tbl_size = sizeof(name_tbl_t) +
		num_entries * sizeof(name_tbl_entry_t);
	name_tbl      = aligned_malloc(name_tbl_size, ODP_CACHE_LINE_SIZE);
	memset(name_tbl, 0, name_tbl_size);

	name_tbl->num_allocd             = num_entries;
	name_tbl->num_used               = 0;
	name_tbl->num_added_to_free_list = 0;
	name_tbl->num_avail_to_add       = num_entries;
	name_tbl->free_list_head         = NULL;
	name_tbl->base_id                = (name_tbls_idx + 1) << 26;
	return name_tbl;
}

static int new_name_tbl_add(void)
{
	name_tbl_t *new_name_tbl;
	uint32_t    name_tbls_idx, num_entries;

	if (NUM_NAME_TBLS <= name_tbls.num_name_tbls)
		return -1;

	name_tbls_idx = name_tbls.num_name_tbls;
	num_entries   = INITIAL_NAME_TBL_SIZE << name_tbls_idx;
	new_name_tbl  = name_tbl_alloc(name_tbls_idx, num_entries);
	name_tbl_free_list_add(new_name_tbl, MIN(num_entries, UINT32_C(256)));

	name_tbls.tbls[name_tbls_idx]   = new_name_tbl;
	name_tbls.avail_space_bit_mask |= 1 << name_tbls_idx;
	name_tbls.num_name_tbls++;
	return 0;
}

static name_tbl_entry_t *name_tbl_entry_alloc(void)
{
	name_tbl_entry_t *name_tbl_entry;
	name_tbl_t       *name_tbl;
	uint32_t          name_tbls_idx, num_added;
	int               rc;

	/* If avail_space_bit_mask == 0 then we need to make a new name_tbl. */
	if (name_tbls.avail_space_bit_mask == 0) {
		rc = new_name_tbl_add();
		if (rc < 0)
			return NULL;
	}

	/* Find first bit set in avail_space_bit_mask. */
	name_tbls_idx = __builtin_ctzl(name_tbls.avail_space_bit_mask);
	name_tbl      = name_tbls.tbls[name_tbls_idx];

	name_tbl_entry = name_tbl->free_list_head;
	name_tbl->free_list_head = name_tbl_entry->next_entry;
	name_tbl->num_used++;

	if (!name_tbl->free_list_head) {
		num_added = name_tbl_free_list_add(name_tbl, 256);
		if (num_added == 0)
			name_tbls.avail_space_bit_mask ^= 1 << name_tbls_idx;
	}

	return name_tbl_entry;
}

static name_tbl_entry_t *name_tbl_id_parse(_odp_int_name_t name_tbl_id,
					   name_tbl_t    **name_tbl_ptr)
{
	name_tbl_t *name_tbl;
	uint32_t    name_tbls_idx, name_tbl_idx;

	/* Convert the name_tbl_id into a name_tbls_idx and name_tbl_idx */
	if (name_tbl_id == ODP_INVALID_NAME)
		return NULL;

	name_tbls_idx = (((uint32_t)name_tbl_id) >> 26) - 1;
	name_tbl_idx  = ((uint32_t)name_tbl_id) & 0x03FFFFFF;
	if (name_tbls.num_name_tbls < name_tbls_idx)
		return NULL;

	name_tbl = name_tbls.tbls[name_tbls_idx];
	if (!name_tbl)
		return NULL;

	if (name_tbl->num_used < name_tbl_idx)
		return NULL;

	if (name_tbl_ptr)
		*name_tbl_ptr = name_tbl;

	return &name_tbl->entries[name_tbl_idx];
}

static void name_tbl_entry_free(name_tbl_entry_t *name_tbl_entry)
{
	name_tbl_entry_t *entry;
	_odp_int_name_t   name_tbl_id;
	name_tbl_t       *name_tbl;

	name_tbl_id = name_tbl_entry->name_tbl_id;
	entry       = name_tbl_id_parse(name_tbl_id, &name_tbl);
	if (!entry)
		return;

	memset(name_tbl_entry, 0, sizeof(name_tbl_entry_t));
	name_tbl_entry->next_entry = name_tbl->free_list_head;
	name_tbl->free_list_head   = name_tbl_entry;
}

static hash_tbl_entry_t make_hash_tbl_entry(name_tbl_entry_t *name_tbl_entry,
					    uint32_t          entry_cnt)
{
	hash_tbl_entry_t hash_tbl_entry;
	uint32_t         new_entry_cnt;

	new_entry_cnt   = MIN(entry_cnt + 1, UINT32_C(0x3F));
	hash_tbl_entry  = (hash_tbl_entry_t)(uintptr_t)name_tbl_entry;
	hash_tbl_entry &= ~0x3F;
	hash_tbl_entry |= new_entry_cnt;
	return hash_tbl_entry;
}

static name_tbl_entry_t *name_hash_tbl_lookup(uint32_t hash_value)
{
	secondary_hash_tbl_t *secondary_hash;
	hash_tbl_entry_t      hash_tbl_entry;
	uint32_t              hash_idx;

	hash_idx       = hash_value & (PRIMARY_HASH_TBL_SIZE - 1);
	hash_tbl_entry = name_hash_tbl.hash_entries[hash_idx];
	if (hash_tbl_entry == 0)
		return NULL;
	else if ((hash_tbl_entry & 0x3F) != 0)
		return (name_tbl_entry_t *)(uintptr_t)(hash_tbl_entry & ~0x3F);

       /* This hash_tbl_entry references a secondary hash table, so get
	* some more hash_value bits and index that table.
	*/
	hash_idx       = (hash_value >> 16) & (SECONDARY_HASH_TBL_SIZE - 1);
	secondary_hash = (secondary_hash_tbl_t *)(uintptr_t)hash_tbl_entry;
	hash_tbl_entry = secondary_hash->hash_entries[hash_idx];
	if (hash_tbl_entry == 0)
		return NULL;
	else if ((hash_tbl_entry & 0x3F) != 0)
		return (name_tbl_entry_t *)(uintptr_t)(hash_tbl_entry & ~0x3F);

       /* Yet again, this hash_tbl_entry references a secondary hash table,
	* so get some more hash_value bits and index that table.  We only
	* allow two secondary tables in the path, so if this hash_tbl_entry
	* doesn't point to a name_tbl_entry then we signal failure by
	* returning NULL.
	*/
	hash_idx       = (hash_value >> 24) & (SECONDARY_HASH_TBL_SIZE - 1);
	secondary_hash = (secondary_hash_tbl_t *)(uintptr_t)hash_tbl_entry;
	hash_tbl_entry = secondary_hash->hash_entries[hash_idx];
	if (hash_tbl_entry == 0)
		return NULL;
	else if ((hash_tbl_entry & 0x3F) != 0)
		return (name_tbl_entry_t *)(uintptr_t)(hash_tbl_entry & ~0x3F);

	return NULL;
}

static name_tbl_entry_t *internal_name_lookup(const char *name,
					      uint8_t     name_kind)
{
	name_tbl_entry_t *name_tbl_entry;
	uint32_t          hash_value, name_len;

	hash_value = hash_name_and_kind(name, name_kind);
	name_len   = strlen(name);

	name_tbl_entry = name_hash_tbl_lookup(hash_value);
	while (name_tbl_entry) {
		if ((name_tbl_entry->name_kind == name_kind)   &&
		    (name_tbl_entry->name_len  == name_len)    &&
		    (memcmp(name_tbl_entry->name, name, name_len) == 0))
			return name_tbl_entry;

		name_tbl_entry = name_tbl_entry->next_entry;
	}

	return NULL;
}

static hash_tbl_entry_t secondary_hash_add(name_tbl_entry_t *name_tbl_entry,
					   uint32_t level,
					   uint32_t hash_shift)
{
	secondary_hash_tbl_t *secondary_hash;
	name_tbl_entry_t     *next_entry, *first_entry;
	hash_tbl_entry_t      hash_tbl_entry, new_hash_tbl_entry;
	uint32_t              shifted_hash_value, hash_idx, entry_cnt;

	secondary_hash = secondary_hash_tbl_alloc();
	name_hash_tbl.num_secondary_tbls[level]++;
	while (name_tbl_entry) {
		next_entry         = name_tbl_entry->next_entry;
		shifted_hash_value = name_tbl_entry->hash_value >> hash_shift;
		hash_idx           = shifted_hash_value &
			(SECONDARY_HASH_TBL_SIZE - 1);

		hash_tbl_entry = secondary_hash->hash_entries[hash_idx];
		entry_cnt      = hash_tbl_entry & 0x3F;
		first_entry    =
			(name_tbl_entry_t *)(uintptr_t)(hash_tbl_entry & ~0x3F);

		name_tbl_entry->next_entry = first_entry;
		new_hash_tbl_entry =
			make_hash_tbl_entry(name_tbl_entry, entry_cnt);

		secondary_hash->hash_entries[hash_idx] = new_hash_tbl_entry;
		name_tbl_entry = next_entry;
	}

	if (SECONDARY_HASH_DUMP)
		secondary_hash_dump(secondary_hash);
	return (hash_tbl_entry_t)(uintptr_t)secondary_hash;
}

static hash_tbl_entry_t hash_tbl_remove(secondary_hash_tbl_t *hash_tbl,
					uint32_t  level,  /* 0 or 1 */
					name_tbl_entry_t    **list_head_ptr,
					name_tbl_entry_t    **list_tail_ptr)
{
	secondary_hash_tbl_t *secondary_hash;
	name_tbl_entry_t     *linked_list_head, *linked_list_tail;
	name_tbl_entry_t     *head_entry, *tail_entry;
	hash_tbl_entry_t      hash_tbl_entry;
	uint32_t              idx, entry_cnt;

	check_secondary_hash(hash_tbl);
	linked_list_head = NULL;
	linked_list_tail = NULL;

	for (idx = 0; idx < SECONDARY_HASH_TBL_SIZE; idx++) {
		hash_tbl_entry = hash_tbl->hash_entries[idx];
		if (hash_tbl_entry != 0) {
			if ((hash_tbl_entry & 0x3F) != 0) {
				/* This secondar hash table points to a
				 * name_tbl_entry_t linked list, so add this
				 * new entry onto the front of it.
				 */
				head_entry = (name_tbl_entry_t *)
					(uintptr_t)(hash_tbl_entry & ~0x3F);
				tail_entry = head_entry;
			} else {
				secondary_hash = (secondary_hash_tbl_t *)
					(uintptr_t)hash_tbl_entry;
				check_secondary_hash(secondary_hash);
				if (level == 1)
					break;

				hash_tbl_remove(secondary_hash, level + 1,
						&head_entry, &tail_entry);
			}

			/* Now concate lists. */
			if (!linked_list_tail) {
				linked_list_head = head_entry;
				linked_list_tail = tail_entry;
			} else {
				linked_list_tail->next_entry = head_entry;
				linked_list_tail             = tail_entry;
			}
		}
	}

	if (list_head_ptr)
		*list_head_ptr = linked_list_head;

	if (list_tail_ptr)
		*list_tail_ptr = linked_list_tail;

	secondary_hash_tbl_free(hash_tbl);
	if (name_hash_tbl.num_secondary_tbls[level] != 0)
		name_hash_tbl.num_secondary_tbls[level]--;

	entry_cnt = linked_list_len(linked_list_head);
	if ((!linked_list_head) || (entry_cnt == 0))
		return 0;

	hash_tbl_entry = make_hash_tbl_entry(linked_list_head, entry_cnt - 1);
	return hash_tbl_entry;
}

static int name_hash_tbl_add(name_tbl_entry_t *entry_to_add,
			     uint32_t          hash_value)
{
	secondary_hash_tbl_t *secondary_hash;
	name_tbl_entry_t     *name_tbl_entry;
	hash_tbl_entry_t      hash_tbl_entry;
	uint32_t              primary_hash_idx, hash_idx, collisions, entry_cnt;

	primary_hash_idx = hash_value & (PRIMARY_HASH_TBL_SIZE - 1);
	hash_tbl_entry   = name_hash_tbl.hash_entries[primary_hash_idx];
	entry_cnt        = hash_tbl_entry & 0x3F;
	name_hash_tbl.hash_collisions[primary_hash_idx]++;
	if (hash_tbl_entry == 0) {
		/* This primary hash table entry points to an empty bucket, so
		 * start a new name_tbl_entry_t linked list.
		 */
		hash_tbl_entry = make_hash_tbl_entry(entry_to_add, 0);
		name_hash_tbl.hash_entries[primary_hash_idx] = hash_tbl_entry;
		return 0;
	} else if (entry_cnt != 0) {
		/* This primary hash table entry points to a name_tbl_entry_t
		 * linked list, so add this new entry onto the front of it.
		 */
		name_tbl_entry =
			(name_tbl_entry_t *)(uintptr_t)(hash_tbl_entry & ~0x3F);
		entry_to_add->next_entry = name_tbl_entry;
		hash_tbl_entry = make_hash_tbl_entry(entry_to_add, entry_cnt);
		name_hash_tbl.hash_entries[primary_hash_idx] = hash_tbl_entry;

	       /* See if there are enough hash collisions within this hash
		* bucket to justify replacing the linked list with a
		* secondary hash table.
		*/
		collisions = name_hash_tbl.hash_collisions[primary_hash_idx];
		if (collisions <= MAX_PRIMARY_LIST_SIZE)
			return 0;

	       /* Replace the current linked list with a secondary hash
		* table.
		*/
		hash_tbl_entry = secondary_hash_add(entry_to_add, 0, 16);
		name_hash_tbl.hash_entries[primary_hash_idx] = hash_tbl_entry;
		return 0;
	}

       /* This hash_tbl_entry references a secondary hash table, so get
	* some more hash_value bits and index that table.
	*/
	hash_idx       = (hash_value >> 16) & (SECONDARY_HASH_TBL_SIZE - 1);
	secondary_hash = (secondary_hash_tbl_t *)(uintptr_t)hash_tbl_entry;
	check_secondary_hash(secondary_hash);
	hash_tbl_entry = secondary_hash->hash_entries[hash_idx];
	entry_cnt      = hash_tbl_entry & 0x3F;
	if (hash_tbl_entry == 0) {
		/* This secondary hash table entry points to an empty bucket,
		 * so start a new name_tbl_entry_t linked list.
		 */
		hash_tbl_entry = make_hash_tbl_entry(entry_to_add, 0);
		secondary_hash->hash_entries[hash_idx] = hash_tbl_entry;
		return 0;
	} else if (entry_cnt != 0) {
		/* This secondary hash table entry points to a
		 * name_tbl_entry_t linked list, so add this new entry onto
		 * the front of it.
		 */
		name_tbl_entry =
			(name_tbl_entry_t *)(uintptr_t)(hash_tbl_entry & ~0x3F);
		entry_to_add->next_entry = name_tbl_entry;
		hash_tbl_entry = make_hash_tbl_entry(entry_to_add, entry_cnt);
		secondary_hash->hash_entries[hash_idx] = hash_tbl_entry;

	       /* See if there are enough hash collisions within this
		* secondary hash bucket to justify replacing the linked list
		* with yet another secondary hash table.
		*/
		if (entry_cnt < MAX_SECONDARY_LIST_SIZE)
			return 0;

	       /* Replace the current linked list with a secondary hash
		* table.
		*/
		hash_tbl_entry = secondary_hash_add(entry_to_add, 1, 24);
		secondary_hash->hash_entries[hash_idx] = hash_tbl_entry;
		check_secondary_hash(secondary_hash);
		return 0;
	}

       /* Yet again, this (secondary) hash_tbl_entry references a level 2
	* secondary hash table, so get some more hash_value bits and index
	* that table.  We only allow two secondary tables in the path, so if
	* this hash_tbl_entry doesn't point to a name_tbl_entry then we
	* signal failure by returning -1.
	*/
	hash_idx       = (hash_value >> 24) & (SECONDARY_HASH_TBL_SIZE - 1);
	secondary_hash = (secondary_hash_tbl_t *)(uintptr_t)hash_tbl_entry;
	check_secondary_hash(secondary_hash);
	hash_tbl_entry = secondary_hash->hash_entries[hash_idx];
	entry_cnt      = hash_tbl_entry & 0x3F;
	if (hash_tbl_entry == 0) {
		/* This secondary hash table entry points to an empty bucket,
		 * so start a new name_tbl_entry_t linked list.
		 */
		hash_tbl_entry = make_hash_tbl_entry(entry_to_add, 0);
		secondary_hash->hash_entries[hash_idx] = hash_tbl_entry;
		check_secondary_hash(secondary_hash);
		return 0;
	} else if (entry_cnt != 0) {
		/* This secondary hash table entry points to a
		 * name_tbl_entry_t linked list, so add this new entry onto
		 * the front of it.  Note that regardless of the size of this
		 * linked list, we never add another hash table, so we don't
		 * need to update any secondary table counts.
		 */
		name_tbl_entry =
			(name_tbl_entry_t *)(uintptr_t)(hash_tbl_entry & ~0x3F);
		entry_to_add->next_entry = name_tbl_entry;
		hash_tbl_entry = make_hash_tbl_entry(entry_to_add, entry_cnt);
		secondary_hash->hash_entries[hash_idx] = hash_tbl_entry;
		check_secondary_hash(secondary_hash);
		return 0;
	}

	name_hash_tbl.hash_collisions[primary_hash_idx]--;
	return -1;
}

static int name_tbl_entry_list_remove(hash_tbl_entry_t *hash_entry_ptr,
				      name_tbl_entry_t *linked_list,
				      name_tbl_entry_t *entry_to_delete,
				      uint32_t          entry_cnt)
{
	name_tbl_entry_t *name_tbl_entry, *prev_entry, *next_entry;
	hash_tbl_entry_t  hash_tbl_entry;

	name_tbl_entry = linked_list;
	prev_entry     = NULL;
	while (name_tbl_entry) {
		next_entry = name_tbl_entry->next_entry;
		if (name_tbl_entry == entry_to_delete) {
			/* We have found the name_tbl_entry that is to be
			 * deleted.
			 */
			if (!prev_entry) {
				hash_tbl_entry  =
					(hash_tbl_entry_t)(uintptr_t)next_entry;
				hash_tbl_entry &= ~0x3F;
				hash_tbl_entry |= entry_cnt;
				*hash_entry_ptr = hash_tbl_entry;
			} else {
				prev_entry->next_entry = next_entry;
			}

		       /* Now decrement the entry_cnt field - if in the range
			* 1 - 0x3E
			*/
			if ((entry_cnt != 0) && (entry_cnt < 0x3F))
				*hash_entry_ptr = (*hash_entry_ptr) - 1;

			return 0;
		}

		prev_entry     = name_tbl_entry;
		name_tbl_entry = next_entry;
	}

	return -2;
}

static int name_hash_tbl_delete(name_tbl_entry_t *entry_to_delete,
				uint32_t          hash_value)
{
	secondary_hash_tbl_t *secondary_hash;
	hash_tbl_entry_t     *hash_entry_ptr, hash_tbl_entry;
	name_tbl_entry_t     *name_tbl_entry;
	uint64_t              tbn;
	uint32_t              primary_hash_idx, hash_idx, collisions, entry_cnt;
	int                   rc;

	primary_hash_idx = hash_value & (PRIMARY_HASH_TBL_SIZE - 1);
	hash_entry_ptr   = &name_hash_tbl.hash_entries[primary_hash_idx];
	hash_tbl_entry   = *hash_entry_ptr;
	entry_cnt        = hash_tbl_entry & 0x3F;
	if (hash_tbl_entry == 0) {
		/* This primary hash table entry points to an empty bucket, so
		 * we have failed to find the matching entry.
		 */
		return -1;
	} else if (entry_cnt != 0) {
		/* This primary hash table entry points to a name_tbl_entry_t
		 * linked list, so remove entry from this linked list.
		 */
		name_tbl_entry =
			(name_tbl_entry_t *)(uintptr_t)(hash_tbl_entry & ~0x3F);
		rc = name_tbl_entry_list_remove(hash_entry_ptr, name_tbl_entry,
						entry_to_delete, entry_cnt);
		tbn = (*hash_entry_ptr) & ~0x3F;
		if (tbn == 0xFFFFFFFFFFFFFFC0)
			abort();

		if (rc < 0)
			return rc;

		name_hash_tbl.hash_collisions[primary_hash_idx]--;
		return 0;
	}

       /* This hash_tbl_entry references a secondary hash table, so get
	* some more hash_value bits and index that table.
	*/
	hash_idx       = (hash_value >> 16) & (SECONDARY_HASH_TBL_SIZE - 1);
	secondary_hash = (secondary_hash_tbl_t *)(uintptr_t)hash_tbl_entry;
	check_secondary_hash(secondary_hash);
	hash_entry_ptr = &secondary_hash->hash_entries[hash_idx];
	hash_tbl_entry = *hash_entry_ptr;
	entry_cnt      = hash_tbl_entry & 0x3F;
	if (hash_tbl_entry == 0) {
		/* This secondary hash table entry points to an empty bucket,
		 * so we have failed to find the matching entry.
		 */
		return -1;
	} else if (entry_cnt != 0) {
		/* This secondary hash table entry points to a
		 * name_tbl_entry_t linked list, so try to remove
		 * entry_to_delete from this linked list.
		 */
		name_tbl_entry =
			(name_tbl_entry_t *)(uintptr_t)(hash_tbl_entry & ~0x3F);
		rc = name_tbl_entry_list_remove(hash_entry_ptr, name_tbl_entry,
						entry_to_delete, entry_cnt);
		tbn = (*hash_entry_ptr) & ~0x3F;
		if (tbn == 0xFFFFFFFFFFFFFFC0)
			abort();

		check_secondary_hash(secondary_hash);
		if (rc < 0)
			return rc;

		name_hash_tbl.hash_collisions[primary_hash_idx]--;

	       /* See if we should replace this secondary hash table with a
		* linked list.
		*/
		collisions = name_hash_tbl.hash_collisions[primary_hash_idx];
		if (MIN_SECONDARY_TBL_SIZE < collisions)
			return 0;

		/* Replace the secondary hash table with a linked list. */
		hash_tbl_entry = hash_tbl_remove(secondary_hash, 0, NULL, NULL);
		name_hash_tbl.hash_entries[primary_hash_idx] = hash_tbl_entry;
		return 0;
	}

       /* Yet again, this (secondary) hash_tbl_entry references a level 2
	* secondary hash table, so get some more hash_value bits and index
	* that table.  We only allow two secondary tables in the path, so if
	* this hash_tbl_entry doesn't point to a name_tbl_entry then we
	* signal failure by returning -1.
	*/
	hash_idx       = (hash_value >> 24) & (SECONDARY_HASH_TBL_SIZE - 1);
	secondary_hash = (secondary_hash_tbl_t *)(uintptr_t)hash_tbl_entry;
	check_secondary_hash(secondary_hash);
	hash_entry_ptr = &secondary_hash->hash_entries[hash_idx];
	hash_tbl_entry = *hash_entry_ptr;
	entry_cnt      = hash_tbl_entry & 0x3F;
	if (hash_tbl_entry == 0) {
		/* This secondary hash table entry points to an empty bucket,
		 * so we have failed to find the matching entry.
		 */
		return -1;
	} else if (entry_cnt != 0) {
		/* This secondary hash table entry points to a
		 * name_tbl_entry_t linked list, so try to remove
		 * entry_to_delete from this linked list.
		 */
		name_tbl_entry =
			(name_tbl_entry_t *)(uintptr_t)(hash_tbl_entry & ~0x3F);
		rc = name_tbl_entry_list_remove(hash_entry_ptr, name_tbl_entry,
						entry_to_delete, entry_cnt);
		tbn = (*hash_entry_ptr) & ~0x3F;
		if (tbn == 0xFFFFFFFFFFFFFFC0)
			abort();

		check_secondary_hash(secondary_hash);
		if (rc < 0)
			return rc;

		name_hash_tbl.hash_collisions[primary_hash_idx]--;
		check_secondary_hash(secondary_hash);
		return 0;
	}

	return -1;
}

_odp_int_name_t _odp_int_name_tbl_add(const char *name,
				      uint8_t     name_kind,
				      uint64_t    user_data)
{
	name_tbl_entry_t *name_tbl_entry;
	uint32_t          hash_value, name_len;
	int               rc;

	/* Check for name_tbls_initialized. */
	if (name_tbls_initialized == 0)
		return ODP_INVALID_NAME;

	/* Check for NULL names or zero length names. */
	if ((!name) || (name[0] == '\0'))
		return ODP_INVALID_NAME;

	/* Check for names that are too long. */
	name_len = strlen(name);
	if (_ODP_INT_NAME_LEN < name_len)
		return ODP_INVALID_NAME;

       /* Next lookup the <name, name_kind> pair to make sure it doesn't
	* already exist.
	*/
	odp_ticketlock_lock(&name_table_lock);
	name_tbl_entry = internal_name_lookup(name, name_kind);
	if (name_tbl_entry) {
		odp_ticketlock_unlock(&name_table_lock);
		return ODP_INVALID_NAME;
	}

	/* Allocate a name_tbl_entry record.*/
	name_len       = strlen(name);
	name_tbl_entry = name_tbl_entry_alloc();
	if (!name_tbl_entry) {
		odp_ticketlock_unlock(&name_table_lock);
		return ODP_INVALID_NAME;
	}

	hash_value                  = hash_name_and_kind(name, name_kind);
	name_tbl_entry->next_entry  = NULL;
	name_tbl_entry->user_data   = user_data;
	name_tbl_entry->hash_value  = hash_value;
	name_tbl_entry->name_kind   = name_kind;
	name_tbl_entry->name_len    = name_len;
	memcpy(name_tbl_entry->name, name, name_len);
	name_tbl_entry->name[name_len] = '\0';

	rc = name_hash_tbl_add(name_tbl_entry, hash_value);
	if (rc < 0) {
		name_tbl_entry_free(name_tbl_entry);
		odp_ticketlock_unlock(&name_table_lock);
		return ODP_INVALID_NAME;
	}

	name_tbls.num_adds++;
	name_tbls.current_num_names++;
	odp_ticketlock_unlock(&name_table_lock);
	return name_tbl_entry->name_tbl_id;
}

int _odp_int_name_tbl_delete(_odp_int_name_t odp_name)
{
	name_tbl_entry_t *entry_to_delete;
	int               rc;

	/* Check for name_tbls_initialized. */
	if (name_tbls_initialized == 0)
		return -3;

	entry_to_delete = name_tbl_id_parse(odp_name, NULL);
	if (!entry_to_delete)
		return -1;

	/* First disconnect this entry from its hash bucket linked list. */
	odp_ticketlock_lock(&name_table_lock);
	rc = name_hash_tbl_delete(entry_to_delete, entry_to_delete->hash_value);
	if (0 <= rc) {
		name_tbls.num_deletes++;
		if (name_tbls.current_num_names != 0)
			name_tbls.current_num_names--;

		name_tbl_entry_free(entry_to_delete);
	}

	odp_ticketlock_unlock(&name_table_lock);
	return rc;
}

const char *_odp_int_name_tbl_name(_odp_int_name_t odp_name)
{
	name_tbl_entry_t *name_tbl_entry;

	name_tbl_entry = name_tbl_id_parse(odp_name, NULL);
	if (!name_tbl_entry)
		return NULL;
	else
		return name_tbl_entry->name;
}

uint64_t _odp_int_name_tbl_user_data(_odp_int_name_t odp_name)
{
	name_tbl_entry_t *name_tbl_entry;

	name_tbl_entry = name_tbl_id_parse(odp_name, NULL);
	if (!name_tbl_entry)
		return 0;
	else
		return name_tbl_entry->user_data;
}

_odp_int_name_t _odp_int_name_tbl_lookup(const char *name, uint8_t name_kind)
{
	name_tbl_entry_t *name_tbl_entry;
	_odp_int_name_t   name_tbl_id;

	/* Check for name_tbls_initialized. */
	if (name_tbls_initialized == 0)
		return ODP_INVALID_NAME;

	/* Check for NULL names or zero length names. */
	name_tbl_id = ODP_INVALID_NAME;
	if ((!name) || (name[0] == '\0'))
		return name_tbl_id;

	odp_ticketlock_lock(&name_table_lock);
	name_tbl_entry = internal_name_lookup(name, name_kind);
	if (name_tbl_entry)
		name_tbl_id = name_tbl_entry->name_tbl_id;
	odp_ticketlock_unlock(&name_table_lock);

	return name_tbl_id;
}

#ifdef SECONDARY_HASH_HISTO_PRINT

static uint32_t level2_hash_histo(secondary_hash_tbl_t *hash_tbl,
				  uint32_t              level2_histo[])
{
	name_tbl_entry_t *name_tbl_entry;
	hash_tbl_entry_t  hash_tbl_entry;
	uint32_t          idx, collisions, total_collisions;

	total_collisions = 0;
	for (idx = 0; idx < SECONDARY_HASH_TBL_SIZE; idx++) {
		hash_tbl_entry = hash_tbl->hash_entries[idx];
		if (hash_tbl_entry == 0) {
			collisions = 0;
		} else {
			name_tbl_entry = (name_tbl_entry_t *)
				(uintptr_t)(hash_tbl_entry & ~0x3F);
			collisions     = linked_list_len(name_tbl_entry);
		}

		level2_histo[MIN(collisions, UINT32_C(256))]++;
		total_collisions += collisions;
	}

	return total_collisions;
}

static uint32_t level1_hash_histo(secondary_hash_tbl_t *hash_tbl,
				  uint32_t              level1_histo[],
				  uint32_t              level2_histo[])
{
	secondary_hash_tbl_t *secondary_hash;
	name_tbl_entry_t     *name_tbl_entry;
	hash_tbl_entry_t      hash_tbl_entry;
	uint32_t              idx, collisions, total_collisions;

	total_collisions = 0;
	for (idx = 0; idx < SECONDARY_HASH_TBL_SIZE; idx++) {
		hash_tbl_entry = hash_tbl->hash_entries[idx];
		if (hash_tbl_entry == 0) {
			collisions = 0;
		} else if ((hash_tbl_entry & 0x3F) != 0) {
			name_tbl_entry = (name_tbl_entry_t *)
				(uintptr_t)(hash_tbl_entry & ~0x3F);
			collisions     = linked_list_len(name_tbl_entry);
		} else {
			secondary_hash = (secondary_hash_tbl_t *)
				(uintptr_t)hash_tbl_entry;
			collisions     = level2_hash_histo(secondary_hash,
							   level2_histo);
		}

		level1_histo[MIN(collisions, UINT32_C(256))]++;
		total_collisions += collisions;
	}

	return total_collisions;
}

static void secondary_hash_histo_print(void)
{
	secondary_hash_tbl_t *secondary_hash;
	hash_tbl_entry_t      hash_tbl_entry;
	uint32_t              level1_histo[257], level2_histo[257];
	uint32_t              avg, idx, count, total_count;

	memset(level1_histo, 0, sizeof(level1_histo));
	memset(level2_histo, 0, sizeof(level2_histo));

	for (idx = 0; idx < PRIMARY_HASH_TBL_SIZE; idx++) {
		hash_tbl_entry = name_hash_tbl.hash_entries[idx];
		if ((hash_tbl_entry != 0) && ((hash_tbl_entry & 0x3F) == 0)) {
			/* This hash_tbl_entry references a level 0 secondary
			 * hash table
			 */
			secondary_hash = (secondary_hash_tbl_t *)
				(uintptr_t)hash_tbl_entry;
			level1_hash_histo(secondary_hash, level1_histo,
					  level2_histo);
		}
	}

	if (name_hash_tbl.num_secondary_tbls[0] == 0)
		return;

	ODP_DBG("  level1 secondary hash histogram:\n");
	total_count = 0;
	for (idx = 0; idx < 256; idx++) {
		count = level1_histo[idx];
		if (idx != 0)
			total_count += count * idx;

		if (count != 0)
			ODP_DBG("    num collisions=%02u    count=%u\n",
				idx, count);
	}

	count = level1_histo[256];
	total_count += count;
	if (count != 0)
		ODP_DBG("    num collisions >=256  count=%u\n", count);

	avg = (100 * total_count) / name_hash_tbl.num_secondary_tbls[0];
	avg = avg / SECONDARY_HASH_TBL_SIZE;
	ODP_DBG("    avg collisions=%02u.%02u total=%u\n\n",
		avg / 100, avg % 100, total_count);

	if (name_hash_tbl.num_secondary_tbls[1] == 0)
		return;

	ODP_DBG("  level2 secondary hash histogram:\n");
	total_count = 0;
	for (idx = 0; idx < 256; idx++) {
		count = level2_histo[idx];
		if (idx != 0)
			total_count += count * idx;

		if (count != 0)
			ODP_DBG("    num collisions=%02u    count=%u\n",
				idx, count);
	}

	count = level2_histo[256];
	total_count += count;
	if (count != 0)
		ODP_DBG("    num collisions >=256  count=%u\n", count);

	avg = (100 * total_count) / name_hash_tbl.num_secondary_tbls[1];
	avg = avg / SECONDARY_HASH_TBL_SIZE;
	ODP_DBG("    avg collisions=%02u.%02u total=%u\n\n",
		avg / 100, avg % 100, total_count);
}

#endif

void _odp_int_name_tbl_stats_print(void)
{
	name_tbl_t *name_tbl;
	uint32_t primary_hash_histo[257], idx, collisions,
		count, total_count;
	uint32_t avg;

	ODP_DBG("\nname table stats:\n");
	ODP_DBG("  num_names=%u num_adds=%lu "
		"num_deletes=%lu num_name_tbls=%u\n",
		name_tbls.current_num_names, name_tbls.num_adds,
		name_tbls.num_deletes, name_tbls.num_name_tbls);
	for (idx = 0; idx < NUM_NAME_TBLS; idx++) {
		name_tbl = name_tbls.tbls[idx];
		if ((name_tbl) && (name_tbl->num_used != 0))
			ODP_DBG("  name_tbl %u  num_allocd=%7u "
				"num_added_to_free_list=%7u "
				"num_used=%7u num_avail_to_add=%7u\n", idx,
				name_tbl->num_allocd,
				name_tbl->num_added_to_free_list,
				name_tbl->num_used,
				name_tbl->num_avail_to_add);
	}

	memset(primary_hash_histo, 0, sizeof(primary_hash_histo));
	for (idx = 0; idx < PRIMARY_HASH_TBL_SIZE; idx++) {
		collisions =
		    MIN(name_hash_tbl.hash_collisions[idx], UINT32_C(256));
		primary_hash_histo[collisions]++;
	}

	ODP_DBG("  name_tbl primary hash histogram:\n");
	total_count = 0;
	for (idx = 0; idx < 256; idx++) {
		count = primary_hash_histo[idx];
		if (idx != 0)
			total_count += count * idx;

		if (count != 0)
			ODP_DBG("    num collisions=%02u    count=%u\n",
				idx, count);
	}

	count = primary_hash_histo[256];
	total_count += count;
	if (count != 0)
		ODP_DBG("    num collisions >=256  count=%u\n", count);

	avg = (100 * total_count) / PRIMARY_HASH_TBL_SIZE;
	ODP_DBG("    avg collisions=%02u.%02u total=%u\n\n",
		avg / 100, avg % 100, total_count);

	ODP_DBG("  num of first level secondary hash tbls=%u "
		"second level tbls=%u\n",
		name_hash_tbl.num_secondary_tbls[0],
		name_hash_tbl.num_secondary_tbls[1]);

#ifdef SECONDARY_HASH_HISTO_PRINT
	if (name_hash_tbl.num_secondary_tbls[0] != 0)
		secondary_hash_histo_print();
#endif
}

int _odp_int_name_tbl_init_global(void)
{
	name_tbl_t *new_name_tbl;

	memset(&name_hash_tbl, 0, sizeof(name_hash_tbl));
	odp_ticketlock_init(&name_table_lock);

	memset(&name_tbls, 0, sizeof(name_tbls));
	new_name_tbl = name_tbl_alloc(0, INITIAL_NAME_TBL_SIZE);
	name_tbl_free_list_add(new_name_tbl, INITIAL_NAME_TBL_SIZE);

	name_tbls.tbls[0]               = new_name_tbl;
	name_tbls.avail_space_bit_mask |= 1;
	name_tbls.num_name_tbls         = 1;
	name_tbls_initialized           = 1;

	return 0;
}

int _odp_int_name_tbl_term_global(void)
{
	int i;

	for (i = 0; i < name_tbls.num_name_tbls; i++)
		aligned_free(name_tbls.tbls[i]);

	name_tbls_initialized = 0;
	return 0;
}
