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
#include <odp_timer_wheel_internal.h>
#include <odp_traffic_mngr_internal.h>
#include <odp_debug_internal.h>
#include <odp_macros_internal.h>

/* The following constants can be changed either at compile time or run time
 * as long as the following constraints are met (by the way REV stands for
 * REVOLUTION, i.e. one complete sweep through a specific timer wheel):
 */
#define TIME_TO_TICKS_SHIFT    10
#define TIME_PER_TICK          BIT(TIME_TO_TICKS_SHIFT)
#define CURRENT_TIMER_SLOTS    1024
#define LEVEL1_TIMER_SLOTS     2048
#define LEVEL2_TIMER_SLOTS     1024
#define LEVEL3_TIMER_SLOTS     1024

/* The following values are derived and should generally not be changed.  The
 * basic idea is that the ticks per current timer wheel slot should always be
 * 1, since that defines what a tick is - namely the time period of a single
 * current timer wheel slot.  Then for all levels (including current), the
 * ticks per revolution is clearly equal to the ticks per slot times the
 * number of slots.  Finally the ticks per slot for levels 1 through 3, must be
 * the ticks per revolution of the previous level divided by a small power of
 * 2 - e.g. 2, 4, 8, 16 - (but not 1).  The idea being that when an upper
 * level slot is processed, its entries will be spread across this fraction of
 * the lower level wheel and we want to make sure that none of these entries
 * is near the lower level's current index.  Currently we use 4 for all
 * levels.
 */
#define CURRENT_GEAR_RATIO     4
#define LEVEL1_GEAR_RATIO      4
#define LEVEL2_GEAR_RATIO      4
#define TICKS_PER_CURRENT_SLOT 1
#define TICKS_PER_CURRENT_REV  (CURRENT_TIMER_SLOTS * TICKS_PER_CURRENT_SLOT)
#define TICKS_PER_LEVEL1_SLOT  (TICKS_PER_CURRENT_REV / CURRENT_GEAR_RATIO)
#define TICKS_PER_LEVEL1_REV   (LEVEL1_TIMER_SLOTS * TICKS_PER_LEVEL1_SLOT)
#define TICKS_PER_LEVEL2_SLOT  (TICKS_PER_LEVEL1_REV / LEVEL1_GEAR_RATIO)
#define TICKS_PER_LEVEL2_REV   (LEVEL2_TIMER_SLOTS * TICKS_PER_LEVEL2_SLOT)
#define TICKS_PER_LEVEL3_SLOT  (TICKS_PER_LEVEL2_REV / LEVEL2_GEAR_RATIO)
#define TICKS_PER_LEVEL3_REV   (LEVEL3_TIMER_SLOTS * TICKS_PER_LEVEL3_SLOT)

#define EXPIRED_RING_ENTRIES  256

typedef struct timer_blk_s timer_blk_t;

typedef struct { /* Should be 120 bytes long */
	uint64_t user_data[15];
} current_blk_t;

typedef struct { /* Should be 120 bytes long */
	uint64_t user_data[10];
	uint32_t wakeup32[10];
} general_blk_t;

/* Must be exactly 128 bytes long AND cacheline aligned! */
struct timer_blk_s {
	timer_blk_t *next_timer_blk;
	union {
		current_blk_t current_blk;
		general_blk_t general_blk;
	};
};

/* The following record type is only needed/used to free the timer_blks. */
typedef struct blk_of_timer_blks_desc_s blk_of_timer_blks_desc_t;
struct blk_of_timer_blks_desc_s {
	blk_of_timer_blks_desc_t *next;
	timer_blk_t              *block_of_timer_blks;
};

/* Each current_timer_slot is 8 bytes long. */
typedef union {
       /* The selection of which union element to use is based on the LSB
	* bit, under the required assumption that both of these pointers are
	* at least 8-byte aligned.  If the entire 8 bytes is zero, then this
	* entry is empty, otherwise a LSB bit of 0 indicates a timer_blk_list
	* and a LSB bit of 1 indicates a single entry with a 64-bit user_data
	* word.
	*/
	uint64_t     user_data;
	timer_blk_t *timer_blk_list;
} current_timer_slot_t;

typedef struct {
	current_timer_slot_t slots[0];
} current_wheel_t;

typedef struct {
	uint32_t             count;
	uint32_t             peak_count;
	uint32_t             expired_ring_full_cnt;
	uint32_t             head_idx;
	uint32_t             tail_idx;
	uint32_t             max_idx;
	current_timer_slot_t entries[0];
} expired_ring_t;

typedef struct {
	uint32_t kind;                  /* 1 for single_entry_t */
	uint32_t wakeup32;
	uint64_t user_data;
} single_entry_t;

typedef struct {
	uint32_t     kind;              /* 2 for list_entry_t */
	uint32_t     num_blks;
	timer_blk_t *timer_blk_list;
} list_entry_t;

typedef union  { /* Each general_timer_slot is 16 bytes long. */
       /* The selection of which union element to use is based on the first 4
	* byte field which is always the "kind".  If kind is 0, then this
	* slot is empty, else if the kind is 1 then it is a single_entry and
	* if the kind is 2 then it is a list_entry.
	*/
	single_entry_t single_entry;
	list_entry_t   list_entry;
} general_timer_slot_t;

typedef struct {
	general_timer_slot_t slots[0];
} general_wheel_t;

typedef struct {
       /* Note that rev stands for revolution - one complete sweep through
	* this timer wheel.
	*/
	uint16_t num_slots;        /* Must be a power of 2. */
	uint16_t slot_idx;
	uint16_t gear_mask;        /* = (num_slots / gear_ratio) - 1 */
	uint16_t gear_ratio;       /* num of next level wheel updates per this
				    * rev
				    */
	uint32_t ticks_shift;
	uint32_t ticks_per_slot;   /* Must be a power of 2. */
	uint64_t ticks_per_rev;    /* = num_slots * ticks_per_slot */
	uint64_t max_ticks;        /* = current_ticks + ticks_per_rev */
} wheel_desc_t;

typedef struct {
	uint32_t          last_slot_served;
	uint32_t          free_list_size;
	uint32_t          min_free_list_size;
	uint32_t          peak_free_list_size;
	uint32_t          current_cnt;
	timer_blk_t      *free_list_head;
	uint64_t          total_timer_inserts;
	uint64_t          insert_fail_cnt;
	uint64_t          total_timer_removes;
	uint64_t          total_promote_cnt;
	uint64_t          promote_fail_cnt;
	uint64_t          current_ticks;
	wheel_desc_t      wheel_descs[4];
	current_wheel_t  *current_wheel;
	general_wheel_t  *general_wheels[3];
	expired_ring_t   *expired_timers_ring;
	tm_system_t      *tm_system;

	blk_of_timer_blks_desc_t *timer_blks_list_head;
} timer_wheels_t;

static uint32_t _odp_internal_ilog2(uint64_t value)
{
	uint64_t pwr_of_2;
	uint32_t bit_shift;

	if (value == 0)
		return 64;

	for (bit_shift = 0; bit_shift < 64; bit_shift++) {
		pwr_of_2 = 1ULL << bit_shift;
		if (value == pwr_of_2)
			return bit_shift;
		else if (value < pwr_of_2)
			return bit_shift - 1;
	}

	return 64;
}

static current_wheel_t *current_wheel_alloc(timer_wheels_t *timer_wheels,
					    uint32_t        desc_idx)
{
	current_wheel_t *current_wheel;
	wheel_desc_t    *wheel_desc;
	uint32_t         num_slots, malloc_len;

	wheel_desc    = &timer_wheels->wheel_descs[desc_idx];
	num_slots     = wheel_desc->num_slots;
	malloc_len    = num_slots * sizeof(current_timer_slot_t);
	current_wheel = malloc(malloc_len);
	memset(current_wheel, 0, malloc_len);

	wheel_desc->slot_idx      = 0;
	wheel_desc->ticks_per_rev = num_slots;
	wheel_desc->ticks_shift   = 0;
	wheel_desc->max_ticks     = 0;
	wheel_desc->gear_mask     = (num_slots / wheel_desc->gear_ratio) - 1;
	return current_wheel;
}

static void current_wheel_start(timer_wheels_t *timer_wheels,
				uint32_t        desc_idx,
				uint64_t        current_ticks)
{
	wheel_desc_t *wheel_desc;
	uint32_t      wheel_idx;

	wheel_desc = &timer_wheels->wheel_descs[desc_idx];
	wheel_idx  = current_ticks & (wheel_desc->num_slots - 1);

	wheel_desc->slot_idx  = wheel_idx;
	wheel_desc->max_ticks = wheel_idx + wheel_desc->ticks_per_rev;
}

static general_wheel_t *general_wheel_alloc(timer_wheels_t *timer_wheels,
					    uint32_t        desc_idx)
{
	general_wheel_t *general_wheel;
	wheel_desc_t    *wheel_desc;
	uint64_t         ticks_per_slot;
	uint32_t         num_slots, ticks_shift, malloc_len;

	wheel_desc     = &timer_wheels->wheel_descs[desc_idx];
	num_slots      = wheel_desc->num_slots;
	ticks_per_slot = (uint64_t)wheel_desc->ticks_per_slot;
	ticks_shift    = _odp_internal_ilog2(ticks_per_slot);
	malloc_len     = num_slots * sizeof(general_timer_slot_t);
	general_wheel  = malloc(malloc_len);
	memset(general_wheel, 0, malloc_len);

	wheel_desc->slot_idx      = 0;
	wheel_desc->ticks_per_rev = num_slots * ticks_per_slot;
	wheel_desc->ticks_shift   = ticks_shift;
	wheel_desc->max_ticks     = 0;
	wheel_desc->gear_mask     = (num_slots / wheel_desc->gear_ratio) - 1;
	return general_wheel;
}

static void general_wheel_start(timer_wheels_t *timer_wheels,
				uint32_t        desc_idx,
				uint64_t        current_ticks)
{
	wheel_desc_t *wheel_desc;
	uint32_t      num_slots, ticks_shift, wheel_idx;

	wheel_desc  = &timer_wheels->wheel_descs[desc_idx];
	num_slots   = wheel_desc->num_slots;
	ticks_shift = wheel_desc->ticks_shift;
	wheel_idx   = (current_ticks >> ticks_shift) & (num_slots - 1);

	wheel_desc->slot_idx  = wheel_idx;
	wheel_desc->max_ticks = wheel_idx + wheel_desc->ticks_per_rev;
}

static int expired_ring_create(timer_wheels_t *timer_wheels,
			       uint32_t        num_entries)
{
	expired_ring_t *expired_ring;
	uint32_t        malloc_len;

	malloc_len = sizeof(expired_ring_t) +
		(sizeof(current_timer_slot_t) * num_entries);
	expired_ring = malloc(malloc_len);
	memset(expired_ring, 0, malloc_len);
	expired_ring->max_idx = num_entries - 1;

	timer_wheels->expired_timers_ring = expired_ring;
	return 0;
}

static int free_list_add(timer_wheels_t *timer_wheels,
			 uint32_t        num_timer_blks)
{
	blk_of_timer_blks_desc_t *blk_of_timer_blks_desc;
	timer_blk_t              *block_of_timer_blks, *timer_blk;
	timer_blk_t              *next_timer_blk;
	uint32_t                  malloc_len, idx;

	/* Should be cacheline aligned! */
	malloc_len          = num_timer_blks * sizeof(timer_blk_t);
	block_of_timer_blks = malloc(malloc_len);
	if (!block_of_timer_blks)
		return -1;

	memset(block_of_timer_blks, 0, malloc_len);

	/* Now malloc, initialize and link a descriptor record describing this
	 * block_of_timer_blks allocation done above.  This is only used to
	 * free this memory. */
	blk_of_timer_blks_desc = malloc(sizeof(blk_of_timer_blks_desc_t));
	memset(blk_of_timer_blks_desc, 0, sizeof(blk_of_timer_blks_desc_t));
	blk_of_timer_blks_desc->block_of_timer_blks = block_of_timer_blks;
	blk_of_timer_blks_desc->next = timer_wheels->timer_blks_list_head;
	timer_wheels->timer_blks_list_head = blk_of_timer_blks_desc;

	/* Link these timer_blks together. */
	timer_blk      = block_of_timer_blks;
	next_timer_blk = timer_blk + 1;
	for (idx = 0; idx < num_timer_blks - 1; idx++) {
		timer_blk->next_timer_blk = next_timer_blk;
		timer_blk = next_timer_blk;
		next_timer_blk++;
	}

	timer_blk->next_timer_blk     = timer_wheels->free_list_head;
	timer_wheels->free_list_size += num_timer_blks;
	timer_wheels->free_list_head  = block_of_timer_blks;
	if (timer_wheels->peak_free_list_size < timer_wheels->free_list_size)
		timer_wheels->peak_free_list_size =
			timer_wheels->free_list_size;
	return 0;
}

static timer_blk_t *timer_blk_alloc(timer_wheels_t *timer_wheels)
{
	timer_blk_t *head_timer_blk;
	int         rc;

	if (timer_wheels->free_list_size <= 1) {
		/* Replenish the timer_blk_t free list. */
		timer_wheels->min_free_list_size = timer_wheels->free_list_size;
		rc = free_list_add(timer_wheels, 1024);
		if (rc < 0)
			return NULL;
	}

	head_timer_blk = timer_wheels->free_list_head;
	timer_wheels->free_list_size--;
	timer_wheels->free_list_head = head_timer_blk->next_timer_blk;
	if (timer_wheels->free_list_size < timer_wheels->min_free_list_size)
		timer_wheels->min_free_list_size = timer_wheels->free_list_size;

	memset(head_timer_blk, 0, sizeof(timer_blk_t));
	return head_timer_blk;
}

static void timer_blk_free(timer_wheels_t *timer_wheels,
			   timer_blk_t    *timer_blk)
{
	timer_blk->next_timer_blk = timer_wheels->free_list_head;
	timer_wheels->free_list_head = timer_blk;
	timer_wheels->free_list_size++;
	if (timer_wheels->peak_free_list_size < timer_wheels->free_list_size)
		timer_wheels->peak_free_list_size =
			timer_wheels->free_list_size;
}

static int current_wheel_insert(timer_wheels_t *timer_wheels,
				uint64_t        rel_ticks,
				uint64_t        user_data)
{
	current_timer_slot_t *timer_slot;
	current_wheel_t      *current_wheel;
	wheel_desc_t         *wheel_desc;
	timer_blk_t          *new_timer_blk, *timer_blk;
	uint64_t              num_slots, slot_idx;
	uint32_t              wheel_idx, idx;

       /* To reach here it must be the case that (wakeup_ticks -
	* current_ticks) is < 2 * current_wheel->num_slots.
	*/
	wheel_desc    = &timer_wheels->wheel_descs[0];
	current_wheel = timer_wheels->current_wheel;
	slot_idx      = wheel_desc->slot_idx;
	num_slots     = (uint64_t)wheel_desc->num_slots;
	wheel_idx     = (uint32_t)((slot_idx + rel_ticks) & (num_slots - 1));
	timer_slot    = &current_wheel->slots[wheel_idx];

       /* Three cases: (a) the timer_slot is currently empty, (b) the
	* timer_slot contains a single user_data word directly inside it or
	* (c) the timer_slot contains a pointer to a linked list of
	* timer_blk's.
	*/
	if (timer_slot->user_data == 0) {                    /* case (a) */
		timer_slot->user_data = user_data | 0x01;
	} else if ((timer_slot->user_data & 0x3) == 0x01)  { /* case (b) */
	       /* Need to promote this pre-existing single user_data plus the
		* new user_data into a timer_blk with two entries.
		*/
		new_timer_blk = timer_blk_alloc(timer_wheels);
		if (!new_timer_blk)
			return -1;

		new_timer_blk->next_timer_blk           = NULL;
		new_timer_blk->current_blk.user_data[0] = timer_slot->user_data;
		new_timer_blk->current_blk.user_data[1] = user_data;
		timer_slot->timer_blk_list              = new_timer_blk;
	} else {   /* case (c) */
		/* First try to find an empty slot in the current timer_blk. */
		timer_blk = timer_slot->timer_blk_list;
		for (idx = 0; idx < 15; idx++) {
			if (timer_blk->current_blk.user_data[idx] == 0) {
				timer_blk->current_blk.user_data[idx] =
					user_data;
				return 0;
			}
		}

	       /* current timer_blk is full, so we need to allocate a new one
		* and link it in.
		*/
		new_timer_blk = timer_blk_alloc(timer_wheels);
		if (!new_timer_blk)
			return -1;

		new_timer_blk->next_timer_blk           = timer_blk;
		new_timer_blk->current_blk.user_data[0] = user_data;
		timer_slot->timer_blk_list              = new_timer_blk;
	}

	return 0;
}

static int general_wheel_insert(timer_wheels_t *timer_wheels,
				uint32_t        desc_idx,
				uint64_t        wakeup_ticks,
				uint64_t        rel_ticks,
				uint64_t        user_data)
{
	general_timer_slot_t *timer_slot;
	general_wheel_t      *general_wheel;
	wheel_desc_t         *wheel_desc;
	timer_blk_t          *new_timer_blk, *timer_blk;
	uint64_t              num_slots, old_user_data;
	uint32_t              slot_idx, wheel_idx, wakeup32, kind;
	uint32_t              old_wakeup32, idx;

	/* To reach here it must be the case that
	 * "(wakeup_ticks - current_ticks) >> ticks_shift < 2 * num_slots".
	 */
	wheel_desc    = &timer_wheels->wheel_descs[desc_idx];
	general_wheel = timer_wheels->general_wheels[desc_idx - 1];
	slot_idx      = wheel_desc->slot_idx;
	num_slots     = (uint64_t)wheel_desc->num_slots;
	wakeup32      = (uint32_t)(wakeup_ticks & 0xFFFFFFFF);
	rel_ticks     = rel_ticks >> wheel_desc->ticks_shift;
	wheel_idx     = (uint32_t)((slot_idx + rel_ticks) & (num_slots - 1));
	timer_slot    = &general_wheel->slots[wheel_idx];
	kind          = timer_slot->single_entry.kind;

       /* Three cases: (a) the timer_slot is currently empty, (b) the
	* timer_slot contains a single user_data word directly inside it or
	* (c) the timer_slot contains a pointer to a linked list of
	* timer_blk's.
	*/
	if (kind == 0) {                 /* case (a) */
		timer_slot->single_entry.kind      = 1;
		timer_slot->single_entry.wakeup32  = wakeup32;
		timer_slot->single_entry.user_data = user_data;
	} else if (kind == 1) {          /* case (b) */
	       /* Need to promote this single entry plus the new user_data
		* into a timer_blk with two entries.
		*/
		new_timer_blk = timer_blk_alloc(timer_wheels);
		if (!new_timer_blk)
			return -1;

		old_user_data = timer_slot->single_entry.user_data;
		old_wakeup32  = timer_slot->single_entry.wakeup32;

		new_timer_blk->next_timer_blk           = NULL;
		new_timer_blk->general_blk.user_data[0] = old_user_data;
		new_timer_blk->general_blk.wakeup32[0]  = old_wakeup32;
		new_timer_blk->general_blk.user_data[1] = user_data;
		new_timer_blk->general_blk.wakeup32[1]  = wakeup32;
		timer_slot->list_entry.kind             = 2;
		timer_slot->list_entry.num_blks         = 1;
		timer_slot->list_entry.timer_blk_list   = new_timer_blk;
	} else  { /* case (c) */
		/* First try to find an empty slot in the first timer_blk. */
		timer_blk = timer_slot->list_entry.timer_blk_list;
		for (idx = 0; idx < 10; idx++) {
			if (timer_blk->general_blk.user_data[idx] == 0) {
				timer_blk->general_blk.user_data[idx] =
					user_data;
				timer_blk->general_blk.wakeup32[idx]  =
					wakeup32;
				return 0;
			}
		}

	       /* The first timer_blk is full, so we need to allocate a new
		* one and link it in.
		*/
		new_timer_blk = timer_blk_alloc(timer_wheels);
		if (!new_timer_blk)
			return -1;

		new_timer_blk->next_timer_blk           = timer_blk;
		new_timer_blk->general_blk.user_data[0] = user_data;
		new_timer_blk->general_blk.wakeup32[0]  = wakeup32;
		timer_slot->list_entry.kind             = 2;
		timer_slot->list_entry.num_blks++;
		timer_slot->list_entry.timer_blk_list   = new_timer_blk;
	}

	return 0;
}

static int expired_timers_append(timer_wheels_t       *timer_wheels,
				 current_timer_slot_t *timer_slot)
{
	expired_ring_t *expired_ring;
	uint32_t        tail_idx;

	/* Append either this single entry or the entire timer_blk_list to the
	 * ring of expired_timers.
	 */
	expired_ring = timer_wheels->expired_timers_ring;
	if (expired_ring->max_idx <= expired_ring->count)
		return -1;

	tail_idx = expired_ring->tail_idx;
	expired_ring->entries[tail_idx] = *timer_slot;
	tail_idx++;
	if (expired_ring->max_idx < tail_idx)
		tail_idx = 0;

	expired_ring->tail_idx = tail_idx;
	expired_ring->count++;
	if (expired_ring->peak_count < expired_ring->count)
		expired_ring->peak_count = expired_ring->count;
	return 0;
}

static int timer_blk_list_search(timer_wheels_t       *timer_wheels,
				 current_timer_slot_t *head_entry,
				 uint64_t             *user_data_ptr)
{
	timer_blk_t *timer_blk, *next_timer_blk;
	uint64_t     user_data;
	uint32_t     idx;

	timer_blk = head_entry->timer_blk_list;
	while (timer_blk) {
		for (idx = 0; idx < 15; idx++) {
			user_data = timer_blk->current_blk.user_data[idx];
			if (user_data != 0) {
				*user_data_ptr =
					timer_blk->current_blk.user_data[idx];
				timer_blk->current_blk.user_data[idx] = 0;
				return 1;
			}
		}

		next_timer_blk = timer_blk->next_timer_blk;
		timer_blk_free(timer_wheels, timer_blk);
		timer_blk = next_timer_blk;
	}

	return 0;
}

static int expired_timers_remove(timer_wheels_t *timer_wheels,
				 uint64_t       *user_data_ptr)
{
	current_timer_slot_t *head_entry;
	expired_ring_t       *expired_ring;
	uint32_t              count, head_idx;
	int                   rc;

	expired_ring = timer_wheels->expired_timers_ring;
	for (count = 1; count <= 2; count++) {
		if (expired_ring->count == 0)
			return 0;

		head_idx   = expired_ring->head_idx;
		head_entry = &expired_ring->entries[head_idx];
		if ((head_entry->user_data & 0x3) == 1) {
			*user_data_ptr = head_entry->user_data;
			expired_ring->entries[head_idx].user_data = 0;
			head_idx++;
			if (expired_ring->max_idx < head_idx)
				head_idx = 0;

			expired_ring->head_idx = head_idx;
			expired_ring->count--;
			return 1;
		}

		/* Search timer_blk_list for non-empty user_data values. */
		rc = timer_blk_list_search(timer_wheels, head_entry,
					   user_data_ptr);
		if (0 < rc)
			return 1;

		/* Advance to use the next ring entry. */
		expired_ring->entries[head_idx].user_data = 0;
		head_idx++;
		if (expired_ring->max_idx < head_idx)
			head_idx = 0;

		expired_ring->head_idx = head_idx;
		expired_ring->count--;
	}

	return 0;
}

static int timer_current_wheel_update(timer_wheels_t *timer_wheels,
				      uint32_t        elapsed_ticks)
{
	current_timer_slot_t *timer_slot;
	current_wheel_t      *current_wheel;
	wheel_desc_t         *wheel_desc;
	uint64_t              max_ticks;
	uint32_t              num_slots, slot_idx, max_cnt, cnt;
	int                   ret_code, rc;

	/* Advance current wheel for each elapsed tick, up to a maximum. */
	wheel_desc    = &timer_wheels->wheel_descs[0];
	slot_idx      = wheel_desc->slot_idx;
	num_slots     = wheel_desc->num_slots;
	max_ticks     = wheel_desc->max_ticks;
	max_cnt       = MIN(elapsed_ticks, UINT32_C(32));
	current_wheel = timer_wheels->current_wheel;
	ret_code      = 0;
	rc            = -1;

	for (cnt = 1; cnt <= max_cnt; cnt++) {
		ret_code  |= (slot_idx & wheel_desc->gear_mask) == 0;
		timer_slot = &current_wheel->slots[slot_idx];
		if (timer_slot->user_data != 0) {
			rc = expired_timers_append(timer_wheels, timer_slot);
			if (rc < 0)
				timer_wheels->
					expired_timers_ring->
					expired_ring_full_cnt++;

			timer_slot->user_data = 0;
		}

		timer_wheels->current_ticks++;
		slot_idx++;
		max_ticks++;
		if (num_slots <= slot_idx) {
			slot_idx = 0;
			max_ticks = wheel_desc->ticks_per_rev;
		}
	}

	wheel_desc->slot_idx  = slot_idx;
	wheel_desc->max_ticks = max_ticks;
	return ret_code;
}

static int _odp_int_timer_wheel_promote(timer_wheels_t *timer_wheels,
					uint32_t        desc_idx,
					uint64_t        wakeup_ticks,
					uint64_t        user_data)
{
	uint64_t rel_ticks;

	rel_ticks = wakeup_ticks - timer_wheels->current_ticks;
	if (desc_idx == 0)
		return current_wheel_insert(timer_wheels, rel_ticks, user_data);
	else
		return general_wheel_insert(timer_wheels, desc_idx,
					    wakeup_ticks, rel_ticks, user_data);
}

static void timer_wheel_slot_promote(timer_wheels_t       *timer_wheels,
				     uint32_t              desc_idx,
				     general_timer_slot_t *timer_slot)
{
	general_blk_t *general_blk;
	timer_blk_t   *timer_blk, *next_timer_blk;
	uint64_t       user_data, current_ticks, current_ticks_msb;
	uint64_t       wakeup_ticks;
	uint32_t       idx, wakeup32;
	int            rc;

	current_ticks     = timer_wheels->current_ticks;
	current_ticks_msb = (current_ticks >> 32) << 32;
	if (timer_slot->single_entry.kind == 1) {
		user_data    = timer_slot->single_entry.user_data;
		wakeup32     = timer_slot->single_entry.wakeup32;
		wakeup_ticks = current_ticks_msb | (uint64_t)wakeup32;
		if (wakeup_ticks <= current_ticks) {
			if ((current_ticks - wakeup_ticks) <= (1ULL << 31))
				wakeup_ticks = current_ticks + 1;
			else
				wakeup_ticks += 1ULL << 32;
		}

		rc = _odp_int_timer_wheel_promote(timer_wheels, desc_idx,
						  wakeup_ticks, user_data);
		if (rc < 0)
			timer_wheels->promote_fail_cnt++;
		else
			timer_wheels->total_promote_cnt++;
		return;
	}

	timer_blk = timer_slot->list_entry.timer_blk_list;
	while (timer_blk) {
		general_blk = &timer_blk->general_blk;
		for (idx = 0; idx < 10; idx++) {
			user_data = general_blk->user_data[idx];
			if (user_data == 0)
				break;

			wakeup32     = general_blk->wakeup32[idx];
			wakeup_ticks = current_ticks_msb | (uint64_t)wakeup32;
			if (wakeup_ticks <= current_ticks) {
				if ((current_ticks - wakeup_ticks) <=
				    (1ULL << 31))
					wakeup_ticks = current_ticks + 1;
				else
					wakeup_ticks += 1ULL << 32;
			}

			rc = _odp_int_timer_wheel_promote(timer_wheels,
							  desc_idx,
							  wakeup_ticks,
							  user_data);
			if (rc < 0)
				timer_wheels->promote_fail_cnt++;
			else
				timer_wheels->total_promote_cnt++;
		}

		next_timer_blk = timer_blk->next_timer_blk;
		timer_blk_free(timer_wheels, timer_blk);
		timer_blk = next_timer_blk;
	}
}

static int timer_general_wheel_update(timer_wheels_t *timer_wheels,
				      uint32_t        desc_idx)
{
	general_timer_slot_t *timer_slot;
	general_wheel_t      *general_wheel;
	wheel_desc_t         *wheel_desc;
	uint64_t              max_ticks;
	uint32_t              num_slots, slot_idx;
	int                   ret_code;

	wheel_desc    = &timer_wheels->wheel_descs[desc_idx];
	slot_idx      = wheel_desc->slot_idx;
	num_slots     = wheel_desc->num_slots;
	max_ticks     = wheel_desc->max_ticks;
	general_wheel = timer_wheels->general_wheels[desc_idx - 1];
	timer_slot    = &general_wheel->slots[slot_idx];
	ret_code      = (slot_idx & wheel_desc->gear_mask) == 0;

	if (timer_slot->single_entry.kind != 0) {
		timer_wheel_slot_promote(timer_wheels,
					 desc_idx - 1, timer_slot);
		timer_slot->single_entry.kind = 0;
	}

	slot_idx++;
	max_ticks++;
	if (num_slots <= slot_idx) {
		slot_idx = 0;
		max_ticks = wheel_desc->ticks_per_rev;
	}

	wheel_desc->slot_idx  = slot_idx;
	wheel_desc->max_ticks = max_ticks;
	return ret_code;
}

_odp_timer_wheel_t _odp_timer_wheel_create(uint32_t max_concurrent_timers,
					   void    *tm_system)
{
	timer_wheels_t *timer_wheels;
	int             rc;

	timer_wheels  = malloc(sizeof(timer_wheels_t));
	memset(timer_wheels, 0, sizeof(timer_wheels_t));

	timer_wheels->wheel_descs[0].num_slots = CURRENT_TIMER_SLOTS;
	timer_wheels->wheel_descs[1].num_slots = LEVEL1_TIMER_SLOTS;
	timer_wheels->wheel_descs[2].num_slots = LEVEL2_TIMER_SLOTS;
	timer_wheels->wheel_descs[3].num_slots = LEVEL3_TIMER_SLOTS;

	timer_wheels->wheel_descs[0].gear_ratio = CURRENT_GEAR_RATIO;
	timer_wheels->wheel_descs[1].gear_ratio = LEVEL1_GEAR_RATIO;
	timer_wheels->wheel_descs[2].gear_ratio = LEVEL2_GEAR_RATIO;
	timer_wheels->wheel_descs[3].gear_ratio = 1;

	timer_wheels->wheel_descs[0].ticks_per_slot = TICKS_PER_CURRENT_SLOT;
	timer_wheels->wheel_descs[1].ticks_per_slot = TICKS_PER_LEVEL1_SLOT;
	timer_wheels->wheel_descs[2].ticks_per_slot = TICKS_PER_LEVEL2_SLOT;
	timer_wheels->wheel_descs[3].ticks_per_slot = TICKS_PER_LEVEL3_SLOT;

	timer_wheels->current_wheel     = current_wheel_alloc(timer_wheels, 0);
	timer_wheels->general_wheels[0] = general_wheel_alloc(timer_wheels, 1);
	timer_wheels->general_wheels[1] = general_wheel_alloc(timer_wheels, 2);
	timer_wheels->general_wheels[2] = general_wheel_alloc(timer_wheels, 3);

	timer_wheels->tm_system = tm_system;

	rc = expired_ring_create(timer_wheels, EXPIRED_RING_ENTRIES);
	if (rc < 0)
		return _ODP_INT_TIMER_WHEEL_INVALID;

	free_list_add(timer_wheels, max_concurrent_timers / 4);
	timer_wheels->min_free_list_size  = timer_wheels->free_list_size;
	timer_wheels->peak_free_list_size = timer_wheels->free_list_size;
	return (_odp_timer_wheel_t)(uintptr_t)timer_wheels;
}

void _odp_timer_wheel_start(_odp_timer_wheel_t timer_wheel,
			    uint64_t           current_time)
{
	timer_wheels_t *timer_wheels;
	uint64_t        current_ticks;

	timer_wheels  = (timer_wheels_t *)(uintptr_t)timer_wheel;
	current_ticks = current_time >> TIME_TO_TICKS_SHIFT;
	timer_wheels->current_ticks = current_ticks;

	current_wheel_start(timer_wheels, 0, current_ticks);
	general_wheel_start(timer_wheels, 1, current_ticks);
	general_wheel_start(timer_wheels, 2, current_ticks);
	general_wheel_start(timer_wheels, 3, current_ticks);
}

uint32_t _odp_timer_wheel_curr_time_update(_odp_timer_wheel_t timer_wheel,
					   uint64_t           current_time)
{
	timer_wheels_t *timer_wheels;
	uint64_t        new_current_ticks, elapsed_ticks;
	uint32_t        desc_idx;
	int             rc;

	timer_wheels      = (timer_wheels_t *)(uintptr_t)timer_wheel;
	new_current_ticks = current_time >> TIME_TO_TICKS_SHIFT;
	elapsed_ticks     = new_current_ticks - timer_wheels->current_ticks;
	if (elapsed_ticks == 0)
		return 0;

       /* Advance current wheel for each elapsed tick, up to a maximum. This
	* function returns a value > 0, then the next level's timer wheel
	* needs to be updated.
	*/
	rc = timer_current_wheel_update(timer_wheels, (uint32_t)elapsed_ticks);

	/* See if we need to do any higher wheel advancing or processing.*/
	desc_idx = 1;
	while ((0 < rc) && (desc_idx <= 3))
		rc = timer_general_wheel_update(timer_wheels, desc_idx++);

	return timer_wheels->expired_timers_ring->count;
}

int _odp_timer_wheel_insert(_odp_timer_wheel_t timer_wheel,
			    uint64_t           wakeup_time,
			    uint64_t           user_context)
{
	timer_wheels_t *timer_wheels;
	uint64_t        wakeup_ticks, rel_ticks;
	int             rc;

	if (user_context == 0)
		return -4;  /* user_context cannot be 0! */
	else if ((user_context & 0x3) != 0)
		return -5;  /* user_context must be at least 4-byte aligned. */

	timer_wheels = (timer_wheels_t *)(uintptr_t)timer_wheel;
	wakeup_ticks = (wakeup_time >> TIME_TO_TICKS_SHIFT) + 1;
	if (wakeup_time <= timer_wheels->current_ticks)
		return -6;

	rel_ticks = wakeup_ticks - timer_wheels->current_ticks;
	if (rel_ticks < timer_wheels->wheel_descs[0].max_ticks)
		rc = current_wheel_insert(timer_wheels, rel_ticks,
					  user_context);
	else if (rel_ticks < timer_wheels->wheel_descs[1].max_ticks)
		rc = general_wheel_insert(timer_wheels, 1, wakeup_ticks,
					  rel_ticks, user_context);
	else if (rel_ticks < timer_wheels->wheel_descs[2].max_ticks)
		rc = general_wheel_insert(timer_wheels, 2, wakeup_ticks,
					  rel_ticks, user_context);
	else if (rel_ticks < timer_wheels->wheel_descs[3].max_ticks)
		rc = general_wheel_insert(timer_wheels, 3, wakeup_ticks,
					  rel_ticks, user_context);
	else
		return -1;

	if (rc < 0) {
		timer_wheels->insert_fail_cnt++;
		return rc;
	}

	timer_wheels->total_timer_inserts++;
	timer_wheels->current_cnt++;
	return 0;
}

uint64_t _odp_timer_wheel_next_expired(_odp_timer_wheel_t timer_wheel)
{
	timer_wheels_t *timer_wheels;
	uint64_t        user_data;
	int             rc;

	/* Remove the head of the timer wheel. */
	timer_wheels = (timer_wheels_t *)(uintptr_t)timer_wheel;
	rc = expired_timers_remove(timer_wheels, &user_data);
	if (rc <= 0)
		return 0;

	user_data &= ~0x3;
	timer_wheels->total_timer_removes++;
	if (timer_wheels->current_cnt != 0)
		timer_wheels->current_cnt--;
	return user_data;
}

uint32_t _odp_timer_wheel_count(_odp_timer_wheel_t timer_wheel)
{
	timer_wheels_t *timer_wheels;

	timer_wheels = (timer_wheels_t *)(uintptr_t)timer_wheel;
	return timer_wheels->total_timer_inserts -
		timer_wheels->total_timer_removes;
}

static void _odp_int_timer_wheel_desc_print(wheel_desc_t *wheel_desc,
					    uint32_t      wheel_idx)
{
	ODP_PRINT("  wheel=%u num_slots=%u ticks_shift=%u ticks_per_slot=%u"
		  " ticks_per_rev=%" PRIu64 "\n",
		  wheel_idx, wheel_desc->num_slots, wheel_desc->ticks_shift,
		  wheel_desc->ticks_per_slot, wheel_desc->ticks_per_rev);
}

void _odp_timer_wheel_stats_print(_odp_timer_wheel_t timer_wheel)
{
	timer_wheels_t *timer_wheels;
	expired_ring_t *expired_ring;
	uint32_t        wheel_idx;

	timer_wheels = (timer_wheels_t *)(uintptr_t)timer_wheel;
	expired_ring = timer_wheels->expired_timers_ring;

	ODP_PRINT("_odp_int_timer_wheel_stats current_ticks=%" PRIu64 "\n",
		  timer_wheels->current_ticks);
	for (wheel_idx = 0; wheel_idx < 4; wheel_idx++)
		_odp_int_timer_wheel_desc_print(
			&timer_wheels->wheel_descs[wheel_idx],
			wheel_idx);

	ODP_PRINT("  total timer_inserts=%" PRIu64 " timer_removes=%" PRIu64
		  " insert_fails=%" PRIu64 "\n",
		  timer_wheels->total_timer_inserts,
		  timer_wheels->total_timer_removes,
		  timer_wheels->insert_fail_cnt);
	ODP_PRINT("  total_promote_cnt=%" PRIu64 " promote_fail_cnt=%"
		  PRIu64 "\n", timer_wheels->total_promote_cnt,
		  timer_wheels->promote_fail_cnt);
	ODP_PRINT("  free_list_size=%u min_size=%u peak_size=%u\n",
		  timer_wheels->free_list_size,
		  timer_wheels->min_free_list_size,
		  timer_wheels->peak_free_list_size);
	ODP_PRINT("  expired_timers_ring size=%u count=%u "
		  "peak_count=%u full_cnt=%u\n",
		  expired_ring->max_idx + 1, expired_ring->count,
		  expired_ring->peak_count,
		  expired_ring->expired_ring_full_cnt);
}

void _odp_timer_wheel_destroy(_odp_timer_wheel_t timer_wheel)
{
	blk_of_timer_blks_desc_t *blk_of_timer_blks_desc, *next_desc;
	timer_wheels_t           *timer_wheels;
	expired_ring_t           *expired_ring;

	timer_wheels = (timer_wheels_t *)(uintptr_t)timer_wheel;
	expired_ring = timer_wheels->expired_timers_ring;

	/* First free all of the block_of_timer_blks */
	blk_of_timer_blks_desc = timer_wheels->timer_blks_list_head;
	while (blk_of_timer_blks_desc) {
		next_desc = blk_of_timer_blks_desc->next;
		free(blk_of_timer_blks_desc->block_of_timer_blks);
		free(blk_of_timer_blks_desc);
		blk_of_timer_blks_desc = next_desc;
	}

	free(timer_wheels->current_wheel);
	free(timer_wheels->general_wheels[0]);
	free(timer_wheels->general_wheels[1]);
	free(timer_wheels->general_wheels[2]);
	free(expired_ring);
	free(timer_wheels);
}
