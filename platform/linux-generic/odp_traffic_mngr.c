/* Copyright 2015 EZchip Semiconductor Ltd. All Rights Reserved.
 *
 * Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdint.h>
#include <string.h>
#include <malloc.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pthread.h>
#include <odp/api/std_types.h>
#include <odp_traffic_mngr_internal.h>

/* Local vars */
static const
_odp_int_name_kind_t PROFILE_TO_HANDLE_KIND[ODP_TM_NUM_PROFILES] = {
	[TM_SHAPER_PROFILE] = ODP_TM_SHAPER_PROFILE_HANDLE,
	[TM_SCHED_PROFILE] = ODP_TM_SCHED_PROFILE_HANDLE,
	[TM_THRESHOLD_PROFILE] = ODP_TM_THRESHOLD_PROFILE_HANDLE,
	[TM_WRED_PROFILE] = ODP_TM_WRED_PROFILE_HANDLE
};

static const pkt_desc_t EMPTY_PKT_DESC = { .word = 0 };

#define MAX_PRIORITIES ODP_TM_MAX_PRIORITIES
#define NUM_SHAPER_COLORS ODP_NUM_SHAPER_COLORS

static tm_prop_t basic_prop_tbl[MAX_PRIORITIES][NUM_SHAPER_COLORS] = {
	[0] = {
		[ODP_TM_SHAPER_GREEN] = { 0, DECR_BOTH },
		[ODP_TM_SHAPER_YELLOW] = { 0, DECR_BOTH },
		[ODP_TM_SHAPER_RED] = { 0, DELAY_PKT } },
	[1] = {
		[ODP_TM_SHAPER_GREEN] = { 1, DECR_BOTH },
		[ODP_TM_SHAPER_YELLOW] = { 1, DECR_BOTH },
		[ODP_TM_SHAPER_RED] = { 1, DELAY_PKT } },
	[2] = {
		[ODP_TM_SHAPER_GREEN] = { 2, DECR_BOTH },
		[ODP_TM_SHAPER_YELLOW] = { 2, DECR_BOTH },
		[ODP_TM_SHAPER_RED] = { 2, DELAY_PKT } },
	[3] = {
		[ODP_TM_SHAPER_GREEN] = { 3, DECR_BOTH },
		[ODP_TM_SHAPER_YELLOW] = { 3, DECR_BOTH },
		[ODP_TM_SHAPER_RED] = { 3, DELAY_PKT } },
	[4] = {
		[ODP_TM_SHAPER_GREEN] = { 4, DECR_BOTH },
		[ODP_TM_SHAPER_YELLOW] = { 4, DECR_BOTH },
		[ODP_TM_SHAPER_RED] = { 4, DELAY_PKT } },
	[5] = {
		[ODP_TM_SHAPER_GREEN] = { 5, DECR_BOTH },
		[ODP_TM_SHAPER_YELLOW] = { 5, DECR_BOTH },
		[ODP_TM_SHAPER_RED] = { 5, DELAY_PKT } },
	[6] = {
		[ODP_TM_SHAPER_GREEN] = { 6, DECR_BOTH },
		[ODP_TM_SHAPER_YELLOW] = { 6, DECR_BOTH },
		[ODP_TM_SHAPER_RED] = { 6, DELAY_PKT } },
	[7] = {
		[ODP_TM_SHAPER_GREEN] = { 7, DECR_BOTH },
		[ODP_TM_SHAPER_YELLOW] = { 7, DECR_BOTH },
		[ODP_TM_SHAPER_RED] = { 7, DELAY_PKT } }
};

/* Profile tables. */
static dynamic_tbl_t odp_tm_profile_tbls[ODP_TM_NUM_PROFILES];

/* TM systems table. */
static tm_system_t *odp_tm_systems[ODP_TM_MAX_NUM_SYSTEMS];

static uint64_t odp_tm_cycles_per_sec = ODP_CYCLES_PER_SEC;

static odp_ticketlock_t tm_create_lock;
static odp_ticketlock_t tm_profile_lock;
static odp_barrier_t tm_first_enq;

/* Forward function declarations. */
static void tm_queue_cnts_decrement(tm_system_t *tm_system,
				    tm_wred_node_t *tm_wred_node,
				    uint32_t priority,
				    uint32_t frame_len);

static int tm_demote_pkt_desc(tm_system_t *tm_system,
			      tm_node_obj_t *tm_node_obj,
			      tm_schedulers_obj_t *blocked_scheduler,
			      tm_shaper_obj_t *timer_shaper,
			      pkt_desc_t *demoted_pkt_desc);

static tm_queue_obj_t *get_tm_queue_obj(tm_system_t *tm_system,
					pkt_desc_t *pkt_desc)
{
	tm_queue_obj_t *tm_queue_obj;
	uint32_t queue_num;

	if ((!pkt_desc) || (pkt_desc->queue_num == 0))
		return NULL;

	queue_num = pkt_desc->queue_num;
	/* Assert(queue_num < tm_system->next_queue_num); */

	tm_queue_obj = tm_system->queue_num_tbl[queue_num];
	return tm_queue_obj;
}

static odp_bool_t pkt_descs_equal(pkt_desc_t *pkt_desc1, pkt_desc_t *pkt_desc2)
{
	if ((!pkt_desc1) || (pkt_desc1->queue_num == 0))
		return 0;
	else if ((!pkt_desc2) || (pkt_desc2->queue_num == 0))
		return 0;
	else if ((pkt_desc1->queue_num == pkt_desc2->queue_num) &&
		 (pkt_desc1->epoch     == pkt_desc2->epoch)     &&
		 (pkt_desc1->pkt_len   == pkt_desc2->pkt_len))
		return 1;
	else
		return 0;
}

static odp_bool_t pkt_descs_not_equal(pkt_desc_t *pkt_desc1,
				      pkt_desc_t *pkt_desc2)
{
	if ((!pkt_desc1) || (pkt_desc1->queue_num == 0))
		return 1;
	else if ((!pkt_desc2) || (pkt_desc2->queue_num == 0))
		return 1;
	else if ((pkt_desc1->queue_num == pkt_desc2->queue_num) &&
		 (pkt_desc1->epoch     == pkt_desc2->epoch)     &&
		 (pkt_desc1->pkt_len   == pkt_desc2->pkt_len))
		return 0;
	else
		return 1;
}

static void tm_init_random_data(tm_random_data_t *tm_random_data)
{
	uint32_t byte_cnt;

       /* Keep calling odp_random_data until we have filled the entire random
	* data buffer.  Hopefully we don't need to call odp_random_data too
	* many times to get 256 bytes worth of random data.
	*/
	byte_cnt = 0;
	while (byte_cnt < 256)
		byte_cnt += odp_random_data(&tm_random_data->buf[byte_cnt],
					    256 - byte_cnt, 1);

	tm_random_data->next_random_byte = 0;
}

static uint16_t tm_random16(tm_random_data_t *tm_random_data)
{
	uint32_t buf_idx;
	uint16_t rand8a, rand8b;

	if (256 <= tm_random_data->next_random_byte)
		tm_init_random_data(tm_random_data);

       /* Collect 2 random bytes and return them.  Endianness does NOT matter
	* here.  This code does assume that next_random_byte is a multiple of
	* 2.
	*/
	buf_idx = tm_random_data->next_random_byte;
	rand8a = tm_random_data->buf[buf_idx++];
	rand8b = tm_random_data->buf[buf_idx++];

	tm_random_data->next_random_byte = buf_idx;
	return (rand8b << 8) | rand8a;
}

static odp_bool_t tm_random_drop(tm_random_data_t *tm_random_data,
				 odp_tm_percent_t drop_prob)
{
	odp_bool_t drop;
	uint32_t random_int, scaled_random_int;

	/* Pick a random integer between 0 and 10000. */
	random_int = tm_random16(tm_random_data);
	scaled_random_int = (random_int * 10000) >> 16;
	drop = scaled_random_int < (uint32_t)drop_prob;
	return drop;
}

static void *alloc_entry_in_dynamic_tbl(dynamic_tbl_t *dynamic_tbl,
					uint32_t record_size,
					uint32_t *dynamic_idx_ptr)
{
	uint32_t num_allocd, new_num_allocd, idx;
	void **new_array_ptrs, *new_record;

	num_allocd = dynamic_tbl->num_allocd;
	if (num_allocd <= dynamic_tbl->num_used) {
		/* Need to alloc or realloc the array of ptrs. */
		if (num_allocd <= 32)
			new_num_allocd = 64;
		else
			new_num_allocd = 4 * num_allocd;

		new_array_ptrs = malloc(new_num_allocd * sizeof(void *));
		memset(new_array_ptrs, 0, new_num_allocd * sizeof(void *));

		if (dynamic_tbl->num_used != 0)
			memcpy(new_array_ptrs, dynamic_tbl->array_ptrs,
			       dynamic_tbl->num_used * sizeof(void *));

		if (dynamic_tbl->array_ptrs)
			free(dynamic_tbl->array_ptrs);

		dynamic_tbl->num_allocd = new_num_allocd;
		dynamic_tbl->array_ptrs = new_array_ptrs;
	}

	idx = dynamic_tbl->num_used;
	new_record = malloc(record_size);
	memset(new_record, 0, record_size);

	dynamic_tbl->array_ptrs[idx] = new_record;
	dynamic_tbl->num_used++;
	if (dynamic_idx_ptr)
		*dynamic_idx_ptr = idx;

	return new_record;
}

static void free_dynamic_tbl_entry(dynamic_tbl_t *dynamic_tbl ODP_UNUSED,
				   uint32_t record_size ODP_UNUSED,
				   uint32_t dynamic_idx ODP_UNUSED)
{
	/* < @todo Currently we don't bother with freeing. */
}

static input_work_queue_t *input_work_queue_create(void)
{
	input_work_queue_t *input_work_queue;

	input_work_queue = malloc(sizeof(input_work_queue_t));
	memset(input_work_queue, 0, sizeof(input_work_queue_t));
	odp_atomic_init_u32(&input_work_queue->queue_cnt, 0);
	odp_ticketlock_init(&input_work_queue->lock);
	return input_work_queue;
}

static void input_work_queue_destroy(input_work_queue_t *input_work_queue)
{
       /* We first need to "flush/drain" this input_work_queue before
	* freeing it.  Of course, elsewhere it is essential to have first
	* stopped new tm_enq() (et al) calls from succeeding.
	*/
	odp_ticketlock_lock(&input_work_queue->lock);
	free(input_work_queue);
}

static int input_work_queue_append(tm_system_t *tm_system,
				   input_work_item_t *work_item)
{
	input_work_queue_t *input_work_queue;
	input_work_item_t *entry_ptr;
	uint32_t queue_cnt, tail_idx;

	input_work_queue = tm_system->input_work_queue;
	queue_cnt = odp_atomic_load_u32(&input_work_queue->queue_cnt);
	if (INPUT_WORK_RING_SIZE <= queue_cnt) {
		input_work_queue->enqueue_fail_cnt++;
		return -1;
	}

	odp_ticketlock_lock(&input_work_queue->lock);
	tail_idx = input_work_queue->tail_idx;
	entry_ptr = &input_work_queue->work_ring[tail_idx];

	*entry_ptr = *work_item;
	tail_idx++;
	if (INPUT_WORK_RING_SIZE <= tail_idx)
		tail_idx = 0;

	input_work_queue->total_enqueues++;
	input_work_queue->tail_idx = tail_idx;
	odp_ticketlock_unlock(&input_work_queue->lock);
	odp_atomic_inc_u32(&input_work_queue->queue_cnt);
	if (input_work_queue->peak_cnt <= queue_cnt)
		input_work_queue->peak_cnt = queue_cnt + 1;
	return 0;
}

static int input_work_queue_remove(input_work_queue_t *input_work_queue,
				   input_work_item_t *work_item)
{
	input_work_item_t *entry_ptr;
	uint32_t queue_cnt, head_idx;

	queue_cnt = odp_atomic_load_u32(&input_work_queue->queue_cnt);
	if (queue_cnt == 0)
		return -1;

	odp_ticketlock_lock(&input_work_queue->lock);
	head_idx = input_work_queue->head_idx;
	entry_ptr = &input_work_queue->work_ring[head_idx];

	*work_item = *entry_ptr;
	head_idx++;
	if (INPUT_WORK_RING_SIZE <= head_idx)
		head_idx = 0;

	input_work_queue->total_dequeues++;
	input_work_queue->head_idx = head_idx;
	odp_ticketlock_unlock(&input_work_queue->lock);
	odp_atomic_dec_u32(&input_work_queue->queue_cnt);
	return 0;
}

static tm_system_t *tm_system_alloc(void)
{
	tm_system_t *tm_system;
	uint32_t tm_idx;

	/* Find an open slot in the odp_tm_systems array. */
	for (tm_idx = 0; tm_idx < ODP_TM_MAX_NUM_SYSTEMS; tm_idx++) {
		if (!odp_tm_systems[tm_idx]) {
			tm_system = malloc(sizeof(tm_system_t));
			memset(tm_system, 0, sizeof(tm_system_t));
			odp_tm_systems[tm_idx] = tm_system;
			tm_system->tm_idx = tm_idx;
			return tm_system;
		}
	}

	return NULL;
}

static void tm_system_free(tm_system_t *tm_system)
{
	/* @todo Free any internally malloc'd blocks. */
	odp_tm_systems[tm_system->tm_idx] = NULL;
	free(tm_system);
}

static void *tm_common_profile_create(const char *name,
				      profile_kind_t profile_kind,
				      uint32_t object_size,
				      tm_handle_t *profile_handle_ptr,
				      _odp_int_name_t *name_tbl_id_ptr)
{
	_odp_int_name_kind_t handle_kind;
	_odp_int_name_t name_tbl_id;
	dynamic_tbl_t *dynamic_tbl;
	tm_handle_t profile_handle;
	uint32_t dynamic_tbl_idx;
	void *object_ptr;

	dynamic_tbl = &odp_tm_profile_tbls[profile_kind];
	object_ptr = alloc_entry_in_dynamic_tbl(dynamic_tbl, object_size,
						&dynamic_tbl_idx);
	if (!object_ptr)
		return NULL;

	handle_kind = PROFILE_TO_HANDLE_KIND[profile_kind];
	profile_handle = MAKE_PROFILE_HANDLE(profile_kind, dynamic_tbl_idx);
	name_tbl_id = ODP_INVALID_NAME;

	if ((!name) && (name[0] != '\0')) {
		name_tbl_id = _odp_int_name_tbl_add(name, handle_kind,
						    profile_handle);
		if (name_tbl_id == ODP_INVALID_NAME) {
			free_dynamic_tbl_entry(dynamic_tbl, object_size,
					       dynamic_tbl_idx);
			return NULL;
		}
	}

	*profile_handle_ptr = profile_handle;
	if (name_tbl_id_ptr)
		*name_tbl_id_ptr = name_tbl_id;
	return object_ptr;
}

static void *tm_get_profile_params(tm_handle_t profile_handle,
				   profile_kind_t expected_profile_kind)
{
	profile_kind_t profile_kind;
	dynamic_tbl_t *dynamic_tbl;
	uint32_t dynamic_tbl_idx;

	profile_kind = GET_PROFILE_KIND(profile_handle);
	if (profile_kind != expected_profile_kind)
		return NULL;
	/* @todo Call some odp error function */

	dynamic_tbl = &odp_tm_profile_tbls[profile_kind];
	dynamic_tbl_idx = GET_TBL_IDX(profile_handle);
	return dynamic_tbl->array_ptrs[dynamic_tbl_idx];
}

static uint64_t tm_bps_to_rate(uint64_t bps)
{
	/* This code assumes that bps is in the range 1 kbps .. 1 tbps. */
	if ((bps >> 32) == 0)
		return (bps << 29) / odp_tm_cycles_per_sec;
	else
		return ((bps << 21) / odp_tm_cycles_per_sec) << 8;
}

static uint64_t tm_rate_to_bps(uint64_t rate)
{
	/* This code assumes that bps is in the range 1 kbps .. 1 tbps. */
	return (rate * odp_tm_cycles_per_sec) >> 29;
}

static uint64_t tm_max_time_delta(uint64_t rate)
{
	if (rate == 0)
		return 0;
	else
		return (1ULL << (26 + 30)) / rate;
}

static void tm_shaper_params_cvt_to(odp_tm_shaper_params_t *odp_shaper_params,
				    tm_shaper_params_t *tm_shaper_params)
{
	uint64_t commit_rate, peak_rate, max_commit_time_delta, highest_rate;
	uint64_t max_peak_time_delta;
	uint32_t min_time_delta;
	int64_t commit_burst, peak_burst;

	commit_rate = tm_bps_to_rate(odp_shaper_params->commit_bps);
	peak_rate = tm_bps_to_rate(odp_shaper_params->peak_bps);
	max_commit_time_delta = tm_max_time_delta(commit_rate);
	max_peak_time_delta = tm_max_time_delta(peak_rate);
	highest_rate = MAX(commit_rate, peak_rate);
	min_time_delta = (uint32_t)((1 << 26) / highest_rate);
	commit_burst = (int64_t)odp_shaper_params->commit_burst;
	peak_burst = (int64_t)odp_shaper_params->peak_burst;

	tm_shaper_params->max_commit_time_delta = max_commit_time_delta;
	tm_shaper_params->max_peak_time_delta = max_peak_time_delta;

	tm_shaper_params->commit_rate = commit_rate;
	tm_shaper_params->peak_rate = peak_rate;
	tm_shaper_params->max_commit = commit_burst << (26 - 3);
	tm_shaper_params->max_peak = peak_burst << (26 - 3);
	tm_shaper_params->min_time_delta = min_time_delta;
	tm_shaper_params->len_adjust = odp_shaper_params->shaper_len_adjust;
	tm_shaper_params->dual_rate = odp_shaper_params->dual_rate;
	tm_shaper_params->enabled = commit_rate != 0;
}

static void
tm_shaper_params_cvt_from(tm_shaper_params_t *tm_shaper_params,
			  odp_tm_shaper_params_t *odp_shaper_params)
{
	uint64_t commit_bps, peak_bps, commit_burst, peak_burst;

	commit_bps = tm_rate_to_bps(tm_shaper_params->commit_rate);
	peak_bps = tm_rate_to_bps(tm_shaper_params->peak_rate);
	commit_burst = tm_shaper_params->max_commit >> (26 - 3);
	peak_burst = tm_shaper_params->max_peak >> (26 - 3);

	odp_shaper_params->commit_bps = commit_bps;
	odp_shaper_params->peak_bps = peak_bps;
	odp_shaper_params->commit_burst = (uint32_t)commit_burst;
	odp_shaper_params->peak_burst = (uint32_t)peak_burst;
	odp_shaper_params->shaper_len_adjust = tm_shaper_params->len_adjust;
	odp_shaper_params->dual_rate = tm_shaper_params->dual_rate;
}

static void tm_shaper_obj_init(tm_system_t *tm_system,
			       tm_shaper_params_t *shaper_params,
			       tm_shaper_obj_t *shaper_obj)
{
	shaper_obj->shaper_params = shaper_params;
	shaper_obj->last_update_time = tm_system->current_cycles;
	shaper_obj->callback_time = 0;
	shaper_obj->commit_cnt = shaper_params->max_commit;
	shaper_obj->peak_cnt = shaper_params->max_peak;
	shaper_obj->callback_reason = NO_CALLBACK;
	shaper_obj->initialized = 1;
}

/* Any locking required must be done by the caller! */
static void tm_shaper_config_set(tm_system_t *tm_system,
				 odp_tm_shaper_t shaper_profile,
				 tm_shaper_obj_t *shaper_obj)
{
	tm_shaper_params_t *shaper_params;

	if (shaper_profile == ODP_TM_INVALID)
		return;

	shaper_params = tm_get_profile_params(shaper_profile,
					      TM_SHAPER_PROFILE);
	if (shaper_obj->initialized == 0)
		tm_shaper_obj_init(tm_system, shaper_params, shaper_obj);
	else
		shaper_obj->shaper_params = shaper_params;
}

static void update_shaper_elapsed_time(tm_system_t *tm_system,
				       tm_shaper_params_t *shaper_params,
				       tm_shaper_obj_t *shaper_obj)
{
	uint64_t time_delta;
	int64_t commit, peak, commit_inc, peak_inc, max_commit, max_peak;

       /* If the time_delta is "too small" then we just exit without making
	* any changes.  Too small is defined such that
	* time_delta/cycles_per_sec * MAX(commit_rate, peak_rate) is less
	* than a byte.
	*/
	time_delta = tm_system->current_cycles - shaper_obj->last_update_time;
	if (time_delta < (uint64_t)shaper_params->min_time_delta)
		return;

	commit = shaper_obj->commit_cnt;
	max_commit = shaper_params->max_commit;

       /* If the time_delta is "too large" then we need to prevent overflow
	* of the multiplications of time_delta and either commit_rate or
	* peak_rate.
	*/
	if (shaper_params->max_commit_time_delta <= time_delta)
		commit_inc = max_commit;
	else
		commit_inc = time_delta * shaper_params->commit_rate;

	shaper_obj->commit_cnt = (int64_t)MIN(max_commit, commit + commit_inc);

	if (shaper_params->peak_rate != 0) {
		peak = shaper_obj->peak_cnt;
		max_peak = shaper_params->max_peak;
		if (shaper_params->max_peak_time_delta <= time_delta)
			peak_inc = max_peak;
		else
			peak_inc = time_delta * shaper_params->peak_rate;

		shaper_obj->peak_cnt = (int64_t)MIN(max_peak, peak + peak_inc);
	}

	shaper_obj->last_update_time = tm_system->current_cycles;
}

static uint64_t cycles_till_not_red(tm_shaper_params_t *shaper_params,
				    tm_shaper_obj_t *shaper_obj)
{
	uint64_t min_time_delay, commit_delay, peak_delay;

       /* Normal case requires that peak_cnt be <= commit_cnt and that
	* peak_rate be >= commit_rate, but just in case this code handles other
	* weird cases that might actually be invalid.
	*/
	commit_delay = 0;
	if (shaper_obj->commit_cnt < 0)
		commit_delay = (-shaper_obj->commit_cnt)
			/ shaper_params->commit_rate;

	min_time_delay = MAX(shaper_obj->shaper_params->min_time_delta, 256);
	commit_delay = MAX(commit_delay, min_time_delay);
	if (shaper_params->peak_rate == 0)
		return commit_delay;

	peak_delay = 0;
	if (shaper_obj->peak_cnt < 0)
		peak_delay = (-shaper_obj->peak_cnt) / shaper_params->peak_rate;

	peak_delay = MAX(peak_delay, min_time_delay);
	if (0 < shaper_obj->commit_cnt)
		return peak_delay;
	else if (0 < shaper_obj->peak_cnt)
		return commit_delay;
	else
		return MIN(commit_delay, peak_delay);
}

static int delete_timer(tm_system_t *tm_system ODP_UNUSED,
			tm_queue_obj_t *tm_queue_obj,
			uint8_t cancel_timer)
{
	tm_shaper_obj_t *shaper_obj;

	shaper_obj = tm_queue_obj->timer_shaper;
	if (cancel_timer)
		tm_queue_obj->timer_cancels_outstanding++;

	if ((tm_queue_obj->timer_reason == NO_CALLBACK) ||
	    (!shaper_obj))
		return -1;

	tm_queue_obj->timer_reason = NO_CALLBACK;
	tm_queue_obj->timer_seq++;
	tm_queue_obj->timer_shaper = NULL;

	if (tm_queue_obj->delayed_cnt != 0)
		tm_queue_obj->delayed_cnt--;

	if (shaper_obj->timer_outstanding != 0)
		shaper_obj->timer_outstanding--;

	shaper_obj->timer_tm_queue = NULL;
	shaper_obj->callback_reason = NO_CALLBACK;
	return 0;
}

static void tm_unblock_pkt(tm_system_t *tm_system, pkt_desc_t *pkt_desc)
{
	tm_queue_obj_t *tm_queue_obj;

	tm_queue_obj = get_tm_queue_obj(tm_system, pkt_desc);
	tm_queue_obj->blocked_scheduler = NULL;
	if (tm_queue_obj->blocked_cnt != 0)
		tm_queue_obj->blocked_cnt--;
}

static void tm_block_pkt(tm_system_t *tm_system,
			 tm_node_obj_t *tm_node_obj,
			 tm_schedulers_obj_t *schedulers_obj,
			 pkt_desc_t *pkt_desc,
			 uint8_t priority)
{
	tm_queue_obj_t *tm_queue_obj;

       /* Remove the blocked pkt from all downstream entities.
	* This only happens if the propagation of another pkt caused this pkt
	* to become blocked, since if the propagation of a pkt causes itself
	* to be blocked then there can't be any downstream copies to remove.
	* The caller signals us which case it is by whether the tm_node_obj
	* is NULL or not.
	*/
	tm_queue_obj = get_tm_queue_obj(tm_system, pkt_desc);
	if (tm_node_obj)
		tm_demote_pkt_desc(tm_system, tm_node_obj,
				   tm_queue_obj->blocked_scheduler,
				   tm_queue_obj->timer_shaper, pkt_desc);

	tm_queue_obj->blocked_cnt = 1;
	tm_queue_obj->blocked_scheduler = schedulers_obj;
	tm_queue_obj->blocked_priority = priority;
}

static int tm_delay_pkt(tm_system_t *tm_system, tm_shaper_obj_t *shaper_obj,
			pkt_desc_t *pkt_desc)
{
	tm_queue_obj_t *tm_queue_obj;
	uint64_t delay_cycles, wakeup_time, timer_context;

       /* Calculate elapsed time before this pkt will be
	* green or yellow.
	*/
	delay_cycles = cycles_till_not_red(shaper_obj->shaper_params,
					   shaper_obj);
	wakeup_time = tm_system->current_cycles + delay_cycles;

	tm_queue_obj = get_tm_queue_obj(tm_system, pkt_desc);
	tm_queue_obj->delayed_cnt++;

	/* Insert into timer wheel. */
	tm_queue_obj->timer_seq++;
	timer_context = (((uint64_t)tm_queue_obj->timer_seq) << 32) |
		(((uint64_t)tm_queue_obj->queue_num) << 4);
	_odp_timer_wheel_insert(tm_system->_odp_int_timer_wheel,
				wakeup_time, (void *)(uintptr_t)timer_context);

	tm_queue_obj->timer_reason = UNDELAY_PKT;
	tm_queue_obj->timer_shaper = shaper_obj;

	shaper_obj->timer_outstanding++;
	shaper_obj->callback_reason = UNDELAY_PKT;
	shaper_obj->callback_time = wakeup_time;
	shaper_obj->timer_tm_queue  = tm_queue_obj;
	shaper_obj->in_pkt_desc = *pkt_desc;
	shaper_obj->out_pkt_desc = EMPTY_PKT_DESC;
	shaper_obj->valid_finish_time = 0;
	return 1;
}

/* We call remove_pkt_from_shaper for pkts sent AND for pkts demoted. */

static int remove_pkt_from_shaper(tm_system_t *tm_system,
				  tm_shaper_obj_t *shaper_obj,
				  pkt_desc_t *pkt_desc_to_remove,
				  uint8_t is_sent_pkt)
{
	tm_shaper_params_t *shaper_params;
	tm_shaper_action_t shaper_action;
	tm_queue_obj_t *tm_queue_obj;
	uint32_t frame_len;
	int64_t  tkn_count;

	tm_queue_obj = get_tm_queue_obj(tm_system, pkt_desc_to_remove);
	if (shaper_obj->in_pkt_desc.queue_num != pkt_desc_to_remove->queue_num)
		return -1;

	shaper_action = shaper_obj->propagation_result.action;
	if ((tm_queue_obj->timer_shaper  == shaper_obj) ||
	    (shaper_obj->callback_reason == UNDELAY_PKT)) {
		/* Need to delete the timer - which is either a cancel or just
		 * a delete of a sent_pkt.
		 */
		if (tm_queue_obj->timer_reason == NO_CALLBACK)
			return -1;

		if (!is_sent_pkt)
			tm_queue_obj->timer_cancels_outstanding++;

		tm_queue_obj->timer_reason = NO_CALLBACK;
		tm_queue_obj->timer_seq++;
		tm_queue_obj->timer_shaper = NULL;
		if (tm_queue_obj->delayed_cnt != 0)
			tm_queue_obj->delayed_cnt--;

		if (shaper_obj->timer_outstanding != 0)
			shaper_obj->timer_outstanding--;

		shaper_obj->callback_time = 0;
		shaper_obj->callback_reason = NO_CALLBACK;
		shaper_obj->timer_tm_queue = NULL;
	}

	shaper_obj->propagation_result.action = DECR_NOTHING;
	shaper_obj->in_pkt_desc = EMPTY_PKT_DESC;
	shaper_obj->out_pkt_desc = EMPTY_PKT_DESC;
	shaper_obj->out_priority = 0;

	if ((!is_sent_pkt) || (shaper_action == DECR_NOTHING) ||
	    (shaper_action == DELAY_PKT))
		return 0;

	shaper_params = shaper_obj->shaper_params;
	frame_len = pkt_desc_to_remove->pkt_len +
		pkt_desc_to_remove->shaper_len_adjust +
		shaper_params->len_adjust;

	tkn_count = ((int64_t)frame_len) << 26;
	if ((shaper_action == DECR_BOTH) || (shaper_action == DECR_COMMIT))
		shaper_obj->commit_cnt -= tkn_count;

	if (shaper_params->peak_rate != 0)
		if ((shaper_action == DECR_BOTH) ||
		    (shaper_action == DECR_PEAK))
			shaper_obj->peak_cnt -= tkn_count;
	return 0;
}

static int tm_run_shaper(tm_system_t *tm_system, tm_shaper_obj_t *shaper_obj,
			 pkt_desc_t *pkt_desc, uint8_t priority)
{
	odp_tm_shaper_color_t shaper_color;
	tm_shaper_params_t *shaper_params;
	odp_bool_t output_change;
	tm_prop_t propagation;

	shaper_params = shaper_obj->shaper_params;

	if ((!shaper_params) || (shaper_params->enabled == 0)) {
		output_change =
			pkt_descs_not_equal(&shaper_obj->out_pkt_desc,
					    pkt_desc) ||
			(shaper_obj->out_priority != priority);

		shaper_obj->in_pkt_desc = *pkt_desc;
		shaper_obj->input_priority = priority;
		shaper_obj->out_pkt_desc = *pkt_desc;
		shaper_obj->out_priority = priority;
		if (output_change)
			shaper_obj->valid_finish_time = 0;

		return output_change;
	}

	update_shaper_elapsed_time(tm_system, shaper_params, shaper_obj);
	if (0 < shaper_obj->commit_cnt)
		shaper_color = ODP_TM_SHAPER_GREEN;
	else if (shaper_params->peak_rate == 0)
		shaper_color = ODP_TM_SHAPER_RED;
	else if (shaper_obj->peak_cnt <= 0)
		shaper_color = ODP_TM_SHAPER_RED;
	else
		shaper_color = ODP_TM_SHAPER_YELLOW;

	if (shaper_color == ODP_TM_SHAPER_GREEN)
		tm_system->shaper_green_cnt++;
	else if (shaper_color == ODP_TM_SHAPER_YELLOW)
		tm_system->shaper_yellow_cnt++;
	else
		tm_system->shaper_red_cnt++;

	/* Run thru propagation tbl to get shaper_action and out_priority */
	propagation = basic_prop_tbl[priority][shaper_color];

       /* See if this shaper had a previous timer associated with it.  If so
	* we need to cancel it.
	*/
	if ((shaper_obj->timer_outstanding != 0) &&
	    (shaper_obj->in_pkt_desc.queue_num != 0))
		remove_pkt_from_shaper(tm_system, shaper_obj,
				       &shaper_obj->in_pkt_desc, 0);

	shaper_obj->propagation_result = propagation;
	if (propagation.action == DELAY_PKT)
		return tm_delay_pkt(tm_system, shaper_obj, pkt_desc);

	shaper_obj->callback_time = 0;
	shaper_obj->callback_reason = NO_CALLBACK;

	/* Propagate pkt_desc to the next level */
	priority = propagation.output_priority;
	output_change =
		pkt_descs_not_equal(&shaper_obj->out_pkt_desc, pkt_desc) ||
		(shaper_obj->out_priority != priority);

	shaper_obj->in_pkt_desc = *pkt_desc;
	shaper_obj->input_priority = priority;
	shaper_obj->out_pkt_desc = *pkt_desc;
	shaper_obj->out_priority = priority;
	if (output_change)
		shaper_obj->valid_finish_time = 0;

	return output_change;
}

static int tm_set_finish_time(tm_schedulers_obj_t *schedulers_obj,
			      tm_shaper_obj_t *prod_shaper_obj,
			      pkt_desc_t *new_pkt_desc,
			      uint8_t new_priority)
{
	odp_tm_sched_mode_t mode;
	tm_sched_params_t *sched_params;
	tm_sched_state_t *sched_state;
	uint64_t base_virtual_time, virtual_finish_time;
	uint32_t inverted_weight, frame_len, frame_weight;

	/* Check to see if this pkt_desc is "new" or not */
	if (prod_shaper_obj->valid_finish_time) {
		/* return 0 or 1 depending on whether this pkt_desc is the
		 * current chosen one
		 */
		return 0;
	}

	/* First determine the virtual finish_time of this new pkt. */
	sched_params = prod_shaper_obj->sched_params;
	if (!sched_params) {
		mode = ODP_TM_BYTE_BASED_WEIGHTS;
		inverted_weight = 4096;
		/* Same as a weight of 16. */
	} else {
		mode = sched_params->sched_modes[new_priority];
		inverted_weight = sched_params->inverted_weights[new_priority];
	}

	frame_len = new_pkt_desc->pkt_len;
	if (mode == ODP_TM_FRAME_BASED_WEIGHTS)
		frame_len = 256;

	frame_weight = ((inverted_weight * frame_len) + (1 << 15)) >> 16;

	sched_state = &schedulers_obj->sched_states[new_priority];
	base_virtual_time = MAX(prod_shaper_obj->virtual_finish_time,
				sched_state->base_virtual_time);

	virtual_finish_time = base_virtual_time + frame_weight;
	prod_shaper_obj->virtual_finish_time = virtual_finish_time;
	prod_shaper_obj->valid_finish_time = 1;
	return 1;
}

static int tm_run_scheduler(tm_system_t *tm_system,
			    tm_shaper_obj_t *prod_shaper_obj,
			    tm_schedulers_obj_t *schedulers_obj,
			    pkt_desc_t *new_pkt_desc,
			    uint8_t new_priority)
{
	tm_sched_state_t *new_sched_state;
	tm_node_obj_t *tm_node_obj;
	pkt_desc_t prev_best_pkt_desc;
	uint64_t new_finish_time, prev_best_time;
	uint32_t new_priority_mask;
	int rc;

	/* Determine the virtual finish_time of this new pkt. */
	tm_set_finish_time(schedulers_obj, prod_shaper_obj, new_pkt_desc,
			   new_priority);
	new_finish_time = prod_shaper_obj->virtual_finish_time;
	new_sched_state = &schedulers_obj->sched_states[new_priority];

	prev_best_pkt_desc = new_sched_state->smallest_pkt_desc;
	prev_best_time     = new_sched_state->smallest_finish_time;
	if (prev_best_pkt_desc.queue_num) {
		/* See if this new pkt has the smallest virtual finish time
		 * for all fanin at the given input priority level, as
		 * represented by the new_sched_state.
		 */
		if (prev_best_time <= new_finish_time) {
			/* Since this new pkt doesn't have the smallest
			 * virtual finish time, just insert it into this
			 * sched_state's list sorted by virtual finish times.
			 */
			rc = _odp_sorted_list_insert(
				tm_system->_odp_int_sorted_pool,
				new_sched_state->sorted_list,
				new_finish_time, new_pkt_desc->word);

			if (0 <= rc) {
				new_sched_state->sorted_list_cnt++;
				tm_block_pkt(tm_system, NULL, schedulers_obj,
					     new_pkt_desc, new_priority);
			}

			return 0;
		}

	       /* Since this new pkt does have the smallest virtual finish
		* time, insert the previous best into this sched_state's list
		* sorted by virtual finish times (though it should always be
		* inserted at the front), and continue processing.
		*/
		rc = _odp_sorted_list_insert
			(tm_system->_odp_int_sorted_pool,
			 new_sched_state->sorted_list, prev_best_time,
			 prev_best_pkt_desc.word);
		if (rc < 0)
			return rc;

		new_sched_state->sorted_list_cnt++;
		tm_node_obj = schedulers_obj->enclosing_entity;
		tm_block_pkt(tm_system, tm_node_obj, schedulers_obj,
			     &prev_best_pkt_desc, new_priority);
	}

       /* Record the fact that this new pkt is now the best choice of this
	* sched_state.
	*/
	new_sched_state->smallest_finish_time = new_finish_time;
	new_sched_state->smallest_pkt_desc = *new_pkt_desc;
	schedulers_obj->priority_bit_mask |= 1ULL << new_priority;

       /* Next see if this new pkt is the highest priority pkt of all of the
	* schedulers within this tm_node (recalling that the highest priority
	* has the lowest priority value).
	*/
	new_priority_mask = (1ULL << new_priority) - 1;
	if ((schedulers_obj->priority_bit_mask & new_priority_mask) != 0) {
		tm_block_pkt(tm_system, NULL, schedulers_obj, new_pkt_desc,
			     new_priority);
		return 0;
	} else if (schedulers_obj->out_pkt_desc.queue_num != 0) {
		tm_node_obj = schedulers_obj->enclosing_entity;
		tm_block_pkt(tm_system, tm_node_obj, schedulers_obj,
			     &schedulers_obj->out_pkt_desc,
			     schedulers_obj->highest_priority);
	}

	schedulers_obj->highest_priority = new_priority;
	schedulers_obj->out_pkt_desc = *new_pkt_desc;
	return 1;
}

/* We call remove_pkt_from_scheduler both for pkts sent AND for pkts demoted. */

static int remove_pkt_from_scheduler(tm_system_t *tm_system,
				     tm_schedulers_obj_t *schedulers_obj,
				     pkt_desc_t *pkt_desc_to_remove,
				     uint8_t pkt_desc_priority,
				     uint8_t is_sent_pkt)
{
	_odp_int_sorted_pool_t sorted_pool;
	_odp_int_sorted_list_t sorted_list;
	tm_sched_state_t *sched_state, *best_sched_state;
	pkt_desc_t best_pkt_desc, pkt_desc;
	uint64_t finish_time;
	uint32_t priority, best_priority;
	uint8_t found;
	int rc;

	if (is_sent_pkt)
		priority = schedulers_obj->highest_priority;
	else
		priority = pkt_desc_priority;

	sched_state = &schedulers_obj->sched_states[priority];
	sorted_pool = tm_system->_odp_int_sorted_pool;
	sorted_list = sched_state->sorted_list;
	found       = 0;
	if (pkt_descs_equal(&sched_state->smallest_pkt_desc,
			    pkt_desc_to_remove))
		found = 1;
	else if (!is_sent_pkt) {
		rc = _odp_sorted_list_delete(sorted_pool, sorted_list,
					     pkt_desc_to_remove->word);
		if (0 <= rc) {
			sched_state->sorted_list_cnt--;
			return 0;
		}
	}

	if (!found)
		return -1;

       /* This is the case where the pkt_desc_to_remove is NOT in a sorted
	* list but is instead the best/smallest pkt_desc for "some" priority
	* level.  If is_sent_pkt is TRUE, then this priority level MUST be
	* the highest_priority level, but if FALSE then this priority level
	* can be at any priority.
	*/
	if (is_sent_pkt) {
		finish_time = sched_state->smallest_finish_time;
		sched_state->base_virtual_time = finish_time;
	}

	sched_state->smallest_finish_time = 0;
	sched_state->smallest_pkt_desc = EMPTY_PKT_DESC;
	schedulers_obj->priority_bit_mask &= ~(1ULL << priority);
	if (pkt_descs_equal(&schedulers_obj->out_pkt_desc,
			    pkt_desc_to_remove)) {
		schedulers_obj->out_pkt_desc = EMPTY_PKT_DESC;
		schedulers_obj->highest_priority = 0;
	}

       /* Now that we have removed the pkt_desc_to_remove, we need to see if
	* there is a new pkt_desc available to become the best pkt_desc for
	* this priority level/sched_state.
	*/
	if (sched_state->sorted_list_cnt != 0) {
		rc = _odp_sorted_list_remove(sorted_pool, sorted_list,
					     &finish_time, &pkt_desc.word);
		if (rc <= 0)
			return -1;

		sched_state->sorted_list_cnt--;
		sched_state->smallest_finish_time = finish_time;
		sched_state->smallest_pkt_desc = pkt_desc;
		schedulers_obj->priority_bit_mask |= 1ULL << priority;
	}

       /* Finally we must see if there is a new_pkt desc that is now the
	* best/smallest for this entire schedulers_obj - which could even be
	* the pkt_desc we just removed from the sorted_list, or not.
	*/
	if (schedulers_obj->priority_bit_mask == 0) {
		schedulers_obj->out_pkt_desc = EMPTY_PKT_DESC;
		schedulers_obj->highest_priority = 0;
	} else {
	       /* Set the highest_priority and out_pkt_desc of the
		* schedulers_obj.  Such a pkt_desc must exist because
		* otherwise priority_bit_mask would be 0.
		*/
		best_priority =
			__builtin_ctz(schedulers_obj->priority_bit_mask);
		best_sched_state = &schedulers_obj->sched_states[best_priority];
		best_pkt_desc = best_sched_state->smallest_pkt_desc;

		schedulers_obj->highest_priority = best_priority;
		schedulers_obj->out_pkt_desc = best_pkt_desc;
		tm_unblock_pkt(tm_system, &best_pkt_desc);
	}

	return 0;
}

static int tm_propagate_pkt_desc(tm_system_t *tm_system,
				 tm_shaper_obj_t *shaper_obj,
				 pkt_desc_t *new_pkt_desc,
				 uint8_t new_priority)
{
	tm_schedulers_obj_t *schedulers_obj;
	tm_node_obj_t *tm_node_obj;
	int rc, ret_code;

	/* Run shaper. */
	tm_run_shaper(tm_system, shaper_obj, new_pkt_desc, new_priority);

	tm_node_obj = shaper_obj->next_tm_node;
	while (tm_node_obj) { /* not at egress */
		/* Run scheduler, including priority multiplexor. */
		new_pkt_desc = &shaper_obj->out_pkt_desc;
		new_priority = shaper_obj->out_priority;
		if ((!new_pkt_desc) || (new_pkt_desc->queue_num == 0))
			return 0;

		schedulers_obj = tm_node_obj->schedulers_obj;
		rc = tm_run_scheduler(tm_system, shaper_obj, schedulers_obj,
				      new_pkt_desc, new_priority);

		if (rc <= 0)
			return rc;

		/* Run shaper. */
		new_pkt_desc = &schedulers_obj->out_pkt_desc;
		new_priority = schedulers_obj->highest_priority;
		shaper_obj = &tm_node_obj->shaper_obj;
		if ((!new_pkt_desc) || (new_pkt_desc->queue_num == 0))
			return 0;

		tm_run_shaper(tm_system, shaper_obj, new_pkt_desc,
			      new_priority);

		tm_node_obj  = shaper_obj->next_tm_node;
	}

	new_pkt_desc = &shaper_obj->out_pkt_desc;
	new_priority = shaper_obj->out_priority;
	ret_code = 0;
	if ((new_pkt_desc) && (new_pkt_desc->queue_num != 0)) {
		tm_system->egress_pkt_desc = *new_pkt_desc;
		ret_code = 1;
	}

	return ret_code;
}

static void tm_pkt_desc_init(pkt_desc_t *pkt_desc, odp_packet_t pkt,
			     tm_queue_obj_t *tm_queue_obj)
{
	tm_queue_obj->epoch++;
	pkt_desc->queue_num = tm_queue_obj->queue_num;
	pkt_desc->pkt_len = odp_packet_len(pkt);
	pkt_desc->shaper_len_adjust = odp_packet_shaper_len_adjust(pkt);
	pkt_desc->drop_eligible = odp_packet_drop_eligible(pkt);
	pkt_desc->pkt_color = odp_packet_color(pkt);
	pkt_desc->epoch = tm_queue_obj->epoch & 0x0F;
}

static int tm_demote_pkt_desc(tm_system_t *tm_system,
			      tm_node_obj_t *tm_node_obj,
			      tm_schedulers_obj_t *blocked_scheduler,
			      tm_shaper_obj_t *timer_shaper,
			      pkt_desc_t *demoted_pkt_desc)
{
	tm_schedulers_obj_t *schedulers_obj;
	tm_shaper_obj_t *shaper_obj;
	pkt_desc_t *new_pkt_desc;
	uint8_t new_priority, demoted_priority;
	int ret_code;

	shaper_obj = &tm_node_obj->shaper_obj;
	if ((!blocked_scheduler) && (!timer_shaper))
		return 0;

	if (tm_node_obj->schedulers_obj == blocked_scheduler)
		return 0;

	demoted_priority = 3;
	if (pkt_descs_equal(&shaper_obj->out_pkt_desc, demoted_pkt_desc))
		demoted_priority = shaper_obj->out_priority;

	/* See if this first shaper_obj is delaying the demoted_pkt_desc */
	if (pkt_descs_equal(&shaper_obj->out_pkt_desc, demoted_pkt_desc))
		demoted_priority = shaper_obj->out_priority;

	remove_pkt_from_shaper(tm_system, shaper_obj, demoted_pkt_desc, 0);
	if (shaper_obj == timer_shaper) {
		demoted_pkt_desc = NULL;
		return 0;
	}

	tm_node_obj = shaper_obj->next_tm_node;

	while (tm_node_obj) { /* not at egress */
		schedulers_obj = tm_node_obj->schedulers_obj;
		if (demoted_pkt_desc) {
			remove_pkt_from_scheduler(tm_system, schedulers_obj,
						  demoted_pkt_desc,
						  demoted_priority, 0);
			if (schedulers_obj == blocked_scheduler)
				demoted_pkt_desc = NULL;
		}

		new_pkt_desc = &shaper_obj->out_pkt_desc;
		new_priority = shaper_obj->out_priority;
		if ((new_pkt_desc) && (new_pkt_desc->queue_num != 0))
			tm_run_scheduler(tm_system, shaper_obj, schedulers_obj,
					 new_pkt_desc, new_priority);
		else if (!demoted_pkt_desc)
			return 0;

		new_pkt_desc = &schedulers_obj->out_pkt_desc;
		new_priority = schedulers_obj->highest_priority;
		shaper_obj   = &tm_node_obj->shaper_obj;

		if (demoted_pkt_desc) {
			if (pkt_descs_equal(&shaper_obj->out_pkt_desc,
					    demoted_pkt_desc))
				demoted_priority = shaper_obj->out_priority;

			remove_pkt_from_shaper(tm_system, shaper_obj,
					       demoted_pkt_desc, 0);
			if (shaper_obj == timer_shaper)
				demoted_pkt_desc = NULL;
		}

		if ((new_pkt_desc) && (new_pkt_desc->queue_num != 0))
			tm_run_shaper(tm_system, shaper_obj, new_pkt_desc,
				      new_priority);
		else if (!demoted_pkt_desc)
			return 0;

		tm_node_obj = shaper_obj->next_tm_node;
	}

	new_pkt_desc = &shaper_obj->out_pkt_desc;
	new_priority = shaper_obj->out_priority;
	ret_code = 0;
	if ((new_pkt_desc) && (new_pkt_desc->queue_num != 0)) {
		tm_system->egress_pkt_desc = *new_pkt_desc;
		ret_code = 1;
	}

	return ret_code;
}

static int tm_consume_pkt_desc(tm_system_t *tm_system,
			       tm_shaper_obj_t *shaper_obj,
			       pkt_desc_t *new_pkt_desc,
			       uint8_t new_priority,
			       pkt_desc_t *sent_pkt_desc)
{
	tm_schedulers_obj_t *schedulers_obj;
	tm_node_obj_t *tm_node_obj;
	uint8_t sent_priority;
	int rc, ret_code;

	remove_pkt_from_shaper(tm_system, shaper_obj, sent_pkt_desc, 1);
	if ((new_pkt_desc) && (new_pkt_desc->queue_num != 0))
		tm_run_shaper(tm_system, shaper_obj, new_pkt_desc,
			      new_priority);

	tm_node_obj = shaper_obj->next_tm_node;
	while (tm_node_obj) { /* not at egress */
		schedulers_obj = tm_node_obj->schedulers_obj;
		sent_priority = schedulers_obj->highest_priority;
		remove_pkt_from_scheduler(tm_system, schedulers_obj,
					  sent_pkt_desc, sent_priority, 1);

		new_pkt_desc = &shaper_obj->out_pkt_desc;
		new_priority = shaper_obj->out_priority;

		if ((new_pkt_desc) && (new_pkt_desc->queue_num != 0)) {
			rc = tm_run_scheduler(tm_system, shaper_obj,
					      schedulers_obj,
					      new_pkt_desc, new_priority);
			if (rc < 0)
				return rc;
		}

		new_pkt_desc = &schedulers_obj->out_pkt_desc;
		new_priority = schedulers_obj->highest_priority;

		shaper_obj = &tm_node_obj->shaper_obj;
		remove_pkt_from_shaper(tm_system, shaper_obj, sent_pkt_desc, 1);
		if ((new_pkt_desc) && (new_pkt_desc->queue_num != 0))
			tm_run_shaper(tm_system, shaper_obj, new_pkt_desc,
				      new_priority);

		tm_node_obj = shaper_obj->next_tm_node;
	}

	new_pkt_desc = &shaper_obj->out_pkt_desc;
	new_priority = shaper_obj->out_priority;

	ret_code = 0;
	if ((new_pkt_desc) && (new_pkt_desc->queue_num != 0)) {
		tm_system->egress_pkt_desc = *new_pkt_desc;
		ret_code = 1;
	}

	return ret_code;
}

static int tm_consume_sent_pkt(tm_system_t *tm_system,
			       pkt_desc_t *sent_pkt_desc)
{
	_odp_int_pkt_queue_t _odp_int_pkt_queue;
	tm_queue_obj_t *tm_queue_obj;
	odp_packet_t pkt;
	pkt_desc_t *new_pkt_desc;
	uint32_t queue_num, pkt_len;
	int rc;

	queue_num = sent_pkt_desc->queue_num;
	tm_queue_obj = tm_system->queue_num_tbl[queue_num];
	pkt_len = sent_pkt_desc->pkt_len;
	tm_queue_obj->pkts_consumed_cnt++;
	tm_queue_cnts_decrement(tm_system, tm_queue_obj->tm_wred_node,
				tm_queue_obj->priority, pkt_len);

	/* Get the next pkt in the tm_queue, if there is one. */
	_odp_int_pkt_queue = tm_queue_obj->_odp_int_pkt_queue;
	rc = _odp_pkt_queue_remove(tm_system->_odp_int_queue_pool,
				   _odp_int_pkt_queue, &pkt);
	if (rc < 0)
		return rc;

	new_pkt_desc = NULL;
	if (0 < rc) {
		tm_queue_obj->pkt = pkt;
		tm_pkt_desc_init(&tm_queue_obj->in_pkt_desc, pkt, tm_queue_obj);
		new_pkt_desc = &tm_queue_obj->in_pkt_desc;
		tm_queue_obj->pkts_dequeued_cnt++;
	}

	rc = tm_consume_pkt_desc(tm_system, &tm_queue_obj->shaper_obj,
				 new_pkt_desc, tm_queue_obj->priority,
				 sent_pkt_desc);

	return rc > 0;
}

static odp_tm_percent_t tm_queue_fullness(odp_tm_wred_params_t *wred_params,
					  tm_queue_thresholds_t *thresholds,
					  tm_queue_cnts_t *queue_cnts)
{
	uint64_t current_cnt, max_cnt, fullness;

	if (wred_params->use_byte_fullness) {
		current_cnt = odp_atomic_load_u64(&queue_cnts->byte_cnt);
		max_cnt = thresholds->max_bytes;
	} else {
		current_cnt = odp_atomic_load_u64(&queue_cnts->pkt_cnt);
		max_cnt = thresholds->max_pkts;
	}

	if (max_cnt == 0)
		return 0;

	fullness = (10000 * current_cnt) / max_cnt;
	return (odp_tm_percent_t)MIN(fullness, 50000);
}

static odp_bool_t tm_local_random_drop(tm_system_t *tm_system,
				       odp_tm_wred_params_t *wred_params,
				       odp_tm_percent_t queue_fullness)
{
	odp_tm_percent_t min_threshold, med_threshold, first_threshold,
		drop_prob;
	odp_tm_percent_t med_drop_prob, max_drop_prob;
	uint32_t denom, numer;

	if (wred_params->enable_wred == 0)
		return 0;

	min_threshold = wred_params->min_threshold;
	med_threshold = wred_params->med_threshold;
	first_threshold = (min_threshold != 0) ? min_threshold : med_threshold;
	if (10000 <= queue_fullness)
		return 1;
	else if (queue_fullness <= first_threshold)
		return 0;

       /* Determine if we have two active thresholds, min_threshold and
	* med_threshold or just med_threshold.
	*/
	med_drop_prob = wred_params->med_drop_prob;
	max_drop_prob = wred_params->max_drop_prob;
	if (min_threshold == 0) {
		denom = (uint32_t)(10000 - med_threshold);
		numer = (uint32_t)max_drop_prob;
		drop_prob =
			(numer * (uint32_t)(queue_fullness - med_threshold)) /
			denom;
	} else if ((min_threshold < queue_fullness) &&
		   (queue_fullness < med_threshold)) {
		denom = (uint32_t)(med_threshold - min_threshold);
		numer = (uint32_t)med_drop_prob;
		drop_prob =
			(numer * (uint32_t)(queue_fullness - min_threshold)) /
			denom;
	} else { /* med_threshold <= queue_fullness. */
		denom = (uint32_t)(10000 - med_threshold);
		numer = (uint32_t)(max_drop_prob - med_drop_prob);
		drop_prob = max_drop_prob -
			((numer * (10000 - queue_fullness)) / denom);
	}

	if (drop_prob == 0)
		return 0;
	else if (10000 <= drop_prob)
		return 1;
	else
		return tm_random_drop(&tm_system->tm_random_data, drop_prob);
}

static odp_bool_t tm_queue_is_full(tm_queue_thresholds_t *thresholds,
				   tm_queue_cnts_t *queue_cnts)
{
	odp_bool_t queue_is_full;
	uint64_t max_bytes;
	uint32_t max_pkts;

	max_bytes = thresholds->max_bytes;
	max_pkts = thresholds->max_pkts;
	queue_is_full = 0;
	if (max_pkts != 0)
		queue_is_full =
			max_pkts <= odp_atomic_load_u64(&queue_cnts->pkt_cnt);

	if (max_bytes != 0)
		queue_is_full |=
			max_bytes <= odp_atomic_load_u64(&queue_cnts->byte_cnt);

	return queue_is_full;
}

static odp_bool_t tm_random_early_discard(tm_system_t *tm_system,
					  tm_queue_obj_t *tm_queue_obj
					  ODP_UNUSED,
					  tm_wred_node_t *tm_wred_node,
					  odp_packet_color_t pkt_color)
{
	tm_queue_thresholds_t *thresholds;
	odp_tm_wred_params_t *wred_params;
	odp_tm_percent_t fullness;
	tm_queue_cnts_t *queue_cnts;

	thresholds = tm_wred_node->threshold_params;
	if (thresholds) {
		wred_params = tm_wred_node->wred_params[pkt_color];
		queue_cnts = &tm_wred_node->queue_cnts;
		if ((!wred_params) || (wred_params->enable_wred == 0)) {
			if (tm_queue_is_full(thresholds, queue_cnts))
				return 1;
		} else {
			fullness = tm_queue_fullness(wred_params, thresholds,
						     queue_cnts);
			if (tm_local_random_drop(tm_system, wred_params,
						 fullness))
				return 1;
		}
	}

       /* For each tm_wred_node between the initial and a TM egress, do a
	* Random Early Discard check, if enabled.
	*/
	tm_wred_node = tm_wred_node->next_tm_wred_node;
	while (tm_wred_node) {
		thresholds = tm_wred_node->threshold_params;
		if (thresholds) {
			wred_params = tm_wred_node->wred_params[pkt_color];
			queue_cnts = &tm_wred_node->queue_cnts;
			if ((wred_params) && wred_params->enable_wred) {
				fullness = tm_queue_fullness(wred_params,
							     thresholds,
							     queue_cnts);
				if (tm_local_random_drop(tm_system, wred_params,
							 fullness))
					return 1;
			}
		}

		tm_wred_node = tm_wred_node->next_tm_wred_node;
	}

	return 0;
}

/* Returns the current queue pkt_cnt. */
static uint32_t tm_queue_cnts_increment(tm_system_t *tm_system,
					tm_wred_node_t *tm_wred_node,
					uint32_t priority,
					uint32_t frame_len)
{
	tm_queue_cnts_t *queue_cnts;
	uint32_t tm_queue_pkt_cnt;

	odp_ticketlock_lock(&tm_wred_node->tm_wred_node_lock);
	queue_cnts = &tm_wred_node->queue_cnts;
	odp_atomic_inc_u64(&queue_cnts->pkt_cnt);
	odp_atomic_add_u64(&queue_cnts->byte_cnt, frame_len);

	tm_queue_pkt_cnt = (uint32_t)odp_atomic_load_u64(&queue_cnts->pkt_cnt);
	odp_ticketlock_unlock(&tm_wred_node->tm_wred_node_lock);

       /* For each tm_wred_node between the initial one and a TM egress,
	* increment its queue_cnts, if enabled.
	*/
	tm_wred_node = tm_wred_node->next_tm_wred_node;
	while (tm_wred_node) {
		odp_ticketlock_lock(&tm_wred_node->tm_wred_node_lock);
		queue_cnts = &tm_wred_node->queue_cnts;
		odp_atomic_inc_u64(&queue_cnts->pkt_cnt);
		odp_atomic_add_u64(&queue_cnts->byte_cnt, frame_len);
		odp_ticketlock_unlock(&tm_wred_node->tm_wred_node_lock);

		tm_wred_node = tm_wred_node->next_tm_wred_node;
	}

	queue_cnts = &tm_system->total_info.queue_cnts;
	odp_atomic_inc_u64(&queue_cnts->pkt_cnt);
	odp_atomic_add_u64(&queue_cnts->byte_cnt, frame_len);

	queue_cnts = &tm_system->priority_info[priority].queue_cnts;
	odp_atomic_inc_u64(&queue_cnts->pkt_cnt);
	odp_atomic_add_u64(&queue_cnts->byte_cnt, frame_len);

	return tm_queue_pkt_cnt;
}

static void tm_queue_cnts_decrement(tm_system_t *tm_system,
				    tm_wred_node_t *tm_wred_node,
				    uint32_t priority,
				    uint32_t frame_len)
{
	tm_queue_cnts_t *queue_cnts;

	odp_ticketlock_lock(&tm_wred_node->tm_wred_node_lock);
	queue_cnts = &tm_wred_node->queue_cnts;
	odp_atomic_dec_u64(&queue_cnts->pkt_cnt);
	odp_atomic_sub_u64(&queue_cnts->byte_cnt, frame_len);
	odp_ticketlock_unlock(&tm_wred_node->tm_wred_node_lock);

       /* For each tm_wred_node between the initial one and a TM egress,
	* decrement its queue_cnts, if enabled.
	*/
	tm_wred_node = tm_wred_node->next_tm_wred_node;
	while (tm_wred_node) {
		odp_ticketlock_lock(&tm_wred_node->tm_wred_node_lock);
		queue_cnts = &tm_wred_node->queue_cnts;
		odp_atomic_dec_u64(&queue_cnts->pkt_cnt);
		odp_atomic_sub_u64(&queue_cnts->byte_cnt, frame_len);
		odp_ticketlock_unlock(&tm_wred_node->tm_wred_node_lock);
		tm_wred_node = tm_wred_node->next_tm_wred_node;
	}

	queue_cnts = &tm_system->total_info.queue_cnts;
	odp_atomic_dec_u64(&queue_cnts->pkt_cnt);
	odp_atomic_sub_u64(&queue_cnts->byte_cnt, frame_len);

	queue_cnts = &tm_system->priority_info[priority].queue_cnts;
	odp_atomic_dec_u64(&queue_cnts->pkt_cnt);
	odp_atomic_sub_u64(&queue_cnts->byte_cnt, frame_len);
}

static int tm_enqueue(tm_system_t *tm_system,
		      tm_queue_obj_t *tm_queue_obj,
		      odp_packet_t pkt)
{
	input_work_item_t work_item;
	odp_packet_color_t pkt_color;
	tm_wred_node_t *initial_tm_wred_node;
	odp_bool_t drop_eligible, drop;
	uint32_t frame_len, pkt_depth;
	int rc;
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);

	/* If we're from an ordered queue and not in order
	 * record the event and wait until order is resolved
	 */
	if (queue_tm_reorder(&tm_queue_obj->tm_qentry,
			     &pkt_hdr->buf_hdr))
		return 0;

	if (tm_system->first_enq == 0) {
		odp_barrier_wait(&tm_system->tm_system_barrier);
		tm_system->first_enq = 1;
	}

	pkt_color = odp_packet_color(pkt);
	drop_eligible = odp_packet_drop_eligible(pkt);

	initial_tm_wred_node = tm_queue_obj->tm_wred_node;
	if (drop_eligible) {
		drop = tm_random_early_discard(tm_system, tm_queue_obj,
					       initial_tm_wred_node, pkt_color);
		if (drop)
			return -1;
	}

	work_item.tm_queue_obj = tm_queue_obj;
	work_item.pkt = pkt;
	rc = input_work_queue_append(tm_system, &work_item);
	if (rc < 0) {
		ODP_DBG("%s work queue full\n", __func__);
		return rc;
	}

	frame_len = odp_packet_len(pkt);
	pkt_depth = tm_queue_cnts_increment(tm_system, initial_tm_wred_node,
					    tm_queue_obj->priority, frame_len);
	return pkt_depth;
}

static void tm_send_pkt(tm_system_t *tm_system,
			uint32_t max_consume_sends ODP_UNUSED)
{
	tm_queue_obj_t *tm_queue_obj;
	odp_packet_t odp_pkt;
	pkt_desc_t *pkt_desc;
	uint32_t cnt, queue_num;

	/* for (cnt = 1; cnt < max_consume_sends; cnt++) @todo */
	for (cnt = 1; cnt < 1000; cnt++) {
		pkt_desc = &tm_system->egress_pkt_desc;
		queue_num = pkt_desc->queue_num;
		if (queue_num == 0)
			return;

		tm_system->egress_pkt_desc = EMPTY_PKT_DESC;
		tm_queue_obj = tm_system->queue_num_tbl[queue_num];
		odp_pkt = tm_queue_obj->pkt;
		if (odp_pkt == INVALID_PKT)
			return;

		tm_system->egress.egress_fcn(odp_pkt);
		tm_queue_obj->sent_pkt = tm_queue_obj->pkt;
		tm_queue_obj->sent_pkt_desc = tm_queue_obj->in_pkt_desc;
		tm_queue_obj->pkt = INVALID_PKT;
		tm_queue_obj->in_pkt_desc = EMPTY_PKT_DESC;
		tm_consume_sent_pkt(tm_system, &tm_queue_obj->sent_pkt_desc);
		tm_queue_obj->sent_pkt = INVALID_PKT;
		tm_queue_obj->sent_pkt_desc = EMPTY_PKT_DESC;
		if (tm_system->egress_pkt_desc.queue_num == 0)
			return;
	}
}

static int tm_process_input_work_queue(tm_system_t *tm_system,
				       input_work_queue_t *input_work_queue,
				       uint32_t pkts_to_process)
{
	input_work_item_t work_item;
	tm_queue_obj_t *tm_queue_obj;
	tm_shaper_obj_t *shaper_obj;
	odp_packet_t pkt;
	pkt_desc_t *pkt_desc;
	uint32_t cnt;
	int rc;

	for (cnt = 1; cnt <= pkts_to_process; cnt++) {
		rc = input_work_queue_remove(input_work_queue, &work_item);
		if (rc < 0)
			return rc;

		tm_queue_obj = work_item.tm_queue_obj;
		pkt = work_item.pkt;
		tm_queue_obj->pkts_rcvd_cnt++;
		if (tm_queue_obj->pkt != INVALID_PKT) {
			/* If the tm_queue_obj already has a pkt to work with,
			 * then just add this new pkt to the associated
			 * _odp_int_pkt_queue.
			 */
			rc = _odp_pkt_queue_append(
				tm_system->_odp_int_queue_pool,
				tm_queue_obj->_odp_int_pkt_queue, pkt);
			tm_queue_obj->pkts_enqueued_cnt++;
		} else {
			/* If the tm_queue_obj doesn't have a pkt to work
			 * with, then make this one the head pkt.
			 */
			tm_queue_obj->pkt = pkt;
			tm_pkt_desc_init(&tm_queue_obj->in_pkt_desc, pkt,
					 tm_queue_obj);
			pkt_desc = &tm_queue_obj->in_pkt_desc;
			shaper_obj = &tm_queue_obj->shaper_obj;
			rc = tm_propagate_pkt_desc(tm_system, shaper_obj,
						   pkt_desc,
						   tm_queue_obj->priority);
			if (0 < rc)
				return 1;
			/* Send thru spigot */
		}
	}

	return 0;
}

static int tm_process_expired_timers(tm_system_t *tm_system,
				     _odp_timer_wheel_t _odp_int_timer_wheel,
				     uint64_t current_cycles ODP_UNUSED)
{
	tm_shaper_obj_t *shaper_obj;
	tm_queue_obj_t *tm_queue_obj;
	pkt_desc_t *pkt_desc;
	uint64_t timer_context;
	uint32_t work_done, cnt, queue_num, timer_seq;
	uint8_t priority;
	void *ptr;

	work_done = 0;
	for (cnt = 1; cnt <= 4; cnt++) {
		ptr = _odp_timer_wheel_next_expired(_odp_int_timer_wheel);
		if (!ptr)
			return work_done;

		timer_context = (uint64_t)(uintptr_t)ptr;
		queue_num = (timer_context & 0xFFFFFFFF) >> 4;
		timer_seq = timer_context >> 32;
		tm_queue_obj = tm_system->queue_num_tbl[queue_num];

		if ((!tm_queue_obj) ||
		    (tm_queue_obj->timer_reason == NO_CALLBACK) ||
		    (!tm_queue_obj->timer_shaper) ||
		    (tm_queue_obj->timer_seq != timer_seq)) {
			if (tm_queue_obj->timer_cancels_outstanding != 0)
				tm_queue_obj->timer_cancels_outstanding--;
			return work_done;
		}

		shaper_obj = tm_queue_obj->timer_shaper;
		pkt_desc = &shaper_obj->in_pkt_desc;
		priority = shaper_obj->input_priority;

		delete_timer(tm_system, tm_queue_obj, 0);

		tm_propagate_pkt_desc(tm_system, shaper_obj,
				      pkt_desc, priority);
		work_done++;
		if (tm_system->egress_pkt_desc.queue_num != 0)
			tm_send_pkt(tm_system, 4);
	}

	return work_done;
}

static void *tm_system_thread(void *arg)
{
	_odp_timer_wheel_t _odp_int_timer_wheel;
	input_work_queue_t *input_work_queue;
	tm_system_t *tm_system;
	uint64_t current_cycles;
	uint32_t destroying, work_queue_cnt, timer_cnt;
	int rc;

	odp_init_local(ODP_THREAD_WORKER);
	tm_system = arg;
	_odp_int_timer_wheel = tm_system->_odp_int_timer_wheel;
	input_work_queue = tm_system->input_work_queue;

	/* Wait here until we have seen the first enqueue operation. */
	odp_barrier_wait(&tm_system->tm_system_barrier);

	current_cycles = 100;
	destroying = odp_atomic_load_u32(&tm_system->destroying);
	while (destroying == 0) {
		tm_system->current_cycles = current_cycles;
		rc = _odp_timer_wheel_curr_time_update(_odp_int_timer_wheel,
						       current_cycles);
		if (0 < rc) {
			/* Process a batch of expired timers - each of which
			 * could cause a pkt to egress the tm system.
			 */
			timer_cnt = 1;
			rc = tm_process_expired_timers(tm_system,
						       _odp_int_timer_wheel,
						       current_cycles);
			current_cycles += 16;
		} else {
			timer_cnt =
				_odp_timer_wheel_count(_odp_int_timer_wheel);
		}

		work_queue_cnt =
			odp_atomic_load_u32(&input_work_queue->queue_cnt);
		if (work_queue_cnt != 0) {
			rc = tm_process_input_work_queue(tm_system,
							 input_work_queue, 1);
			current_cycles += 8;
			if (tm_system->egress_pkt_desc.queue_num != 0) {
				tm_send_pkt(tm_system, 4);
				current_cycles += 8;
			}
		}

		current_cycles += 16;
		tm_system->is_idle = (timer_cnt == 0) &&
			(work_queue_cnt == 0);
		destroying = odp_atomic_load_u32(&tm_system->destroying);
	}

	odp_barrier_wait(&tm_system->tm_system_destroy_barrier);
	return NULL;
}

odp_bool_t odp_tm_is_idle(odp_tm_t odp_tm)
{
	tm_system_t *tm_system;

	tm_system = GET_TM_SYSTEM(odp_tm);
	return tm_system->is_idle;
}

void odp_tm_capability_init(odp_tm_capability_t *capability)
{
	memset(capability, 0, sizeof(odp_tm_capability_t));
}

void odp_tm_params_init(odp_tm_params_t *params)
{
	memset(params, 0, sizeof(odp_tm_params_t));
}

odp_tm_t odp_tm_create(const char *name, odp_tm_params_t *params)
{
	_odp_int_name_t name_tbl_id;
	tm_system_t *tm_system;
	odp_bool_t create_fail;
	pthread_t pthread;
	odp_tm_t odp_tm;
	uint64_t current_cycles;
	uint32_t malloc_len, max_num_queues, max_queued_pkts, max_timers;
	uint32_t max_sorted_lists;
	int rc;

	/* Allocate tm_system_t record. */
	odp_ticketlock_lock(&tm_create_lock);
	tm_system = tm_system_alloc();
	if (!tm_system) {
		odp_ticketlock_unlock(&tm_create_lock);
		return ODP_TM_INVALID;
	}

	odp_tm = MAKE_ODP_TM_HANDLE(tm_system);
	name_tbl_id = _odp_int_name_tbl_add(name, ODP_TM_HANDLE, odp_tm);
	if (name_tbl_id == ODP_INVALID_NAME) {
		tm_system_free(tm_system);
		odp_ticketlock_unlock(&tm_create_lock);
		return ODP_TM_INVALID;
	}

	tm_system->name_tbl_id = name_tbl_id;
	memcpy(&tm_system->egress, &params->egress, sizeof(odp_tm_egress_t));
	memcpy(&tm_system->capability, &params->capability,
	       sizeof(odp_tm_capability_t));

	malloc_len = params->capability.max_tm_queues
		* sizeof(tm_queue_obj_t *);
	tm_system->queue_num_tbl = malloc(malloc_len);
	memset(tm_system->queue_num_tbl, 0, malloc_len);
	tm_system->next_queue_num = 1;

	tm_init_random_data(&tm_system->tm_random_data);

	max_sorted_lists = 2 * params->capability.max_tm_queues;
	max_num_queues = params->capability.max_tm_queues;
	max_queued_pkts = 16 * params->capability.max_tm_queues;
	max_timers = 2 * params->capability.max_tm_queues;
	current_cycles = 10;
	create_fail = 0;

	tm_system->_odp_int_sorted_pool = _ODP_INT_SORTED_POOL_INVALID;
	tm_system->_odp_int_queue_pool = _ODP_INT_QUEUE_POOL_INVALID;
	tm_system->_odp_int_timer_wheel = _ODP_INT_TIMER_WHEEL_INVALID;

	odp_ticketlock_init(&tm_system->tm_system_lock);
	odp_barrier_init(&tm_system->tm_system_barrier, 2);
	odp_atomic_init_u32(&tm_system->destroying, 0);

	tm_system->_odp_int_sorted_pool = _odp_sorted_pool_create(
		max_sorted_lists);
	create_fail |= tm_system->_odp_int_sorted_pool
		== _ODP_INT_SORTED_POOL_INVALID;

	if (create_fail == 0) {
		tm_system->_odp_int_queue_pool = _odp_queue_pool_create(
			max_num_queues, max_queued_pkts);
		create_fail |= tm_system->_odp_int_queue_pool
			== _ODP_INT_QUEUE_POOL_INVALID;
	}

	if (create_fail == 0) {
		tm_system->_odp_int_timer_wheel = _odp_timer_wheel_create(
			max_timers, current_cycles);
		create_fail |= tm_system->_odp_int_timer_wheel
			== _ODP_INT_TIMER_WHEEL_INVALID;
	}

	if (create_fail == 0) {
		tm_system->input_work_queue = input_work_queue_create();
		create_fail |= !tm_system->input_work_queue;
	}

	if (create_fail == 0) {
		rc = pthread_create(&pthread, NULL, tm_system_thread,
				    tm_system);
		create_fail |= rc < 0;
	}

	if (create_fail) {
		_odp_int_name_tbl_delete(name_tbl_id);
		if (tm_system->input_work_queue)
			input_work_queue_destroy(tm_system->input_work_queue);

		if (tm_system->_odp_int_sorted_pool
		    != _ODP_INT_SORTED_POOL_INVALID)
			_odp_sorted_pool_destroy(
				tm_system->_odp_int_sorted_pool);

		if (tm_system->_odp_int_queue_pool !=
		    _ODP_INT_QUEUE_POOL_INVALID)
			_odp_queue_pool_destroy(
				tm_system->_odp_int_queue_pool);

		if (tm_system->_odp_int_timer_wheel
		    != _ODP_INT_TIMER_WHEEL_INVALID)
			_odp_timer_wheel_destroy(
				tm_system->_odp_int_timer_wheel);

		tm_system_free(tm_system);
		odp_ticketlock_unlock(&tm_create_lock);
		return ODP_TM_INVALID;
	}

	odp_ticketlock_unlock(&tm_create_lock);
	return odp_tm;
}

odp_tm_t odp_tm_find(const char *name ODP_UNUSED,
		     odp_tm_capability_t *capability ODP_UNUSED)
{
	return ODP_TM_INVALID; /* @todo Not yet implemented. */
}

int odp_tm_capability(odp_tm_t odp_tm, odp_tm_capability_t *capability)
{
	tm_system_t *tm_system;

	tm_system = GET_TM_SYSTEM(odp_tm);
	memcpy(capability, &tm_system->capability, sizeof(odp_tm_capability_t));
	return 0;
}

int odp_tm_destroy(odp_tm_t odp_tm)
{
	tm_system_t *tm_system;

	tm_system = GET_TM_SYSTEM(odp_tm);

       /* First mark the tm_system as being in the destroying state so that
	* all new pkts are prevented from coming in.
	*/
	odp_barrier_init(&tm_system->tm_system_destroy_barrier, 2);
	odp_atomic_inc_u32(&tm_system->destroying);
	odp_barrier_wait(&tm_system->tm_system_destroy_barrier);

	input_work_queue_destroy(tm_system->input_work_queue);
	_odp_sorted_pool_destroy(tm_system->_odp_int_sorted_pool);
	_odp_queue_pool_destroy(tm_system->_odp_int_queue_pool);
	_odp_timer_wheel_destroy(tm_system->_odp_int_timer_wheel);

	tm_system_free(tm_system);
	return 0;
}

void odp_tm_shaper_params_init(odp_tm_shaper_params_t *params)
{
	memset(params, 0, sizeof(odp_tm_shaper_params_t));
}

odp_tm_shaper_t odp_tm_shaper_create(const char *name,
				     odp_tm_shaper_params_t *params)
{
	tm_shaper_params_t *profile_obj;
	odp_tm_shaper_t shaper_handle;
	_odp_int_name_t name_tbl_id;

	profile_obj = tm_common_profile_create(name, TM_SHAPER_PROFILE,
					       sizeof(tm_shaper_params_t),
					       &shaper_handle,
					       &name_tbl_id);
	if (!profile_obj)
		return ODP_TM_INVALID;

	tm_shaper_params_cvt_to(params, profile_obj);
	profile_obj->name_tbl_id = name_tbl_id;
	return shaper_handle;
}

int odp_tm_shaper_params_read(odp_tm_shaper_t shaper_profile,
			      odp_tm_shaper_params_t *params)
{
	tm_shaper_params_t *profile_obj;

	profile_obj = tm_get_profile_params(shaper_profile, TM_SHAPER_PROFILE);
	if (!profile_obj)
		return -1;

	tm_shaper_params_cvt_from(profile_obj, params);
	return 0;
}

int odp_tm_shaper_params_update(odp_tm_shaper_t shaper_profile,
				odp_tm_shaper_params_t *params)
{
	tm_shaper_params_t *profile_obj;

	profile_obj = tm_get_profile_params(shaper_profile, TM_SHAPER_PROFILE);
	if (!profile_obj)
		return -1;

	tm_shaper_params_cvt_to(params, profile_obj);
	return 0;
}

odp_tm_shaper_t odp_tm_shaper_lookup(const char *name)
{
	return _odp_int_name_tbl_lookup(name, ODP_TM_SHAPER_PROFILE_HANDLE);
}

void odp_tm_sched_params_init(odp_tm_sched_params_t *params)
{
	memset(params, 0, sizeof(odp_tm_sched_params_t));
}

odp_tm_sched_t odp_tm_sched_create(const char *name,
				   odp_tm_sched_params_t *params)
{
	odp_tm_sched_mode_t sched_mode;
	tm_sched_params_t *profile_obj;
	_odp_int_name_t name_tbl_id;
	odp_tm_sched_t sched_handle;
	uint32_t priority, weight;

	profile_obj = tm_common_profile_create(name, TM_SCHED_PROFILE,
					       sizeof(tm_sched_params_t),
					       &sched_handle, &name_tbl_id);
	if (!profile_obj)
		return ODP_TM_INVALID;

	profile_obj->name_tbl_id = name_tbl_id;

	for (priority = 0; priority < ODP_TM_MAX_PRIORITIES; priority++) {
		sched_mode = params->sched_modes[priority];
		weight = params->sched_weights[priority];

		profile_obj->sched_modes[priority] = sched_mode;
		profile_obj->inverted_weights[priority] = 0x10000 / weight;
	}

	return sched_handle;
}

int odp_tm_sched_params_read(odp_tm_sched_t sched_profile,
			     odp_tm_sched_params_t *params)
{
	odp_tm_sched_params_t *sched_params;

	sched_params = tm_get_profile_params(sched_profile, TM_SCHED_PROFILE);
	if (!sched_params)
		return -1;

	*params = *sched_params;
	return 0;
}

int odp_tm_sched_params_update(odp_tm_sched_t sched_profile,
			       odp_tm_sched_params_t *params)
{
	odp_tm_sched_params_t *sched_params;

	sched_params = tm_get_profile_params(sched_profile, TM_SCHED_PROFILE);
	if (!sched_params)
		return -1;

	*sched_params = *params;
	return 0;
}

odp_tm_sched_t odp_tm_sched_lookup(const char *name)
{
	return _odp_int_name_tbl_lookup(name, ODP_TM_SCHED_PROFILE_HANDLE);
}

void odp_tm_threshold_params_init(odp_tm_threshold_params_t *params)
{
	memset(params, 0, sizeof(odp_tm_threshold_params_t));
}

odp_tm_threshold_t odp_tm_threshold_create(const char *name,
					   odp_tm_threshold_params_t *params)
{
	tm_queue_thresholds_t *profile_obj;
	odp_tm_threshold_t threshold_handle;
	_odp_int_name_t name_tbl_id;

	profile_obj =
		tm_common_profile_create(name, TM_THRESHOLD_PROFILE,
					 sizeof(odp_tm_threshold_params_t),
					 &threshold_handle,
					 &name_tbl_id);
	if (!profile_obj)
		return ODP_TM_INVALID;

	profile_obj->max_pkts = params->enable_max_pkts ? params->max_pkts : 0;
	profile_obj->max_bytes =
		params->enable_max_bytes ? params->max_bytes : 0;
	profile_obj->name_tbl_id = name_tbl_id;
	return threshold_handle;
}

int odp_tm_thresholds_params_read(odp_tm_threshold_t threshold_profile,
				  odp_tm_threshold_params_t *params)
{
	tm_queue_thresholds_t *threshold_params;

	threshold_params = tm_get_profile_params(threshold_profile,
						 TM_THRESHOLD_PROFILE);
	if (!threshold_params)
		return -1;

	params->max_pkts = threshold_params->max_pkts;
	params->max_bytes = threshold_params->max_bytes;
	params->enable_max_pkts = threshold_params->max_pkts != 0;
	params->enable_max_bytes = threshold_params->max_bytes != 0;
	return 0;
}

int odp_tm_thresholds_params_update(odp_tm_threshold_t threshold_profile,
				    odp_tm_threshold_params_t *params)
{
	tm_queue_thresholds_t *profile_obj;

	profile_obj = tm_get_profile_params(threshold_profile,
					    TM_THRESHOLD_PROFILE);
	if (!profile_obj)
		return -1;

	profile_obj->max_pkts = params->enable_max_pkts ? params->max_pkts : 0;
	profile_obj->max_bytes =
		params->enable_max_bytes ? params->max_bytes : 0;
	return 0;
}

odp_tm_threshold_t odp_tm_thresholds_lookup(const char *name)
{
	return _odp_int_name_tbl_lookup(name, ODP_TM_THRESHOLD_PROFILE_HANDLE);
}

void odp_tm_wred_params_init(odp_tm_wred_params_t *params)
{
	memset(params, 0, sizeof(odp_tm_wred_params_t));
}

odp_tm_wred_t odp_tm_wred_create(const char *name, odp_tm_wred_params_t *params)
{
	odp_tm_wred_params_t *profile_obj;
	odp_tm_wred_t wred_handle;
	_odp_int_name_t name_tbl_id;

	profile_obj = tm_common_profile_create(name, TM_WRED_PROFILE,
					       sizeof(odp_tm_wred_params_t),
					       &wred_handle,
					       &name_tbl_id);
	if (!profile_obj)
		return ODP_TM_INVALID;

	*profile_obj = *params;
	return wred_handle;
}

int odp_tm_wred_params_read(odp_tm_wred_t wred_profile,
			    odp_tm_wred_params_t *params)
{
	odp_tm_wred_params_t *wred_params;

	wred_params = tm_get_profile_params(wred_profile, TM_WRED_PROFILE);
	if (!wred_params)
		return -1;

	*params = *wred_params;
	return 0;
}

int odp_tm_wred_params_update(odp_tm_wred_t wred_profile,
			      odp_tm_wred_params_t *params)
{
	odp_tm_wred_params_t *wred_params;

	wred_params = tm_get_profile_params(wred_profile, TM_WRED_PROFILE);
	if (!wred_params)
		return -1;

	*wred_params = *params;
	return 0;
}

odp_tm_wred_t odp_tm_wred_lookup(const char *name)
{
	return _odp_int_name_tbl_lookup(name, ODP_TM_WRED_PROFILE_HANDLE);
}

void odp_tm_node_params_init(odp_tm_node_params_t *params)
{
	memset(params, 0, sizeof(odp_tm_node_params_t));
}

odp_tm_node_t odp_tm_node_create(odp_tm_t odp_tm, const char *name,
				 odp_tm_node_params_t *params)
{
	_odp_int_sorted_list_t sorted_list;
	tm_schedulers_obj_t *schedulers_obj;
	_odp_int_name_t name_tbl_id;
	tm_wred_node_t *tm_wred_node;
	tm_node_obj_t *tm_node_obj;
	odp_tm_node_t odp_tm_node;
	odp_tm_wred_t wred_profile;
	tm_system_t *tm_system;
	uint32_t num_priorities, priority, schedulers_obj_len, color;

	/* Allocate a tm_node_obj_t record. */
	tm_system = GET_TM_SYSTEM(odp_tm);
	tm_node_obj = malloc(sizeof(tm_node_obj_t));
	if (!tm_node_obj)
		return ODP_TM_INVALID;

	tm_wred_node = malloc(sizeof(tm_wred_node_t));
	if (!tm_wred_node) {
		free(tm_node_obj);
		return ODP_TM_INVALID;
	}

	num_priorities = tm_system->capability.max_priority + 1;
	schedulers_obj_len = sizeof(tm_schedulers_obj_t)
		+ (sizeof(tm_sched_state_t) * num_priorities);
	schedulers_obj = malloc(schedulers_obj_len);
	if (!schedulers_obj) {
		free(tm_wred_node);
		free(tm_node_obj);
		return ODP_TM_INVALID;
	}

	memset(schedulers_obj, 0, schedulers_obj_len);
	odp_tm_node = MAKE_ODP_TM_NODE(tm_node_obj);
	name_tbl_id = ODP_INVALID_NAME;
	if ((name) && (name[0] != '\0')) {
		name_tbl_id = _odp_int_name_tbl_add(name, ODP_TM_NODE_HANDLE,
						    odp_tm_node);
		if (name_tbl_id == ODP_INVALID_NAME) {
			free(schedulers_obj);
			free(tm_wred_node);
			free(tm_node_obj);
			return ODP_TM_INVALID;
		}
	}

	memset(tm_node_obj, 0, sizeof(tm_node_obj_t));
	memset(tm_wred_node, 0, sizeof(tm_wred_node_t));
	memset(schedulers_obj, 0, schedulers_obj_len);
	tm_node_obj->name_tbl_id = name_tbl_id;
	tm_node_obj->max_fanin = params->max_fanin;
	tm_node_obj->level = params->level;
	tm_node_obj->tm_idx = tm_system->tm_idx;
	tm_node_obj->tm_wred_node = tm_wred_node;
	tm_node_obj->schedulers_obj = schedulers_obj;
	odp_ticketlock_init(&tm_wred_node->tm_wred_node_lock);

	schedulers_obj->num_priorities = num_priorities;
	for (priority = 0; priority < num_priorities; priority++) {
		sorted_list = _odp_sorted_list_create(
			tm_system->_odp_int_sorted_pool,
			params->max_fanin);
		schedulers_obj->sched_states[priority].sorted_list =
			sorted_list;
	}

	odp_ticketlock_lock(&tm_system->tm_system_lock);
	if (params->shaper_profile != ODP_TM_INVALID)
		tm_shaper_config_set(tm_system, params->shaper_profile,
				     &tm_node_obj->shaper_obj);

	if (params->threshold_profile != ODP_TM_INVALID)
		tm_wred_node->threshold_params = tm_get_profile_params(
			params->threshold_profile,
			TM_THRESHOLD_PROFILE);

	for (color = 0; color < ODP_NUM_PACKET_COLORS; color++) {
		wred_profile = params->wred_profile[color];
		if (wred_profile != ODP_TM_INVALID)
			tm_wred_node->wred_params[color] =
				tm_get_profile_params(wred_profile,
						      TM_WRED_PROFILE);
	}

	tm_node_obj->magic_num = TM_NODE_MAGIC_NUM;
	tm_node_obj->shaper_obj.enclosing_entity = tm_node_obj;
	tm_node_obj->shaper_obj.in_tm_node_obj = 1;
	tm_node_obj->schedulers_obj->enclosing_entity = tm_node_obj;

	odp_ticketlock_unlock(&tm_system->tm_system_lock);
	return odp_tm_node;
}

int odp_tm_node_shaper_config(odp_tm_node_t tm_node,
			      odp_tm_shaper_t shaper_profile)
{
	tm_node_obj_t *tm_node_obj;
	tm_system_t *tm_system;

	tm_node_obj = GET_TM_NODE_OBJ(tm_node);
	if (!tm_node_obj)
		return -1;

	tm_system = odp_tm_systems[tm_node_obj->tm_idx];
	if (!tm_system)
		return -2;

	odp_ticketlock_lock(&tm_profile_lock);
	tm_shaper_config_set(tm_system, shaper_profile,
			     &tm_node_obj->shaper_obj);
	odp_ticketlock_unlock(&tm_profile_lock);
	return 0;
}

int odp_tm_node_sched_config(odp_tm_node_t tm_node,
			     odp_tm_node_t tm_fan_in_node,
			     odp_tm_sched_t sched_profile)
{
	tm_shaper_obj_t *child_shaper_obj;
	tm_node_obj_t *tm_node_obj, *child_tm_node_obj;

	tm_node_obj = GET_TM_NODE_OBJ(tm_node);
	if (!tm_node_obj)
		return -1;

	child_tm_node_obj = GET_TM_NODE_OBJ(tm_fan_in_node);
	if (!child_tm_node_obj)
		return -1;

	odp_ticketlock_lock(&tm_profile_lock);
	child_shaper_obj = &child_tm_node_obj->shaper_obj;
	child_shaper_obj->sched_params =
		tm_get_profile_params(sched_profile,
				      TM_SCHED_PROFILE);
	odp_ticketlock_unlock(&tm_profile_lock);
	return 0;
}

int odp_tm_node_threshold_config(odp_tm_node_t tm_node,
				 odp_tm_threshold_t thresholds_profile)
{
	tm_node_obj_t *tm_node_obj;

	tm_node_obj = GET_TM_NODE_OBJ(tm_node);
	if (!tm_node_obj)
		return -1;

	odp_ticketlock_lock(&tm_profile_lock);
	tm_node_obj->tm_wred_node->threshold_params = tm_get_profile_params(
		thresholds_profile, TM_THRESHOLD_PROFILE);
	odp_ticketlock_unlock(&tm_profile_lock);
	return 0;
}

int odp_tm_node_wred_config(odp_tm_node_t tm_node, odp_packet_color_t pkt_color,
			    odp_tm_wred_t wred_profile)
{
	tm_node_obj_t *tm_node_obj;
	uint32_t color;
	int rc;

	tm_node_obj = GET_TM_NODE_OBJ(tm_node);
	if (!tm_node_obj)
		return -1;

	odp_ticketlock_lock(&tm_profile_lock);
	rc = 0;
	if (pkt_color == ODP_PACKET_ALL_COLORS) {
		for (color = 0; color < ODP_NUM_PACKET_COLORS; color++)
			tm_node_obj->tm_wred_node->wred_params[color] =
				tm_get_profile_params(wred_profile,
						      TM_WRED_PROFILE);
	} else if (pkt_color < ODP_NUM_PACKET_COLORS) {
		tm_node_obj->tm_wred_node->wred_params[pkt_color] =
			tm_get_profile_params(wred_profile,
					      TM_WRED_PROFILE);
	} else {
		rc = -1;
	}

	odp_ticketlock_unlock(&tm_profile_lock);
	return rc;
}

odp_tm_node_t odp_tm_node_lookup(odp_tm_t odp_tm ODP_UNUSED, const char *name)
{
	return _odp_int_name_tbl_lookup(name, ODP_TM_NODE_HANDLE);
}

void odp_tm_queue_params_init(odp_tm_queue_params_t *params)
{
	memset(params, 0, sizeof(odp_tm_queue_params_t));
}

odp_tm_queue_t odp_tm_queue_create(odp_tm_t odp_tm,
				   odp_tm_queue_params_t *params)
{
	_odp_int_pkt_queue_t _odp_int_pkt_queue;
	tm_queue_obj_t *tm_queue_obj;
	tm_wred_node_t *tm_wred_node;
	odp_tm_queue_t odp_tm_queue;
	odp_tm_wred_t wred_profile;
	tm_system_t *tm_system;
	uint32_t color;

	/* Allocate a tm_queue_obj_t record. */
	tm_system = GET_TM_SYSTEM(odp_tm);
	tm_queue_obj = malloc(sizeof(tm_queue_obj_t));
	if (!tm_queue_obj)
		return ODP_TM_INVALID;

	tm_wred_node = malloc(sizeof(tm_wred_node_t));
	if (!tm_wred_node) {
		free(tm_queue_obj);
		return ODP_TM_INVALID;
	}

	_odp_int_pkt_queue = _odp_pkt_queue_create(
		tm_system->_odp_int_queue_pool);
	if (_odp_int_pkt_queue == _ODP_INT_PKT_QUEUE_INVALID) {
		free(tm_wred_node);
		free(tm_queue_obj);
		return ODP_TM_INVALID;
	}

	odp_tm_queue = MAKE_ODP_TM_QUEUE(tm_queue_obj);
	memset(tm_queue_obj, 0, sizeof(tm_queue_obj_t));
	memset(tm_wred_node, 0, sizeof(tm_wred_node_t));
	tm_queue_obj->priority = params->priority;
	tm_queue_obj->tm_idx = tm_system->tm_idx;
	tm_queue_obj->queue_num = tm_system->next_queue_num++;
	tm_queue_obj->tm_wred_node = tm_wred_node;
	tm_queue_obj->_odp_int_pkt_queue = _odp_int_pkt_queue;
	tm_queue_obj->pkt = INVALID_PKT;
	odp_ticketlock_init(&tm_wred_node->tm_wred_node_lock);

	tm_queue_obj->tm_qentry.s.type = ODP_QUEUE_TYPE_TM;
	tm_queue_obj->tm_qentry.s.enqueue = queue_tm_reenq;
	tm_queue_obj->tm_qentry.s.enqueue_multi = queue_tm_reenq_multi;

	tm_system->queue_num_tbl[tm_queue_obj->queue_num] = tm_queue_obj;
	odp_ticketlock_lock(&tm_system->tm_system_lock);
	if (params->shaper_profile != ODP_TM_INVALID)
		tm_shaper_config_set(tm_system, params->shaper_profile,
				     &tm_queue_obj->shaper_obj);

	if (params->threshold_profile != ODP_TM_INVALID)
		tm_wred_node->threshold_params = tm_get_profile_params(
			params->threshold_profile,
			TM_THRESHOLD_PROFILE);

	for (color = 0; color < ODP_NUM_PACKET_COLORS; color++) {
		wred_profile = params->wred_profile[color];
		if (wred_profile != ODP_TM_INVALID)
			tm_wred_node->wred_params[color] =
				tm_get_profile_params(wred_profile,
						      TM_WRED_PROFILE);
	}

	tm_queue_obj->magic_num = TM_QUEUE_MAGIC_NUM;
	tm_queue_obj->shaper_obj.enclosing_entity = tm_queue_obj;
	tm_queue_obj->shaper_obj.in_tm_node_obj = 0;

	odp_ticketlock_unlock(&tm_system->tm_system_lock);
	return odp_tm_queue;
}

int odp_tm_queue_shaper_config(odp_tm_queue_t tm_queue,
			       odp_tm_shaper_t shaper_profile)
{
	tm_queue_obj_t *tm_queue_obj;
	tm_system_t *tm_system;

	tm_queue_obj = GET_TM_QUEUE_OBJ(tm_queue);
	if (!tm_queue_obj)
		return -1;

	tm_system = odp_tm_systems[tm_queue_obj->tm_idx];
	if (!tm_system)
		return -2;

	odp_ticketlock_lock(&tm_profile_lock);
	tm_shaper_config_set(tm_system, shaper_profile,
			     &tm_queue_obj->shaper_obj);
	odp_ticketlock_unlock(&tm_profile_lock);
	return 0;
}

int odp_tm_queue_sched_config(odp_tm_node_t tm_node,
			      odp_tm_queue_t tm_fan_in_queue,
			      odp_tm_sched_t sched_profile)
{
	tm_shaper_obj_t *child_shaper_obj;
	tm_queue_obj_t *child_tm_queue_obj;
	tm_node_obj_t *tm_node_obj;

	tm_node_obj = GET_TM_NODE_OBJ(tm_node);
	if (!tm_node_obj)
		return -1;

	child_tm_queue_obj = GET_TM_QUEUE_OBJ(tm_fan_in_queue);
	if (!child_tm_queue_obj)
		return -1;

	odp_ticketlock_lock(&tm_profile_lock);
	child_shaper_obj = &child_tm_queue_obj->shaper_obj;
	child_shaper_obj->sched_params =
		tm_get_profile_params(sched_profile,
				      TM_SCHED_PROFILE);
	odp_ticketlock_unlock(&tm_profile_lock);
	return 0;
}

int odp_tm_queue_threshold_config(odp_tm_queue_t tm_queue,
				  odp_tm_threshold_t thresholds_profile)
{
	tm_queue_obj_t *tm_queue_obj;

	tm_queue_obj = GET_TM_QUEUE_OBJ(tm_queue);
	if (!tm_queue_obj)
		return -1;

	odp_ticketlock_lock(&tm_profile_lock);
	tm_queue_obj->tm_wred_node->threshold_params = tm_get_profile_params(
		thresholds_profile, TM_THRESHOLD_PROFILE);
	odp_ticketlock_unlock(&tm_profile_lock);
	return 0;
}

int odp_tm_queue_wred_config(odp_tm_queue_t tm_queue,
			     odp_packet_color_t pkt_color,
			     odp_tm_wred_t wred_profile)
{
	tm_queue_obj_t *tm_queue_obj;
	uint32_t color;
	int rc;

	tm_queue_obj = GET_TM_QUEUE_OBJ(tm_queue);
	if (!tm_queue_obj)
		return -1;

	odp_ticketlock_lock(&tm_profile_lock);
	rc = 0;
	if (pkt_color == ODP_PACKET_ALL_COLORS) {
		for (color = 0; color < ODP_NUM_PACKET_COLORS; color++)
			tm_queue_obj->tm_wred_node->wred_params[color] =
				tm_get_profile_params(wred_profile,
						      TM_WRED_PROFILE);
	} else if (pkt_color < ODP_NUM_PACKET_COLORS) {
		tm_queue_obj->tm_wred_node->wred_params[pkt_color] =
			tm_get_profile_params(wred_profile,
					      TM_WRED_PROFILE);
	} else {
		rc = -1;
	}

	odp_ticketlock_unlock(&tm_profile_lock);
	return rc;
}

int odp_tm_node_connect(odp_tm_node_t src_tm_node, odp_tm_node_t dst_tm_node)
{
	tm_wred_node_t *src_tm_wred_node, *dst_tm_wred_node;
	tm_node_obj_t *src_tm_node_obj, *dst_tm_node_obj;

	src_tm_node_obj = GET_TM_NODE_OBJ(src_tm_node);
	dst_tm_node_obj = GET_TM_NODE_OBJ(dst_tm_node);
	if (!src_tm_node_obj)
		return -1;

	if (dst_tm_node_obj) {
		src_tm_wred_node = src_tm_node_obj->tm_wred_node;
		dst_tm_wred_node = dst_tm_node_obj->tm_wred_node;
		src_tm_wred_node->next_tm_wred_node = dst_tm_wred_node;
	}

	src_tm_node_obj->shaper_obj.next_tm_node = dst_tm_node_obj;
	return 0;
}

int odp_tm_queue_connect(odp_tm_queue_t tm_queue, odp_tm_node_t dst_tm_node)
{
	tm_wred_node_t *src_tm_wred_node, *dst_tm_wred_node;
	tm_queue_obj_t *src_tm_queue_obj;
	tm_node_obj_t *dst_tm_node_obj;

	src_tm_queue_obj = GET_TM_QUEUE_OBJ(tm_queue);
	dst_tm_node_obj = GET_TM_NODE_OBJ(dst_tm_node);
	if ((!src_tm_queue_obj) || (!dst_tm_node_obj))
		return -1;

	src_tm_wred_node = src_tm_queue_obj->tm_wred_node;
	dst_tm_wred_node = dst_tm_node_obj->tm_wred_node;
	src_tm_wred_node->next_tm_wred_node = dst_tm_wred_node;

	src_tm_queue_obj->shaper_obj.next_tm_node = dst_tm_node_obj;
	return 0;
}

int odp_tm_enq(odp_tm_queue_t tm_queue, odp_packet_t pkt)
{
	tm_queue_obj_t *tm_queue_obj;
	tm_system_t *tm_system;

	tm_queue_obj = GET_TM_QUEUE_OBJ(tm_queue);
	if (!tm_queue_obj)
		return -1; /* @todo fix magic number */

	tm_system = odp_tm_systems[tm_queue_obj->tm_idx];
	if (!tm_system)
		return -2; /* @todo fix magic number */

	if (odp_atomic_load_u32(&tm_system->destroying))
		return -6; /* @todo fix magic number */

	return tm_enqueue(tm_system, tm_queue_obj, pkt);
}

int odp_tm_enq_with_cnt(odp_tm_queue_t tm_queue, odp_packet_t pkt)
{
	tm_queue_obj_t *tm_queue_obj;
	tm_system_t *tm_system;
	uint32_t pkt_cnt;
	int rc;

	tm_queue_obj = GET_TM_QUEUE_OBJ(tm_queue);
	if (!tm_queue_obj)
		return -1;

	tm_system = odp_tm_systems[tm_queue_obj->tm_idx];
	if (!tm_system)
		return -2;

	if (odp_atomic_load_u32(&tm_system->destroying))
		return -6;

	rc = tm_enqueue(tm_system, tm_queue_obj, pkt);
	if (rc < 0)
		return rc;

	pkt_cnt = rc;
	return pkt_cnt;
}

#ifdef NOT_USED /* @todo use or delete */
static uint32_t odp_tm_input_work_queue_fullness(odp_tm_t odp_tm ODP_UNUSED)
{
	input_work_queue_t *input_work_queue;
	tm_system_t *tm_system;
	uint32_t queue_cnt, fullness;

	tm_system = GET_TM_SYSTEM(odp_tm);
	input_work_queue = tm_system->input_work_queue;
	queue_cnt = odp_atomic_load_u32(&input_work_queue->queue_cnt);
	fullness = (100 * queue_cnt) / INPUT_WORK_RING_SIZE;
	return fullness;
}
#endif

static int tm_queue_info_copy(tm_queue_info_t *queue_info, uint32_t query_flags,
			      odp_tm_queue_info_t *info)
{
	tm_queue_thresholds_t *threshold_params;

	memset(info, 0, sizeof(odp_tm_queue_info_t));
	info->total_pkt_cnt =
		odp_atomic_load_u64(&queue_info->queue_cnts.pkt_cnt);
	info->total_byte_cnt =
		odp_atomic_load_u64(&queue_info->queue_cnts.byte_cnt);
	info->total_pkt_cnt_valid = 1;
	info->total_byte_cnt_valid = 1;
	info->approx_byte_cnt = 0;

	if (query_flags & ODP_TM_QUERY_THRESHOLDS) {
		threshold_params = queue_info->threshold_params;
		if (!threshold_params)
			return -1;

		info->max_pkt_cnt = threshold_params->max_pkts;
		info->max_byte_cnt = threshold_params->max_bytes;
		info->max_pkt_cnt_valid = info->max_pkt_cnt != 0;
		info->max_byte_cnt_valid = info->max_byte_cnt != 0;
	}

	return 0;
}

int odp_tm_queue_query(odp_tm_queue_t tm_queue, uint32_t query_flags,
		       odp_tm_queue_info_t *info)
{
	tm_queue_info_t queue_info;
	tm_queue_obj_t *tm_queue_obj;
	tm_wred_node_t *tm_wred_node;

	tm_queue_obj = GET_TM_QUEUE_OBJ(tm_queue);
	if (!tm_queue_obj)
		return -1;

	tm_wred_node = tm_queue_obj->tm_wred_node;
	if (!tm_wred_node)
		return -2;

	queue_info.threshold_params = tm_wred_node->threshold_params;
	queue_info.queue_cnts = tm_wred_node->queue_cnts;
	return tm_queue_info_copy(&queue_info, query_flags, info);
}

int odp_tm_priority_query(odp_tm_t odp_tm, uint8_t priority,
			  uint32_t query_flags, odp_tm_queue_info_t *info)
{
	tm_queue_info_t queue_info;
	tm_system_t *tm_system;

	tm_system = GET_TM_SYSTEM(odp_tm);
	queue_info = tm_system->priority_info[priority];
	return tm_queue_info_copy(&queue_info, query_flags, info);
}

int odp_tm_total_query(odp_tm_t odp_tm, uint32_t query_flags,
		       odp_tm_queue_info_t *info)
{
	tm_queue_info_t queue_info;
	tm_system_t *tm_system;

	tm_system = GET_TM_SYSTEM(odp_tm);
	queue_info = tm_system->total_info;
	return tm_queue_info_copy(&queue_info, query_flags, info);
}

int odp_tm_priority_threshold_config(odp_tm_t odp_tm, uint8_t priority,
				     odp_tm_threshold_t thresholds_profile)
{
	tm_system_t *tm_system;

	tm_system = GET_TM_SYSTEM(odp_tm);

	odp_ticketlock_lock(&tm_profile_lock);
	tm_system->priority_info[priority].threshold_params =
		tm_get_profile_params(thresholds_profile,
				      TM_THRESHOLD_PROFILE);
	odp_ticketlock_unlock(&tm_profile_lock);
	return 0;
}

int odp_tm_total_threshold_config(odp_tm_t odp_tm,
				  odp_tm_threshold_t thresholds_profile)
{
	tm_system_t *tm_system;

	tm_system = GET_TM_SYSTEM(odp_tm);

	odp_ticketlock_lock(&tm_profile_lock);
	tm_system->total_info.threshold_params = tm_get_profile_params(
		thresholds_profile, TM_THRESHOLD_PROFILE);
	odp_ticketlock_unlock(&tm_profile_lock);
	return 0;
}

void odp_tm_stats_print(odp_tm_t odp_tm)
{
	input_work_queue_t *input_work_queue;
	tm_queue_obj_t *tm_queue_obj;
	tm_system_t *tm_system;
	uint32_t queue_num, max_queue_num;

	tm_system = GET_TM_SYSTEM(odp_tm);
	input_work_queue = tm_system->input_work_queue;

	ODP_DBG("odp_tm_stats_print - tm_system=0x%lX tm_idx=%u\n", odp_tm,
		tm_system->tm_idx);
	ODP_DBG("  input_work_queue size=%u current cnt=%u peak cnt=%u\n",
		INPUT_WORK_RING_SIZE, input_work_queue->queue_cnt,
		input_work_queue->peak_cnt);
	ODP_DBG("  input_work_queue enqueues=%lu dequeues=%lu fail_cnt=%lu\n",
		input_work_queue->total_enqueues,
		input_work_queue->total_dequeues,
		input_work_queue->enqueue_fail_cnt);
	ODP_DBG("  green_cnt=%lu yellow_cnt=%lu red_cnt=%lu\n",
		tm_system->shaper_green_cnt,
		tm_system->shaper_yellow_cnt,
		tm_system->shaper_red_cnt);

	_odp_pkt_queue_stats_print(tm_system->_odp_int_queue_pool);
	_odp_timer_wheel_stats_print(tm_system->_odp_int_timer_wheel);
	_odp_sorted_list_stats_print(tm_system->_odp_int_sorted_pool);

	max_queue_num = tm_system->next_queue_num;
	for (queue_num = 1; queue_num < max_queue_num; queue_num++) {
		tm_queue_obj = tm_system->queue_num_tbl[queue_num];
		ODP_DBG("queue_num=%u priority=%u rcvd=%u enqueued=%u "
			"dequeued=%u consumed=%u\n",
			queue_num,
			tm_queue_obj->priority,
			tm_queue_obj->pkts_rcvd_cnt,
			tm_queue_obj->pkts_enqueued_cnt,
			tm_queue_obj->pkts_dequeued_cnt,
			tm_queue_obj->pkts_consumed_cnt);
	}
}

void odp_tm_periodic_update(void)
{
	return; /* Nothing to be done here for this implementation. */
}

int odp_tm_init_global(void)
{
	odp_ticketlock_init(&tm_create_lock);
	odp_ticketlock_init(&tm_profile_lock);
	odp_barrier_init(&tm_first_enq, 2);

	return 0;
}
