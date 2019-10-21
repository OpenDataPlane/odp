/* Copyright 2015 EZchip Semiconductor Ltd. All Rights Reserved.
 *
 * Copyright (c) 2015-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <odp_posix_extensions.h>

#include <stdint.h>
#include <string.h>
#include <malloc.h>
#include <stdio.h>
#include <stdbool.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sched.h>
#include <unistd.h>
#include <pthread.h>
#include <odp/api/std_types.h>
#include <protocols/eth.h>
#include <protocols/ip.h>
#include <odp_traffic_mngr_internal.h>
#include <odp/api/plat/packet_inlines.h>
#include <odp/api/plat/byteorder_inlines.h>
#include <odp/api/time.h>
#include <odp/api/plat/time_inlines.h>
#include <odp_macros_internal.h>
#include <odp_init_internal.h>
#include <odp_errno_define.h>

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

static const tm_prop_t basic_prop_tbl[MAX_PRIORITIES][NUM_SHAPER_COLORS] = {
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

#define MAX_SHAPER_PROFILES 128
#define MAX_SCHED_PROFILES 128
#define MAX_THRESHOLD_PROFILES 128
#define MAX_WRED_PROFILES 128

typedef struct {
	struct {
		tm_shaper_params_t profile[MAX_SHAPER_PROFILES];
		odp_ticketlock_t lock;
	} shaper;
	struct {
		tm_sched_params_t profile[MAX_SCHED_PROFILES];
		odp_ticketlock_t lock;
	} sched;
	struct {
		tm_queue_thresholds_t profile[MAX_THRESHOLD_PROFILES];
		odp_ticketlock_t lock;
	} threshold;
	struct {
		tm_wred_params_t profile[MAX_WRED_PROFILES];
		odp_ticketlock_t lock;
	} wred;
} profile_tbl_t;

typedef struct {
	tm_system_t system[ODP_TM_MAX_NUM_SYSTEMS];

	struct {
		tm_system_group_t group[ODP_TM_MAX_NUM_SYSTEMS];
		odp_ticketlock_t lock;
	} system_group;
	struct {
		tm_queue_obj_t obj[ODP_TM_MAX_TM_QUEUES];
		odp_ticketlock_t lock;
	} queue_obj;
	struct {
		tm_node_obj_t obj[ODP_TM_MAX_NUM_TM_NODES];
		odp_ticketlock_t lock;
	} node_obj;

	profile_tbl_t profile_tbl;

	odp_ticketlock_t create_lock;
	odp_ticketlock_t profile_lock;
	odp_barrier_t first_enq;

	int main_thread_cpu;
	int cpu_num;

	/* Service threads */
	uint64_t         busy_wait_counter;
	odp_bool_t       main_loop_running;
	odp_atomic_u64_t atomic_request_cnt;
	odp_atomic_u64_t currently_serving_cnt;
	odp_atomic_u64_t atomic_done_cnt;

	odp_shm_t shm;
} tm_global_t;

static tm_global_t *tm_glb;

/* Forward function declarations. */
static void tm_queue_cnts_decrement(tm_system_t *tm_system,
				    tm_wred_node_t *tm_wred_node,
				    uint32_t priority,
				    uint32_t frame_len);

static odp_bool_t tm_demote_pkt_desc(tm_system_t *tm_system,
				     tm_node_obj_t *tm_node_obj,
				     tm_schedulers_obj_t *blocked_scheduler,
				     tm_shaper_obj_t *timer_shaper,
				     pkt_desc_t *demoted_pkt_desc);

static inline tm_queue_obj_t *tm_qobj_from_index(uint32_t queue_id)
{
	return &tm_glb->queue_obj.obj[queue_id];
}

static inline tm_node_obj_t *tm_nobj_from_index(uint32_t node_id)
{
	return &tm_glb->node_obj.obj[node_id];
}

static int queue_tm_reenq(odp_queue_t queue, odp_buffer_hdr_t *buf_hdr)
{
	odp_tm_queue_t tm_queue = MAKE_ODP_TM_QUEUE(odp_queue_context(queue));
	odp_packet_t pkt = packet_from_buf_hdr(buf_hdr);

	return odp_tm_enq(tm_queue, pkt);
}

static int queue_tm_reenq_multi(odp_queue_t queue, odp_buffer_hdr_t *buf[],
				int num)
{
	(void)queue;
	(void)buf;
	(void)num;
	ODP_ABORT("Invalid call to queue_tm_reenq_multi()\n");
	return 0;
}

static tm_queue_obj_t *get_tm_queue_obj(tm_system_t *tm_system,
					pkt_desc_t *pkt_desc)
{
	tm_queue_obj_t *tm_queue_obj;
	uint32_t queue_num;

	if ((!pkt_desc) || (pkt_desc->queue_num == 0))
		return NULL;

	queue_num    = pkt_desc->queue_num;
	tm_queue_obj = tm_system->queue_num_tbl[queue_num - 1];
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
					    256 - byte_cnt, ODP_RANDOM_BASIC);

	tm_random_data->next_random_byte = 0;
}

static uint16_t tm_random16(tm_random_data_t *tm_random_data)
{
	uint32_t buf_idx;
	uint16_t rand8a, rand8b;

	if (255 <= tm_random_data->next_random_byte)
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

static void *alloc_entry_in_tbl(profile_tbl_t *profile_tbl,
				profile_kind_t profile_kind,
				uint32_t *idx)
{
	uint32_t i;

	switch (profile_kind) {
	case TM_SHAPER_PROFILE: {
		tm_shaper_params_t *profile = NULL;

		odp_ticketlock_lock(&profile_tbl->shaper.lock);
		for (i = 0; i < MAX_SHAPER_PROFILES; i++) {
			if (profile_tbl->shaper.profile[i].status !=
					TM_STATUS_FREE)
				continue;

			profile = &profile_tbl->shaper.profile[i];
			memset(profile, 0, sizeof(tm_shaper_params_t));
			profile->status = TM_STATUS_RESERVED;
			*idx = i;
			break;
		}
		odp_ticketlock_unlock(&profile_tbl->shaper.lock);
		return profile;
	}
	case TM_SCHED_PROFILE: {
		tm_sched_params_t *profile = NULL;

		odp_ticketlock_lock(&profile_tbl->sched.lock);
		for (i = 0; i < MAX_SCHED_PROFILES; i++) {
			if (profile_tbl->sched.profile[i].status !=
					TM_STATUS_FREE)
				continue;

			profile = &profile_tbl->sched.profile[i];
			memset(profile, 0, sizeof(tm_sched_params_t));
			profile->status = TM_STATUS_RESERVED;
			*idx = i;
			break;
		}
		odp_ticketlock_unlock(&profile_tbl->sched.lock);
		return profile;
	}
	case TM_THRESHOLD_PROFILE: {
		tm_queue_thresholds_t *profile = NULL;

		odp_ticketlock_lock(&profile_tbl->threshold.lock);
		for (i = 0; i < MAX_THRESHOLD_PROFILES; i++) {
			if (profile_tbl->threshold.profile[i].status !=
					TM_STATUS_FREE)
				continue;

			profile = &profile_tbl->threshold.profile[i];
			memset(profile, 0, sizeof(tm_queue_thresholds_t));
			profile->status = TM_STATUS_RESERVED;
			*idx = i;
			break;
		}
		odp_ticketlock_unlock(&profile_tbl->threshold.lock);
		return profile;
	}
	case TM_WRED_PROFILE: {
		tm_wred_params_t *profile = NULL;

		odp_ticketlock_lock(&profile_tbl->wred.lock);
		for (i = 0; i < MAX_WRED_PROFILES; i++) {
			if (profile_tbl->wred.profile[i].status !=
					TM_STATUS_FREE)
				continue;

			profile = &profile_tbl->wred.profile[i];
			memset(profile, 0, sizeof(tm_wred_params_t));
			profile->status = TM_STATUS_RESERVED;
			*idx = i;
			break;
		}
		odp_ticketlock_unlock(&profile_tbl->wred.lock);
		return profile;
	}
	default:
		ODP_ERR("Invalid TM profile\n");
		return NULL;

	}
}

static void free_tbl_entry(profile_tbl_t *profile_tbl,
			   profile_kind_t profile_kind,
			   uint32_t idx)
{
	switch (profile_kind) {
	case TM_SHAPER_PROFILE:
		odp_ticketlock_lock(&profile_tbl->shaper.lock);
		profile_tbl->shaper.profile[idx].status = TM_STATUS_RESERVED;
		odp_ticketlock_unlock(&profile_tbl->shaper.lock);
		return;

	case TM_SCHED_PROFILE:
		odp_ticketlock_lock(&profile_tbl->sched.lock);
		profile_tbl->sched.profile[idx].status = TM_STATUS_RESERVED;
		odp_ticketlock_unlock(&profile_tbl->sched.lock);
		return;

	case TM_THRESHOLD_PROFILE:
		odp_ticketlock_lock(&profile_tbl->threshold.lock);
		profile_tbl->threshold.profile[idx].status = TM_STATUS_RESERVED;
		odp_ticketlock_unlock(&profile_tbl->threshold.lock);
		return;

	case TM_WRED_PROFILE:
		odp_ticketlock_lock(&profile_tbl->wred.lock);
		profile_tbl->wred.profile[idx].status = TM_STATUS_RESERVED;
		odp_ticketlock_unlock(&profile_tbl->wred.lock);
		return;

	default:
		ODP_ERR("Invalid TM profile\n");
		return;

	}
}

static void input_work_queue_init(input_work_queue_t *input_work_queue)
{
	memset(input_work_queue, 0, sizeof(input_work_queue_t));
	odp_atomic_init_u64(&input_work_queue->queue_cnt, 0);
	odp_ticketlock_init(&input_work_queue->lock);
}

static void input_work_queue_destroy(input_work_queue_t *input_work_queue)
{
       /* We first need to "flush/drain" this input_work_queue before
	* freeing it.  Of course, elsewhere it is essential to have first
	* stopped new tm_enq() (et al) calls from succeeding.
	*/
	odp_ticketlock_lock(&input_work_queue->lock);
	memset(input_work_queue, 0, sizeof(input_work_queue_t));
}

static int input_work_queue_append(tm_system_t *tm_system,
				   input_work_item_t *work_item)
{
	input_work_queue_t *input_work_queue;
	input_work_item_t *entry_ptr;
	uint32_t queue_cnt, tail_idx;

	input_work_queue = &tm_system->input_work_queue;
	queue_cnt = odp_atomic_load_u64(&input_work_queue->queue_cnt);
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
	odp_atomic_inc_u64(&input_work_queue->queue_cnt);
	if (input_work_queue->peak_cnt <= queue_cnt)
		input_work_queue->peak_cnt = queue_cnt + 1;
	return 0;
}

static int input_work_queue_remove(input_work_queue_t *input_work_queue,
				   input_work_item_t *work_item)
{
	input_work_item_t *entry_ptr;
	uint32_t queue_cnt, head_idx;

	queue_cnt = odp_atomic_load_u64(&input_work_queue->queue_cnt);
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
	odp_atomic_dec_u64(&input_work_queue->queue_cnt);
	return 0;
}

static tm_system_t *tm_system_alloc(void)
{
	tm_system_t *tm_system;
	uint32_t tm_idx;

	/* Find an open slot in the odp_tm_systems array. */
	for (tm_idx = 0; tm_idx < ODP_TM_MAX_NUM_SYSTEMS; tm_idx++) {
		if (tm_glb->system[tm_idx].status == TM_STATUS_FREE) {
			tm_system = &tm_glb->system[tm_idx];
			memset(tm_system, 0, sizeof(tm_system_t));
			tm_system->tm_idx = tm_idx;
			tm_system->status = TM_STATUS_RESERVED;
			return tm_system;
		}
	}

	return NULL;
}

static void tm_system_free(tm_system_t *tm_system)
{
	tm_glb->system[tm_system->tm_idx].status = TM_STATUS_FREE;
}

static void *tm_common_profile_create(const char      *name,
				      profile_kind_t   profile_kind,
				      tm_handle_t     *profile_handle_ptr,
				      _odp_int_name_t *name_tbl_id_ptr)
{
	_odp_int_name_kind_t handle_kind;
	_odp_int_name_t      name_tbl_id;
	tm_handle_t          profile_handle;
	void                *object_ptr;
	uint32_t             idx = 0;

	/* Note that alloc_entry_in_tbl will zero out all of the memory that it
	 * allocates, so an additional memset here is unnecessary. */
	object_ptr  = alloc_entry_in_tbl(&tm_glb->profile_tbl, profile_kind,
					 &idx);
	if (!object_ptr) {
		ODP_ERR("No free profiles left\n");
		return NULL;
	}

	handle_kind    = PROFILE_TO_HANDLE_KIND[profile_kind];
	profile_handle = MAKE_PROFILE_HANDLE(profile_kind, idx);
	name_tbl_id    = ODP_INVALID_NAME;

	if ((name != NULL) && (name[0] != '\0')) {
		name_tbl_id = _odp_int_name_tbl_add(name, handle_kind,
						    profile_handle);
		if (name_tbl_id == ODP_INVALID_NAME) {
			free_tbl_entry(&tm_glb->profile_tbl, profile_kind, idx);
			return NULL;
		}
	}

	*profile_handle_ptr = profile_handle;
	if (name_tbl_id_ptr)
		*name_tbl_id_ptr = name_tbl_id;
	return object_ptr;
}

static int tm_common_profile_destroy(tm_handle_t profile_handle,
				     _odp_int_name_t name_tbl_id)
{
	profile_kind_t profile_kind;
	uint32_t idx;

	if (name_tbl_id != ODP_INVALID_NAME)
		_odp_int_name_tbl_delete(name_tbl_id);

	profile_kind = GET_PROFILE_KIND(profile_handle);
	idx = GET_TBL_IDX(profile_handle);
	free_tbl_entry(&tm_glb->profile_tbl, profile_kind, idx);

	return 0;
}

static void *tm_get_profile_params(tm_handle_t profile_handle,
				   profile_kind_t expected_profile_kind)
{
	profile_kind_t profile_kind;
	uint32_t idx;

	profile_kind = GET_PROFILE_KIND(profile_handle);
	if (profile_kind != expected_profile_kind)
		return NULL;

	idx = GET_TBL_IDX(profile_handle);

	switch (profile_kind) {
	case TM_SHAPER_PROFILE:
		return &tm_glb->profile_tbl.shaper.profile[idx];

	case TM_SCHED_PROFILE:
		return &tm_glb->profile_tbl.sched.profile[idx];

	case TM_THRESHOLD_PROFILE:
		return &tm_glb->profile_tbl.threshold.profile[idx];

	case TM_WRED_PROFILE:
		return &tm_glb->profile_tbl.wred.profile[idx];

	default:
		ODP_ERR("Invalid TM profile\n");
		return NULL;
	}
}

static uint64_t tm_bps_to_rate(uint64_t bps)
{
	/* This code assumes that bps is in the range 1 kbps .. 1 tbps. */
	if ((bps >> 32) == 0)
		return (bps << 23) / ODP_TIME_SEC_IN_NS;
	else
		return ((bps << 15) / ODP_TIME_SEC_IN_NS) << 8;
}

static uint64_t tm_rate_to_bps(uint64_t rate)
{
	/* This code assumes that bps is in the range 1 kbps .. 1 tbps. */
	return (rate * ODP_TIME_SEC_IN_NS) >> 23;
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
	int64_t  commit_burst, peak_burst;

	commit_rate = tm_bps_to_rate(odp_shaper_params->commit_bps);
	if ((odp_shaper_params->commit_bps == 0) || (commit_rate == 0)) {
		tm_shaper_params->max_commit_time_delta = 0;
		tm_shaper_params->max_peak_time_delta   = 0;
		tm_shaper_params->commit_rate           = 0;
		tm_shaper_params->peak_rate             = 0;
		tm_shaper_params->max_commit            = 0;
		tm_shaper_params->max_peak              = 0;
		tm_shaper_params->min_time_delta        = 0;
		tm_shaper_params->len_adjust            = 0;
		tm_shaper_params->dual_rate             = 0;
		tm_shaper_params->enabled               = 0;
		return;
	}

	max_commit_time_delta = tm_max_time_delta(commit_rate);
	commit_burst = (int64_t)odp_shaper_params->commit_burst;

	peak_rate = tm_bps_to_rate(odp_shaper_params->peak_bps);
	if ((odp_shaper_params->peak_bps == 0) || (peak_rate == 0)) {
		peak_rate = 0;
		max_peak_time_delta = 0;
		peak_burst = 0;
		min_time_delta = (uint32_t)((1 << 26) / commit_rate);
	} else {
		max_peak_time_delta = tm_max_time_delta(peak_rate);
		peak_burst = (int64_t)odp_shaper_params->peak_burst;
		highest_rate = MAX(commit_rate, peak_rate);
		min_time_delta = (uint32_t)((1 << 26) / highest_rate);
	}

	tm_shaper_params->max_commit_time_delta = max_commit_time_delta;
	tm_shaper_params->max_peak_time_delta = max_peak_time_delta;

	tm_shaper_params->commit_rate = commit_rate;
	tm_shaper_params->peak_rate = peak_rate;
	tm_shaper_params->max_commit = commit_burst << (26 - 3);
	tm_shaper_params->max_peak = peak_burst << (26 - 3);
	tm_shaper_params->min_time_delta = min_time_delta;
	tm_shaper_params->len_adjust = odp_shaper_params->shaper_len_adjust;
	tm_shaper_params->dual_rate = odp_shaper_params->dual_rate;
	tm_shaper_params->enabled = 1;
}

static void tm_shaper_params_cvt_from(tm_shaper_params_t     *tm_shaper_params,
				      odp_tm_shaper_params_t *odp_shaper_params)
{
	uint64_t commit_bps, peak_bps, commit_burst, peak_burst;

	if (tm_shaper_params->enabled == 0) {
		memset(odp_shaper_params, 0, sizeof(odp_tm_shaper_params_t));
		return;
	}

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
	shaper_obj->last_update_time = tm_system->current_time;
	shaper_obj->callback_time = 0;
	shaper_obj->commit_cnt = shaper_params->max_commit;
	shaper_obj->peak_cnt = shaper_params->max_peak;
	shaper_obj->callback_reason = NO_CALLBACK;
	shaper_obj->initialized = 1;
}

/* Any locking required and validity checks must be done by the caller! */
static void tm_shaper_config_set(tm_system_t     *tm_system,
				 odp_tm_shaper_t  shaper_profile,
				 tm_shaper_obj_t *shaper_obj)
{
	tm_shaper_params_t *shaper_params;

	/* First remove any old shaper_params. */
	if (shaper_obj->shaper_params != NULL) {
		shaper_obj->shaper_params->ref_cnt--;
		shaper_obj->shaper_params = NULL;
	}

	if (shaper_profile == ODP_TM_INVALID)
		return;

	shaper_params = tm_get_profile_params(shaper_profile,
					      TM_SHAPER_PROFILE);
	if (shaper_params == NULL)
		return;

	shaper_params->ref_cnt++;
	if (shaper_obj->initialized == 0)
		tm_shaper_obj_init(tm_system, shaper_params, shaper_obj);
	else
		shaper_obj->shaper_params = shaper_params;
}

/* Any locking required and validity checks must be done by the caller! */
static void tm_sched_config_set(tm_shaper_obj_t *shaper_obj,
				odp_tm_sched_t   sched_profile)
{
	tm_sched_params_t *sched_params;

	if (shaper_obj->sched_params != NULL) {
		shaper_obj->sched_params->ref_cnt--;
		shaper_obj->sched_params = NULL;
	}

	if (sched_profile == ODP_TM_INVALID)
		return;

	sched_params = tm_get_profile_params(sched_profile, TM_SCHED_PROFILE);
	if (sched_params == NULL)
		return;

	sched_params->ref_cnt++;
	shaper_obj->sched_params = sched_params;
}

/* Any locking required and validity checks must be done by the caller! */
static int tm_threshold_config_set(tm_wred_node_t    *wred_node,
				   odp_tm_threshold_t thresholds_profile)
{
	tm_queue_thresholds_t *threshold_params;

	if (wred_node->threshold_params != NULL) {
		wred_node->threshold_params->ref_cnt--;
		wred_node->threshold_params = NULL;
	}

	if (thresholds_profile == ODP_TM_INVALID)
		return 0;

	threshold_params = tm_get_profile_params(thresholds_profile,
						 TM_THRESHOLD_PROFILE);
	if (threshold_params == NULL) {
		ODP_DBG("threshold_params is NULL\n");
		return -1;
	}

	threshold_params->ref_cnt++;
	wred_node->threshold_params = threshold_params;
	return 0;
}

/* Any locking required and validity checks must be done by the caller! */
static void tm_wred_config_set(tm_wred_node_t *wred_node,
			       uint32_t        color,
			       odp_tm_wred_t   wred_profile)
{
	tm_wred_params_t *wred_params;

	if (wred_node->wred_params[color] != NULL) {
		wred_node->wred_params[color]->ref_cnt--;
		wred_node->wred_params[color] = NULL;
	}

	if (wred_profile == ODP_TM_INVALID)
		return;

	wred_params = tm_get_profile_params(wred_profile, TM_WRED_PROFILE);
	if (wred_params == NULL)
		return;

	wred_params->ref_cnt++;
	wred_node->wred_params[color] = wred_params;
}

static void update_shaper_elapsed_time(tm_system_t        *tm_system,
				       tm_shaper_params_t *shaper_params,
				       tm_shaper_obj_t    *shaper_obj)
{
	uint64_t time_delta;
	int64_t  commit, peak, commit_inc, peak_inc, max_commit, max_peak;

	if (shaper_params->enabled == 0) {
		shaper_obj->commit_cnt       = shaper_params->max_commit;
		shaper_obj->peak_cnt         = shaper_params->max_peak;
		shaper_obj->last_update_time = tm_system->current_time;
		return;
	}

       /* If the time_delta is "too small" then we just exit without making
	* any changes.  Too small is defined such that
	* time_delta/ODP_TIME_SEC_IN_NS * MAX(commit_rate, peak_rate) is less
	* than a byte.
	*/
	time_delta = tm_system->current_time - shaper_obj->last_update_time;
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

	shaper_obj->last_update_time = tm_system->current_time;
}

static uint64_t time_till_not_red(tm_shaper_params_t *shaper_params,
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

	min_time_delay =
	    MAX(shaper_obj->shaper_params->min_time_delta, UINT64_C(256));
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
	    (!shaper_obj)) {
		tm_queue_obj->timer_reason = NO_CALLBACK;
		tm_queue_obj->timer_shaper = NULL;
		return -1;
	}

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
	if (!tm_queue_obj)
		return;

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
	* is NULL or not. */
	tm_queue_obj = get_tm_queue_obj(tm_system, pkt_desc);
	if (!tm_queue_obj)
		return;

	if (tm_node_obj)
		tm_demote_pkt_desc(tm_system, tm_node_obj,
				   tm_queue_obj->blocked_scheduler,
				   tm_queue_obj->timer_shaper, pkt_desc);

	else if (tm_queue_obj->timer_reason != NO_CALLBACK)
		ODP_DBG("%s timer_reason != NO_CALLBACK\n", __func__);

	tm_queue_obj->blocked_cnt = 1;
	tm_queue_obj->blocked_scheduler = schedulers_obj;
	tm_queue_obj->blocked_priority = priority;
}

static odp_bool_t delay_pkt(tm_system_t *tm_system,
			    tm_shaper_obj_t *shaper_obj,
			    pkt_desc_t *pkt_desc)
{
	tm_queue_obj_t *tm_queue_obj;
	uint64_t delay_time, wakeup_time, timer_context;
	int rc;

       /* Calculate elapsed time before this pkt will be
	* green or yellow. */
	delay_time  = time_till_not_red(shaper_obj->shaper_params, shaper_obj);
	wakeup_time = tm_system->current_time + delay_time;

	tm_queue_obj = get_tm_queue_obj(tm_system, pkt_desc);
	if (!tm_queue_obj)
		return false;

	/* Insert into timer wheel. */
	timer_context = (((uint64_t)tm_queue_obj->timer_seq + 1) << 32) |
			(((uint64_t)tm_queue_obj->queue_num)     << 4);
	rc = _odp_timer_wheel_insert(tm_system->_odp_int_timer_wheel,
				     wakeup_time, timer_context);
	if (rc < 0) {
		ODP_DBG("%s odp_timer_wheel_insert() failed rc=%d\n",
			__func__, rc);
		return false;
	}

	tm_queue_obj->delayed_cnt++;
	tm_queue_obj->timer_seq++;
	tm_queue_obj->timer_reason = UNDELAY_PKT;
	tm_queue_obj->timer_shaper = shaper_obj;

	shaper_obj->timer_outstanding++;
	shaper_obj->callback_reason = UNDELAY_PKT;
	shaper_obj->callback_time = wakeup_time;
	shaper_obj->timer_tm_queue  = tm_queue_obj;
	shaper_obj->in_pkt_desc = *pkt_desc;
	shaper_obj->out_pkt_desc = EMPTY_PKT_DESC;
	shaper_obj->valid_finish_time = 0;
	return true;
}

/* We call rm_pkt_from_shaper for pkts sent AND for pkts demoted. This function
 * returns true iff the shaper has a change in its output (e.g. empty to
 * non-empty, non-empty to empty or non-empty to a different non-empty pkt). */

static odp_bool_t rm_pkt_from_shaper(tm_system_t *tm_system,
				     tm_shaper_obj_t *shaper_obj,
				     pkt_desc_t *pkt_desc_to_remove,
				     uint8_t is_sent_pkt)
{
	tm_shaper_params_t *shaper_params;
	tm_shaper_action_t shaper_action;
	tm_queue_obj_t *tm_queue_obj;
	odp_bool_t was_empty;
	uint32_t frame_len;
	int64_t  tkn_count;

	tm_queue_obj = get_tm_queue_obj(tm_system, pkt_desc_to_remove);
	if (!tm_queue_obj)
		return false;

	if (pkt_descs_not_equal(&shaper_obj->in_pkt_desc, pkt_desc_to_remove))
		return false;

	was_empty     = shaper_obj->out_pkt_desc.queue_num == 0;
	shaper_action = shaper_obj->propagation_result.action;
	if ((tm_queue_obj->timer_shaper  == shaper_obj) ||
	    (shaper_obj->callback_reason == UNDELAY_PKT)) {
		/* Need to delete the timer - which is either a cancel or just
		 * a delete of a sent_pkt. */
		if (tm_queue_obj->timer_reason == NO_CALLBACK)
			return false;

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
		return !was_empty;

	shaper_params = shaper_obj->shaper_params;
	if (shaper_params->enabled) {
		frame_len = pkt_desc_to_remove->pkt_len +
			    pkt_desc_to_remove->shaper_len_adjust +
			    shaper_params->len_adjust;

		tkn_count = ((int64_t)frame_len) << 26;
		if ((shaper_action == DECR_BOTH) ||
		    (shaper_action == DECR_COMMIT))
			shaper_obj->commit_cnt -= tkn_count;

		if (shaper_params->peak_rate != 0)
			if ((shaper_action == DECR_BOTH) ||
			    (shaper_action == DECR_PEAK))
				shaper_obj->peak_cnt -= tkn_count;
	}

	return !was_empty;
}

/* The run_shaper function returns true iff the shaper has a change in its
 * output (e.g. empty to non-empty, non-empty to empty or non-empty to a
 * different non-empty pkt). */

static odp_bool_t run_shaper(tm_system_t     *tm_system,
			     tm_shaper_obj_t *shaper_obj,
			     pkt_desc_t      *pkt_desc,
			     uint8_t          priority)
{
	odp_tm_shaper_color_t shaper_color;
	tm_shaper_params_t *shaper_params;
	odp_bool_t output_change;
	tm_prop_t propagation;

	shaper_params = shaper_obj->shaper_params;
	shaper_color  = ODP_TM_SHAPER_GREEN;

	if (shaper_params) {
		update_shaper_elapsed_time(tm_system, shaper_params,
					   shaper_obj);
		if (shaper_params->enabled) {
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
		}

		/* Run through propagation tbl to get shaper_action and
		 * out_priority */
		propagation = basic_prop_tbl[priority][shaper_color];
		priority   = propagation.output_priority;

		/* See if this shaper had a previous timer associated with it.
		 * If so we need to cancel it. */
		if ((shaper_obj->timer_outstanding != 0) &&
		    (shaper_obj->in_pkt_desc.queue_num != 0))
			(void)rm_pkt_from_shaper(tm_system, shaper_obj,
						 &shaper_obj->in_pkt_desc, 0);

		shaper_obj->propagation_result = propagation;
		if (propagation.action == DELAY_PKT)
			return delay_pkt(tm_system, shaper_obj, pkt_desc);
	}

	shaper_obj->callback_time   = 0;
	shaper_obj->callback_reason = NO_CALLBACK;

	/* Propagate pkt_desc to the next level */
	output_change =
		pkt_descs_not_equal(&shaper_obj->out_pkt_desc, pkt_desc) ||
		(shaper_obj->out_priority != priority);

	shaper_obj->in_pkt_desc    = *pkt_desc;
	shaper_obj->input_priority = priority;
	shaper_obj->out_pkt_desc   = *pkt_desc;
	shaper_obj->out_priority   = priority;
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

/* The run_sched function returns true iff the scheduler has a change in its
 * output (e.g. empty to non-empty, non-empty to empty or non-empty to a
 * different non-empty pkt). */

static odp_bool_t run_sched(tm_system_t *tm_system,
			    tm_shaper_obj_t *prod_shaper_obj,
			    tm_schedulers_obj_t *schedulers_obj,
			    pkt_desc_t *new_pkt_desc,
			    uint8_t new_priority)
{
	tm_sched_state_t *new_sched_state;
	tm_node_obj_t *tm_node_obj;
	pkt_desc_t prev_best_pkt_desc;
	uint64_t new_finish_time, prev_best_time;
	uint32_t new_priority_mask, num_priorities, priority;
	int rc;

	/* First make sure that this "new_pkt_desc" isn't already in this
	 * scheduler */
	num_priorities = schedulers_obj->num_priorities;
	for (priority = 0; priority < num_priorities; priority++) {
		new_sched_state = &schedulers_obj->sched_states[priority];
		prev_best_pkt_desc = new_sched_state->smallest_pkt_desc;
		if (pkt_descs_equal(new_pkt_desc, &prev_best_pkt_desc)) {
			ODP_DBG("%s spurious execution ****\n", __func__);
			return false;
		}
	}

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

			return false;
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
			return false;

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
		return false;
	} else if (schedulers_obj->out_pkt_desc.queue_num != 0) {
		tm_node_obj = schedulers_obj->enclosing_entity;
		tm_block_pkt(tm_system, tm_node_obj, schedulers_obj,
			     &schedulers_obj->out_pkt_desc,
			     schedulers_obj->highest_priority);
	}

	schedulers_obj->highest_priority = new_priority;
	schedulers_obj->out_pkt_desc = *new_pkt_desc;
	return true;
}

/* We call rm_pkt_from_scheduler both for pkts sent AND for pkts demoted.
 * This function returns true iff the shaper has a change in its output
 * (e.g. empty to non-empty, non-empty to empty or non-empty to a different
 * non-empty pkt). */

static odp_bool_t rm_pkt_from_sched(tm_system_t *tm_system,
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
			return false;
		}
	}

	if (!found)
		return false;

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
			return false;

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

	return true;
}

/* The propagate_pkt_desc function returns true iff there is a new pkt at the
 * egress (i.e tm_system->egress_pkt_desc was set). */

static odp_bool_t tm_propagate_pkt_desc(tm_system_t     *tm_system,
					tm_shaper_obj_t *shaper_obj,
					pkt_desc_t      *new_pkt_desc,
					uint8_t          new_priority)
{
	tm_schedulers_obj_t *schedulers_obj;
	tm_node_obj_t *tm_node_obj;
	pkt_desc_t prev_shaper_pkt, new_shaper_pkt, prev_sched_pkt;
	pkt_desc_t new_sched_pkt;
	odp_bool_t shaper_change, shaper_was_empty, shaper_is_empty;
	odp_bool_t sched_change, sched_was_empty, sched_is_empty, ret_code;
	uint8_t    prev_shaper_prio, new_shaper_prio, new_sched_prio;

	/* Run shaper. */
	prev_shaper_pkt  = shaper_obj->out_pkt_desc;
	prev_shaper_prio = shaper_obj->out_priority;
	shaper_was_empty = prev_shaper_pkt.queue_num == 0;
	shaper_change    = run_shaper(tm_system, shaper_obj, new_pkt_desc,
				      new_priority);
	new_shaper_pkt  = shaper_obj->out_pkt_desc;
	new_shaper_prio = shaper_obj->out_priority;
	shaper_is_empty = new_shaper_pkt.queue_num == 0;

	tm_node_obj = shaper_obj->next_tm_node;
	while (!tm_node_obj->is_root_node) { /* not at egress */
		if (!shaper_change)
			return false;

		schedulers_obj  = &tm_node_obj->schedulers_obj;
		prev_sched_pkt  = schedulers_obj->out_pkt_desc;
		sched_was_empty = prev_sched_pkt.queue_num == 0;
		sched_change    = false;

		/* First remove any old pkt from the scheduler. */
		if (!shaper_was_empty)
			sched_change = rm_pkt_from_sched(tm_system,
							 schedulers_obj,
							 &prev_shaper_pkt,
							 prev_shaper_prio,
							 false);

		/* Run scheduler, including priority multiplexor. */
		if (!shaper_is_empty)
			sched_change |= run_sched(tm_system, shaper_obj,
						  schedulers_obj,
						  &new_shaper_pkt,
						  new_shaper_prio);
		if (!sched_change)
			return false;

		new_sched_pkt  = schedulers_obj->out_pkt_desc;
		new_sched_prio = schedulers_obj->highest_priority;
		sched_is_empty = new_sched_pkt.queue_num == 0;

		shaper_obj       = &tm_node_obj->shaper_obj;
		prev_shaper_pkt  = shaper_obj->out_pkt_desc;
		prev_shaper_prio = shaper_obj->out_priority;
		shaper_was_empty = prev_shaper_pkt.queue_num == 0;
		shaper_change    = false;

		/* First remove any old pkt from the shaper. */
		if (!sched_was_empty)
			shaper_change = rm_pkt_from_shaper(tm_system,
							   shaper_obj,
							   &prev_sched_pkt,
							   false);

		/* Run shaper. */
		if (!sched_is_empty)
			shaper_change |= run_shaper(tm_system, shaper_obj,
						    &new_sched_pkt,
						    new_sched_prio);

		new_shaper_pkt  = shaper_obj->out_pkt_desc;
		new_shaper_prio = shaper_obj->out_priority;
		shaper_is_empty = new_shaper_pkt.queue_num == 0;
		tm_node_obj     = shaper_obj->next_tm_node;
	}

	ret_code = false;
	if (!shaper_is_empty) {
		tm_system->egress_pkt_desc = new_shaper_pkt;
		ret_code = true;
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

/* The demote_pkt_desc function returns true iff there is a new pkt at the
 * egress (i.e tm_system->egress_pkt_desc was set). */

static odp_bool_t tm_demote_pkt_desc(tm_system_t         *tm_system,
				     tm_node_obj_t       *tm_node_obj,
				     tm_schedulers_obj_t *blocked_scheduler,
				     tm_shaper_obj_t     *timer_shaper,
				     pkt_desc_t          *demoted_pkt_desc)
{
	tm_schedulers_obj_t *schedulers_obj;
	tm_shaper_obj_t *shaper_obj;
	pkt_desc_t prev_shaper_pkt, new_shaper_pkt, prev_sched_pkt;
	pkt_desc_t new_sched_pkt;
	odp_bool_t shaper_change, shaper_was_empty, shaper_is_empty;
	odp_bool_t sched_change, sched_was_empty, sched_is_empty, ret_code;
	uint8_t    prev_shaper_prio, new_shaper_prio, new_sched_prio;
	uint8_t    demoted_priority;

	shaper_obj = &tm_node_obj->shaper_obj;
	if ((!blocked_scheduler) && (!timer_shaper))
		return false;

	if (&tm_node_obj->schedulers_obj == blocked_scheduler)
		return false;

	/* See if this first shaper_obj is delaying the demoted_pkt_desc */
	prev_shaper_pkt  = shaper_obj->out_pkt_desc;
	prev_shaper_prio = shaper_obj->out_priority;
	shaper_was_empty = prev_shaper_pkt.queue_num == 0;

	demoted_priority = 3;
	if (pkt_descs_equal(&shaper_obj->out_pkt_desc, demoted_pkt_desc))
		demoted_priority = shaper_obj->out_priority;

	shaper_change = rm_pkt_from_shaper(tm_system, shaper_obj,
					   demoted_pkt_desc, 0);
	if (shaper_obj == timer_shaper)
		return false;

	new_shaper_pkt  = shaper_obj->out_pkt_desc;
	new_shaper_prio = shaper_obj->out_priority;
	shaper_is_empty = new_shaper_pkt.queue_num == 0;

	tm_node_obj = shaper_obj->next_tm_node;
	while (!tm_node_obj->is_root_node) { /* not at egress */
		if ((!demoted_pkt_desc) && (!shaper_change))
			return false;

		schedulers_obj  = &tm_node_obj->schedulers_obj;
		prev_sched_pkt  = schedulers_obj->out_pkt_desc;
		sched_was_empty = prev_sched_pkt.queue_num == 0;
		sched_change    = false;

		/* First remove the demoted pkt or any old pkt from the
		 * scheduler. */
		if (demoted_pkt_desc) {
			sched_change = rm_pkt_from_sched(tm_system,
							 schedulers_obj,
							 demoted_pkt_desc,
							 demoted_priority, 0);
			if (schedulers_obj == blocked_scheduler)
				demoted_pkt_desc = NULL;
		} else if (!shaper_was_empty)
			sched_change = rm_pkt_from_sched(tm_system,
							 schedulers_obj,
							 &prev_shaper_pkt,
							 prev_shaper_prio,
							 false);

		/* Run scheduler, including priority multiplexor. */
		if (!shaper_is_empty)
			sched_change |= run_sched(tm_system, shaper_obj,
						  schedulers_obj,
						  &new_shaper_pkt,
						  new_shaper_prio);
		if ((!demoted_pkt_desc) && (!sched_change))
			return false;

		new_sched_pkt  = schedulers_obj->out_pkt_desc;
		new_sched_prio = schedulers_obj->highest_priority;
		sched_is_empty = new_sched_pkt.queue_num == 0;

		shaper_obj       = &tm_node_obj->shaper_obj;
		prev_shaper_pkt  = shaper_obj->out_pkt_desc;
		prev_shaper_prio = shaper_obj->out_priority;
		shaper_was_empty = prev_shaper_pkt.queue_num == 0;
		shaper_change    = false;

		/* First remove the demoted pkt or any old pkt from the
		 * scheduler. */
		if (demoted_pkt_desc) {
			if (pkt_descs_equal(&shaper_obj->out_pkt_desc,
					    demoted_pkt_desc))
				demoted_priority = shaper_obj->out_priority;

			shaper_change = rm_pkt_from_shaper(tm_system,
							   shaper_obj,
							   demoted_pkt_desc, 0);
			if (shaper_obj == timer_shaper)
				demoted_pkt_desc = NULL;
		} else if (!sched_was_empty)
			shaper_change = rm_pkt_from_shaper(tm_system,
							   shaper_obj,
							   &prev_sched_pkt,
							   false);

		/* Run shaper. */
		if (!sched_is_empty)
			shaper_change |= run_shaper(tm_system, shaper_obj,
						    &new_sched_pkt,
						    new_sched_prio);

		new_shaper_pkt  = shaper_obj->out_pkt_desc;
		new_shaper_prio = shaper_obj->out_priority;
		shaper_is_empty = new_shaper_pkt.queue_num == 0;
		tm_node_obj     = shaper_obj->next_tm_node;
	}

	ret_code = false;
	if (!shaper_is_empty) {
		tm_system->egress_pkt_desc = new_shaper_pkt;
		ret_code = true;
	}

	return ret_code;
}

/* The consume_pkt_desc function returns true iff there is a new pkt at the
 * egress (i.e tm_system->egress_pkt_desc was set). */

static odp_bool_t tm_consume_pkt_desc(tm_system_t     *tm_system,
				      tm_shaper_obj_t *shaper_obj,
				      pkt_desc_t      *new_pkt_desc,
				      uint8_t          new_priority,
				      pkt_desc_t      *sent_pkt_desc)
{
	tm_schedulers_obj_t *schedulers_obj;
	tm_node_obj_t *tm_node_obj;
	pkt_desc_t prev_shaper_pkt, new_shaper_pkt, prev_sched_pkt;
	pkt_desc_t new_sched_pkt;
	odp_bool_t shaper_is_empty, sched_is_empty, ret_code;
	uint8_t    sent_priority, new_shaper_prio, new_sched_prio;

	/* Verify that the shaper output is the sent_pkt_desc. */
	prev_shaper_pkt = shaper_obj->out_pkt_desc;
	if (pkt_descs_not_equal(&prev_shaper_pkt, sent_pkt_desc))
		return false;

	/* Remove the sent_pkt_desc from the shaper. */
	rm_pkt_from_shaper(tm_system, shaper_obj, sent_pkt_desc, true);

	/* If there is a new pkt then run that through the shaper. */
	if (new_pkt_desc && (new_pkt_desc->queue_num != 0))
		run_shaper(tm_system, shaper_obj, new_pkt_desc,
			   new_priority);

	new_shaper_pkt  = shaper_obj->out_pkt_desc;
	new_shaper_prio = shaper_obj->out_priority;
	shaper_is_empty = new_shaper_pkt.queue_num == 0;

	if (pkt_descs_equal(&new_shaper_pkt, sent_pkt_desc))
		ODP_DBG("%s shaper has old pkt_desc\n", __func__);

	tm_node_obj = shaper_obj->next_tm_node;
	while (!tm_node_obj->is_root_node) { /* not at egress */
		schedulers_obj = &tm_node_obj->schedulers_obj;
		prev_sched_pkt = schedulers_obj->out_pkt_desc;
		sent_priority  = schedulers_obj->highest_priority;

		/* Verify that the scheduler output is the sent_pkt_desc. */
		if (pkt_descs_not_equal(&prev_sched_pkt, sent_pkt_desc)) {
			ODP_DBG("%s sched has bad out pkt_desc\n", __func__);
			return false;
		}

		/* Remove the sent_pkt_desc from the scheduler. */
		rm_pkt_from_sched(tm_system, schedulers_obj,
				  sent_pkt_desc, sent_priority, true);

		/* If there is a new pkt then run that through the scheduler. */
		if (!shaper_is_empty)
			run_sched(tm_system, shaper_obj, schedulers_obj,
				  &new_shaper_pkt, new_shaper_prio);

		new_sched_pkt  = schedulers_obj->out_pkt_desc;
		new_sched_prio = schedulers_obj->highest_priority;
		sched_is_empty = new_sched_pkt.queue_num == 0;

		if (pkt_descs_equal(&new_sched_pkt, sent_pkt_desc))
			ODP_DBG("%s sched has old pkt_desc\n", __func__);

		if (pkt_descs_equal(&new_sched_pkt, sent_pkt_desc))
			ODP_DBG("%s scheduler has old pkt_desc\n", __func__);

		shaper_obj      = &tm_node_obj->shaper_obj;
		prev_shaper_pkt = shaper_obj->out_pkt_desc;

		/* Verify that the shaper output is the sent_pkt_desc. */
		if (pkt_descs_not_equal(&prev_shaper_pkt, sent_pkt_desc)) {
			ODP_DBG("%s shaper has bad out pkt_desc\n", __func__);
			return false;
		}

		/* Remove the sent_pkt_desc from the shaper. */
		rm_pkt_from_shaper(tm_system, shaper_obj, sent_pkt_desc, true);

		/* If there is a new pkt then run that through the shaper. */
		if (!sched_is_empty)
			run_shaper(tm_system, shaper_obj, &new_sched_pkt,
				   new_sched_prio);

		new_shaper_pkt  = shaper_obj->out_pkt_desc;
		new_shaper_prio = shaper_obj->out_priority;
		shaper_is_empty = new_shaper_pkt.queue_num == 0;

		if (pkt_descs_equal(&new_shaper_pkt, sent_pkt_desc))
			ODP_DBG("%s shaper has old pkt_desc\n", __func__);

		tm_node_obj = shaper_obj->next_tm_node;
	}

	ret_code = false;
	if (!shaper_is_empty) {
		tm_system->egress_pkt_desc = new_shaper_pkt;
		ret_code = true;
	}

	return ret_code;
}

/* The consume_sent_pkt function returns true iff there is a new pkt at the
 * egress (i.e tm_system->egress_pkt_desc was set). */

static odp_bool_t tm_consume_sent_pkt(tm_system_t *tm_system,
				      pkt_desc_t *sent_pkt_desc)
{
	_odp_int_pkt_queue_t _odp_int_pkt_queue;
	tm_queue_obj_t *tm_queue_obj;
	odp_packet_t pkt;
	pkt_desc_t *new_pkt_desc;
	uint32_t pkt_len;
	int rc;

	tm_queue_obj = get_tm_queue_obj(tm_system, sent_pkt_desc);
	if (!tm_queue_obj)
		return false;

	pkt_len = sent_pkt_desc->pkt_len;
	tm_queue_obj->pkts_consumed_cnt++;
	tm_queue_cnts_decrement(tm_system, &tm_queue_obj->tm_wred_node,
				tm_queue_obj->priority, pkt_len);

	/* Get the next pkt in the tm_queue, if there is one. */
	_odp_int_pkt_queue = tm_queue_obj->_odp_int_pkt_queue;
	rc = _odp_pkt_queue_remove(tm_system->_odp_int_queue_pool,
				   _odp_int_pkt_queue, &pkt);
	if (rc < 0)
		return false;

	new_pkt_desc = NULL;
	if (0 < rc) {
		tm_queue_obj->pkt = pkt;
		tm_pkt_desc_init(&tm_queue_obj->in_pkt_desc, pkt, tm_queue_obj);
		new_pkt_desc = &tm_queue_obj->in_pkt_desc;
		tm_queue_obj->pkts_dequeued_cnt++;
	}

	return tm_consume_pkt_desc(tm_system, &tm_queue_obj->shaper_obj,
				   new_pkt_desc, tm_queue_obj->priority,
				   sent_pkt_desc);
}

static odp_tm_percent_t tm_queue_fullness(tm_wred_params_t      *wred_params,
					  tm_queue_thresholds_t *thresholds,
					  tm_queue_cnts_t       *queue_cnts)
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
	return (odp_tm_percent_t)MIN(fullness, UINT64_C(50000));
}

static odp_bool_t tm_local_random_drop(tm_system_t      *tm_system,
				       tm_wred_params_t *wred_params,
				       odp_tm_percent_t  queue_fullness)
{
	odp_tm_percent_t min_threshold, med_threshold, first_threshold;
	odp_tm_percent_t drop_prob;
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
	* med_threshold or just med_threshold. */
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

static odp_bool_t random_early_discard(tm_system_t *tm_system,
				       tm_queue_obj_t *tm_queue_obj ODP_UNUSED,
				       tm_wred_node_t *tm_wred_node,
				       odp_packet_color_t pkt_color)
{
	tm_queue_thresholds_t *thresholds;
	tm_wred_params_t      *wred_params;
	odp_tm_percent_t       fullness;
	tm_queue_cnts_t       *queue_cnts;

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
	tm_system_group_t *tm_group;
	input_work_item_t work_item;
	odp_packet_color_t pkt_color;
	tm_wred_node_t *initial_tm_wred_node;
	odp_bool_t drop_eligible, drop;
	uint32_t frame_len, pkt_depth;
	int rc;

	tm_group = GET_TM_GROUP(tm_system->odp_tm_group);
	if (tm_group->first_enq == 0) {
		odp_barrier_wait(&tm_group->tm_group_barrier);
		tm_group->first_enq = 1;
	}

	pkt_color = odp_packet_color(pkt);
	drop_eligible = odp_packet_drop_eligible(pkt);

	initial_tm_wred_node = &tm_queue_obj->tm_wred_node;
	if (drop_eligible) {
		drop = random_early_discard(tm_system, tm_queue_obj,
					    initial_tm_wred_node, pkt_color);
		if (drop)
			return -1;
	}

	work_item.queue_num = tm_queue_obj->queue_num;
	work_item.pkt = pkt;
	sched_fn->order_lock();
	rc = input_work_queue_append(tm_system, &work_item);
	sched_fn->order_unlock();

	if (rc < 0) {
		ODP_DBG("%s work queue full\n", __func__);
		return rc;
	}

	frame_len = odp_packet_len(pkt);
	pkt_depth = tm_queue_cnts_increment(tm_system, initial_tm_wred_node,
					    tm_queue_obj->priority, frame_len);
	return pkt_depth;
}

static void egress_vlan_marking(tm_vlan_marking_t *vlan_marking,
				odp_packet_t       odp_pkt)
{
	_odp_vlanhdr_t  vlan_hdr, *vlan_hdr_ptr;
	_odp_ethhdr_t  *ether_hdr_ptr;
	odp_bool_t      split_hdr;
	uint16_t        old_tci, new_tci;
	uint32_t        hdr_len = 0;

	ether_hdr_ptr = odp_packet_l2_ptr(odp_pkt, &hdr_len);
	vlan_hdr_ptr  = (_odp_vlanhdr_t *)(ether_hdr_ptr + 1);

	/* If the split_hdr variable below is TRUE, then this indicates that
	 * for this odp (output) packet the VLAN header is not all in the same
	 * segment and so cannot be accessed using a traditional header record
	 * overlay.  This should be a very rare occurrence, but still need to
	 * handle this case for correctness, but because of the rarity the
	 * code handling this is more optimized for ease of understanding and
	 * correctness rather then performance. */
	split_hdr = hdr_len < (_ODP_ETHHDR_LEN + _ODP_VLANHDR_LEN);
	if (split_hdr) {
		odp_packet_copy_to_mem(odp_pkt, _ODP_ETHHDR_LEN,
					_ODP_VLANHDR_LEN, &vlan_hdr);
		vlan_hdr_ptr = &vlan_hdr;
	}

	old_tci = odp_be_to_cpu_16(vlan_hdr_ptr->tci);
	new_tci = old_tci;
	if (vlan_marking->drop_eligible_enabled)
		new_tci |= _ODP_VLANHDR_DEI_MASK;

	if (new_tci == old_tci)
		return;

	vlan_hdr_ptr->tci = odp_cpu_to_be_16(new_tci);
	if (split_hdr)
		odp_packet_copy_from_mem(odp_pkt, _ODP_ETHHDR_LEN,
					  _ODP_VLANHDR_LEN, &vlan_hdr);
}

static void egress_ipv4_tos_marking(tm_tos_marking_t *tos_marking,
				    odp_packet_t      odp_pkt)
{
	_odp_ipv4hdr_t ipv4_hdr, *ipv4_hdr_ptr;
	odp_bool_t     split_hdr;
	uint32_t       l3_offset, old_chksum, ones_compl_sum, tos_diff;
	uint8_t        old_tos, new_tos, ecn;
	uint32_t       hdr_len = 0;

	l3_offset    = odp_packet_l3_offset(odp_pkt);
	ipv4_hdr_ptr = odp_packet_l3_ptr(odp_pkt, &hdr_len);

	/* If the split_hdr variable below is TRUE, then this indicates that
	 * for this odp (output) packet the IPv4 header is not all in the same
	 * segment and so cannot be accessed using a traditional header record
	 * overlay.  This should be a very rare occurrence, but still need to
	 * handle this case for correctness, but because of the rarity the
	 * code handling this is more optimized for ease of understanding and
	 * correctness rather then performance. */
	split_hdr = hdr_len < 12;
	if (split_hdr) {
		odp_packet_copy_to_mem(odp_pkt, l3_offset,
					_ODP_IPV4HDR_LEN, &ipv4_hdr);
		ipv4_hdr_ptr = &ipv4_hdr;
	}

	old_tos = ipv4_hdr_ptr->tos;
	new_tos = old_tos;
	if (tos_marking->drop_prec_enabled)
		new_tos = (new_tos & tos_marking->inverted_dscp_mask) |
				tos_marking->shifted_dscp;

	if (tos_marking->ecn_ce_enabled && odp_packet_has_tcp(odp_pkt)) {
		ecn = old_tos & _ODP_IP_TOS_ECN_MASK;
		if ((ecn == _ODP_IP_ECN_ECT0) || (ecn == _ODP_IP_ECN_ECT1))
			new_tos = (new_tos & ~_ODP_IP_TOS_ECN_MASK) |
				  (_ODP_IP_ECN_CE << _ODP_IP_TOS_ECN_SHIFT);
	}

	if (new_tos == old_tos)
		return;

	/* Now do an incremental IPv4 header checksum (see RFC 1624).  Note
	 * that the underlying one's complement arithmetic must be done using
	 * 32-bit arithmetic in order to capture carry bits, but all "~"
	 * operations must be anded with 0xFFFF to constrain the "~" result to
	 * fit in 16 bits.  Also note the last step which wraps any carry
	 * bits back into the sum - this being the key difference between
	 * one's complement summation and two's complement.  Finally note that
	 * in this specific case the carry out check does NOT need to be
	 * repeated since it can be proven that the carry in sum cannot
	 * cause another carry out. */
	old_chksum     = (uint32_t)odp_be_to_cpu_16(ipv4_hdr_ptr->chksum);
	ones_compl_sum = (~old_chksum) & 0xFFFF;
	tos_diff       = ((uint32_t)new_tos) + ((~(uint32_t)old_tos) & 0xFFFF);
	ones_compl_sum += tos_diff;
	if (ones_compl_sum >= 0x10000)
		ones_compl_sum = (ones_compl_sum >> 16) +
				 (ones_compl_sum & 0xFFFF);

	ipv4_hdr_ptr->tos    = new_tos;
	ipv4_hdr_ptr->chksum = odp_cpu_to_be_16((~ones_compl_sum) & 0xFFFF);
	if (split_hdr)
		odp_packet_copy_from_mem(odp_pkt, l3_offset,
					  _ODP_IPV4HDR_LEN, &ipv4_hdr);
}

static void egress_ipv6_tc_marking(tm_tos_marking_t *tos_marking,
				   odp_packet_t      odp_pkt)
{
	_odp_ipv6hdr_t ipv6_hdr, *ipv6_hdr_ptr;
	odp_bool_t     split_hdr;
	uint32_t       old_ver_tc_flow, new_ver_tc_flow, l3_offset;
	uint8_t        old_tc, new_tc, ecn;
	uint32_t       hdr_len = 0;

	l3_offset    = odp_packet_l3_offset(odp_pkt);
	ipv6_hdr_ptr = odp_packet_l3_ptr(odp_pkt, &hdr_len);

	/* If the split_hdr variable below is TRUE, then this indicates that
	 * for this odp (output) packet the IPv6 header is not all in the same
	 * segment and so cannot be accessed using a traditional header record
	 * overlay.  This should be a very rare occurrence, but still need to
	 * handle this case for correctness, but because of the rarity the
	 * code handling this is more optimized for ease of understanding and
	 * correctness rather then performance. */
	split_hdr = hdr_len < 4;
	if (split_hdr) {
		odp_packet_copy_to_mem(odp_pkt, l3_offset,
					_ODP_IPV6HDR_LEN, &ipv6_hdr);
		ipv6_hdr_ptr = &ipv6_hdr;
	}

	old_ver_tc_flow = odp_be_to_cpu_32(ipv6_hdr_ptr->ver_tc_flow);
	old_tc          = (old_ver_tc_flow & _ODP_IPV6HDR_TC_MASK)
				>> _ODP_IPV6HDR_TC_SHIFT;
	new_tc          = old_tc;

	if (tos_marking->drop_prec_enabled)
		new_tc = (new_tc & tos_marking->inverted_dscp_mask) |
			       tos_marking->shifted_dscp;

	if (tos_marking->ecn_ce_enabled && odp_packet_has_tcp(odp_pkt)) {
		ecn = old_tc & _ODP_IP_TOS_ECN_MASK;
		if ((ecn == _ODP_IP_ECN_ECT0) || (ecn == _ODP_IP_ECN_ECT1))
			new_tc = (new_tc & ~_ODP_IP_TOS_ECN_MASK) |
				 (_ODP_IP_ECN_CE << _ODP_IP_TOS_ECN_SHIFT);
	}

	if (new_tc == old_tc)
		return;

	new_ver_tc_flow = (old_ver_tc_flow & ~_ODP_IPV6HDR_TC_MASK) |
			  (new_tc << _ODP_IPV6HDR_TC_SHIFT);
	ipv6_hdr_ptr->ver_tc_flow = odp_cpu_to_be_32(new_ver_tc_flow);

	if (split_hdr)
		odp_packet_copy_from_mem(odp_pkt, l3_offset,
					  _ODP_IPV6HDR_LEN, &ipv6_hdr);
}

static void tm_egress_marking(tm_system_t *tm_system, odp_packet_t odp_pkt)
{
	odp_packet_color_t color;
	tm_vlan_marking_t *vlan_marking;
	tm_tos_marking_t  *ip_marking;

	color = odp_packet_color(odp_pkt);

	if (odp_packet_has_vlan(odp_pkt)) {
		vlan_marking = &tm_system->marking.vlan_marking[color];
		if (vlan_marking->marking_enabled)
			egress_vlan_marking(vlan_marking, odp_pkt);
	}

	if (odp_packet_has_ipv4(odp_pkt)) {
		ip_marking = &tm_system->marking.ip_tos_marking[color];
		if (ip_marking->marking_enabled)
			egress_ipv4_tos_marking(ip_marking, odp_pkt);
	} else if (odp_packet_has_ipv6(odp_pkt)) {
		ip_marking = &tm_system->marking.ip_tos_marking[color];
		if (ip_marking->marking_enabled)
			egress_ipv6_tc_marking(ip_marking, odp_pkt);
	}
}

static void tm_send_pkt(tm_system_t *tm_system, uint32_t max_sends)
{
	tm_queue_obj_t *tm_queue_obj;
	odp_packet_t odp_pkt;
	pkt_desc_t *pkt_desc;
	uint32_t cnt;

	for (cnt = 1; cnt <= max_sends; cnt++) {
		pkt_desc = &tm_system->egress_pkt_desc;
		tm_queue_obj = get_tm_queue_obj(tm_system, pkt_desc);
		if (!tm_queue_obj)
			return;

		odp_pkt = tm_queue_obj->pkt;
		if (odp_pkt == ODP_PACKET_INVALID) {
			tm_system->egress_pkt_desc = EMPTY_PKT_DESC;
			return;
		}

		if (tm_system->marking_enabled)
			tm_egress_marking(tm_system, odp_pkt);

		tm_system->egress_pkt_desc = EMPTY_PKT_DESC;
		if (tm_system->egress.egress_kind == ODP_TM_EGRESS_PKT_IO)
			odp_pktout_send(tm_system->pktout, &odp_pkt, 1);
		else if (tm_system->egress.egress_kind == ODP_TM_EGRESS_FN)
			tm_system->egress.egress_fcn(odp_pkt);
		else
			return;

		tm_queue_obj->sent_pkt = tm_queue_obj->pkt;
		tm_queue_obj->sent_pkt_desc = tm_queue_obj->in_pkt_desc;
		tm_queue_obj->pkt = ODP_PACKET_INVALID;
		tm_queue_obj->in_pkt_desc = EMPTY_PKT_DESC;
		tm_consume_sent_pkt(tm_system, &tm_queue_obj->sent_pkt_desc);
		tm_queue_obj->sent_pkt = ODP_PACKET_INVALID;
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
		if (rc < 0) {
			ODP_DBG("%s input_work_queue_remove() failed\n",
				__func__);
			return rc;
		}

		tm_queue_obj =
			tm_system->queue_num_tbl[work_item.queue_num - 1];
		pkt = work_item.pkt;
		if (!tm_queue_obj) {
			odp_packet_free(pkt);
			return 0;
		}

		tm_queue_obj->pkts_rcvd_cnt++;
		if (tm_queue_obj->pkt != ODP_PACKET_INVALID) {
			/* If the tm_queue_obj already has a pkt to work with,
			 * then just add this new pkt to the associated
			 * _odp_int_pkt_queue. */
			(void)_odp_pkt_queue_append(
				tm_system->_odp_int_queue_pool,
				tm_queue_obj->_odp_int_pkt_queue, pkt);
			tm_queue_obj->pkts_enqueued_cnt++;
		} else {
			/* If the tm_queue_obj doesn't have a pkt to work
			 * with, then make this one the head pkt. */
			tm_queue_obj->pkt = pkt;
			tm_pkt_desc_init(&tm_queue_obj->in_pkt_desc, pkt,
					 tm_queue_obj);
			pkt_desc = &tm_queue_obj->in_pkt_desc;
			shaper_obj = &tm_queue_obj->shaper_obj;
			rc = tm_propagate_pkt_desc(tm_system, shaper_obj,
						   pkt_desc,
						   tm_queue_obj->priority);
			if (0 < rc)
				return 1;  /* Send through spigot */
		}
	}

	return 0;
}

static int tm_process_expired_timers(tm_system_t *tm_system,
				     _odp_timer_wheel_t _odp_int_timer_wheel,
				     uint64_t current_time ODP_UNUSED)
{
	tm_shaper_obj_t *shaper_obj;
	tm_queue_obj_t *tm_queue_obj;
	pkt_desc_t *pkt_desc;
	uint64_t timer_context;
	uint32_t work_done, cnt, queue_num, timer_seq;
	uint8_t priority;

	work_done = 0;
	for (cnt = 1; cnt <= 2; cnt++) {
		timer_context =
			_odp_timer_wheel_next_expired(_odp_int_timer_wheel);
		if (!timer_context)
			return work_done;

		queue_num = (timer_context & 0xFFFFFFFF) >> 4;
		timer_seq = timer_context >> 32;
		tm_queue_obj = tm_system->queue_num_tbl[queue_num - 1];
		if (!tm_queue_obj)
			return work_done;

		if ((tm_queue_obj->timer_reason == NO_CALLBACK) ||
		    (!tm_queue_obj->timer_shaper) ||
		    (tm_queue_obj->timer_seq != timer_seq)) {
			if (tm_queue_obj->timer_cancels_outstanding != 0)
				tm_queue_obj->timer_cancels_outstanding--;
			else
				ODP_DBG("%s bad timer return\n", __func__);

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
			tm_send_pkt(tm_system, 2);
	}

	return work_done;
}

static void busy_wait(uint32_t iterations)
{
	uint32_t cnt;

	for (cnt = 1; cnt <= iterations; cnt++)
		tm_glb->busy_wait_counter++;
}

static void signal_request(void)
{
	uint64_t request_num, serving;

	request_num = odp_atomic_fetch_inc_u64(&tm_glb->atomic_request_cnt) + 1;

	serving = odp_atomic_load_u64(&tm_glb->currently_serving_cnt);
	while (serving != request_num) {
		busy_wait(100);
		serving = odp_atomic_load_u64(&tm_glb->currently_serving_cnt);
	}
}

static void check_for_request(void)
{
	uint64_t request_num, serving_cnt, done_cnt;

	request_num = odp_atomic_load_u64(&tm_glb->atomic_request_cnt);
	serving_cnt = odp_atomic_load_u64(&tm_glb->currently_serving_cnt);
	if (serving_cnt == request_num)
		return;

	/* Signal the other requesting thread to proceed and then
	 * wait for their done indication */
	odp_atomic_inc_u64(&tm_glb->currently_serving_cnt);
	busy_wait(100);

	done_cnt = odp_atomic_load_u64(&tm_glb->atomic_done_cnt);
	while (done_cnt != request_num) {
		busy_wait(100);
		done_cnt = odp_atomic_load_u64(&tm_glb->atomic_done_cnt);
	}
}

static void signal_request_done(void)
{
	odp_atomic_inc_u64(&tm_glb->atomic_done_cnt);
}

static int thread_affinity_get(odp_cpumask_t *odp_cpu_mask)
{
	cpu_set_t linux_cpu_set;
	uint32_t  cpu_num;
	int       rc;

	CPU_ZERO(&linux_cpu_set);
	rc = sched_getaffinity(0, sizeof(cpu_set_t), &linux_cpu_set);
	if (rc != 0) {
		ODP_DBG("%s sched_getaffinity failed with rc=%d\n",
			__func__, rc);
		return -1;
	}

	odp_cpumask_zero(odp_cpu_mask);
	for (cpu_num = 0; cpu_num < sizeof(cpu_set_t); cpu_num++)
		if (CPU_ISSET(cpu_num, &linux_cpu_set))
			odp_cpumask_set(odp_cpu_mask, cpu_num);

	return 0;
}

static void *tm_system_thread(void *arg)
{
	_odp_timer_wheel_t _odp_int_timer_wheel;
	input_work_queue_t *input_work_queue;
	tm_system_group_t  *tm_group;
	tm_system_t *tm_system;
	uint64_t current_ns;
	uint32_t destroying, work_queue_cnt, timer_cnt;
	int rc;

	rc = odp_init_local((odp_instance_t)odp_global_ro.main_pid,
			    ODP_THREAD_WORKER);
	ODP_ASSERT(rc == 0);
	tm_group = arg;

	tm_system = tm_group->first_tm_system;
	_odp_int_timer_wheel = tm_system->_odp_int_timer_wheel;
	input_work_queue = &tm_system->input_work_queue;

	/* Wait here until we have seen the first enqueue operation. */
	odp_barrier_wait(&tm_group->tm_group_barrier);
	tm_glb->main_loop_running = true;

	destroying = odp_atomic_load_u64(&tm_system->destroying);

	current_ns = odp_time_to_ns(odp_time_local());
	_odp_timer_wheel_start(_odp_int_timer_wheel, current_ns);

	while (destroying == 0) {
		/* See if another thread wants to make a configuration
		 * change. */
		check_for_request();

		current_ns = odp_time_to_ns(odp_time_local());
		tm_system->current_time = current_ns;
		rc = _odp_timer_wheel_curr_time_update(_odp_int_timer_wheel,
						       current_ns);
		if (0 < rc) {
			/* Process a batch of expired timers - each of which
			 * could cause a pkt to egress the tm system. */
			timer_cnt = 1;
			(void)tm_process_expired_timers(tm_system,
							_odp_int_timer_wheel,
							current_ns);
		} else {
			timer_cnt =
				_odp_timer_wheel_count(_odp_int_timer_wheel);
		}

		current_ns = odp_time_to_ns(odp_time_local());
		tm_system->current_time = current_ns;
		work_queue_cnt =
			odp_atomic_load_u64(&input_work_queue->queue_cnt);

		if (work_queue_cnt != 0) {
			tm_process_input_work_queue(tm_system,
						    input_work_queue, 1);
		}

		if (tm_system->egress_pkt_desc.queue_num != 0)
			tm_send_pkt(tm_system, 1);

		current_ns = odp_time_to_ns(odp_time_local());
		tm_system->current_time = current_ns;
		tm_system->is_idle = (timer_cnt == 0) &&
			(work_queue_cnt == 0);
		destroying = odp_atomic_load_u64(&tm_system->destroying);

		/* Advance to the next tm_system in the tm_system_group. */
		tm_system = tm_system->next;
		_odp_int_timer_wheel = tm_system->_odp_int_timer_wheel;
		input_work_queue = &tm_system->input_work_queue;
	}

	odp_barrier_wait(&tm_system->tm_system_destroy_barrier);
	odp_term_local();
	return NULL;
}

odp_bool_t odp_tm_is_idle(odp_tm_t odp_tm)
{
	tm_system_t *tm_system;

	tm_system = GET_TM_SYSTEM(odp_tm);
	return tm_system->is_idle;
}

void odp_tm_requirements_init(odp_tm_requirements_t *requirements)
{
	memset(requirements, 0, sizeof(odp_tm_requirements_t));
}

void odp_tm_egress_init(odp_tm_egress_t *egress)
{
	memset(egress, 0, sizeof(odp_tm_egress_t));
}

int odp_tm_capabilities(odp_tm_capabilities_t capabilities[] ODP_UNUSED,
			uint32_t              capabilities_size)
{
	odp_tm_level_capabilities_t *per_level_cap;
	odp_tm_capabilities_t       *cap_ptr;
	odp_packet_color_t           color;
	uint32_t                     level_idx;

	if (capabilities_size == 0)
		return -1;

	cap_ptr = &capabilities[0];
	memset(cap_ptr, 0, sizeof(odp_tm_capabilities_t));

	cap_ptr->max_tm_queues                 = ODP_TM_MAX_TM_QUEUES;
	cap_ptr->max_levels                    = ODP_TM_MAX_LEVELS;
	cap_ptr->tm_queue_shaper_supported     = true;
	cap_ptr->egress_fcn_supported          = true;
	cap_ptr->tm_queue_wred_supported       = true;
	cap_ptr->tm_queue_dual_slope_supported = true;
	cap_ptr->vlan_marking_supported        = true;
	cap_ptr->ecn_marking_supported         = true;
	cap_ptr->drop_prec_marking_supported   = true;

	for (color = 0; color < ODP_NUM_PACKET_COLORS; color++)
		cap_ptr->marking_colors_supported[color] = true;

	for (level_idx = 0; level_idx < cap_ptr->max_levels; level_idx++) {
		per_level_cap = &cap_ptr->per_level[level_idx];

		per_level_cap->max_num_tm_nodes   = ODP_TM_MAX_NUM_TM_NODES;
		per_level_cap->max_fanin_per_node = ODP_TM_MAX_TM_NODE_FANIN;
		per_level_cap->max_priority       = ODP_TM_MAX_PRIORITIES - 1;
		per_level_cap->min_weight         = ODP_TM_MIN_SCHED_WEIGHT;
		per_level_cap->max_weight         = ODP_TM_MAX_SCHED_WEIGHT;

		per_level_cap->tm_node_shaper_supported     = true;
		per_level_cap->tm_node_wred_supported       = true;
		per_level_cap->tm_node_dual_slope_supported = true;
		per_level_cap->fair_queuing_supported       = true;
		per_level_cap->weights_supported            = true;
	}

	return 1;
}

static void tm_system_capabilities_set(odp_tm_capabilities_t *cap_ptr,
				       odp_tm_requirements_t *req_ptr)
{
	odp_tm_level_requirements_t *per_level_req;
	odp_tm_level_capabilities_t *per_level_cap;
	odp_packet_color_t           color;
	odp_bool_t                   shaper_supported, wred_supported;
	odp_bool_t                   dual_slope;
	uint32_t                     num_levels, level_idx, max_nodes;
	uint32_t                     max_queues, max_fanin;
	uint8_t                      max_priority, min_weight, max_weight;

	num_levels = MAX(MIN(req_ptr->num_levels, ODP_TM_MAX_LEVELS), 1);
	memset(cap_ptr, 0, sizeof(odp_tm_capabilities_t));

	max_queues       = MIN(req_ptr->max_tm_queues,
			       (uint32_t)ODP_TM_MAX_NUM_TM_NODES);
	shaper_supported = req_ptr->tm_queue_shaper_needed;
	wred_supported   = req_ptr->tm_queue_wred_needed;
	dual_slope       = req_ptr->tm_queue_dual_slope_needed;

	cap_ptr->max_tm_queues                 = max_queues;
	cap_ptr->max_levels                    = num_levels;
	cap_ptr->tm_queue_shaper_supported     = shaper_supported;
	cap_ptr->tm_queue_wred_supported       = wred_supported;
	cap_ptr->tm_queue_dual_slope_supported = dual_slope;
	cap_ptr->vlan_marking_supported        = req_ptr->vlan_marking_needed;
	cap_ptr->ecn_marking_supported         = req_ptr->ecn_marking_needed;
	cap_ptr->drop_prec_marking_supported   =
					req_ptr->drop_prec_marking_needed;

	for (color = 0; color < ODP_NUM_PACKET_COLORS; color++)
		cap_ptr->marking_colors_supported[color] =
			req_ptr->marking_colors_needed[color];

	for (level_idx = 0; level_idx < num_levels; level_idx++) {
		per_level_cap = &cap_ptr->per_level[level_idx];
		per_level_req = &req_ptr->per_level[level_idx];

		max_nodes        = MIN(per_level_req->max_num_tm_nodes,
				       (uint32_t)ODP_TM_MAX_NUM_TM_NODES);
		max_fanin        = MIN(per_level_req->max_fanin_per_node,
				       UINT32_C(1024));
		max_priority     = MIN(per_level_req->max_priority,
				       ODP_TM_MAX_PRIORITIES - 1);
		min_weight       = MAX(per_level_req->min_weight,
				       ODP_TM_MIN_SCHED_WEIGHT);
		max_weight       = MIN(per_level_req->max_weight,
				       ODP_TM_MAX_SCHED_WEIGHT);
		shaper_supported = per_level_req->tm_node_shaper_needed;
		wred_supported   = per_level_req->tm_node_wred_needed;
		dual_slope       = per_level_req->tm_node_dual_slope_needed;

		per_level_cap->max_num_tm_nodes   = max_nodes;
		per_level_cap->max_fanin_per_node = max_fanin;
		per_level_cap->max_priority       = max_priority;
		per_level_cap->min_weight         = min_weight;
		per_level_cap->max_weight         = max_weight;

		per_level_cap->tm_node_shaper_supported     = shaper_supported;
		per_level_cap->tm_node_wred_supported       = wred_supported;
		per_level_cap->tm_node_dual_slope_supported = dual_slope;
		per_level_cap->fair_queuing_supported       = true;
		per_level_cap->weights_supported            = true;
	}
}

static int affinitize_main_thread(void)
{
	odp_cpumask_t odp_cpu_mask;
	cpu_set_t     linux_cpu_set;
	uint32_t      cpu_count, cpu_num;
	int           rc;

	rc = thread_affinity_get(&odp_cpu_mask);
	if (rc != 0)
		return rc;

	/* If the affinity cpu set returned above has exactly one cpu, then
	 * just record this value and return. */
	cpu_count = odp_cpumask_count(&odp_cpu_mask);
	if (cpu_count == 1) {
		tm_glb->main_thread_cpu = odp_cpumask_first(&odp_cpu_mask);
		return 0;
	} else if (cpu_count == 0) {
		return -1;
	}

	cpu_num = odp_cpumask_first(&odp_cpu_mask);

	CPU_ZERO(&linux_cpu_set);
	CPU_SET(cpu_num, &linux_cpu_set);
	rc = sched_setaffinity(0, sizeof(cpu_set_t), &linux_cpu_set);
	if (rc == 0)
		tm_glb->main_thread_cpu = cpu_num;
	else
		ODP_DBG("%s sched_setaffinity failed with rc=%d\n",
			__func__, rc);
	return rc;
}

static uint32_t tm_thread_cpu_select(void)
{
	odp_cpumask_t odp_cpu_mask;
	int           cpu_count, cpu;

	odp_cpumask_default_worker(&odp_cpu_mask, 0);
	if ((tm_glb->main_thread_cpu != -1) &&
	    odp_cpumask_isset(&odp_cpu_mask, tm_glb->main_thread_cpu))
		odp_cpumask_clr(&odp_cpu_mask, tm_glb->main_thread_cpu);

	cpu_count = odp_cpumask_count(&odp_cpu_mask);
	if (cpu_count < 1) {
		odp_cpumask_all_available(&odp_cpu_mask);
		if ((tm_glb->main_thread_cpu != -1) &&
		    odp_cpumask_isset(&odp_cpu_mask, tm_glb->main_thread_cpu))
			cpu_count = odp_cpumask_count(&odp_cpu_mask);

		if (cpu_count < 1)
			odp_cpumask_all_available(&odp_cpu_mask);
	}

	if (tm_glb->cpu_num == 0) {
		cpu = odp_cpumask_first(&odp_cpu_mask);
	} else {
		cpu = odp_cpumask_next(&odp_cpu_mask, tm_glb->cpu_num);
		if (cpu == -1) {
			tm_glb->cpu_num = 0;
			cpu = odp_cpumask_first(&odp_cpu_mask);
		}
	}

	tm_glb->cpu_num++;
	return cpu;
}

static int tm_thread_create(tm_system_group_t *tm_group)
{
	cpu_set_t      cpu_set;
	uint32_t       cpu_num;
	int            rc;

	pthread_attr_init(&tm_group->attr);
	cpu_num = tm_thread_cpu_select();
	CPU_ZERO(&cpu_set);
	CPU_SET(cpu_num, &cpu_set);
	pthread_attr_setaffinity_np(&tm_group->attr, sizeof(cpu_set_t),
				    &cpu_set);

	rc = pthread_create(&tm_group->thread, &tm_group->attr,
			    tm_system_thread, tm_group);
	if (rc != 0)
		ODP_DBG("Failed to start thread on cpu num=%u\n", cpu_num);

	return rc;
}
static void _odp_tm_group_destroy(_odp_tm_group_t odp_tm_group)
{
	tm_system_group_t *tm_group;
	int                rc;

	tm_group = GET_TM_GROUP(odp_tm_group);

	/* Wait for the thread to exit. */
	ODP_ASSERT(tm_group->num_tm_systems <= 1);
	rc = pthread_join(tm_group->thread, NULL);
	ODP_ASSERT(rc == 0);
	pthread_attr_destroy(&tm_group->attr);
	if (tm_glb->cpu_num > 0)
		tm_glb->cpu_num--;

	odp_ticketlock_lock(&tm_glb->system_group.lock);
	tm_group->status = TM_STATUS_FREE;
	odp_ticketlock_unlock(&tm_glb->system_group.lock);
}

static int _odp_tm_group_add(_odp_tm_group_t odp_tm_group, odp_tm_t odp_tm)
{
	tm_system_group_t *tm_group;
	tm_system_t       *tm_system, *first_tm_system, *second_tm_system;

	tm_group  = GET_TM_GROUP(odp_tm_group);
	tm_system = GET_TM_SYSTEM(odp_tm);
	tm_group->num_tm_systems++;
	tm_system->odp_tm_group = odp_tm_group;

	/* Link this tm_system into the circular linked list of all tm_systems
	 * belonging to the same tm_group. */
	if (tm_group->num_tm_systems == 1) {
		tm_group->first_tm_system = tm_system;
		tm_system->next           = tm_system;
		tm_system->prev           = tm_system;
	} else {
		first_tm_system        = tm_group->first_tm_system;
		second_tm_system       = first_tm_system->next;
		first_tm_system->next  = tm_system;
		second_tm_system->prev = tm_system;
		tm_system->prev        = first_tm_system;
		tm_system->next        = second_tm_system;
		tm_group->first_tm_system = tm_system;
	}

	/* If this is the first tm_system associated with this group, then
	 * create the service thread and the input work queue. */
	if (tm_group->num_tm_systems >= 2)
		return 0;

	affinitize_main_thread();
	return tm_thread_create(tm_group);
}

static int _odp_tm_group_remove(_odp_tm_group_t odp_tm_group, odp_tm_t odp_tm)
{
	tm_system_group_t *tm_group;
	tm_system_t       *tm_system, *prev_tm_system, *next_tm_system;

	tm_group  = GET_TM_GROUP(odp_tm_group);
	tm_system = GET_TM_SYSTEM(odp_tm);
	if (tm_system->odp_tm_group != odp_tm_group)
		return -1;

	if ((tm_group->num_tm_systems  == 0) ||
	    (tm_group->first_tm_system == NULL))
		return -1;

	/* Remove this tm_system from the tm_group linked list. */
	if (tm_group->first_tm_system == tm_system)
		tm_group->first_tm_system = tm_system->next;

	prev_tm_system       = tm_system->prev;
	next_tm_system       = tm_system->next;
	prev_tm_system->next = next_tm_system;
	next_tm_system->prev = prev_tm_system;
	tm_system->next      = NULL;
	tm_system->prev      = NULL;
	tm_group->num_tm_systems--;

	/* If this is the last tm_system associated with this group then
	 * destroy the group (and thread etc). */
	if (tm_group->num_tm_systems == 0)
		_odp_tm_group_destroy(odp_tm_group);

	return 0;
}

static void _odp_tm_init_tm_group(tm_system_group_t *tm_group)
{
	memset(tm_group, 0, sizeof(tm_system_group_t));

	tm_group->status = TM_STATUS_RESERVED;
	odp_barrier_init(&tm_group->tm_group_barrier, 2);
}

static int tm_group_attach(odp_tm_t odp_tm)
{
	tm_system_group_t *tm_group, *min_tm_group;
	_odp_tm_group_t    odp_tm_group;
	odp_cpumask_t      all_cpus, worker_cpus;
	uint32_t           total_cpus, avail_cpus;
	uint32_t           i;

	/* If this platform has a small number of cpu's then allocate one
	 * tm_group and assign all tm_system's to this tm_group.  Otherwise in
	 * the case of a manycore platform try to allocate one tm_group per
	 * tm_system, as long as there are still extra cpu's left.  If not
	 * enough cpu's left than allocate this tm_system to the next tm_group
	 * in a round robin fashion. */
	odp_cpumask_all_available(&all_cpus);
	odp_cpumask_default_worker(&worker_cpus, 0);
	total_cpus = odp_cpumask_count(&all_cpus);
	avail_cpus = odp_cpumask_count(&worker_cpus);

	if (total_cpus < 24) {
		tm_group     = &tm_glb->system_group.group[0];

		odp_ticketlock_lock(&tm_glb->system_group.lock);
		if (tm_group->status == TM_STATUS_FREE)
			_odp_tm_init_tm_group(tm_group);
		odp_ticketlock_unlock(&tm_glb->system_group.lock);

		odp_tm_group = MAKE_ODP_TM_SYSTEM_GROUP(tm_group);
		_odp_tm_group_add(odp_tm_group, odp_tm);
		return 0;
	}

	/* Pick a tm_group according to the smallest number of tm_systems. */
	min_tm_group = NULL;
	odp_ticketlock_lock(&tm_glb->system_group.lock);
	for (i = 0; i < ODP_TM_MAX_NUM_SYSTEMS && i < avail_cpus; i++) {
		tm_group = &tm_glb->system_group.group[i];

		if (tm_group->status == TM_STATUS_FREE) {
			_odp_tm_init_tm_group(tm_group);
			min_tm_group = tm_group;
			break;
		}

		if (min_tm_group == NULL)
			min_tm_group = tm_group;
		else if (tm_group->num_tm_systems <
			 min_tm_group->num_tm_systems)
			min_tm_group = tm_group;
	}
	odp_ticketlock_unlock(&tm_glb->system_group.lock);

	if (min_tm_group == NULL)
		return -1;

	odp_tm_group = MAKE_ODP_TM_SYSTEM_GROUP(tm_group);
	_odp_tm_group_add(odp_tm_group, odp_tm);
	return 0;
}

odp_tm_t odp_tm_create(const char            *name,
		       odp_tm_requirements_t *requirements,
		       odp_tm_egress_t       *egress)
{
	_odp_int_name_t name_tbl_id;
	tm_system_t *tm_system;
	odp_bool_t create_fail;
	odp_tm_t odp_tm;
	odp_pktout_queue_t pktout;
	uint32_t max_num_queues, max_queued_pkts, max_timers;
	uint32_t max_tm_queues, max_sorted_lists;
	int rc;

	if (odp_global_ro.init_param.not_used.feat.tm) {
		ODP_ERR("TM has been disabled\n");
		return ODP_TM_INVALID;
	}

	/* If we are using pktio output (usual case) get the first associated
	 * pktout_queue for this pktio and fail if there isn't one.
	 */
	if (egress->egress_kind == ODP_TM_EGRESS_PKT_IO &&
	    odp_pktout_queue(egress->pktio, &pktout, 1) != 1)
		return ODP_TM_INVALID;

	/* Allocate tm_system_t record. */
	odp_ticketlock_lock(&tm_glb->create_lock);
	tm_system = tm_system_alloc();
	if (!tm_system) {
		odp_ticketlock_unlock(&tm_glb->create_lock);
		return ODP_TM_INVALID;
	}

	odp_tm = MAKE_ODP_TM_HANDLE(tm_system);
	name_tbl_id = _odp_int_name_tbl_add(name, ODP_TM_HANDLE, odp_tm);
	if (name_tbl_id == ODP_INVALID_NAME) {
		tm_system_free(tm_system);
		odp_ticketlock_unlock(&tm_glb->create_lock);
		return ODP_TM_INVALID;
	}

	if (egress->egress_kind == ODP_TM_EGRESS_PKT_IO)
		tm_system->pktout = pktout;

	tm_system->name_tbl_id = name_tbl_id;
	max_tm_queues = requirements->max_tm_queues;
	memcpy(&tm_system->egress, egress, sizeof(odp_tm_egress_t));
	memcpy(&tm_system->requirements, requirements,
	       sizeof(odp_tm_requirements_t));

	tm_system_capabilities_set(&tm_system->capabilities,
				   &tm_system->requirements);

	tm_system->next_queue_num = 1;
	tm_system->root_node.is_root_node = true;

	tm_init_random_data(&tm_system->tm_random_data);

	max_sorted_lists = 2 * max_tm_queues;
	max_num_queues = max_tm_queues;
	max_queued_pkts = 16 * max_tm_queues;
	max_timers = 2 * max_tm_queues;
	create_fail = 0;

	tm_system->_odp_int_sorted_pool = _ODP_INT_SORTED_POOL_INVALID;
	tm_system->_odp_int_queue_pool = _ODP_INT_QUEUE_POOL_INVALID;
	tm_system->_odp_int_timer_wheel = _ODP_INT_TIMER_WHEEL_INVALID;

	odp_ticketlock_init(&tm_system->tm_system_lock);
	odp_atomic_init_u64(&tm_system->destroying, 0);

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
			max_timers, tm_system);
		create_fail |= tm_system->_odp_int_timer_wheel
			== _ODP_INT_TIMER_WHEEL_INVALID;
	}

	input_work_queue_init(&tm_system->input_work_queue);

	if (create_fail == 0) {
		/* Pass any odp_groups or hints to tm_group_attach here. */
		affinitize_main_thread();
		rc = tm_group_attach(odp_tm);
		create_fail |= rc < 0;
	}

	if (create_fail) {
		_odp_int_name_tbl_delete(name_tbl_id);

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
		odp_ticketlock_unlock(&tm_glb->create_lock);
		return ODP_TM_INVALID;
	}

	odp_ticketlock_unlock(&tm_glb->create_lock);
	return odp_tm;
}

odp_tm_t odp_tm_find(const char            *name,
		     odp_tm_requirements_t *requirements ODP_UNUSED,
		     odp_tm_egress_t       *egress       ODP_UNUSED)
{
	_odp_int_name_t odp_name;
	uint64_t        user_data;

	/* Currently does not consider the requirements in the lookup -
	 * just the name */
	odp_name  = _odp_int_name_tbl_lookup(name, ODP_TM_HANDLE);
	user_data = _odp_int_name_tbl_user_data(odp_name);
	return (odp_tm_t)user_data;
}

int odp_tm_capability(odp_tm_t odp_tm, odp_tm_capabilities_t *capabilities)
{
	tm_system_t *tm_system;

	tm_system = GET_TM_SYSTEM(odp_tm);
	memcpy(capabilities, &tm_system->capabilities,
	       sizeof(odp_tm_capabilities_t));
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
	odp_atomic_inc_u64(&tm_system->destroying);
	odp_barrier_wait(&tm_system->tm_system_destroy_barrier);

	/* Remove ourselves from the group.  If we are the last tm_system in
	 * this group, odp_tm_group_remove will destroy any service threads
	 * allocated by this group. */
	_odp_tm_group_remove(tm_system->odp_tm_group, odp_tm);

	input_work_queue_destroy(&tm_system->input_work_queue);
	_odp_sorted_pool_destroy(tm_system->_odp_int_sorted_pool);
	_odp_queue_pool_destroy(tm_system->_odp_int_queue_pool);
	_odp_timer_wheel_destroy(tm_system->_odp_int_timer_wheel);

	tm_system_free(tm_system);
	return 0;
}

/* Return true if any of the marking enables is set, otherwise return FALSE */
static odp_bool_t tm_marking_enabled(tm_system_t *tm_system)
{
	odp_packet_color_t color;
	tm_marking_t      *tm_marking;

	tm_marking = &tm_system->marking;
	for (color = 0; color < ODP_NUM_PACKET_COLORS; color++) {
		if ((tm_marking->vlan_marking[color].marking_enabled) ||
		    (tm_marking->ip_tos_marking[color].marking_enabled))
			return true;
	}

	return false;
}

int odp_tm_vlan_marking(odp_tm_t           odp_tm,
			odp_packet_color_t color,
			odp_bool_t         drop_eligible_enabled)
{
	tm_vlan_marking_t *vlan_marking;
	tm_system_t       *tm_system;

	tm_system = GET_TM_SYSTEM(odp_tm);
	if ((tm_system == NULL) || (ODP_NUM_PACKET_COLORS <= color))
		return -1;

	if (drop_eligible_enabled)
		if ((!tm_system->requirements.vlan_marking_needed) ||
		    (!tm_system->requirements.marking_colors_needed[color]))
			return -1;

	vlan_marking = &tm_system->marking.vlan_marking[color];
	vlan_marking->marking_enabled       = drop_eligible_enabled;
	vlan_marking->drop_eligible_enabled = drop_eligible_enabled;
	if (vlan_marking->marking_enabled)
		tm_system->marking_enabled = true;
	else
		tm_system->marking_enabled = tm_marking_enabled(tm_system);

	return 0;
}

int odp_tm_ecn_marking(odp_tm_t           odp_tm,
		       odp_packet_color_t color,
		       odp_bool_t         ecn_ce_enabled)
{
	tm_tos_marking_t *tos_marking;
	tm_system_t      *tm_system;

	tm_system = GET_TM_SYSTEM(odp_tm);
	if ((tm_system == NULL) || (ODP_NUM_PACKET_COLORS <= color))
		return -1;

	if (ecn_ce_enabled)
		if ((!tm_system->requirements.ecn_marking_needed) ||
		    (!tm_system->requirements.marking_colors_needed[color]))
			return -1;

	tos_marking = &tm_system->marking.ip_tos_marking[color];
	tos_marking->marking_enabled = tos_marking->drop_prec_enabled |
					      ecn_ce_enabled;
	tos_marking->ecn_ce_enabled  = ecn_ce_enabled;

	if (ecn_ce_enabled)
		tm_system->marking_enabled = true;
	else
		tm_system->marking_enabled = tm_marking_enabled(tm_system);

	return 0;
}

int odp_tm_drop_prec_marking(odp_tm_t           odp_tm,
			     odp_packet_color_t color,
			     odp_bool_t         drop_prec_enabled)
{
	tm_tos_marking_t *tos_marking;
	tm_system_t      *tm_system;
	uint8_t           dscp_mask, new_dscp, inverted_mask, tos_mask;
	uint8_t           shifted_dscp;

	tm_system = GET_TM_SYSTEM(odp_tm);
	if ((tm_system == NULL) || (ODP_NUM_PACKET_COLORS <= color))
		return -1;

	if (drop_prec_enabled)
		if ((!tm_system->requirements.drop_prec_marking_needed) ||
		    (!tm_system->requirements.marking_colors_needed[color]))
			return -1;

	dscp_mask = DROP_PRECEDENCE_MASK;
	if (color == ODP_PACKET_YELLOW)
		new_dscp = MEDIUM_DROP_PRECEDENCE;
	else if (color == ODP_PACKET_RED)
		new_dscp = HIGH_DROP_PRECEDENCE;
	else
		new_dscp = LOW_DROP_PRECEDENCE;

	if (drop_prec_enabled) {
		new_dscp      = new_dscp & dscp_mask;
		inverted_mask = (uint8_t)~dscp_mask;
		tos_mask      = (inverted_mask << _ODP_IP_TOS_DSCP_SHIFT) |
					_ODP_IP_TOS_ECN_MASK;
		shifted_dscp  = new_dscp << _ODP_IP_TOS_DSCP_SHIFT;
	} else {
		tos_mask     = 0xFF;  /* Note that this is an inverted mask */
		shifted_dscp = 0;
	}

	tos_marking = &tm_system->marking.ip_tos_marking[color];
	tos_marking->marking_enabled    = drop_prec_enabled |
					  tos_marking->ecn_ce_enabled;
	tos_marking->drop_prec_enabled  = drop_prec_enabled;
	tos_marking->shifted_dscp       = shifted_dscp;
	tos_marking->inverted_dscp_mask = tos_mask;
	if (drop_prec_enabled)
		tm_system->marking_enabled = true;
	else
		tm_system->marking_enabled = tm_marking_enabled(tm_system);

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
	odp_tm_shaper_t     shaper_handle;
	_odp_int_name_t     name_tbl_id;

	profile_obj = tm_common_profile_create(name, TM_SHAPER_PROFILE,
					       &shaper_handle, &name_tbl_id);
	if (!profile_obj)
		return ODP_TM_INVALID;

	tm_shaper_params_cvt_to(params, profile_obj);
	profile_obj->name_tbl_id    = name_tbl_id;
	profile_obj->shaper_profile = shaper_handle;
	return shaper_handle;
}

int odp_tm_shaper_destroy(odp_tm_shaper_t shaper_profile)
{
	tm_shaper_params_t *profile_obj;

	if (shaper_profile == ODP_TM_INVALID)
		return -1;

	profile_obj = tm_get_profile_params(shaper_profile, TM_SHAPER_PROFILE);
	if (!profile_obj)
		return -1;

	if (profile_obj->ref_cnt != 0)
		return -1;

	return tm_common_profile_destroy(shaper_profile,
					 profile_obj->name_tbl_id);
}

int odp_tm_shaper_params_read(odp_tm_shaper_t shaper_profile,
			      odp_tm_shaper_params_t *params)
{
	tm_shaper_params_t *profile_obj;

	if (shaper_profile == ODP_TM_INVALID)
		return -1;

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

	if (shaper_profile == ODP_TM_INVALID)
		return -1;

	profile_obj = tm_get_profile_params(shaper_profile, TM_SHAPER_PROFILE);
	if (!profile_obj)
		return -1;

	if (!tm_glb->main_loop_running) {
		tm_shaper_params_cvt_to(params, profile_obj);
		return 0;
	}

	signal_request();
	tm_shaper_params_cvt_to(params, profile_obj);
	signal_request_done();
	return 0;
}

odp_tm_shaper_t odp_tm_shaper_lookup(const char *name)
{
	_odp_int_name_t odp_name;
	uint64_t        user_data;

	odp_name = _odp_int_name_tbl_lookup(name, ODP_TM_SHAPER_PROFILE_HANDLE);
	user_data = _odp_int_name_tbl_user_data(odp_name);
	return (odp_tm_shaper_t)user_data;
}

void odp_tm_sched_params_init(odp_tm_sched_params_t *params)
{
	memset(params, 0, sizeof(odp_tm_sched_params_t));
}

static void tm_sched_params_cvt_to(odp_tm_sched_params_t *odp_sched_params,
				   tm_sched_params_t     *tm_sched_params)
{
	odp_tm_sched_mode_t sched_mode;
	uint32_t            priority, weight, inv_weight;

	for (priority = 0; priority < ODP_TM_MAX_PRIORITIES; priority++) {
		sched_mode = odp_sched_params->sched_modes[priority];
		weight     = odp_sched_params->sched_weights[priority];
		if (weight == 0)
			inv_weight = 0;
		else
			inv_weight = 0xFFFF / weight;

		tm_sched_params->sched_modes[priority] = sched_mode;
		tm_sched_params->inverted_weights[priority] = inv_weight;
	}
}

static void tm_sched_params_cvt_from(tm_sched_params_t     *tm_sched_params,
				     odp_tm_sched_params_t *odp_sched_params)
{
	odp_tm_sched_mode_t sched_mode;
	uint32_t priority, weight, inv_weight;

	for (priority = 0; priority < ODP_TM_MAX_PRIORITIES; priority++) {
		sched_mode = tm_sched_params->sched_modes[priority];
		inv_weight = tm_sched_params->inverted_weights[priority];
		weight     = 0xFFFF / inv_weight;

		odp_sched_params->sched_modes[priority] = sched_mode;
		odp_sched_params->sched_weights[priority] = weight;
	}
}

odp_tm_sched_t odp_tm_sched_create(const char *name,
				   odp_tm_sched_params_t *params)
{
	tm_sched_params_t *profile_obj;
	_odp_int_name_t    name_tbl_id;
	odp_tm_sched_t     sched_handle;

	profile_obj = tm_common_profile_create(name, TM_SCHED_PROFILE,
					       &sched_handle, &name_tbl_id);
	if (!profile_obj)
		return ODP_TM_INVALID;

	tm_sched_params_cvt_to(params, profile_obj);
	profile_obj->name_tbl_id   = name_tbl_id;
	profile_obj->sched_profile = sched_handle;
	return sched_handle;
}

int odp_tm_sched_destroy(odp_tm_sched_t sched_profile)
{
	tm_sched_params_t *profile_obj;

	if (sched_profile == ODP_TM_INVALID)
		return -1;

	profile_obj = tm_get_profile_params(sched_profile, TM_SCHED_PROFILE);
	if (!profile_obj)
		return -1;

	if (profile_obj->ref_cnt != 0)
		return -1;

	return tm_common_profile_destroy(sched_profile,
					 profile_obj->name_tbl_id);
}

int odp_tm_sched_params_read(odp_tm_sched_t sched_profile,
			     odp_tm_sched_params_t *params)
{
	tm_sched_params_t *profile_obj;

	if (sched_profile == ODP_TM_INVALID)
		return -1;

	profile_obj = tm_get_profile_params(sched_profile, TM_SCHED_PROFILE);
	if (!profile_obj)
		return -1;

	tm_sched_params_cvt_from(profile_obj, params);
	return 0;
}

int odp_tm_sched_params_update(odp_tm_sched_t sched_profile,
			       odp_tm_sched_params_t *params)
{
	tm_sched_params_t *profile_obj;

	if (sched_profile == ODP_TM_INVALID)
		return -1;

	profile_obj = tm_get_profile_params(sched_profile, TM_SCHED_PROFILE);
	if (!profile_obj)
		return -1;

	if (!tm_glb->main_loop_running) {
		tm_sched_params_cvt_to(params, profile_obj);
		return 0;
	}

	signal_request();
	tm_sched_params_cvt_to(params, profile_obj);
	signal_request_done();
	return 0;
}

odp_tm_sched_t odp_tm_sched_lookup(const char *name)
{
	_odp_int_name_t odp_name;
	uint64_t        user_data;

	odp_name  = _odp_int_name_tbl_lookup(name, ODP_TM_SCHED_PROFILE_HANDLE);
	user_data = _odp_int_name_tbl_user_data(odp_name);
	return (odp_tm_sched_t)user_data;
}

void odp_tm_threshold_params_init(odp_tm_threshold_params_t *params)
{
	memset(params, 0, sizeof(odp_tm_threshold_params_t));
}

odp_tm_threshold_t odp_tm_threshold_create(const char *name,
					   odp_tm_threshold_params_t *params)
{
	tm_queue_thresholds_t *profile_obj;
	odp_tm_threshold_t     threshold_handle;
	_odp_int_name_t        name_tbl_id;

	profile_obj = tm_common_profile_create(name, TM_THRESHOLD_PROFILE,
					       &threshold_handle, &name_tbl_id);
	if (!profile_obj)
		return ODP_TM_INVALID;

	profile_obj->max_pkts = params->enable_max_pkts ? params->max_pkts : 0;
	profile_obj->max_bytes =
		params->enable_max_bytes ? params->max_bytes : 0;
	profile_obj->name_tbl_id        = name_tbl_id;
	profile_obj->thresholds_profile = threshold_handle;
	return threshold_handle;
}

int odp_tm_threshold_destroy(odp_tm_threshold_t threshold_profile)
{
	tm_queue_thresholds_t *threshold_params;

	if (threshold_profile == ODP_TM_INVALID)
		return -1;

	threshold_params = tm_get_profile_params(threshold_profile,
						 TM_THRESHOLD_PROFILE);
	if (!threshold_params)
		return -1;

	if (threshold_params->ref_cnt != 0)
		return -1;

	return tm_common_profile_destroy(threshold_profile,
					 threshold_params->name_tbl_id);
}

int odp_tm_thresholds_params_read(odp_tm_threshold_t threshold_profile,
				  odp_tm_threshold_params_t *params)
{
	tm_queue_thresholds_t *threshold_params;

	if (threshold_profile == ODP_TM_INVALID)
		return -1;

	threshold_params = tm_get_profile_params(threshold_profile,
						 TM_THRESHOLD_PROFILE);
	if (!threshold_params)
		return -1;

	params->max_pkts         = threshold_params->max_pkts;
	params->max_bytes        = threshold_params->max_bytes;
	params->enable_max_pkts  = threshold_params->max_pkts  != 0;
	params->enable_max_bytes = threshold_params->max_bytes != 0;
	return 0;
}

int odp_tm_thresholds_params_update(odp_tm_threshold_t threshold_profile,
				    odp_tm_threshold_params_t *params)
{
	tm_queue_thresholds_t *profile_obj;

	if (threshold_profile == ODP_TM_INVALID)
		return -1;

	profile_obj = tm_get_profile_params(threshold_profile,
					    TM_THRESHOLD_PROFILE);
	if (!profile_obj)
		return -1;

	if (!tm_glb->main_loop_running) {
		profile_obj->max_pkts =
			params->enable_max_pkts ? params->max_pkts : 0;
		profile_obj->max_bytes =
			params->enable_max_bytes ? params->max_bytes : 0;
		return 0;
	}

	signal_request();
	profile_obj->max_pkts = params->enable_max_pkts ? params->max_pkts : 0;
	profile_obj->max_bytes =
		params->enable_max_bytes ? params->max_bytes : 0;
	signal_request_done();
	return 0;
}

odp_tm_threshold_t odp_tm_thresholds_lookup(const char *name)
{
	_odp_int_name_t odp_name;
	uint64_t        user_data;

	odp_name  = _odp_int_name_tbl_lookup(name,
					     ODP_TM_THRESHOLD_PROFILE_HANDLE);
	user_data = _odp_int_name_tbl_user_data(odp_name);
	return (odp_tm_threshold_t)user_data;
}

void odp_tm_wred_params_init(odp_tm_wred_params_t *params)
{
	memset(params, 0, sizeof(odp_tm_wred_params_t));
}

static void tm_wred_params_cvt_to(odp_tm_wred_params_t *odp_tm_wred_params,
				  tm_wred_params_t     *wred_params)
{
	wred_params->min_threshold     = odp_tm_wred_params->min_threshold;
	wred_params->med_threshold     = odp_tm_wred_params->med_threshold;
	wred_params->med_drop_prob     = odp_tm_wred_params->med_drop_prob;
	wred_params->max_drop_prob     = odp_tm_wred_params->max_drop_prob;
	wred_params->enable_wred       = odp_tm_wred_params->enable_wred;
	wred_params->use_byte_fullness = odp_tm_wred_params->use_byte_fullness;
}

static void tm_wred_params_cvt_from(tm_wred_params_t     *wred_params,
				    odp_tm_wred_params_t *odp_tm_wred_params)
{
	odp_tm_wred_params->min_threshold     = wred_params->min_threshold;
	odp_tm_wred_params->med_threshold     = wred_params->med_threshold;
	odp_tm_wred_params->med_drop_prob     = wred_params->med_drop_prob;
	odp_tm_wred_params->max_drop_prob     = wred_params->max_drop_prob;
	odp_tm_wred_params->enable_wred       = wred_params->enable_wred;
	odp_tm_wred_params->use_byte_fullness = wred_params->use_byte_fullness;
}

odp_tm_wred_t odp_tm_wred_create(const char *name, odp_tm_wred_params_t *params)
{
	tm_wred_params_t *profile_obj;
	odp_tm_wred_t     wred_handle;
	_odp_int_name_t   name_tbl_id;

	profile_obj = tm_common_profile_create(name, TM_WRED_PROFILE,
					       &wred_handle, &name_tbl_id);

	if (!profile_obj)
		return ODP_TM_INVALID;

	tm_wred_params_cvt_to(params, profile_obj);
	profile_obj->name_tbl_id  = name_tbl_id;
	profile_obj->wred_profile = wred_handle;
	return wred_handle;
}

int odp_tm_wred_destroy(odp_tm_wred_t wred_profile)
{
	tm_wred_params_t *wred_params;

	if (wred_profile == ODP_TM_INVALID)
		return -1;

	wred_params = tm_get_profile_params(wred_profile, TM_WRED_PROFILE);
	if (!wred_params)
		return -1;

	if (wred_params->ref_cnt != 0)
		return -1;

	return tm_common_profile_destroy(wred_profile,
					 ODP_INVALID_NAME);
}

int odp_tm_wred_params_read(odp_tm_wred_t wred_profile,
			    odp_tm_wred_params_t *params)
{
	tm_wred_params_t *wred_params;

	if (wred_profile == ODP_TM_INVALID)
		return -1;

	wred_params = tm_get_profile_params(wred_profile, TM_WRED_PROFILE);
	if (!wred_params)
		return -1;

	tm_wred_params_cvt_from(wred_params, params);
	return 0;
}

int odp_tm_wred_params_update(odp_tm_wred_t wred_profile,
			      odp_tm_wred_params_t *params)
{
	tm_wred_params_t *wred_params;

	if (wred_profile == ODP_TM_INVALID)
		return -1;

	wred_params = tm_get_profile_params(wred_profile, TM_WRED_PROFILE);
	if (!wred_params)
		return -1;

	if (!tm_glb->main_loop_running) {
		tm_wred_params_cvt_to(params, wred_params);
		return 0;
	}

	signal_request();
	tm_wred_params_cvt_to(params, wred_params);
	signal_request_done();
	return 0;
}

odp_tm_wred_t odp_tm_wred_lookup(const char *name)
{
	_odp_int_name_t odp_name;
	uint64_t        user_data;

	odp_name  = _odp_int_name_tbl_lookup(name, ODP_TM_WRED_PROFILE_HANDLE);
	user_data = _odp_int_name_tbl_user_data(odp_name);
	return (odp_tm_wred_t)user_data;
}

void odp_tm_node_params_init(odp_tm_node_params_t *params)
{
	memset(params, 0, sizeof(odp_tm_node_params_t));
}

odp_tm_node_t odp_tm_node_create(odp_tm_t             odp_tm,
				 const char           *name,
				 odp_tm_node_params_t *params)
{
	odp_tm_level_requirements_t *requirements;
	_odp_int_sorted_list_t sorted_list;
	tm_schedulers_obj_t *schedulers_obj;
	_odp_int_name_t name_tbl_id;
	tm_wred_node_t *tm_wred_node;
	tm_node_obj_t *tm_node_obj = NULL;
	odp_tm_node_t odp_tm_node;
	odp_tm_wred_t wred_profile;
	tm_system_t *tm_system;
	uint32_t level, num_priorities, priority, color;
	uint32_t i;

	/* Allocate a tm_node_obj_t record. */
	tm_system = GET_TM_SYSTEM(odp_tm);

	odp_ticketlock_lock(&tm_glb->node_obj.lock);

	for (i = 0; i < ODP_TM_MAX_NUM_TM_NODES; i++) {
		tm_node_obj_t *cur_node_obj = tm_nobj_from_index(i);

		if (cur_node_obj->status != TM_STATUS_FREE)
			continue;

		level = params->level;
		requirements = &tm_system->requirements.per_level[level];
		num_priorities = requirements->max_priority + 1;

		odp_tm_node = MAKE_ODP_TM_NODE(cur_node_obj);
		name_tbl_id = ODP_INVALID_NAME;
		if ((name) && (name[0] != '\0')) {
			name_tbl_id = _odp_int_name_tbl_add(name,
							    ODP_TM_NODE_HANDLE,
							    odp_tm_node);
			if (name_tbl_id == ODP_INVALID_NAME)
				break;
		}
		tm_node_obj = cur_node_obj;

		memset(tm_node_obj, 0, sizeof(tm_node_obj_t));
		tm_node_obj->status = TM_STATUS_RESERVED;

		break;
	}

	odp_ticketlock_unlock(&tm_glb->node_obj.lock);

	if (!tm_node_obj)
		return ODP_TM_INVALID;

	tm_node_obj->user_context = params->user_context;
	tm_node_obj->name_tbl_id = name_tbl_id;
	tm_node_obj->max_fanin = params->max_fanin;
	tm_node_obj->is_root_node = false;
	tm_node_obj->level = params->level;
	tm_node_obj->tm_idx = tm_system->tm_idx;

	tm_wred_node = &tm_node_obj->tm_wred_node;
	odp_ticketlock_init(&tm_wred_node->tm_wred_node_lock);

	schedulers_obj = &tm_node_obj->schedulers_obj;
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
		tm_threshold_config_set(tm_wred_node,
					params->threshold_profile);

	for (color = 0; color < ODP_NUM_PACKET_COLORS; color++) {
		wred_profile = params->wred_profile[color];
		if (wred_profile != ODP_TM_INVALID)
			tm_wred_config_set(tm_wred_node, color, wred_profile);
	}

	tm_node_obj->magic_num = TM_NODE_MAGIC_NUM;
	tm_node_obj->shaper_obj.enclosing_entity = tm_node_obj;
	tm_node_obj->shaper_obj.in_tm_node_obj = 1;
	tm_node_obj->schedulers_obj.enclosing_entity = tm_node_obj;

	odp_ticketlock_unlock(&tm_system->tm_system_lock);
	return odp_tm_node;
}

int odp_tm_node_destroy(odp_tm_node_t tm_node)
{
	_odp_int_sorted_list_t sorted_list;
	_odp_int_sorted_pool_t sorted_pool;
	tm_schedulers_obj_t   *schedulers_obj;
	tm_sched_state_t      *sched_state;
	tm_wred_params_t      *wred_params;
	tm_shaper_obj_t       *shaper_obj;
	tm_wred_node_t        *tm_wred_node;
	tm_node_obj_t         *tm_node_obj;
	tm_system_t           *tm_system;
	uint32_t               color, num_priorities, priority;
	int                    rc;

	/* First lookup tm_node. */
	tm_node_obj = GET_TM_NODE_OBJ(tm_node);
	if (!tm_node_obj)
		return -1;

	tm_system = &tm_glb->system[tm_node_obj->tm_idx];
	if (!tm_system)
		return -1;

	/* Next make sure node_obj is disconnected and has no fanin. */
	shaper_obj = &tm_node_obj->shaper_obj;
	if (shaper_obj->next_tm_node != NULL)
		return -1;

	if ((tm_node_obj->current_tm_queue_fanin != 0) ||
	    (tm_node_obj->current_tm_node_fanin  != 0))
		return -1;

	/* Check that there is no shaper profile, threshold profile or wred
	 * profile currently associated with this tm_node. */
	if (shaper_obj->shaper_params != NULL)
		return -1;

	tm_wred_node = &tm_node_obj->tm_wred_node;
	if (tm_wred_node->threshold_params != NULL)
		return -1;

	for (color = 0; color < ODP_NUM_PACKET_COLORS; color++) {
		wred_params = tm_wred_node->wred_params[color];
		if (wred_params != NULL)
			return -1;
	}

	/* Now that all of the checks are done, time to so some freeing. */
	odp_ticketlock_lock(&tm_system->tm_system_lock);
	if (tm_node_obj->name_tbl_id != ODP_INVALID_NAME)
		_odp_int_name_tbl_delete(tm_node_obj->name_tbl_id);

	schedulers_obj = &tm_node_obj->schedulers_obj;
	num_priorities = schedulers_obj->num_priorities;
	for (priority = 0; priority < num_priorities; priority++) {
		sched_state = &schedulers_obj->sched_states[priority];
		sorted_list = sched_state->sorted_list;
		sorted_pool = tm_system->_odp_int_sorted_pool;
		rc          = _odp_sorted_list_destroy(sorted_pool,
						       sorted_list);
		if (rc != 0)
			return rc;
	}

	odp_ticketlock_lock(&tm_glb->node_obj.lock);
	tm_node_obj->status = TM_STATUS_FREE;
	odp_ticketlock_unlock(&tm_glb->node_obj.lock);

	odp_ticketlock_unlock(&tm_system->tm_system_lock);
	return 0;
}

int odp_tm_node_shaper_config(odp_tm_node_t tm_node,
			      odp_tm_shaper_t shaper_profile)
{
	tm_node_obj_t *tm_node_obj;
	tm_system_t *tm_system;

	tm_node_obj = GET_TM_NODE_OBJ(tm_node);
	if (!tm_node_obj)
		return -1;

	tm_system = &tm_glb->system[tm_node_obj->tm_idx];
	if (!tm_system)
		return -1;

	odp_ticketlock_lock(&tm_glb->profile_lock);
	tm_shaper_config_set(tm_system, shaper_profile,
			     &tm_node_obj->shaper_obj);
	odp_ticketlock_unlock(&tm_glb->profile_lock);
	return 0;
}

int odp_tm_node_sched_config(odp_tm_node_t tm_node,
			     odp_tm_node_t tm_fan_in_node,
			     odp_tm_sched_t sched_profile)
{
	tm_shaper_obj_t   *child_shaper_obj;
	tm_node_obj_t     *tm_node_obj, *child_tm_node_obj;

	tm_node_obj = GET_TM_NODE_OBJ(tm_node);
	if (!tm_node_obj)
		return -1;

	child_tm_node_obj = GET_TM_NODE_OBJ(tm_fan_in_node);
	if (!child_tm_node_obj)
		return -1;

	odp_ticketlock_lock(&tm_glb->profile_lock);
	child_shaper_obj = &child_tm_node_obj->shaper_obj;
	tm_sched_config_set(child_shaper_obj, sched_profile);
	odp_ticketlock_unlock(&tm_glb->profile_lock);
	return 0;
}

int odp_tm_node_threshold_config(odp_tm_node_t tm_node,
				 odp_tm_threshold_t thresholds_profile)
{
	tm_node_obj_t *tm_node_obj;

	tm_node_obj = GET_TM_NODE_OBJ(tm_node);
	if (!tm_node_obj)
		return -1;

	odp_ticketlock_lock(&tm_glb->profile_lock);
	tm_threshold_config_set(&tm_node_obj->tm_wred_node, thresholds_profile);
	odp_ticketlock_unlock(&tm_glb->profile_lock);
	return 0;
}

int odp_tm_node_wred_config(odp_tm_node_t      tm_node,
			    odp_packet_color_t pkt_color,
			    odp_tm_wred_t      wred_profile)
{
	tm_wred_node_t *wred_node;
	tm_node_obj_t  *tm_node_obj;
	uint32_t color;
	int rc;

	tm_node_obj = GET_TM_NODE_OBJ(tm_node);
	if (!tm_node_obj)
		return -1;

	wred_node = &tm_node_obj->tm_wred_node;

	odp_ticketlock_lock(&tm_glb->profile_lock);
	rc = 0;
	if (pkt_color == ODP_PACKET_ALL_COLORS) {
		for (color = 0; color < ODP_NUM_PACKET_COLORS; color++)
			tm_wred_config_set(wred_node, color, wred_profile);
	} else if (pkt_color < ODP_NUM_PACKET_COLORS) {
		tm_wred_config_set(wred_node, pkt_color, wred_profile);
	} else {
		rc = -1;
	}

	odp_ticketlock_unlock(&tm_glb->profile_lock);
	return rc;
}

odp_tm_node_t odp_tm_node_lookup(odp_tm_t odp_tm ODP_UNUSED, const char *name)
{
	_odp_int_name_t odp_name;
	uint64_t        user_data;

	odp_name  = _odp_int_name_tbl_lookup(name, ODP_TM_NODE_HANDLE);
	user_data = _odp_int_name_tbl_user_data(odp_name);
	return (odp_tm_node_t)user_data;
}

void *odp_tm_node_context(odp_tm_node_t tm_node)
{
	tm_node_obj_t *tm_node_obj;

	tm_node_obj = GET_TM_NODE_OBJ(tm_node);
	if (!tm_node_obj)
		return NULL;

	return tm_node_obj->user_context;
}

int odp_tm_node_context_set(odp_tm_node_t tm_node, void *user_context)
{
	tm_node_obj_t *tm_node_obj;

	tm_node_obj = GET_TM_NODE_OBJ(tm_node);
	if (!tm_node_obj)
		return -1;

	tm_node_obj->user_context = user_context;
	return 0;
}

void odp_tm_queue_params_init(odp_tm_queue_params_t *params)
{
	memset(params, 0, sizeof(odp_tm_queue_params_t));
}

odp_tm_queue_t odp_tm_queue_create(odp_tm_t odp_tm,
				   odp_tm_queue_params_t *params)
{
	_odp_int_pkt_queue_t _odp_int_pkt_queue;
	tm_queue_obj_t *queue_obj;
	odp_tm_queue_t odp_tm_queue = ODP_TM_INVALID;
	odp_queue_t queue;
	odp_tm_wred_t wred_profile;
	tm_system_t *tm_system;
	uint32_t color;
	uint32_t i;

	/* Allocate a tm_queue_obj_t record. */
	tm_system = GET_TM_SYSTEM(odp_tm);

	odp_ticketlock_lock(&tm_glb->queue_obj.lock);

	for (i = 0; i < ODP_TM_MAX_TM_QUEUES; i++) {
		_odp_int_queue_pool_t  int_queue_pool;

		queue_obj = tm_qobj_from_index(i);

		if (queue_obj->status != TM_STATUS_FREE)
			continue;

		int_queue_pool = tm_system->_odp_int_queue_pool;
		_odp_int_pkt_queue = _odp_pkt_queue_create(int_queue_pool);
		if (_odp_int_pkt_queue == _ODP_INT_PKT_QUEUE_INVALID)
			continue;

		odp_tm_queue = MAKE_ODP_TM_QUEUE(queue_obj);
		memset(queue_obj, 0, sizeof(tm_queue_obj_t));
		queue_obj->user_context = params->user_context;
		queue_obj->priority = params->priority;
		queue_obj->tm_idx = tm_system->tm_idx;
		queue_obj->queue_num = tm_system->next_queue_num++;
		queue_obj->_odp_int_pkt_queue = _odp_int_pkt_queue;
		queue_obj->pkt = ODP_PACKET_INVALID;
		odp_ticketlock_init(&queue_obj->tm_wred_node.tm_wred_node_lock);

		queue = odp_queue_create(NULL, NULL);
		if (queue == ODP_QUEUE_INVALID) {
			odp_tm_queue = ODP_TM_INVALID;
			continue;
		}

		queue_obj->queue = queue;
		odp_queue_context_set(queue, queue_obj, sizeof(tm_queue_obj_t));
		queue_fn->set_enq_deq_fn(queue, queue_tm_reenq,
					 queue_tm_reenq_multi, NULL, NULL);

		tm_system->queue_num_tbl[queue_obj->queue_num - 1] = queue_obj;

		odp_ticketlock_lock(&tm_system->tm_system_lock);

		if (params->shaper_profile != ODP_TM_INVALID)
			tm_shaper_config_set(tm_system, params->shaper_profile,
					     &queue_obj->shaper_obj);

		if (params->threshold_profile != ODP_TM_INVALID)
			tm_threshold_config_set(&queue_obj->tm_wred_node,
						params->threshold_profile);

		for (color = 0; color < ODP_NUM_PACKET_COLORS; color++) {
			wred_profile = params->wred_profile[color];
			if (wred_profile != ODP_TM_INVALID)
				tm_wred_config_set(&queue_obj->tm_wred_node,
						   color, wred_profile);
		}

		queue_obj->magic_num = TM_QUEUE_MAGIC_NUM;
		queue_obj->shaper_obj.enclosing_entity = queue_obj;
		queue_obj->shaper_obj.in_tm_node_obj = 0;

		odp_ticketlock_unlock(&tm_system->tm_system_lock);

		queue_obj->status = TM_STATUS_RESERVED;
		break;
	}

	odp_ticketlock_unlock(&tm_glb->queue_obj.lock);

	return odp_tm_queue;
}

int odp_tm_queue_destroy(odp_tm_queue_t tm_queue)
{
	tm_shaper_obj_t  *shaper_obj;
	tm_queue_obj_t   *tm_queue_obj;
	tm_system_t      *tm_system;

	/* First lookup tm_queue. */
	tm_queue_obj = GET_TM_QUEUE_OBJ(tm_queue);
	if (!tm_queue_obj)
		return -1;

	tm_system = &tm_glb->system[tm_queue_obj->tm_idx];
	if (!tm_system)
		return -1;

	/* Check to see if the tm_queue_obj is disconnected AND that it has no
	 * current pkt, otherwise the destroy fails. */
	shaper_obj = &tm_queue_obj->shaper_obj;
	if ((shaper_obj->next_tm_node != NULL) ||
	    (tm_queue_obj->pkt        != ODP_PACKET_INVALID))
		return -1;

	/* Now that all of the checks are done, time to so some freeing. */
	odp_ticketlock_lock(&tm_system->tm_system_lock);
	tm_system->queue_num_tbl[tm_queue_obj->queue_num - 1] = NULL;

	odp_queue_destroy(tm_queue_obj->queue);

	odp_ticketlock_lock(&tm_glb->queue_obj.lock);
	tm_queue_obj->status = TM_STATUS_FREE;
	odp_ticketlock_unlock(&tm_glb->queue_obj.lock);

	odp_ticketlock_unlock(&tm_system->tm_system_lock);
	return 0;
}

void *odp_tm_queue_context(odp_tm_queue_t tm_queue)
{
	tm_queue_obj_t *tm_queue_obj;

	tm_queue_obj = GET_TM_QUEUE_OBJ(tm_queue);
	if (!tm_queue_obj)
		return NULL;

	return tm_queue_obj->user_context;
}

int odp_tm_queue_context_set(odp_tm_queue_t tm_queue, void *user_context)
{
	tm_queue_obj_t *tm_queue_obj;

	tm_queue_obj = GET_TM_QUEUE_OBJ(tm_queue);
	if (!tm_queue_obj)
		return -1;

	tm_queue_obj->user_context = user_context;
	return 0;
}

int odp_tm_queue_shaper_config(odp_tm_queue_t tm_queue,
			       odp_tm_shaper_t shaper_profile)
{
	tm_queue_obj_t *tm_queue_obj;
	tm_system_t *tm_system;

	tm_queue_obj = GET_TM_QUEUE_OBJ(tm_queue);
	if (!tm_queue_obj)
		return -1;

	tm_system = &tm_glb->system[tm_queue_obj->tm_idx];
	if (!tm_system)
		return -1;

	odp_ticketlock_lock(&tm_glb->profile_lock);
	tm_shaper_config_set(tm_system, shaper_profile,
			     &tm_queue_obj->shaper_obj);
	odp_ticketlock_unlock(&tm_glb->profile_lock);
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

	odp_ticketlock_lock(&tm_glb->profile_lock);
	child_shaper_obj = &child_tm_queue_obj->shaper_obj;
	tm_sched_config_set(child_shaper_obj, sched_profile);
	odp_ticketlock_unlock(&tm_glb->profile_lock);
	return 0;
}

int odp_tm_queue_threshold_config(odp_tm_queue_t tm_queue,
				  odp_tm_threshold_t thresholds_profile)
{
	tm_queue_obj_t *tm_queue_obj;
	int ret;

	tm_queue_obj = GET_TM_QUEUE_OBJ(tm_queue);
	if (!tm_queue_obj)
		return -1;

	odp_ticketlock_lock(&tm_glb->profile_lock);
	ret = tm_threshold_config_set(&tm_queue_obj->tm_wred_node,
				      thresholds_profile);
	odp_ticketlock_unlock(&tm_glb->profile_lock);
	return ret;
}

int odp_tm_queue_wred_config(odp_tm_queue_t tm_queue,
			     odp_packet_color_t pkt_color,
			     odp_tm_wred_t wred_profile)
{
	tm_wred_node_t *wred_node;
	tm_queue_obj_t *tm_queue_obj;
	uint32_t color;
	int rc;

	tm_queue_obj = GET_TM_QUEUE_OBJ(tm_queue);
	if (!tm_queue_obj)
		return -1;

	wred_node = &tm_queue_obj->tm_wred_node;

	odp_ticketlock_lock(&tm_glb->profile_lock);
	rc = 0;
	if (pkt_color == ODP_PACKET_ALL_COLORS) {
		for (color = 0; color < ODP_NUM_PACKET_COLORS; color++)
			tm_wred_config_set(wred_node, color, wred_profile);
	} else if (pkt_color < ODP_NUM_PACKET_COLORS) {
		tm_wred_config_set(wred_node, pkt_color, wred_profile);
	} else {
		rc = -1;
	}

	odp_ticketlock_unlock(&tm_glb->profile_lock);
	return rc;
}

static int tm_append_to_fanin_list(tm_node_obj_t   *tm_node_obj,
				   tm_shaper_obj_t *shaper_obj)
{
	tm_shaper_obj_t *head_ptr, *tail_ptr;

	head_ptr = tm_node_obj->fanin_list_head;
	tail_ptr = tm_node_obj->fanin_list_tail;

	if ((head_ptr == NULL) && (tail_ptr != NULL))
		return -9;
	else if ((head_ptr != NULL) && (tail_ptr == NULL))
		return -10;

	if (tail_ptr == NULL) {
		tm_node_obj->fanin_list_head = shaper_obj;
		shaper_obj->fanin_list_prev = NULL;
	} else {
		tail_ptr->fanin_list_next = shaper_obj;
		shaper_obj->fanin_list_prev = tail_ptr;
	}

	tm_node_obj->fanin_list_tail = shaper_obj;
	shaper_obj->fanin_list_next = NULL;
	return 0;
}

static int tm_remove_from_fanin_list(tm_node_obj_t   *tm_node_obj,
				     tm_shaper_obj_t *shaper_obj)
{
	tm_shaper_obj_t *next_ptr, *prev_ptr;

	next_ptr = shaper_obj->fanin_list_next;
	prev_ptr = shaper_obj->fanin_list_prev;

	if (next_ptr != NULL)
		next_ptr->fanin_list_prev = prev_ptr;
	else
		tm_node_obj->fanin_list_tail = prev_ptr;

	if (prev_ptr != NULL)
		prev_ptr->fanin_list_next = next_ptr;
	else
		tm_node_obj->fanin_list_head = next_ptr;

	return 0;
}

int odp_tm_node_connect(odp_tm_node_t src_tm_node, odp_tm_node_t dst_tm_node)
{
	tm_wred_node_t *src_tm_wred_node, *dst_tm_wred_node;
	tm_node_obj_t  *src_tm_node_obj, *dst_tm_node_obj;
	tm_system_t    *tm_system;

	if ((src_tm_node == ODP_TM_INVALID) || (src_tm_node == ODP_TM_ROOT) ||
	    (dst_tm_node == ODP_TM_INVALID))
		return -1;

	src_tm_node_obj = GET_TM_NODE_OBJ(src_tm_node);
	if ((!src_tm_node_obj) || src_tm_node_obj->is_root_node)
		return -1;

	tm_system = &tm_glb->system[src_tm_node_obj->tm_idx];
	if (!tm_system)
		return -1;

	src_tm_wred_node = &src_tm_node_obj->tm_wred_node;
	if (dst_tm_node == ODP_TM_ROOT) {
		tm_node_obj_t  *root_node = &tm_system->root_node;

		src_tm_node_obj->shaper_obj.next_tm_node = root_node;
		src_tm_wred_node->next_tm_wred_node = NULL;
		return 0;
	}

	dst_tm_node_obj = GET_TM_NODE_OBJ(dst_tm_node);
	if ((!dst_tm_node_obj) || dst_tm_node_obj->is_root_node)
		return -1;

	dst_tm_wred_node = &dst_tm_node_obj->tm_wred_node;
	if (src_tm_node_obj->tm_idx != dst_tm_node_obj->tm_idx)
		return -1;

	src_tm_wred_node->next_tm_wred_node      = dst_tm_wred_node;
	src_tm_node_obj->shaper_obj.next_tm_node = dst_tm_node_obj;
	dst_tm_node_obj->current_tm_node_fanin++;

	/* Finally add this src_tm_node_obj to the dst_tm_node_obj's fanin
	 * list. */
	return tm_append_to_fanin_list(dst_tm_node_obj,
				       &src_tm_node_obj->shaper_obj);
}

int odp_tm_node_disconnect(odp_tm_node_t src_tm_node)
{
	tm_wred_node_t *src_tm_wred_node;
	tm_node_obj_t  *src_tm_node_obj, *dst_tm_node_obj;

	src_tm_node_obj = GET_TM_NODE_OBJ(src_tm_node);
	if (!src_tm_node_obj)
		return -1;

	dst_tm_node_obj = src_tm_node_obj->shaper_obj.next_tm_node;
	if ((dst_tm_node_obj != NULL) && (!dst_tm_node_obj->is_root_node)) {
		tm_remove_from_fanin_list(dst_tm_node_obj,
					  &src_tm_node_obj->shaper_obj);
		if (dst_tm_node_obj->current_tm_node_fanin != 0)
			dst_tm_node_obj->current_tm_node_fanin--;
	}

	src_tm_wred_node = &src_tm_node_obj->tm_wred_node;
	src_tm_wred_node->next_tm_wred_node = NULL;

	src_tm_node_obj->shaper_obj.next_tm_node = NULL;
	return 0;
}

int odp_tm_queue_connect(odp_tm_queue_t tm_queue, odp_tm_node_t dst_tm_node)
{
	tm_wred_node_t *src_tm_wred_node, *dst_tm_wred_node;
	tm_queue_obj_t *src_tm_queue_obj;
	tm_node_obj_t  *dst_tm_node_obj, *root_node;
	tm_system_t    *tm_system;

	if ((tm_queue == ODP_TM_INVALID) || (tm_queue == ODP_TM_ROOT) ||
	    (dst_tm_node == ODP_TM_INVALID))
		return -1;

	src_tm_queue_obj = GET_TM_QUEUE_OBJ(tm_queue);
	if (!src_tm_queue_obj)
		return -1;

	tm_system = &tm_glb->system[src_tm_queue_obj->tm_idx];
	if (!tm_system)
		return -1;

	src_tm_wred_node = &src_tm_queue_obj->tm_wred_node;
	if (dst_tm_node == ODP_TM_ROOT) {
		root_node = &tm_system->root_node;
		src_tm_queue_obj->shaper_obj.next_tm_node = root_node;
		src_tm_wred_node->next_tm_wred_node = NULL;
		return 0;
	}

	dst_tm_node_obj  = GET_TM_NODE_OBJ(dst_tm_node);
	if ((!dst_tm_node_obj) || dst_tm_node_obj->is_root_node)
		return -1;

	dst_tm_wred_node = &dst_tm_node_obj->tm_wred_node;
	if (src_tm_queue_obj->tm_idx != dst_tm_node_obj->tm_idx)
		return -1;

	src_tm_wred_node->next_tm_wred_node       = dst_tm_wred_node;
	src_tm_queue_obj->shaper_obj.next_tm_node = dst_tm_node_obj;
	dst_tm_node_obj->current_tm_queue_fanin++;

	/* Finally add this src_tm_queue_obj to the dst_tm_node_obj's fanin
	 * list. */
	return tm_append_to_fanin_list(dst_tm_node_obj,
				       &src_tm_queue_obj->shaper_obj);
}

int odp_tm_queue_disconnect(odp_tm_queue_t tm_queue)
{
	tm_wred_node_t *src_tm_wred_node;
	tm_queue_obj_t *src_tm_queue_obj;
	tm_node_obj_t  *dst_tm_node_obj;

	src_tm_queue_obj = GET_TM_QUEUE_OBJ(tm_queue);
	if (!src_tm_queue_obj)
		return -1;

	dst_tm_node_obj = src_tm_queue_obj->shaper_obj.next_tm_node;
	if ((dst_tm_node_obj != NULL) && (!dst_tm_node_obj->is_root_node)) {
		tm_remove_from_fanin_list(dst_tm_node_obj,
					  &src_tm_queue_obj->shaper_obj);
		if (dst_tm_node_obj->current_tm_queue_fanin != 0)
			dst_tm_node_obj->current_tm_queue_fanin--;
	}

	src_tm_wred_node = &src_tm_queue_obj->tm_wred_node;
	src_tm_wred_node->next_tm_wred_node = NULL;

	src_tm_queue_obj->shaper_obj.next_tm_node = NULL;
	return 0;
}

int odp_tm_enq(odp_tm_queue_t tm_queue, odp_packet_t pkt)
{
	tm_queue_obj_t *tm_queue_obj;
	tm_system_t *tm_system;

	tm_queue_obj = GET_TM_QUEUE_OBJ(tm_queue);
	if (!tm_queue_obj)
		return -1;

	tm_system = &tm_glb->system[tm_queue_obj->tm_idx];
	if (!tm_system)
		return -1;

	if (odp_atomic_load_u64(&tm_system->destroying))
		return -1;

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

	tm_system = &tm_glb->system[tm_queue_obj->tm_idx];
	if (!tm_system)
		return -1;

	if (odp_atomic_load_u64(&tm_system->destroying))
		return -1;

	rc = tm_enqueue(tm_system, tm_queue_obj, pkt);
	if (rc < 0)
		return rc;

	pkt_cnt = rc;
	return pkt_cnt;
}

int odp_tm_node_info(odp_tm_node_t tm_node, odp_tm_node_info_t *info)
{
	tm_queue_thresholds_t *threshold_params;
	tm_shaper_params_t    *shaper_params;
	tm_wred_params_t      *wred_params;
	tm_shaper_obj_t       *shaper_obj;
	tm_wred_node_t        *tm_wred_node;
	tm_node_obj_t         *tm_node_obj, *next_tm_node;
	uint32_t               color;

	tm_node_obj = GET_TM_NODE_OBJ(tm_node);
	if (tm_node_obj == NULL)
		return -1;

	info->shaper_profile = ODP_TM_INVALID;
	info->threshold_profile = ODP_TM_INVALID;
	for (color = 0; color < ODP_NUM_PACKET_COLORS; color++)
		info->wred_profile[color] = ODP_TM_INVALID;

	info->level          = tm_node_obj->level;
	info->tm_queue_fanin = tm_node_obj->current_tm_queue_fanin;
	info->tm_node_fanin  = tm_node_obj->current_tm_node_fanin;
	shaper_obj           = &tm_node_obj->shaper_obj;
	next_tm_node         = shaper_obj->next_tm_node;
	if (next_tm_node == NULL)
		info->next_tm_node = ODP_TM_INVALID;
	else if (next_tm_node->is_root_node)
		info->next_tm_node = ODP_TM_ROOT;
	else
		info->next_tm_node = MAKE_ODP_TM_NODE(next_tm_node);

	shaper_params = shaper_obj->shaper_params;
	if (shaper_params != NULL)
		info->shaper_profile = shaper_params->shaper_profile;

	tm_wred_node = &tm_node_obj->tm_wred_node;
	threshold_params = tm_wred_node->threshold_params;
	if (threshold_params != NULL)
		info->threshold_profile =
			threshold_params->thresholds_profile;

	for (color = 0; color < ODP_NUM_PACKET_COLORS; color++) {
		wred_params = tm_wred_node->wred_params[color];
		if (wred_params != NULL)
			info->wred_profile[color] =
				wred_params->wred_profile;
	}

	return 0;
}

int odp_tm_node_fanin_info(odp_tm_node_t             tm_node,
			   odp_tm_node_fanin_info_t *info)
{
	tm_sched_params_t *sched_params;
	tm_shaper_obj_t   *shaper_obj, *next_shaper_obj;
	tm_queue_obj_t    *fanin_tm_queue_obj;
	tm_node_obj_t     *tm_node_obj, *fanin_tm_node_obj;

	tm_node_obj = GET_TM_NODE_OBJ(tm_node);
	if (tm_node_obj == NULL)
		return -1;
	else if ((info->tm_queue != ODP_TM_INVALID) &&
		 (info->tm_node  != ODP_TM_INVALID))
		return -1;
	else if (info->is_last)
		return -1;

	if (info->tm_queue != ODP_TM_INVALID) {
		fanin_tm_queue_obj = GET_TM_QUEUE_OBJ(info->tm_queue);
		if (fanin_tm_queue_obj == NULL)
			return -1;

		shaper_obj = &fanin_tm_queue_obj->shaper_obj;
	} else if (info->tm_node != ODP_TM_INVALID) {
		fanin_tm_node_obj = GET_TM_NODE_OBJ(info->tm_node);
		if (fanin_tm_node_obj == NULL)
			return -1;

		shaper_obj = &fanin_tm_node_obj->shaper_obj;
	} else {
		shaper_obj = NULL;
	}

	if ((shaper_obj != NULL) && (shaper_obj->next_tm_node != tm_node_obj))
		return -1;

	if (shaper_obj == NULL)
		next_shaper_obj = tm_node_obj->fanin_list_head;
	else
		next_shaper_obj = shaper_obj->fanin_list_next;

	if ((next_shaper_obj == NULL) ||
	    (next_shaper_obj->next_tm_node != tm_node_obj))
		return -1;

	info->is_last = next_shaper_obj->fanin_list_next == NULL;
	if (next_shaper_obj->in_tm_node_obj) {
		fanin_tm_node_obj = next_shaper_obj->enclosing_entity;
		info->tm_node     = MAKE_ODP_TM_NODE(fanin_tm_node_obj);
		info->tm_queue    = ODP_TM_INVALID;
	} else {
		fanin_tm_queue_obj = next_shaper_obj->enclosing_entity;
		info->tm_queue     = MAKE_ODP_TM_QUEUE(fanin_tm_queue_obj);
		info->tm_node      = ODP_TM_INVALID;
	}

	info->sched_profile = ODP_TM_INVALID;
	sched_params        = next_shaper_obj->sched_params;
	if (sched_params != NULL)
		info->sched_profile = sched_params->sched_profile;

	return 0;
}

int odp_tm_queue_info(odp_tm_queue_t tm_queue, odp_tm_queue_info_t *info)
{
	tm_queue_thresholds_t *threshold_params;
	tm_shaper_params_t    *shaper_params;
	tm_wred_params_t      *wred_params;
	tm_shaper_obj_t       *shaper_obj;
	tm_wred_node_t        *tm_wred_node;
	tm_queue_obj_t        *tm_queue_obj;
	tm_node_obj_t         *next_tm_node;
	uint32_t               color;

	tm_queue_obj = GET_TM_QUEUE_OBJ(tm_queue);
	if (tm_queue_obj == NULL)
		return -1;

	info->shaper_profile    = ODP_TM_INVALID;
	info->threshold_profile = ODP_TM_INVALID;
	for (color = 0; color < ODP_NUM_PACKET_COLORS; color++)
		info->wred_profile[color] = ODP_TM_INVALID;

	info->active_pkt = tm_queue_obj->pkt;
	shaper_obj       = &tm_queue_obj->shaper_obj;
	next_tm_node     = shaper_obj->next_tm_node;
	if (next_tm_node == NULL)
		info->next_tm_node = ODP_TM_INVALID;
	else if (next_tm_node->is_root_node)
		info->next_tm_node = ODP_TM_ROOT;
	else
		info->next_tm_node = MAKE_ODP_TM_NODE(next_tm_node);

	shaper_params = shaper_obj->shaper_params;
	if (shaper_params != NULL)
		info->shaper_profile = shaper_params->shaper_profile;

	tm_wred_node = &tm_queue_obj->tm_wred_node;
	if (tm_wred_node != NULL) {
		threshold_params = tm_wred_node->threshold_params;
		if (threshold_params != NULL)
			info->threshold_profile =
				threshold_params->thresholds_profile;

		for (color = 0; color < ODP_NUM_PACKET_COLORS; color++) {
			wred_params = tm_wred_node->wred_params[color];
			if (wred_params != NULL)
				info->wred_profile[color] =
					wred_params->wred_profile;
		}
	}

	return 0;
}

static int tm_query_info_copy(tm_queue_info_t     *queue_info,
			      uint32_t             query_flags,
			      odp_tm_query_info_t *info)
{
	tm_queue_thresholds_t *threshold_params;

	memset(info, 0, sizeof(odp_tm_query_info_t));
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

int odp_tm_queue_query(odp_tm_queue_t       tm_queue,
		       uint32_t             query_flags,
		       odp_tm_query_info_t *info)
{
	tm_queue_info_t queue_info;
	tm_queue_obj_t *tm_queue_obj;
	tm_wred_node_t *tm_wred_node;

	tm_queue_obj = GET_TM_QUEUE_OBJ(tm_queue);
	if (!tm_queue_obj)
		return -1;

	tm_wred_node = &tm_queue_obj->tm_wred_node;

	/* **TBD** Where do we get the queue_info from. */
	queue_info.threshold_params = tm_wred_node->threshold_params;
	queue_info.queue_cnts = tm_wred_node->queue_cnts;
	return tm_query_info_copy(&queue_info, query_flags, info);
}

int odp_tm_priority_query(odp_tm_t             odp_tm,
			  uint8_t              priority,
			  uint32_t             query_flags,
			  odp_tm_query_info_t *info)
{
	tm_queue_info_t queue_info;
	tm_system_t    *tm_system;

	tm_system  = GET_TM_SYSTEM(odp_tm);
	queue_info = tm_system->priority_info[priority];
	return tm_query_info_copy(&queue_info, query_flags, info);
}

int odp_tm_total_query(odp_tm_t             odp_tm,
		       uint32_t             query_flags,
		       odp_tm_query_info_t *info)
{
	tm_queue_info_t queue_info;
	tm_system_t    *tm_system;

	tm_system  = GET_TM_SYSTEM(odp_tm);
	queue_info = tm_system->total_info;
	return tm_query_info_copy(&queue_info, query_flags, info);
}

int odp_tm_priority_threshold_config(odp_tm_t           odp_tm,
				     uint8_t            priority,
				     odp_tm_threshold_t thresholds_profile)
{
	tm_system_t *tm_system;

	tm_system = GET_TM_SYSTEM(odp_tm);
	if (thresholds_profile == ODP_TM_INVALID)
		return -1;

	odp_ticketlock_lock(&tm_glb->profile_lock);
	tm_system->priority_info[priority].threshold_params =
		tm_get_profile_params(thresholds_profile,
				      TM_THRESHOLD_PROFILE);
	odp_ticketlock_unlock(&tm_glb->profile_lock);
	return 0;
}

int odp_tm_total_threshold_config(odp_tm_t odp_tm,
				  odp_tm_threshold_t thresholds_profile)
{
	tm_system_t *tm_system;

	tm_system = GET_TM_SYSTEM(odp_tm);
	if (thresholds_profile == ODP_TM_INVALID)
		return -1;

	odp_ticketlock_lock(&tm_glb->profile_lock);
	tm_system->total_info.threshold_params = tm_get_profile_params(
		thresholds_profile, TM_THRESHOLD_PROFILE);
	odp_ticketlock_unlock(&tm_glb->profile_lock);
	return 0;
}

void odp_tm_stats_print(odp_tm_t odp_tm)
{
	input_work_queue_t *input_work_queue;
	tm_queue_obj_t *tm_queue_obj;
	tm_system_t *tm_system;
	uint32_t queue_num, max_queue_num;

	tm_system = GET_TM_SYSTEM(odp_tm);
	input_work_queue = &tm_system->input_work_queue;

	ODP_PRINT("odp_tm_stats_print - tm_system=0x%" PRIX64 " tm_idx=%u\n",
		  odp_tm, tm_system->tm_idx);
	ODP_PRINT("  input_work_queue size=%u current cnt=%u peak cnt=%u\n",
		  INPUT_WORK_RING_SIZE, input_work_queue->queue_cnt,
		  input_work_queue->peak_cnt);
	ODP_PRINT("  input_work_queue enqueues=%" PRIu64 " dequeues=% " PRIu64
		  " fail_cnt=%" PRIu64 "\n", input_work_queue->total_enqueues,
		  input_work_queue->total_dequeues,
		  input_work_queue->enqueue_fail_cnt);
	ODP_PRINT("  green_cnt=%" PRIu64 " yellow_cnt=%" PRIu64 " red_cnt=%"
		  PRIu64 "\n", tm_system->shaper_green_cnt,
		  tm_system->shaper_yellow_cnt,
		  tm_system->shaper_red_cnt);

	_odp_pkt_queue_stats_print(tm_system->_odp_int_queue_pool);
	_odp_timer_wheel_stats_print(tm_system->_odp_int_timer_wheel);
	_odp_sorted_list_stats_print(tm_system->_odp_int_sorted_pool);

	max_queue_num = tm_system->next_queue_num;
	for (queue_num = 1; queue_num < max_queue_num; queue_num++) {
		tm_queue_obj = tm_system->queue_num_tbl[queue_num - 1];
		if (tm_queue_obj && tm_queue_obj->pkts_rcvd_cnt != 0)
			ODP_PRINT("queue_num=%u priority=%u rcvd=%u enqueued=%u "
				  "dequeued=%u consumed=%u\n",
				  queue_num,
				  tm_queue_obj->priority,
				  tm_queue_obj->pkts_rcvd_cnt,
				  tm_queue_obj->pkts_enqueued_cnt,
				  tm_queue_obj->pkts_dequeued_cnt,
				  tm_queue_obj->pkts_consumed_cnt);
	}
}

int _odp_tm_init_global(void)
{
	odp_shm_t shm;

	if (odp_global_ro.init_param.not_used.feat.tm) {
		ODP_DBG("TM disabled\n");
		return 0;
	}

	shm = odp_shm_reserve("_odp_traffic_mng", sizeof(tm_global_t), 0, 0);
	if (shm == ODP_SHM_INVALID)
		return -1;

	tm_glb = odp_shm_addr(shm);
	memset(tm_glb, 0, sizeof(tm_global_t));

	tm_glb->shm = shm;
	tm_glb->main_thread_cpu = -1;

	odp_ticketlock_init(&tm_glb->queue_obj.lock);
	odp_ticketlock_init(&tm_glb->node_obj.lock);
	odp_ticketlock_init(&tm_glb->system_group.lock);
	odp_ticketlock_init(&tm_glb->create_lock);
	odp_ticketlock_init(&tm_glb->profile_lock);
	odp_ticketlock_init(&tm_glb->profile_tbl.sched.lock);
	odp_ticketlock_init(&tm_glb->profile_tbl.shaper.lock);
	odp_ticketlock_init(&tm_glb->profile_tbl.threshold.lock);
	odp_ticketlock_init(&tm_glb->profile_tbl.wred.lock);
	odp_barrier_init(&tm_glb->first_enq, 2);

	odp_atomic_init_u64(&tm_glb->atomic_request_cnt, 0);
	odp_atomic_init_u64(&tm_glb->currently_serving_cnt, 0);
	odp_atomic_init_u64(&tm_glb->atomic_done_cnt, 0);
	return 0;
}

int _odp_tm_term_global(void)
{
	if (odp_global_ro.init_param.not_used.feat.tm)
		return 0;

	if (odp_shm_free(tm_glb->shm)) {
		ODP_ERR("shm free failed\n");
		return -1;
	}
	return 0;
}
