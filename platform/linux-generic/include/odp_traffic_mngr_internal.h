/* Copyright 2015 EZchip Semiconductor Ltd. All Rights Reserved.
 *
 * Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/**
 * @file
 *
 * ODP Traffic Manager - implementation internal
 */

#ifndef ODP_TRAFFIC_MNGR_INTERNAL_H_
#define ODP_TRAFFIC_MNGR_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/traffic_mngr.h>
#include <odp/api/packet_io.h>
#include <odp_name_table_internal.h>
#include <odp_timer_wheel_internal.h>
#include <odp_pkt_queue_internal.h>
#include <odp_sorted_list_internal.h>
#include <odp_internal.h>
#include <odp_debug_internal.h>
#include <odp_buffer_internal.h>
#include <odp_queue_internal.h>
#include <odp_packet_internal.h>

typedef struct stat  file_stat_t;

#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#define MIN(a, b) (((a) < (b)) ? (a) : (b))

#define INPUT_WORK_RING_SIZE  (16 * 1024)

#define INVALID_PKT  0

#define TM_QUEUE_MAGIC_NUM   0xBABEBABE
#define TM_NODE_MAGIC_NUM    0xBEEFBEEF

/* Macros to convert handles to internal pointers and vice versa. */

#define MAKE_ODP_TM_HANDLE(tm_system)  ((odp_tm_t)(uintptr_t)tm_system)
#define GET_TM_SYSTEM(odp_tm)          ((tm_system_t *)(uintptr_t)odp_tm)

#define MAKE_PROFILE_HANDLE(profile_kind, tbl_idx) \
	(((profile_kind & 0xF) << 28) | ((tbl_idx + 1) & 0xFFFFFFF))

#define GET_PROFILE_KIND(profile_handle)  \
	((profile_kind_t)((profile_handle >> 28) & 0xF))

#define GET_TBL_IDX(profile_handle)  ((profile_handle & 0xFFFFFFF) - 1)

#define MAKE_ODP_TM_NODE(tm_node_obj) ((odp_tm_node_t)(uintptr_t)(tm_node_obj))
#define GET_TM_NODE_OBJ(odp_tm_node) \
	((tm_node_obj_t *)(uintptr_t)(odp_tm_node))

#define MAKE_ODP_TM_QUEUE(tm_queue_obj) \
	((odp_tm_queue_t)(uintptr_t)(tm_queue_obj))
#define GET_TM_QUEUE_OBJ(odp_tm_queue) \
	((tm_queue_obj_t *)(uintptr_t)(odp_tm_queue))

typedef uint64_t tm_handle_t;

#define PF_RM_CURRENT_BEST  0x01
#define PF_NEW_PKT_IN       0x02
#define PF_SHAPER_DELAYED   0x10
#define PF_CHANGED_OUT_PKT  0x20
#define PF_REACHED_EGRESS   0x40
#define PF_ERROR            0x80

typedef struct {
	uint32_t num_allocd;
	uint32_t num_used;
	void **array_ptrs; /* Ptr to an array of num_allocd void * ptrs. */
} dynamic_tbl_t;

#define ODP_TM_NUM_PROFILES  4

typedef enum {
	TM_SHAPER_PROFILE,
	TM_SCHED_PROFILE,
	TM_THRESHOLD_PROFILE,
	TM_WRED_PROFILE
} profile_kind_t;

typedef struct tm_queue_obj_s tm_queue_obj_t;
typedef struct tm_node_obj_s tm_node_obj_t;

typedef struct {
       /* A zero value for max_bytes or max_pkts indicates that this quantity
	* is not limited, nor has a RED threshold.
	*/
	uint64_t max_pkts;
	uint64_t max_bytes;
	_odp_int_name_t name_tbl_id;
} tm_queue_thresholds_t;

typedef struct {
	odp_atomic_u64_t pkt_cnt;
	odp_atomic_u64_t byte_cnt;
} tm_queue_cnts_t;

typedef struct tm_wred_node_s tm_wred_node_t;

struct tm_wred_node_s {
	tm_wred_node_t *next_tm_wred_node;
	odp_tm_wred_params_t *wred_params[ODP_NUM_PACKET_COLORS];
	tm_queue_thresholds_t *threshold_params;
	tm_queue_cnts_t queue_cnts;
	odp_ticketlock_t tm_wred_node_lock;
};

typedef struct { /* 64-bits long. */
	union {
		uint64_t word;
		struct {
			uint32_t queue_num;
			uint16_t pkt_len;
			int8_t shaper_len_adjust;
			uint8_t drop_eligible :1;
			uint8_t pkt_color :2;
			uint8_t unused:1;
			uint8_t epoch :4;
		};
	};
} pkt_desc_t;

typedef struct {
	odp_tm_sched_mode_t sched_modes[ODP_TM_MAX_PRIORITIES];
	uint16_t inverted_weights[ODP_TM_MAX_PRIORITIES];
	_odp_int_name_t name_tbl_id;
} tm_sched_params_t;

typedef enum {
	DELAY_PKT, DECR_NOTHING, DECR_COMMIT, DECR_PEAK, DECR_BOTH
} tm_shaper_action_t;

typedef struct {
	uint8_t output_priority;
	tm_shaper_action_t action;
} tm_prop_t;

typedef struct {
	uint64_t commit_rate; /* Bytes per clk cycle as a 26 bit fp integer */
	uint64_t peak_rate;   /* Same as commit_rate */
	int64_t max_commit;   /* Byte cnt as a fp integer with 26 bits. */
	int64_t max_peak;     /* Same as max_commit */
	uint64_t max_commit_time_delta;
	uint64_t max_peak_time_delta;
	uint32_t min_time_delta;
	_odp_int_name_t name_tbl_id;
	int8_t len_adjust;
	odp_bool_t dual_rate;
	odp_bool_t enabled;
} tm_shaper_params_t;

typedef enum { NO_CALLBACK, UNDELAY_PKT } tm_shaper_callback_reason_t;

typedef struct {
	tm_node_obj_t *next_tm_node; /* NULL if connected to egress. */
	void *enclosing_entity;
	tm_shaper_params_t *shaper_params;
	tm_sched_params_t *sched_params;

	uint64_t last_update_time;
	uint64_t callback_time;

       /* The shaper token bucket counters are represented as a number of
	* bytes in a 64-bit fixed point format where the decimal point is at
	* bit 26.  (aka int64_26).  In other words, the number of bytes that
	* commit_cnt represents is "commit_cnt / 2**26".  The commit_rate and
	* peak_rate are in units of bytes per nanoseccond, again using a 26-bit
	* fixed point integer.  Alternatively, ignoring the fixed point,
	* the number of bytes that x nanosecconds represents is equal to
	* "(rate * nanosecconds) / 2**26".
	*/
	int64_t commit_cnt; /* Note token counters can go slightly negative */
	int64_t peak_cnt; /* Note token counters can go slightly negative */

	uint64_t virtual_finish_time;
	pkt_desc_t in_pkt_desc;
	pkt_desc_t out_pkt_desc;
	tm_queue_obj_t *timer_tm_queue;
	uint8_t callback_reason;
	tm_prop_t propagation_result;
	uint8_t input_priority;
	uint8_t out_priority;
	uint8_t valid_finish_time;
	uint8_t timer_outstanding;
	uint8_t in_tm_node_obj;
	uint8_t initialized;
} tm_shaper_obj_t;

typedef struct {
	/* Note that the priority is implicit. */
	pkt_desc_t smallest_pkt_desc;
	uint64_t base_virtual_time;
	uint64_t smallest_finish_time;
	_odp_int_sorted_list_t sorted_list;
	uint32_t sorted_list_cnt; /* Debugging use only. */
} tm_sched_state_t;

typedef struct {
	void *enclosing_entity;
	pkt_desc_t out_pkt_desc; /* highest priority pkt desc. */
	uint32_t priority_bit_mask; /* bit set if priority has pkt. */
	uint8_t num_priorities;
	uint8_t highest_priority;
	uint8_t locked;
	tm_sched_state_t sched_states[0];
} tm_schedulers_obj_t;

struct tm_queue_obj_s {
	uint32_t magic_num;
	uint32_t pkts_rcvd_cnt;
	uint32_t pkts_enqueued_cnt;
	uint32_t pkts_dequeued_cnt;
	uint32_t pkts_consumed_cnt;
	_odp_int_pkt_queue_t _odp_int_pkt_queue;
	tm_wred_node_t *tm_wred_node;
	odp_packet_t pkt;
	odp_packet_t sent_pkt;
	uint32_t timer_seq;
	uint8_t timer_reason;
	uint8_t timer_cancels_outstanding;
	tm_shaper_obj_t *timer_shaper;
	tm_schedulers_obj_t *blocked_scheduler;
	pkt_desc_t in_pkt_desc;
	pkt_desc_t sent_pkt_desc;
	tm_shaper_obj_t shaper_obj;
	uint32_t queue_num;
	uint16_t epoch;
	uint8_t priority;
	uint8_t blocked_priority;
	uint8_t tm_idx;
	uint8_t delayed_cnt;
	uint8_t blocked_cnt;
	queue_entry_t tm_qentry;
};

struct tm_node_obj_s {
	uint32_t             magic_num;
	tm_wred_node_t      *tm_wred_node;
	tm_shaper_obj_t      shaper_obj;
	tm_schedulers_obj_t *schedulers_obj;
	_odp_int_name_t      name_tbl_id;
	uint32_t             max_fanin;
	uint8_t              level; /* Primarily for debugging */
	uint8_t              tm_idx;
	uint8_t              marked;
};

typedef struct {
	tm_queue_obj_t *tm_queue_obj;
	odp_packet_t    pkt;
} input_work_item_t;

typedef struct {
	uint64_t          total_enqueues;
	uint64_t          enqueue_fail_cnt;
	uint64_t          total_dequeues;
	odp_atomic_u32_t  queue_cnt;
	uint32_t          peak_cnt;
	uint32_t          head_idx;
	uint32_t          tail_idx;
	odp_ticketlock_t  lock;
	input_work_item_t work_ring[INPUT_WORK_RING_SIZE];
} input_work_queue_t;

typedef struct {
	uint32_t next_random_byte;
	uint8_t  buf[256];
} tm_random_data_t;

typedef struct {
	tm_queue_thresholds_t *threshold_params;
	tm_queue_cnts_t        queue_cnts;
} tm_queue_info_t;

typedef struct {
	odp_ticketlock_t tm_system_lock;
	odp_barrier_t    tm_system_barrier;
	odp_barrier_t    tm_system_destroy_barrier;
	odp_atomic_u32_t destroying;
	_odp_int_name_t  name_tbl_id;

	void               *trace_buffer;
	uint32_t            next_queue_num;
	tm_queue_obj_t    **queue_num_tbl;
	input_work_queue_t *input_work_queue;
	tm_queue_cnts_t     priority_queue_cnts;
	tm_queue_cnts_t     total_queue_cnts;
	pkt_desc_t          egress_pkt_desc;

	_odp_int_queue_pool_t  _odp_int_queue_pool;
	_odp_timer_wheel_t     _odp_int_timer_wheel;
	_odp_int_sorted_pool_t _odp_int_sorted_pool;

	odp_tm_egress_t     egress;
	odp_tm_capability_t capability;

	tm_queue_info_t total_info;
	tm_queue_info_t priority_info[ODP_TM_MAX_PRIORITIES];

	tm_random_data_t tm_random_data;

	uint64_t   current_time;
	uint8_t    tm_idx;
	uint8_t    first_enq;
	odp_bool_t is_idle;

	uint64_t shaper_green_cnt;
	uint64_t shaper_yellow_cnt;
	uint64_t shaper_red_cnt;
} tm_system_t;

#ifdef __cplusplus
}
#endif

#endif
