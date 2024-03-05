/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2015 EZchip Semiconductor Ltd.
 * Copyright (c) 2015-2018 Linaro Limited
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

#include <odp/api/barrier.h>
#include <odp/api/packet_io.h>
#include <odp/api/traffic_mngr.h>

#include <odp_name_table_internal.h>
#include <odp_timer_wheel_internal.h>
#include <odp_pkt_queue_internal.h>
#include <odp_sorted_list_internal.h>
#include <odp_debug_internal.h>
#include <odp_buffer_internal.h>
#include <odp_queue_if.h>
#include <odp_packet_internal.h>

#include <pthread.h>

typedef struct stat  file_stat_t;

#define INPUT_WORK_RING_SIZE  (16 * 1024)

#define TM_QUEUE_MAGIC_NUM   0xBABEBABE
#define TM_NODE_MAGIC_NUM    0xBEEFBEEF

/* Macros to convert handles to internal pointers and vice versa. */

#define MAKE_ODP_TM_SYSTEM_GROUP(tm_group) \
	((_odp_tm_group_t)(uintptr_t)tm_group)
#define GET_TM_GROUP(odp_tm_group) \
	((tm_system_group_t *)(uintptr_t)odp_tm_group)

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

#define LOW_DROP_PRECEDENCE      0x02
#define MEDIUM_DROP_PRECEDENCE   0x04
#define HIGH_DROP_PRECEDENCE     0x06
#define DROP_PRECEDENCE_MASK     0x06
#define DSCP_CLASS1              0x08
#define DSCP_CLASS2              0x10
#define DSCP_CLASS3              0x18
#define DSCP_CLASS4              0x20

#define PF_RM_CURRENT_BEST  0x01
#define PF_NEW_PKT_IN       0x02
#define PF_SHAPER_DELAYED   0x10
#define PF_CHANGED_OUT_PKT  0x20
#define PF_REACHED_EGRESS   0x40
#define PF_ERROR            0x80

#define ODP_TM_NUM_PROFILES  4

typedef enum {
	TM_SHAPER_PROFILE,
	TM_SCHED_PROFILE,
	TM_THRESHOLD_PROFILE,
	TM_WRED_PROFILE
} profile_kind_t;

typedef enum {
	TM_STATUS_FREE = 0,
	TM_STATUS_RESERVED
} tm_status_t;

typedef struct tm_queue_obj_s tm_queue_obj_t;
typedef struct tm_node_obj_s tm_node_obj_t;

typedef struct {
	/* A zero value for max_bytes or max_pkts indicates that this quantity
	 * is not limited, nor has a RED threshold. */
	uint64_t           max_pkts;
	uint64_t           max_bytes;
	_odp_int_name_t    name_tbl_id;
	odp_tm_threshold_t thresholds_profile;
	uint32_t           ref_cnt;
	tm_status_t        status;
} tm_queue_thresholds_t;

typedef struct {
	_odp_int_name_t  name_tbl_id;
	odp_tm_wred_t    wred_profile;
	uint32_t         ref_cnt;
	odp_tm_percent_t min_threshold;
	odp_tm_percent_t med_threshold;
	odp_tm_percent_t med_drop_prob;
	odp_tm_percent_t max_drop_prob;
	odp_bool_t       enable_wred;
	odp_bool_t       use_byte_fullness;
	tm_status_t      status;
} tm_wred_params_t;

typedef struct {
	odp_atomic_u64_t pkt_cnt;
	odp_atomic_u64_t byte_cnt;
} tm_queue_cnts_t;

typedef struct tm_wred_node_s tm_wred_node_t;

struct tm_wred_node_s {
	tm_wred_node_t        *next_tm_wred_node;
	tm_wred_params_t      *wred_params[ODP_NUM_PACKET_COLORS];
	tm_queue_thresholds_t *threshold_params;
	tm_queue_cnts_t        queue_cnts;
	odp_ticketlock_t       tm_wred_node_lock;
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
	_odp_int_name_t     name_tbl_id;
	odp_tm_sched_t      sched_profile;
	uint32_t            ref_cnt;
	odp_tm_sched_mode_t sched_modes[ODP_TM_MAX_PRIORITIES];
	uint16_t            inverted_weights[ODP_TM_MAX_PRIORITIES];
	tm_status_t         status;
} tm_sched_params_t;

typedef enum {
	DELAY_PKT, DECR_NOTHING, DECR_COMMIT, DECR_PEAK, DECR_BOTH
} tm_shaper_action_t;

typedef struct {
	uint8_t output_priority;
	tm_shaper_action_t action;
} tm_prop_t;

typedef struct {
	/* The original commit rate and peak rate are in units of bits per
	 * second.  These values are converted into the number of bytes per
	 * clock cycle using a fixed point integer format with 26 bits of
	 * fractional part, before being stored into the following fields:
	 * commit_rate and peak_rate.  So a raw uint64_t value of 2^33 stored
	 * in either of these fields would represent 2^33 >> 26 = 128 bytes
	 * per clock cycle.
	 * Similarly the original commit_burst and peak_burst parameters -
	 * which are in units of bits are converted to a byte count using a
	 * fixed point integer format with 26 bits of fractional part, */
	uint64_t        commit_rate;
	uint64_t        peak_rate;
	int64_t         max_commit;
	int64_t         max_peak;
	uint64_t        max_commit_time_delta;
	uint64_t        max_peak_time_delta;
	uint32_t        min_time_delta;
	_odp_int_name_t name_tbl_id;
	odp_tm_shaper_t shaper_profile;
	uint32_t        ref_cnt;   /* num of tm_queues, tm_nodes using this. */
	int8_t          len_adjust;
	odp_bool_t      dual_rate;
	odp_bool_t      enabled;
	tm_status_t     status;
} tm_shaper_params_t;

typedef enum { NO_CALLBACK, UNDELAY_PKT } tm_shaper_callback_reason_t;

typedef struct tm_shaper_obj_s tm_shaper_obj_t;

struct tm_shaper_obj_s {
	tm_node_obj_t *next_tm_node; /* dummy node if connected to egress. */
	void *enclosing_entity;
	tm_shaper_obj_t *fanin_list_next;
	tm_shaper_obj_t *fanin_list_prev;
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
	 * "(rate * nanosecconds) / 2**26". */
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
};

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
	tm_sched_state_t sched_states[ODP_TM_MAX_PRIORITIES];
} tm_schedulers_obj_t;

struct tm_queue_obj_s {
	void    *user_context;
	uint32_t magic_num;
	uint32_t pkts_rcvd_cnt;
	uint32_t pkts_enqueued_cnt;
	uint32_t pkts_dequeued_cnt;
	uint32_t pkts_consumed_cnt;
	_odp_int_pkt_queue_t _odp_int_pkt_queue;
	tm_wred_node_t tm_wred_node;
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
	odp_bool_t ordered_enqueue;
	tm_status_t status;
	/* Statistics for odp_tm_queue_stats_t */
	struct {
		odp_atomic_u64_t discards;
		odp_atomic_u64_t errors;
		odp_atomic_u64_t packets;
	} stats;
};

struct tm_node_obj_s {
	void                *user_context;
	tm_wred_node_t       tm_wred_node;
	tm_schedulers_obj_t  schedulers_obj;
	tm_shaper_obj_t     *fanin_list_head;
	tm_shaper_obj_t     *fanin_list_tail;
	tm_shaper_obj_t      shaper_obj;
	_odp_int_name_t      name_tbl_id;
	uint32_t             magic_num;
	uint32_t             max_fanin;
	uint32_t             current_tm_queue_fanin;
	uint32_t             current_tm_node_fanin;
	uint8_t              is_root_node;  /* Represents the egress. */
	uint8_t              level;   /* Primarily for debugging */
	uint8_t              tm_idx;
	uint8_t              marked;
	tm_status_t          status;
};

typedef struct {
	odp_packet_t pkt;
	uint32_t     queue_num;
} input_work_item_t;

typedef struct {
	uint64_t          total_enqueues;
	uint64_t          enqueue_fail_cnt;
	uint64_t          total_dequeues;
	odp_atomic_u64_t  queue_cnt;
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
	odp_bool_t marking_enabled;
	odp_bool_t drop_eligible_enabled;
} tm_vlan_marking_t;

typedef struct {
	odp_bool_t marking_enabled;
	odp_bool_t drop_prec_enabled;
	uint8_t    shifted_dscp;
	uint8_t    inverted_dscp_mask;
	odp_bool_t ecn_ce_enabled;
} tm_tos_marking_t;

typedef struct {
	tm_vlan_marking_t vlan_marking[ODP_NUM_PACKET_COLORS];
	tm_tos_marking_t  ip_tos_marking[ODP_NUM_PACKET_COLORS];
} tm_marking_t;

typedef struct tm_system_s       tm_system_t;
typedef struct tm_system_group_s tm_system_group_t;
typedef        uint64_t          _odp_tm_group_t;

struct tm_system_s {
	/* The previous and next tm_system in the same tm_system_group. These
	 * links form a circle and so to round robin amongst the tm_system's
	 * one just needs to continue to follow next. In the case where the
	 * tm_system_group only has one tm_system, the prev and next point to
	 * this single tm_system. */
	tm_system_t    *prev;
	tm_system_t    *next;
	_odp_tm_group_t odp_tm_group;

	odp_ticketlock_t tm_system_lock;
	odp_barrier_t    tm_system_destroy_barrier;
	odp_atomic_u64_t destroying;
	_odp_int_name_t  name_tbl_id;

	void               *trace_buffer;
	tm_queue_obj_t     *queue_num_tbl[ODP_TM_MAX_TM_QUEUES];
	input_work_queue_t  input_work_queue;
	tm_queue_cnts_t     priority_queue_cnts;
	tm_queue_cnts_t     total_queue_cnts;
	pkt_desc_t          egress_pkt_desc;

	_odp_int_queue_pool_t  _odp_int_queue_pool;
	_odp_timer_wheel_t     _odp_int_timer_wheel;
	_odp_int_sorted_pool_t _odp_int_sorted_pool;

	tm_node_obj_t         root_node;
	odp_tm_egress_t       egress;
	odp_tm_requirements_t requirements;
	odp_tm_capabilities_t capabilities;

	odp_bool_t   marking_enabled;
	tm_marking_t marking;

	tm_queue_info_t total_info;
	tm_queue_info_t priority_info[ODP_TM_MAX_PRIORITIES];

	tm_random_data_t tm_random_data;
	odp_pktout_queue_t pktout;
	uint64_t   current_time;
	uint8_t    tm_idx;
	uint8_t    first_enq;
	odp_atomic_u32_t is_idle;
	tm_status_t status;

	uint64_t shaper_green_cnt;
	uint64_t shaper_yellow_cnt;
	uint64_t shaper_red_cnt;
};

/* A tm_system_group is a set of 1 to N tm_systems that share some processing
 * resources - like a bunch of service threads, input queue, timers, etc.
 * Currently a tm_system_group only supports a single service thread - and
 * while the input work queue is shared - timers are not. */

struct tm_system_group_s {
	odp_barrier_t  tm_group_barrier;
	tm_system_t   *first_tm_system;
	uint32_t       num_tm_systems;
	uint32_t       first_enq;
	pthread_t      thread;
	pthread_attr_t attr;
	tm_status_t    status;
};

#ifdef __cplusplus
}
#endif

#endif
