/* Copyright (c) 2017, ARM Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_QUEUE_IF_H_
#define ODP_QUEUE_IF_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/queue.h>
#include <odp/api/schedule.h>
#include <odp/api/packet_io.h>
#include <odp_forward_typedefs_internal.h>

#define QUEUE_MULTI_MAX CONFIG_BURST_SIZE

/* Queue API functions */
typedef struct {
	odp_queue_t (*queue_create)(const char *name,
				    const odp_queue_param_t *param);
	int (*queue_destroy)(odp_queue_t queue);
	odp_queue_t (*queue_lookup)(const char *name);
	int (*queue_capability)(odp_queue_capability_t *capa);
	int (*queue_context_set)(odp_queue_t queue, void *context,
				 uint32_t len);
	void *(*queue_context)(odp_queue_t queue);
	int (*queue_enq)(odp_queue_t queue, odp_event_t ev);
	int (*queue_enq_multi)(odp_queue_t queue, const odp_event_t events[],
			       int num);
	odp_event_t (*queue_deq)(odp_queue_t queue);
	int (*queue_deq_multi)(odp_queue_t queue, odp_event_t events[],
			       int num);
	odp_queue_type_t (*queue_type)(odp_queue_t queue);
	odp_schedule_sync_t (*queue_sched_type)(odp_queue_t queue);
	odp_schedule_prio_t (*queue_sched_prio)(odp_queue_t queue);
	odp_schedule_group_t (*queue_sched_group)(odp_queue_t queue);
	int (*queue_lock_count)(odp_queue_t queue);
	uint64_t (*queue_to_u64)(odp_queue_t hdl);
	void (*queue_param_init)(odp_queue_param_t *param);
	int (*queue_info)(odp_queue_t queue, odp_queue_info_t *info);
} queue_api_t;

/* Internal abstract queue handle */
typedef struct { char dummy; } _queue_t;
typedef _queue_t *queue_t;

typedef int (*queue_init_global_fn_t)(void);
typedef int (*queue_term_global_fn_t)(void);
typedef int (*queue_init_local_fn_t)(void);
typedef int (*queue_term_local_fn_t)(void);
typedef queue_t (*queue_from_ext_fn_t)(odp_queue_t handle);
typedef odp_queue_t (*queue_to_ext_fn_t)(queue_t handle);
typedef int (*queue_enq_fn_t)(queue_t handle, odp_buffer_hdr_t *);
typedef int (*queue_enq_multi_fn_t)(queue_t handle, odp_buffer_hdr_t **, int);
typedef odp_buffer_hdr_t *(*queue_deq_fn_t)(queue_t handle);
typedef int (*queue_deq_multi_fn_t)(queue_t handle, odp_buffer_hdr_t **, int);
typedef odp_pktout_queue_t (*queue_get_pktout_fn_t)(queue_t handle);
typedef void (*queue_set_pktout_fn_t)(queue_t handle, odp_pktio_t pktio,
				      int index);
typedef odp_pktin_queue_t (*queue_get_pktin_fn_t)(queue_t handle);
typedef void (*queue_set_pktin_fn_t)(queue_t handle, odp_pktio_t pktio,
				     int index);
typedef void (*queue_set_enq_fn_t)(queue_t handle, queue_enq_fn_t func);
typedef void (*queue_set_enq_multi_fn_t)(queue_t handle,
					 queue_enq_multi_fn_t func);
typedef void (*queue_set_deq_fn_t)(queue_t handle, queue_deq_fn_t func);
typedef void (*queue_set_deq_multi_fn_t)(queue_t handle,
					 queue_deq_multi_fn_t func);
typedef void (*queue_set_type_fn_t)(queue_t handle, odp_queue_type_t type);

/* Queue functions towards other internal components */
typedef struct {
	queue_init_global_fn_t init_global;
	queue_term_global_fn_t term_global;
	queue_init_local_fn_t init_local;
	queue_term_local_fn_t term_local;
	queue_from_ext_fn_t from_ext;
	queue_to_ext_fn_t to_ext;
	queue_enq_fn_t enq;
	queue_enq_multi_fn_t enq_multi;
	queue_deq_fn_t deq;
	queue_deq_multi_fn_t deq_multi;
	queue_get_pktout_fn_t get_pktout;
	queue_set_pktout_fn_t set_pktout;
	queue_get_pktin_fn_t get_pktin;
	queue_set_pktin_fn_t set_pktin;
	queue_set_enq_fn_t set_enq_fn;
	queue_set_enq_multi_fn_t set_enq_multi_fn;
	queue_set_deq_fn_t set_deq_fn;
	queue_set_deq_multi_fn_t set_deq_multi_fn;
	queue_set_type_fn_t set_type;
} queue_fn_t;

extern const queue_fn_t *queue_fn;

#ifdef __cplusplus
}
#endif

#endif
