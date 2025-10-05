/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2013-2018 Linaro Limited
 * Copyright (c) 2023-2025 Nokia
 */

#ifndef ODP_QUEUE_BASIC_INTERNAL_H_
#define ODP_QUEUE_BASIC_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/plat/strong_types.h>
#include <odp/api/queue.h>
#include <odp/api/shared_memory.h>
#include <odp_forward_typedefs_internal.h>
#include <odp_queue_if.h>
#include <odp_buffer_internal.h>
#include <odp/api/packet_io.h>
#include <odp/api/align.h>
#include <odp/api/hints.h>
#include <odp/api/ticketlock.h>
#include <odp_config_internal.h>
#include <odp_debug_internal.h>
#include <odp_macros_internal.h>
#include <odp_ring_mpmc_ptr_internal.h>
#include <odp_ring_st_ptr_internal.h>
#include <odp_ring_spsc_ptr_internal.h>
#include <odp_queue_lf.h>

#define QUEUE_STATUS_FREE         0
#define QUEUE_STATUS_DESTROYED    1
#define QUEUE_STATUS_READY        2
#define QUEUE_STATUS_NOTSCHED     3
#define QUEUE_STATUS_SCHED        4

typedef struct ODP_ALIGNED_CACHE event_aggr_s {
	odp_queue_t base_queue;
	odp_pool_t pool;
	uint32_t max_size;
	odp_event_type_t event_type;

	odp_ticketlock_t lock;
	odp_event_t event_tbl[CONFIG_EVENT_VECTOR_MAX_SIZE];
	uint16_t num_events;

} event_aggr_t;

typedef struct ODP_ALIGNED_CACHE queue_entry_s {
	/* The first cache line is read only */
	queue_enq_fn_t       enqueue ODP_ALIGNED_CACHE;
	queue_deq_fn_t       dequeue;
	queue_enq_multi_fn_t enqueue_multi;
	queue_deq_multi_fn_t dequeue_multi;
	uintptr_t           *ring_data;
	uint32_t             ring_mask;
	uint32_t             index;
	odp_queue_t          handle;
	odp_queue_type_t     type;

	/* MPMC ring (2 cache lines). */
	ring_mpmc_ptr_t      ring_mpmc;

	odp_ticketlock_t     lock;
	union {
		ring_st_ptr_t   ring_st;
		ring_spsc_ptr_t ring_spsc;
	};

	odp_atomic_u64_t     num_timers;
	int                  status;

	event_aggr_t         aggr;       /* Aggregator queue specific fields */
	queue_entry_t       *aggr_queue; /* Links base queue to aggregator queue */

	queue_deq_multi_fn_t orig_dequeue_multi;
	odp_queue_param_t param;
	odp_pktin_queue_t pktin;
	odp_pktout_queue_t pktout;
	void             *queue_lf;
	int               spsc;
	char              name[ODP_QUEUE_NAME_LEN];
} queue_entry_t;

typedef struct queue_global_t {
	queue_entry_t   queue[CONFIG_MAX_QUEUES];
	queue_entry_t   aggr_queue[CONFIG_MAX_EVENT_AGGR];
	uintptr_t      *ring_data;
	uint32_t        queue_lf_num;
	uint32_t        queue_lf_size;
	queue_lf_func_t queue_lf_func;
	odp_shm_t       queue_gbl_shm;
	odp_shm_t       queue_ring_shm;

	struct {
		uint32_t max_queue_size;
		uint32_t default_queue_size;
	} config;

} queue_global_t;

extern queue_global_t *_odp_queue_glb;

static inline uint32_t queue_to_index(odp_queue_t handle)
{
	queue_entry_t *qentry = (queue_entry_t *)(uintptr_t)handle;

	return qentry->index;
}

static inline queue_entry_t *qentry_from_index(uint32_t queue_id)
{
	return &_odp_queue_glb->queue[queue_id];
}

static inline odp_queue_t queue_from_index(uint32_t queue_id)
{
	return (odp_queue_t)qentry_from_index(queue_id);
}

static inline queue_entry_t *qentry_from_handle(odp_queue_t handle)
{
	return (queue_entry_t *)(uintptr_t)handle;
}

void _odp_queue_spsc_init(queue_entry_t *queue, uint32_t queue_size);
void _odp_queue_spsc_event_aggr_init(queue_entry_t *aggr_queue);

/* Functions for schedulers */
void _odp_sched_queue_set_status(uint32_t queue_index, int status);
int _odp_sched_queue_deq(uint32_t queue_index, odp_event_t ev[], int num,
			 int update_status);
int _odp_sched_queue_empty(uint32_t queue_index);

/* Functions by schedulers */
int _odp_sched_basic_get_spread(uint32_t queue_index);

/* Functions for pktio and classifier */
odp_event_vector_t _odp_event_vector_create(odp_queue_t aggr_handle, odp_packet_t pkt_tbl[],
					    uint32_t num);

static inline odp_queue_t _odp_event_aggr_base_queue(odp_queue_t aggr_handle)
{
	queue_entry_t *aggr_queue = qentry_from_handle(aggr_handle);

	_ODP_ASSERT(aggr_queue->type == ODP_QUEUE_TYPE_AGGR);

	return aggr_queue->aggr.base_queue;
}

static inline uint32_t _odp_event_aggr_max_size(odp_queue_t aggr_handle)
{
	queue_entry_t *aggr_queue = qentry_from_handle(aggr_handle);

	_ODP_ASSERT(aggr_queue->type == ODP_QUEUE_TYPE_AGGR);

	return aggr_queue->aggr.max_size;
}

/* Functions for SPSC queue */
int _odp_event_aggr_enq(queue_entry_t *aggr_queue, _odp_event_hdr_t *event_hdr[], uint32_t num);

#ifdef __cplusplus
}
#endif

#endif
