/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2017 ARM Limited
 * Copyright (c) 2017-2018 Linaro Limited
 */

#ifndef ODP_QUEUE_SCALABLE_INTERNAL_H_
#define ODP_QUEUE_SCALABLE_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/plat/strong_types.h>
#include <odp/api/queue.h>
#include <odp_forward_typedefs_internal.h>
#include <odp_queue_if.h>
#include <odp_event_internal.h>
#include <odp/api/packet_io.h>
#include <odp/api/align.h>
#include <odp/api/hints.h>
#include <odp/api/ticketlock.h>
#include <odp_config_internal.h>
#include <odp_macros_internal.h>
#include <odp_schedule_scalable.h>
#include <odp_schedule_scalable_ordered.h>

#define QUEUE_STATUS_FREE         0
#define QUEUE_STATUS_DESTROYED    1
#define QUEUE_STATUS_READY        2

struct ODP_ALIGNED_CACHE queue_entry_s {
	sched_elem_t     sched_elem;

	odp_ticketlock_t lock ODP_ALIGNED_CACHE;
	odp_atomic_u64_t num_timers;
	int              status;

	queue_enq_fn_t       enqueue ODP_ALIGNED_CACHE;
	queue_deq_fn_t       dequeue;
	queue_enq_multi_fn_t enqueue_multi;
	queue_deq_multi_fn_t dequeue_multi;
	queue_deq_multi_fn_t orig_dequeue_multi;

	uint32_t           index;
	odp_queue_t        handle;
	odp_queue_type_t   type;
	odp_queue_param_t  param;
	odp_pktin_queue_t  pktin;
	odp_pktout_queue_t pktout;
	char               name[ODP_QUEUE_NAME_LEN];
};

int _odp_queue_deq(sched_elem_t *q, _odp_event_hdr_t *event_hdr[], int num);
int _odp_queue_deq_sc(sched_elem_t *q, odp_event_t *evp, int num);
int _odp_queue_deq_mc(sched_elem_t *q, odp_event_t *evp, int num);
int _odp_queue_enq_sp(sched_elem_t *q, _odp_event_hdr_t *event_hdr[], int num);
queue_entry_t *_odp_qentry_from_ext(odp_queue_t handle);

/* Round up memory size to next cache line size to
 * align all memory addresses on cache line boundary.
 */
static inline void *shm_pool_alloc_align(_odp_ishm_pool_t *pool, uint32_t size)
{
	void *addr;

	addr = _odp_ishm_pool_alloc(pool, _ODP_ROUNDUP_CACHE_LINE(size));
	_ODP_ASSERT(((uintptr_t)addr & (ODP_CACHE_LINE_SIZE - 1)) == 0);

	return addr;
}

static inline uint32_t queue_to_id(odp_queue_t handle)
{
	return _odp_qentry_from_ext(handle)->index;
}

static inline queue_entry_t *qentry_from_int(odp_queue_t handle)
{
	return (queue_entry_t *)(uintptr_t)handle;
}

static inline odp_queue_t qentry_to_int(queue_entry_t *qentry)
{
	return (odp_queue_t)qentry;
}

static inline odp_queue_t queue_get_handle(queue_entry_t *queue)
{
	return queue->handle;
}

static inline reorder_window_t *queue_get_rwin(queue_entry_t *queue)
{
	return queue->sched_elem.rwin;
}

#ifdef __cplusplus
}
#endif

#endif
