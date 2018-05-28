/* Copyright (c) 2017, ARM Limited. All rights reserved.
 *
 * Copyright (c) 2017-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
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
#include <odp_buffer_internal.h>
#include <odp_align_internal.h>
#include <odp/api/packet_io.h>
#include <odp/api/align.h>
#include <odp/api/hints.h>
#include <odp/api/ticketlock.h>
#include <odp_config_internal.h>
#include <odp_schedule_scalable.h>
#include <odp_schedule_scalable_ordered.h>

#define QUEUE_STATUS_FREE         0
#define QUEUE_STATUS_DESTROYED    1
#define QUEUE_STATUS_READY        2

struct queue_entry_s {
	sched_elem_t     sched_elem;

	odp_ticketlock_t ODP_ALIGNED_CACHE lock;
	int              status;

	queue_enq_fn_t       ODP_ALIGNED_CACHE enqueue;
	queue_deq_fn_t       dequeue;
	queue_enq_multi_fn_t enqueue_multi;
	queue_deq_multi_fn_t dequeue_multi;

	uint32_t           index;
	odp_queue_t        handle;
	odp_queue_type_t   type;
	odp_queue_param_t  param;
	odp_pktin_queue_t  pktin;
	odp_pktout_queue_t pktout;
	char               name[ODP_QUEUE_NAME_LEN];
};

union queue_entry_u {
	struct queue_entry_s s;
	uint8_t pad[ROUNDUP_CACHE_LINE(sizeof(struct queue_entry_s))];
};

int _odp_queue_deq(sched_elem_t *q, odp_buffer_hdr_t *buf_hdr[], int num);
int _odp_queue_deq_sc(sched_elem_t *q, odp_event_t *evp, int num);
int _odp_queue_deq_mc(sched_elem_t *q, odp_event_t *evp, int num);
int _odp_queue_enq_sp(sched_elem_t *q, odp_buffer_hdr_t *buf_hdr[], int num);
queue_entry_t *qentry_from_ext(odp_queue_t handle);

/* Round up memory size to next cache line size to
 * align all memory addresses on cache line boundary.
 */
static inline void *shm_pool_alloc_align(_odp_ishm_pool_t *pool, uint32_t size)
{
	void *addr;

	addr = _odp_ishm_pool_alloc(pool, ROUNDUP_CACHE_LINE(size));
	ODP_ASSERT(((uintptr_t)addr & (ODP_CACHE_LINE_SIZE - 1)) == 0);

	return addr;
}

static inline uint32_t queue_to_id(odp_queue_t handle)
{
	return _odp_typeval(handle) - 1;
}

static inline queue_entry_t *qentry_from_int(void *handle)
{
	return (queue_entry_t *)handle;
}

static inline void *qentry_to_int(queue_entry_t *qentry)
{
	return qentry;
}

static inline odp_queue_t queue_get_handle(queue_entry_t *queue)
{
	return queue->s.handle;
}

static inline reorder_window_t *queue_get_rwin(queue_entry_t *queue)
{
	return queue->s.sched_elem.rwin;
}

#ifdef __cplusplus
}
#endif

#endif
