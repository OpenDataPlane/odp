/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP queue - implementation internal
 */

#ifndef ODP_QUEUE_INTERNAL_H_
#define ODP_QUEUE_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

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

#define QUEUE_STATUS_FREE         0
#define QUEUE_STATUS_DESTROYED    1
#define QUEUE_STATUS_READY        2
#define QUEUE_STATUS_NOTSCHED     3
#define QUEUE_STATUS_SCHED        4

struct queue_entry_s {
	odp_ticketlock_t  lock ODP_ALIGNED_CACHE;

	odp_buffer_hdr_t *head;
	odp_buffer_hdr_t *tail;
	int               status;

	struct {
		odp_atomic_u64_t  ctx; /**< Current ordered context id */
		odp_atomic_u64_t  next_ctx; /**< Next unallocated context id */
		/** Array of ordered locks */
		odp_atomic_u64_t  lock[CONFIG_QUEUE_MAX_ORD_LOCKS];
	} ordered ODP_ALIGNED_CACHE;

	queue_enq_fn_t       enqueue ODP_ALIGNED_CACHE;
	queue_deq_fn_t       dequeue;
	queue_enq_multi_fn_t enqueue_multi;
	queue_deq_multi_fn_t dequeue_multi;

	uint32_t          index;
	odp_queue_t       handle;
	odp_queue_type_t  type;
	odp_queue_param_t param;
	odp_pktin_queue_t pktin;
	odp_pktout_queue_t pktout;
	char              name[ODP_QUEUE_NAME_LEN];
};

union queue_entry_u {
	struct queue_entry_s s;
	uint8_t pad[ROUNDUP_CACHE_LINE(sizeof(struct queue_entry_s))];
};

queue_entry_t *get_qentry(uint32_t queue_id);

void queue_lock(queue_entry_t *queue);
void queue_unlock(queue_entry_t *queue);

static inline uint32_t queue_to_id(odp_queue_t handle)
{
	return _odp_typeval(handle) - 1;
}

static inline queue_entry_t *qentry_from_int(queue_t handle)
{
	return (queue_entry_t *)(void *)(handle);
}

static inline queue_t qentry_to_int(queue_entry_t *qentry)
{
	return (queue_t)(qentry);
}

#ifdef __cplusplus
}
#endif

#endif
