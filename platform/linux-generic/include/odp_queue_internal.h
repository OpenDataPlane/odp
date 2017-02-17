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
#include <odp_schedule_if.h>
#include <odp_buffer_internal.h>
#include <odp_align_internal.h>
#include <odp/api/packet_io.h>
#include <odp/api/align.h>
#include <odp/api/hints.h>
#include <odp/api/ticketlock.h>
#include <odp_config_internal.h>

#define QUEUE_MULTI_MAX CONFIG_BURST_SIZE

#define QUEUE_STATUS_FREE         0
#define QUEUE_STATUS_DESTROYED    1
#define QUEUE_STATUS_READY        2
#define QUEUE_STATUS_NOTSCHED     3
#define QUEUE_STATUS_SCHED        4


/* forward declaration */
union queue_entry_u;

typedef int (*enq_func_t)(union queue_entry_u *, odp_buffer_hdr_t *);
typedef	odp_buffer_hdr_t *(*deq_func_t)(union queue_entry_u *);

typedef int (*enq_multi_func_t)(union queue_entry_u *,
				odp_buffer_hdr_t **, int);
typedef	int (*deq_multi_func_t)(union queue_entry_u *,
				odp_buffer_hdr_t **, int);

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

	enq_func_t       enqueue ODP_ALIGNED_CACHE;
	deq_func_t       dequeue;
	enq_multi_func_t enqueue_multi;
	deq_multi_func_t dequeue_multi;

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
	uint8_t pad[ODP_CACHE_LINE_SIZE_ROUNDUP(sizeof(struct queue_entry_s))];
};


queue_entry_t *get_qentry(uint32_t queue_id);

int queue_enq(queue_entry_t *queue, odp_buffer_hdr_t *buf_hdr);
odp_buffer_hdr_t *queue_deq(queue_entry_t *queue);

int queue_enq_multi(queue_entry_t *queue, odp_buffer_hdr_t *buf_hdr[], int num);
int queue_deq_multi(queue_entry_t *queue, odp_buffer_hdr_t *buf_hdr[], int num);

void queue_lock(queue_entry_t *queue);
void queue_unlock(queue_entry_t *queue);

static inline uint32_t queue_to_id(odp_queue_t handle)
{
	return _odp_typeval(handle) - 1;
}

static inline queue_entry_t *queue_to_qentry(odp_queue_t handle)
{
	uint32_t queue_id;

	queue_id = queue_to_id(handle);
	return get_qentry(queue_id);
}

#ifdef __cplusplus
}
#endif

#endif
