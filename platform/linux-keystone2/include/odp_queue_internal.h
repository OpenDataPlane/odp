/*
 * Copyright (c) 2014, Linaro Limited
 * Copyright (c) 2014, Texas Instruments Incorporated
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

#include <odp_queue.h>
#include <odp_buffer_internal.h>
#include <odp_packet_io.h>
#include <odp_packet_io_internal.h>
#include <odp_align.h>


#define USE_TICKETLOCK

#ifdef USE_TICKETLOCK
#include <odp_ticketlock.h>
#else
#include <odp_spinlock.h>
#endif

#define QUEUE_MULTI_MAX 8

#define QUEUE_STATUS_FREE     0
#define QUEUE_STATUS_READY    1
#define QUEUE_STATUS_NOTSCHED 2
#define QUEUE_STATUS_SCHED    3

/* forward declaration */
union queue_entry_u;

typedef int (*enq_func_t)(union queue_entry_u *, odp_buffer_t);
typedef	odp_buffer_t (*deq_func_t)(union queue_entry_u *);

typedef int (*enq_multi_func_t)(union queue_entry_u *, odp_buffer_t *, int);
typedef	int (*deq_multi_func_t)(union queue_entry_u *, odp_buffer_t *, int);

struct queue_entry_s {
#ifdef USE_TICKETLOCK
	odp_ticketlock_t  lock ODP_ALIGNED_CACHE;
#else
	odp_spinlock_t    lock ODP_ALIGNED_CACHE;
#endif

	int               status;

	enq_func_t        enqueue ODP_ALIGNED_CACHE;
	deq_func_t        dequeue;
	enq_multi_func_t  enqueue_multi;
	deq_multi_func_t  dequeue_multi;

	odp_queue_t       handle;
	odp_buffer_t      sched_buf;
	odp_queue_type_t  type;
	odp_queue_param_t param;
	odp_pktio_t       pktin;
	pktio_entry_t    *pktout_entry;
	Qmss_QueueHnd     qmss_queue;
	char              name[ODP_QUEUE_NAME_LEN];
};

typedef union queue_entry_u {
	struct queue_entry_s s;
	uint8_t pad[ODP_CACHE_LINE_SIZE_ROUNDUP(sizeof(struct queue_entry_s))];
} queue_entry_t;


queue_entry_t *get_qentry(uint32_t queue_id);

int queue_enq(queue_entry_t *queue, odp_buffer_t buf);
odp_buffer_t queue_deq(queue_entry_t *queue);

int queue_enq_multi(queue_entry_t *queue, odp_buffer_t buf[], int num);
int queue_deq_multi(queue_entry_t *queue, odp_buffer_t buf[], int num);

void queue_lock(queue_entry_t *queue);
void queue_unlock(queue_entry_t *queue);

odp_buffer_t queue_sched_buf(odp_queue_t queue);
int queue_sched_atomic(odp_queue_t handle);

static inline uint32_t queue_to_id(odp_queue_t handle)
{
	return handle - 1;
}

static inline odp_queue_t queue_from_id(uint32_t queue_id)
{
	return queue_id + 1;
}

static inline queue_entry_t *queue_to_qentry(odp_queue_t handle)
{
	uint32_t queue_id;

	queue_id = queue_to_id(handle);
	return get_qentry(queue_id);
}

static inline const char *odp_queue_name(odp_queue_t handle)
{
	return queue_to_qentry(handle)->s.name;
}


static inline Qmss_QueueHnd _odp_queue_to_qmss_queue(odp_queue_t queue)
{
	queue_entry_t *entry = queue_to_qentry(queue);
	return entry->s.qmss_queue;
}

odp_queue_t _odp_queue_create(const char *name, odp_queue_type_t type,
			     odp_queue_param_t *param, int32_t hw_queue);

#ifdef __cplusplus
}
#endif

#endif
