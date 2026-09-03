/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2026 Nokia
 */

#ifndef ODP_PENDING_QUEUE_INTERNAL_H_
#define ODP_PENDING_QUEUE_INTERNAL_H_

#include <odp/api/atomic.h>
#include <odp/api/event.h>
#include <odp/api/queue.h>
#include <odp/api/spinlock.h>

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*odp_pending_free_fn_t)(odp_event_t event);

typedef struct {
	odp_event_t event;
	odp_queue_t queue;
} odp_pending_event_t;

/*
 * FIFO of events that could not be enqueued to their destination
 * queue because it was full.
 */
typedef struct {
	odp_spinlock_t lock;
	odp_atomic_u32_t num;		/* Number of pending events */
	uint32_t head;			/* Ring index of the first event */
	uint32_t size;			/* Ring size */
	odp_pending_event_t *ring;	/* Ring buffer of pending events */
	odp_pending_free_fn_t free_fn;	/* Cleanup callback or NULL */
} odp_pending_queue_t;

uint32_t _odp_pending_queue_mem_size(uint32_t ring_size);

/*
 * Initialize a pending queue.
 *
 * ring_addr points to a caller-provided properly aligned memory area of
 * _odp_pending_queue_mem_size(max_pending) bytes.
 *
 * max_pending is the number of pending events the ring can hold.
 *
 * free_fn is an optional callback that gets called for each pending
 * event when the pending queue is being destroyed and can be used to
 * replace the default behaviour of just freeing the pending event.
 */
void _odp_pending_queue_init(odp_pending_queue_t *pending, uint32_t max_pending,
			     odp_pending_free_fn_t free_fn, void *ring_addr);

void _odp_pending_queue_destroy(odp_pending_queue_t *pending);

static inline int _odp_pending_queue_is_empty(odp_pending_queue_t *pending)
{
	return odp_atomic_load_u32(&pending->num) == 0;
}

/*
 * Defer 'num' events whose destination queues are given in the
 * 'queues' array.
 */
void _odp_pending_queue_defer(odp_pending_queue_t *pending,
			      const odp_event_t events[],
			      const odp_queue_t queues[],
			      int num);

/*
 * Retry enqueuing pending events.
 * Return the number of events still pending.
 */
uint32_t _odp_pending_queue_retry(odp_pending_queue_t *pending);

#ifdef __cplusplus
}
#endif

#endif
