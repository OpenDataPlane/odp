/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2018 Linaro Limited
 * Copyright (c) 2021-2025 Nokia
 */

#include <odp_debug_internal.h>
#include <odp_event_internal.h>
#include <odp_pool_internal.h>
#include <odp_queue_basic_internal.h>

#include <string.h>
#include <stdio.h>

static int queue_spsc_enq(odp_queue_t handle, _odp_event_hdr_t *event_hdr)
{
	queue_entry_t *queue = qentry_from_handle(handle);
	ring_spsc_ptr_t *ring_spsc = &queue->ring_spsc;

	if (ODP_DEBUG && odp_unlikely(queue->status < QUEUE_STATUS_READY)) {
		_ODP_ERR("Bad queue status\n");
		return -1;
	}

	if (odp_likely(ring_spsc_ptr_enq(ring_spsc, queue->ring_data, queue->ring_mask,
					 (uintptr_t)event_hdr)))
		return 0;

	return -1;
}

static inline int queue_spsc_enq_aggr(odp_queue_t handle, _odp_event_hdr_t *event_hdr)
{
	queue_entry_t *queue = qentry_from_handle(handle);

	if (ODP_DEBUG && odp_unlikely(queue->status < QUEUE_STATUS_READY)) {
		_ODP_ERR("Bad queue status\n");
		return -1;
	}

	if (odp_likely(_odp_event_aggr_enq(queue, &event_hdr, 1)))
		return 0;

	return -1;
}

static inline int queue_spsc_enq_multi(odp_queue_t handle, _odp_event_hdr_t *event_hdr[], int num)
{
	queue_entry_t *queue = qentry_from_handle(handle);
	ring_spsc_ptr_t *ring_spsc = &queue->ring_spsc;

	if (ODP_DEBUG && odp_unlikely(queue->status < QUEUE_STATUS_READY)) {
		_ODP_ERR("Bad queue status\n");
		return -1;
	}

	return ring_spsc_ptr_enq_multi(ring_spsc, queue->ring_data,
				       queue->ring_mask, (uintptr_t *)event_hdr, num);
}

static inline int queue_spsc_enq_multi_aggr(odp_queue_t handle, _odp_event_hdr_t *event_hdr[],
					    int num)
{
	queue_entry_t *queue = qentry_from_handle(handle);

	if (ODP_DEBUG && odp_unlikely(queue->status < QUEUE_STATUS_READY)) {
		_ODP_ERR("Bad queue status\n");
		return -1;
	}

	return _odp_event_aggr_enq(queue, event_hdr, num);
}

static _odp_event_hdr_t *queue_spsc_deq(odp_queue_t handle)
{
	queue_entry_t *queue = qentry_from_handle(handle);
	ring_spsc_ptr_t *ring_spsc = &queue->ring_spsc;
	_odp_event_hdr_t *event_hdr;

	if (ODP_DEBUG && odp_unlikely(queue->status < QUEUE_STATUS_READY)) {
		/* Bad queue, or queue has been destroyed. */
		return NULL;
	}

	if (ring_spsc_ptr_deq(ring_spsc, queue->ring_data, queue->ring_mask,
			      (uintptr_t *)&event_hdr) == 0)
		return NULL;

	odp_prefetch(event_hdr);

	return event_hdr;
}

static inline int queue_spsc_deq_multi(odp_queue_t handle, _odp_event_hdr_t *event_hdr[], int num)
{
	queue_entry_t *queue = qentry_from_handle(handle);
	ring_spsc_ptr_t *ring_spsc = &queue->ring_spsc;
	uint32_t num_deq;

	if (ODP_DEBUG && odp_unlikely(queue->status < QUEUE_STATUS_READY)) {
		/* Bad queue, or queue has been destroyed. */
		return -1;
	}

	num_deq = ring_spsc_ptr_deq_multi(ring_spsc, queue->ring_data, queue->ring_mask,
					  (uintptr_t *)event_hdr, num);

	if (num_deq == 0)
		return 0;

	for (uint32_t i = 0; i < num_deq; i++)
		odp_prefetch(event_hdr[i]);

	return num_deq;
}

void _odp_queue_spsc_init(queue_entry_t *queue, uint32_t queue_size)
{
	uint64_t offset;

	queue->enqueue = queue_spsc_enq;
	queue->dequeue = queue_spsc_deq;
	queue->enqueue_multi = queue_spsc_enq_multi;
	queue->dequeue_multi = queue_spsc_deq_multi;
	queue->orig_dequeue_multi = queue_spsc_deq_multi;

	offset = queue->index * (uint64_t)_odp_queue_glb->config.max_queue_size;

	queue->ring_data = &_odp_queue_glb->ring_data[offset];
	queue->ring_mask = queue_size - 1;
	ring_spsc_ptr_init(&queue->ring_spsc);
}

void _odp_queue_spsc_event_aggr_init(queue_entry_t *aggr_queue)
{
	aggr_queue->enqueue = queue_spsc_enq_aggr;
	aggr_queue->enqueue_multi = queue_spsc_enq_multi_aggr;
}
