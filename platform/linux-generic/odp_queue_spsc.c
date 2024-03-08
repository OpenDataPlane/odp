/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2018 Linaro Limited
 * Copyright (c) 2021 Nokia
 */

#include <odp_debug_internal.h>
#include <odp_event_internal.h>
#include <odp_pool_internal.h>
#include <odp_queue_basic_internal.h>

#include <string.h>
#include <stdio.h>

static inline void event_index_from_hdr(uint32_t event_index[],
					_odp_event_hdr_t *event_hdr[], int num)
{
	int i;

	for (i = 0; i < num; i++)
		event_index[i] = event_hdr[i]->index.u32;
}

static inline void event_index_to_hdr(_odp_event_hdr_t *event_hdr[],
				      uint32_t event_index[], int num)
{
	int i;

	for (i = 0; i < num; i++) {
		event_hdr[i] = _odp_event_hdr_from_index_u32(event_index[i]);
		odp_prefetch(event_hdr[i]);
	}
}

static inline int spsc_enq_multi(odp_queue_t handle,
				 _odp_event_hdr_t *event_hdr[], int num)
{
	queue_entry_t *queue;
	ring_spsc_t *ring_spsc;
	uint32_t buf_idx[num];

	queue = qentry_from_handle(handle);
	ring_spsc = &queue->ring_spsc;

	event_index_from_hdr(buf_idx, event_hdr, num);

	if (odp_unlikely(queue->status < QUEUE_STATUS_READY)) {
		_ODP_ERR("Bad queue status\n");
		return -1;
	}

	return ring_spsc_enq_multi(ring_spsc, queue->ring_data,
				   queue->ring_mask, buf_idx, num);
}

static inline int spsc_deq_multi(odp_queue_t handle,
				 _odp_event_hdr_t *event_hdr[], int num)
{
	queue_entry_t *queue;
	int num_deq;
	ring_spsc_t *ring_spsc;
	uint32_t buf_idx[num];

	queue = qentry_from_handle(handle);
	ring_spsc = &queue->ring_spsc;

	if (odp_unlikely(queue->status < QUEUE_STATUS_READY)) {
		/* Bad queue, or queue has been destroyed. */
		return -1;
	}

	num_deq = ring_spsc_deq_multi(ring_spsc, queue->ring_data,
				      queue->ring_mask, buf_idx, num);

	if (num_deq == 0)
		return 0;

	event_index_to_hdr(event_hdr, buf_idx, num_deq);

	return num_deq;
}

static int queue_spsc_enq_multi(odp_queue_t handle, _odp_event_hdr_t *event_hdr[],
				int num)
{
	return spsc_enq_multi(handle, event_hdr, num);
}

static int queue_spsc_enq(odp_queue_t handle, _odp_event_hdr_t *event_hdr)
{
	int ret;

	ret = spsc_enq_multi(handle, &event_hdr, 1);

	if (ret == 1)
		return 0;
	else
		return -1;
}

static int queue_spsc_deq_multi(odp_queue_t handle, _odp_event_hdr_t *event_hdr[],
				int num)
{
	return spsc_deq_multi(handle, event_hdr, num);
}

static _odp_event_hdr_t *queue_spsc_deq(odp_queue_t handle)
{
	_odp_event_hdr_t *event_hdr = NULL;
	int ret;

	ret = spsc_deq_multi(handle, &event_hdr, 1);

	if (ret == 1)
		return event_hdr;
	else
		return NULL;
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
	ring_spsc_init(&queue->ring_spsc);
}
