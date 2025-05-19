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

static inline void event_index_from_hdr(uint32_t event_index[],
					_odp_event_hdr_t *event_hdr[], int num)
{
	int i;
	int idx = 0;

	for (i = 0; i < (num & ~0x3); i += 4, idx += 4) {
		event_index[i] = event_hdr[idx]->index.u32;
		event_index[i+1] = event_hdr[idx+1]->index.u32;
		event_index[i+2] = event_hdr[idx+2]->index.u32;
		event_index[i+3] = event_hdr[idx+3]->index.u32;
	}
	switch (num & 0x3) {
	case 3:
		event_index[i++] = event_hdr[idx++]->index.u32;
		__attribute__((fallthrough));
	case 2:
		event_index[i++] = event_hdr[idx++]->index.u32;
		__attribute__((fallthrough));
	case 1:
		event_index[i++] = event_hdr[idx++]->index.u32;
	}
}

static inline void event_index_to_hdr(_odp_event_hdr_t *event_hdr[],
				      uint32_t event_index[], int num)
{
	int i;
	int idx = 0;

	for (i = 0; i < (num & ~0x3); idx += 4, i += 4) {
		event_hdr[i] = _odp_event_hdr_from_index_u32(event_index[idx]);
		event_hdr[i+1] = _odp_event_hdr_from_index_u32(event_index[idx+1]);
		event_hdr[i+2] = _odp_event_hdr_from_index_u32(event_index[idx+2]);
		event_hdr[i+3] = _odp_event_hdr_from_index_u32(event_index[idx+3]);
	}

	switch (num & 0x3) {
	case 3:
		event_hdr[i++] = _odp_event_hdr_from_index_u32(event_index[idx++]);

		__attribute__((fallthrough));
	case 2:
		event_hdr[i++] = _odp_event_hdr_from_index_u32(event_index[idx++]);
		__attribute__((fallthrough));
	case 1:
		event_hdr[i++] = _odp_event_hdr_from_index_u32(event_index[idx++]);
	}
	
}

static int queue_spsc_enq(odp_queue_t handle, _odp_event_hdr_t *event_hdr)
{
	queue_entry_t *queue = qentry_from_handle(handle);
	ring_spsc_u32_t *ring_spsc = &queue->ring_spsc;
	uint32_t num_enq;

	if (ODP_DEBUG && odp_unlikely(queue->status < QUEUE_STATUS_READY)) {
		_ODP_ERR("Bad queue status\n");
		return -1;
	}

	num_enq = ring_spsc_u32_enq(ring_spsc, queue->ring_data, queue->ring_mask,
				    event_hdr->index.u32);
	if (odp_likely(num_enq))
		return 0;

	return -1;
}

static inline int queue_spsc_enq_multi(odp_queue_t handle, _odp_event_hdr_t *event_hdr[], int num)
{
	queue_entry_t *queue;
	ring_spsc_u32_t *ring_spsc;
	uint32_t buf_idx[num];

	queue = qentry_from_handle(handle);
	ring_spsc = &queue->ring_spsc;

	event_index_from_hdr(buf_idx, event_hdr, num);

	if (ODP_DEBUG && odp_unlikely(queue->status < QUEUE_STATUS_READY)) {
		_ODP_ERR("Bad queue status\n");
		return -1;
	}

	return ring_spsc_u32_enq_multi(ring_spsc, queue->ring_data,
				       queue->ring_mask, buf_idx, num);
}

static _odp_event_hdr_t *queue_spsc_deq(odp_queue_t handle)
{
	queue_entry_t *queue = qentry_from_handle(handle);
	ring_spsc_u32_t *ring_spsc = &queue->ring_spsc;
	_odp_event_hdr_t *event_hdr;
	uint32_t num_deq, event_idx;

	if (ODP_DEBUG && odp_unlikely(queue->status < QUEUE_STATUS_READY)) {
		/* Bad queue, or queue has been destroyed. */
		return NULL;
	}

	num_deq = ring_spsc_u32_deq(ring_spsc, queue->ring_data, queue->ring_mask, &event_idx);
	if (num_deq == 0)
		return NULL;

	event_hdr = _odp_event_hdr_from_index_u32(event_idx);
	odp_prefetch(event_hdr);

	return event_hdr;
}

static inline int queue_spsc_deq_multi(odp_queue_t handle, _odp_event_hdr_t *event_hdr[], int num)
{
	queue_entry_t *queue;
	int num_deq;
	ring_spsc_u32_t *ring_spsc;
	uint32_t buf_idx[num];

	queue = qentry_from_handle(handle);
	ring_spsc = &queue->ring_spsc;

	if (ODP_DEBUG && odp_unlikely(queue->status < QUEUE_STATUS_READY)) {
		/* Bad queue, or queue has been destroyed. */
		return -1;
	}

	num_deq = ring_spsc_u32_deq_multi(ring_spsc, queue->ring_data,
					  queue->ring_mask, buf_idx, num);

	if (num_deq == 0)
		return 0;

	event_index_to_hdr(event_hdr, buf_idx, num_deq);

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
	ring_spsc_u32_init(&queue->ring_spsc);
}
