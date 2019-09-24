/* Copyright (c) 2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
#include <string.h>
#include <stdio.h>

#include <odp_queue_basic_internal.h>
#include <odp_pool_internal.h>

#include <odp_debug_internal.h>

static inline void buffer_index_from_buf(uint32_t buffer_index[],
					 odp_buffer_hdr_t *buf_hdr[], int num)
{
	int i;

	for (i = 0; i < num; i++)
		buffer_index[i] = buf_hdr[i]->index.u32;
}

static inline void buffer_index_to_buf(odp_buffer_hdr_t *buf_hdr[],
				       uint32_t buffer_index[], int num)
{
	int i;

	for (i = 0; i < num; i++) {
		buf_hdr[i] = buf_hdr_from_index_u32(buffer_index[i]);
		odp_prefetch(buf_hdr[i]);
	}
}

static inline int spsc_enq_multi(odp_queue_t handle,
				 odp_buffer_hdr_t *buf_hdr[], int num)
{
	queue_entry_t *queue;
	ring_spsc_t *ring_spsc;
	uint32_t buf_idx[num];

	queue = qentry_from_handle(handle);
	ring_spsc = &queue->s.ring_spsc;

	buffer_index_from_buf(buf_idx, buf_hdr, num);

	if (odp_unlikely(queue->s.status < QUEUE_STATUS_READY)) {
		ODP_ERR("Bad queue status\n");
		return -1;
	}

	return ring_spsc_enq_multi(ring_spsc, queue->s.ring_data,
				   queue->s.ring_mask, buf_idx, num);
}

static inline int spsc_deq_multi(odp_queue_t handle,
				 odp_buffer_hdr_t *buf_hdr[], int num)
{
	queue_entry_t *queue;
	int num_deq;
	ring_spsc_t *ring_spsc;
	uint32_t buf_idx[num];

	queue = qentry_from_handle(handle);
	ring_spsc = &queue->s.ring_spsc;

	if (odp_unlikely(queue->s.status < QUEUE_STATUS_READY)) {
		/* Bad queue, or queue has been destroyed. */
		return -1;
	}

	num_deq = ring_spsc_deq_multi(ring_spsc, queue->s.ring_data,
				      queue->s.ring_mask, buf_idx, num);

	if (num_deq == 0)
		return 0;

	buffer_index_to_buf(buf_hdr, buf_idx, num_deq);

	return num_deq;
}

static int queue_spsc_enq_multi(odp_queue_t handle, odp_buffer_hdr_t *buf_hdr[],
				int num)
{
	return spsc_enq_multi(handle, buf_hdr, num);
}

static int queue_spsc_enq(odp_queue_t handle, odp_buffer_hdr_t *buf_hdr)
{
	int ret;

	ret = spsc_enq_multi(handle, &buf_hdr, 1);

	if (ret == 1)
		return 0;
	else
		return -1;
}

static int queue_spsc_deq_multi(odp_queue_t handle, odp_buffer_hdr_t *buf_hdr[],
				int num)
{
	return spsc_deq_multi(handle, buf_hdr, num);
}

static odp_buffer_hdr_t *queue_spsc_deq(odp_queue_t handle)
{
	odp_buffer_hdr_t *buf_hdr = NULL;
	int ret;

	ret = spsc_deq_multi(handle, &buf_hdr, 1);

	if (ret == 1)
		return buf_hdr;
	else
		return NULL;
}

void queue_spsc_init(queue_entry_t *queue, uint32_t queue_size)
{
	uint64_t offset;

	queue->s.enqueue = queue_spsc_enq;
	queue->s.dequeue = queue_spsc_deq;
	queue->s.enqueue_multi = queue_spsc_enq_multi;
	queue->s.dequeue_multi = queue_spsc_deq_multi;
	queue->s.orig_dequeue_multi = queue_spsc_deq_multi;

	offset = queue->s.index * (uint64_t)queue_glb->config.max_queue_size;

	queue->s.ring_data = &queue_glb->ring_data[offset];
	queue->s.ring_mask = queue_size - 1;
	ring_spsc_init(&queue->s.ring_spsc);
}
