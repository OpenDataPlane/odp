/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2026 Nokia
 */

#include <odp/api/atomic.h>
#include <odp/api/event.h>
#include <odp/api/hints.h>
#include <odp/api/queue.h>
#include <odp/api/spinlock.h>

#include <odp_debug_internal.h>
#include <odp_pending_queue_internal.h>

#include <inttypes.h>
#include <stdint.h>

uint32_t _odp_pending_queue_mem_size(uint32_t max_pending)
{
	return max_pending * sizeof(odp_pending_event_t);
}

void _odp_pending_queue_init(odp_pending_queue_t *pending, uint32_t max_pending,
			     odp_pending_free_fn_t free_fn, void *ring_addr)
{
	odp_spinlock_init(&pending->lock);
	odp_atomic_init_u32(&pending->num, 0);
	pending->head = 0;
	pending->size = max_pending;
	pending->free_fn = free_fn;
	pending->ring = ring_addr;
}

void _odp_pending_queue_destroy(odp_pending_queue_t *pending)
{
	uint32_t num = odp_atomic_load_u32(&pending->num);
	uint32_t head = pending->head;

	while (num > 0) {
		odp_event_t event = pending->ring[head].event;

		if (pending->free_fn)
			pending->free_fn(event);
		else
			odp_event_free(event);

		if (++head >= pending->size)
			head = 0;
		num--;
	}
	pending->head = head;
	odp_atomic_store_u32(&pending->num, 0);
}

void _odp_pending_queue_defer(odp_pending_queue_t *pending,
			      const odp_event_t events[],
			      const odp_queue_t queues[],
			      int num_ev)
{
	uint32_t num;

	odp_spinlock_lock(&pending->lock);
	num = odp_atomic_load_u32(&pending->num);

	_ODP_DBG("Deferring %i events\n", num_ev);

	for (int i = 0; i < num_ev; i++) {
		uint32_t tail = pending->head + num;

		if (tail >= pending->size)
			tail -= pending->size;

		_ODP_ASSERT(num < pending->size);
		pending->ring[tail].event = events[i];
		pending->ring[tail].queue = queues[i];
		num++;
	}
	odp_atomic_store_u32(&pending->num, num);
	odp_spinlock_unlock(&pending->lock);
}

uint32_t _odp_pending_queue_retry(odp_pending_queue_t *pending)
{
	uint32_t num, head;

	odp_spinlock_lock(&pending->lock);
	num = odp_atomic_load_u32(&pending->num);
	head = pending->head;
	_ODP_DBG("Retrying sending %" PRIu32 " pending events\n", num);

	while (num > 0) {
		odp_event_t event = pending->ring[head].event;

		if (odp_unlikely(odp_queue_enq(pending->ring[head].queue, event)))
			break;
		if (++head >= pending->size)
			head = 0;
		num--;
	}
	pending->head = head;
	_ODP_DBG("%" PRIu32 " events still pending\n", num);
	odp_atomic_store_u32(&pending->num, num);
	odp_spinlock_unlock(&pending->lock);

	return num;
}
