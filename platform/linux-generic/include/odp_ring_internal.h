/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_RING_INTERNAL_H_
#define ODP_RING_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/atomic.h>
#include <odp/api/hints.h>
#include <odp_align_internal.h>

/* Ring empty, not a valid data value. */
#define RING_EMPTY ((uint32_t)-1)

/* Ring of uint32_t data
 *
 * Ring stores head and tail counters. Ring indexes are formed from these
 * counters with a mask (mask = ring_size - 1), which requires that ring size
 * must be a power of two. Also ring size must be larger than the maximum
 * number of data items that will be stored on it (there's no check against
 * overwriting). */
typedef struct {
	/* Writer head and tail */
	odp_atomic_u32_t w_head;
	odp_atomic_u32_t w_tail;
	uint8_t pad[ODP_CACHE_LINE_SIZE - (2 * sizeof(odp_atomic_u32_t))];

	/* Reader head and tail */
	odp_atomic_u32_t r_head;
	odp_atomic_u32_t r_tail;

	uint32_t data[0];
} ring_t ODP_ALIGNED_CACHE;

/* Initialize ring */
static inline void ring_init(ring_t *ring)
{
	odp_atomic_init_u32(&ring->w_head, 0);
	odp_atomic_init_u32(&ring->w_tail, 0);
	odp_atomic_init_u32(&ring->r_head, 0);
	odp_atomic_init_u32(&ring->r_tail, 0);
}

/* Dequeue data from the ring head */
static inline uint32_t ring_deq(ring_t *ring, uint32_t mask)
{
	uint32_t head, tail, new_head;
	uint32_t data;

	head = odp_atomic_load_u32(&ring->r_head);

	/* Move reader head. This thread owns data at the new head. */
	do {
		tail = odp_atomic_load_u32(&ring->w_tail);

		if (head == tail)
			return RING_EMPTY;

		new_head = head + 1;

	} while (odp_unlikely(odp_atomic_cas_acq_u32(&ring->r_head, &head,
			      new_head) == 0));

	/* Read queue index */
	data = ring->data[new_head & mask];

	/* Wait until other readers have updated the tail */
	while (odp_unlikely(odp_atomic_load_acq_u32(&ring->r_tail) != head))
		odp_cpu_pause();

	/* Now update the reader tail */
	odp_atomic_store_rel_u32(&ring->r_tail, new_head);

	return data;
}

/* Enqueue data into the ring tail */
static inline void ring_enq(ring_t *ring, uint32_t mask, uint32_t data)
{
	uint32_t old_head, new_head;

	/* Reserve a slot in the ring for writing */
	old_head = odp_atomic_fetch_inc_u32(&ring->w_head);
	new_head = old_head + 1;

	/* Ring is full. Wait for the last reader to finish. */
	while (odp_unlikely(odp_atomic_load_acq_u32(&ring->r_tail) == new_head))
		odp_cpu_pause();

	/* Write data */
	ring->data[new_head & mask] = data;

	/* Wait until other writers have updated the tail */
	while (odp_unlikely(odp_atomic_load_acq_u32(&ring->w_tail) != old_head))
		odp_cpu_pause();

	/* Now update the writer tail */
	odp_atomic_store_rel_u32(&ring->w_tail, new_head);
}

#ifdef __cplusplus
}
#endif

#endif
