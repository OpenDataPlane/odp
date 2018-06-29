/* Copyright (c) 2016-2018, Linaro Limited
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
#include <odp/api/cpu.h>
#include <odp/api/hints.h>
#include <odp_align_internal.h>
#include <odp/api/plat/atomic_inlines.h>
#include <odp/api/plat/cpu_inlines.h>

/* Ring empty, not a valid data value. */
#define RING_EMPTY ((uint32_t)-1)

/* Ring of uint32_t data
 *
 * Ring stores head and tail counters. Ring indexes are formed from these
 * counters with a mask (mask = ring_size - 1), which requires that ring size
 * must be a power of two. Also ring size must be larger than the maximum
 * number of data items that will be stored on it (there's no check against
 * overwriting). */
typedef struct ODP_ALIGNED_CACHE {
	/* Writer head and tail */
	odp_atomic_u32_t w_head;
	odp_atomic_u32_t w_tail;
	uint8_t pad[ODP_CACHE_LINE_SIZE - (2 * sizeof(odp_atomic_u32_t))];

	/* Reader head and tail */
	odp_atomic_u32_t r_head;

	uint32_t data[0];
} ring_t;

/* 32-bit CAS with memory order selection */
static inline int cas_mo_u32(odp_atomic_u32_t *atom, uint32_t *old_val,
			     uint32_t new_val, int mo_success, int mo_failure)
{
	return __atomic_compare_exchange_n(&atom->v, old_val, new_val,
					   0 /* strong */,
					   mo_success,
					   mo_failure);
}

/* Initialize ring */
static inline void ring_init(ring_t *ring)
{
	odp_atomic_init_u32(&ring->w_head, 0);
	odp_atomic_init_u32(&ring->w_tail, 0);
	odp_atomic_init_u32(&ring->r_head, 0);
}

/* Dequeue data from the ring head */
static inline uint32_t ring_deq(ring_t *ring, uint32_t mask)
{
	uint32_t head, tail, new_head;

	/* Load/CAS acquire of r_head ensures that w_tail load happens after
	 * r_head load, and thus head value is always behind or equal to tail
	 * value. */
	head = odp_atomic_load_acq_u32(&ring->r_head);

	/* Move reader head. This thread owns data at the new head. */
	do {
		tail = odp_atomic_load_acq_u32(&ring->w_tail);

		if (head == tail)
			return RING_EMPTY;

		new_head = head + 1;

	} while (odp_unlikely(cas_mo_u32(&ring->r_head, &head, new_head,
					 __ATOMIC_ACQ_REL,
					 __ATOMIC_ACQUIRE) == 0));

	/* Read data. CAS acquire-release ensures that data read
	 * does not move above from here. */
	return ring->data[new_head & mask];
}

/* Dequeue multiple data from the ring head. Num is smaller than ring size. */
static inline uint32_t ring_deq_multi(ring_t *ring, uint32_t mask,
				      uint32_t data[], uint32_t num)
{
	uint32_t head, tail, new_head, i;

	/* Load/CAS acquire of r_head ensures that w_tail load happens after
	 * r_head load, and thus head value is always behind or equal to tail
	 * value. */
	head = odp_atomic_load_acq_u32(&ring->r_head);

	/* Move reader head. This thread owns data at the new head. */
	do {
		tail = odp_atomic_load_acq_u32(&ring->w_tail);

		/* Ring is empty */
		if (head == tail)
			return 0;

		/* Try to take all available */
		if ((tail - head) < num)
			num = tail - head;

		new_head = head + num;

	} while (odp_unlikely(cas_mo_u32(&ring->r_head, &head, new_head,
					 __ATOMIC_ACQ_REL,
					 __ATOMIC_ACQUIRE) == 0));

	/* Read data. CAS acquire-release ensures that data read
	 * does not move above from here. */
	for (i = 0; i < num; i++)
		data[i] = ring->data[(head + 1 + i) & mask];

	return num;
}

/* Enqueue data into the ring tail */
static inline void ring_enq(ring_t *ring, uint32_t mask, uint32_t data)
{
	uint32_t old_head, new_head;

	/* Reserve a slot in the ring for writing */
	old_head = odp_atomic_fetch_inc_u32(&ring->w_head);
	new_head = old_head + 1;

	/* Write data */
	ring->data[new_head & mask] = data;

	/* Wait until other writers have updated the tail */
	while (odp_unlikely(odp_atomic_load_acq_u32(&ring->w_tail) != old_head))
		odp_cpu_pause();

	/* Release the new writer tail, readers acquire it. */
	odp_atomic_store_rel_u32(&ring->w_tail, new_head);
}

/* Enqueue multiple data into the ring tail. Num is smaller than ring size. */
static inline void ring_enq_multi(ring_t *ring, uint32_t mask, uint32_t data[],
				  uint32_t num)
{
	uint32_t old_head, new_head, i;

	/* Reserve a slot in the ring for writing */
	old_head = odp_atomic_fetch_add_u32(&ring->w_head, num);
	new_head = old_head + 1;

	/* Write data */
	for (i = 0; i < num; i++)
		ring->data[(new_head + i) & mask] = data[i];

	/* Wait until other writers have updated the tail */
	while (odp_unlikely(odp_atomic_load_acq_u32(&ring->w_tail) != old_head))
		odp_cpu_pause();

	/* Release the new writer tail, readers acquire it. */
	odp_atomic_store_rel_u32(&ring->w_tail, old_head + num);
}

#ifdef __cplusplus
}
#endif

#endif
