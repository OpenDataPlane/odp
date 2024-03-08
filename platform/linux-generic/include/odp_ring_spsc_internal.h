/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2018 Linaro Limited
 */

#ifndef ODP_RING_SPSC_INTERNAL_H_
#define ODP_RING_SPSC_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#include <odp/api/atomic.h>
#include <odp/api/plat/atomic_inlines.h>

/* Lock-free ring for single-producer / single-consumer usage.
 *
 * Thread doing an operation may be different each time, but the same operation
 * (enq- or dequeue) must not be called concurrently. The next thread may call
 * the same operation only when it's sure that the previous thread have returned
 * from the call, or will never return back to finish the call when interrupted
 * during the call.
 *
 * Enqueue and dequeue operations can be done concurrently.
 */
typedef struct {
	odp_atomic_u32_t head;
	odp_atomic_u32_t tail;

} ring_spsc_t;

/* Initialize ring. Ring size must be a power of two. */
static inline void ring_spsc_init(ring_spsc_t *ring)
{
	odp_atomic_init_u32(&ring->head, 0);
	odp_atomic_init_u32(&ring->tail, 0);
}

/* Dequeue data from the ring head. Max_num is smaller than ring size.*/
static inline uint32_t ring_spsc_deq_multi(ring_spsc_t *ring,
					   uint32_t *ring_data,
					   uint32_t ring_mask, uint32_t data[],
					   uint32_t max_num)
{
	uint32_t head, tail, idx;
	uint32_t num, i;

	tail = odp_atomic_load_acq_u32(&ring->tail);
	head = odp_atomic_load_u32(&ring->head);
	num  = tail - head;

	/* Empty */
	if (num == 0)
		return 0;

	if (num > max_num)
		num = max_num;

	idx = head & ring_mask;

	for (i = 0; i < num; i++) {
		data[i] = ring_data[idx];
		idx = (idx + 1) & ring_mask;
	}

	odp_atomic_store_rel_u32(&ring->head, head + num);

	return num;
}

/* Enqueue data into the ring tail. Num_data is smaller than ring size. */
static inline uint32_t ring_spsc_enq_multi(ring_spsc_t *ring,
					   uint32_t *ring_data,
					   uint32_t ring_mask,
					   const uint32_t data[],
					   uint32_t num_data)
{
	uint32_t head, tail, size, idx;
	uint32_t num, i;

	head = odp_atomic_load_acq_u32(&ring->head);
	tail = odp_atomic_load_u32(&ring->tail);
	size = ring_mask + 1;
	num  = size - (tail - head);

	/* Full */
	if (num == 0)
		return 0;

	if (num > num_data)
		num = num_data;

	idx = tail & ring_mask;

	for (i = 0; i < num; i++) {
		ring_data[idx] = data[i];
		idx = (idx + 1) & ring_mask;
	}

	odp_atomic_store_rel_u32(&ring->tail, tail + num);

	return num;
}

/* Check if ring is empty */
static inline int ring_spsc_is_empty(ring_spsc_t *ring)
{
	uint32_t head = odp_atomic_load_u32(&ring->head);
	uint32_t tail = odp_atomic_load_u32(&ring->tail);

	return head == tail;
}

/* Return current ring length */
static inline uint32_t ring_spsc_length(ring_spsc_t *ring)
{
	uint32_t head = odp_atomic_load_u32(&ring->head);
	uint32_t tail = odp_atomic_load_u32(&ring->tail);

	return tail - head;
}

#ifdef __cplusplus
}
#endif

#endif
