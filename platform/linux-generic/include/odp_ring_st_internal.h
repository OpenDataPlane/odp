/* Copyright (c) 2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_RING_ST_INTERNAL_H_
#define ODP_RING_ST_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/hints.h>
#include <odp_align_internal.h>

/* Basic ring for single thread usage. Operations must be synchronized by using
 * locks (or other means), when multiple threads use the same ring. */
typedef struct {
	uint32_t head;
	uint32_t tail;
	uint32_t mask;
	uint32_t *data;

} ring_st_t;

/* Initialize ring. Ring size must be a power of two. */
static inline void ring_st_init(ring_st_t *ring, uint32_t *data, uint32_t size)
{
	ring->head = 0;
	ring->tail = 0;
	ring->mask = size - 1;
	ring->data = data;
}

/* Dequeue data from the ring head. Max_num is smaller than ring size.*/
static inline uint32_t ring_st_deq_multi(ring_st_t *ring, uint32_t data[],
					 uint32_t max_num)
{
	uint32_t head, tail, mask, idx;
	uint32_t num, i;

	head = ring->head;
	tail = ring->tail;
	mask = ring->mask;
	num  = tail - head;

	/* Empty */
	if (num == 0)
		return 0;

	if (num > max_num)
		num = max_num;

	idx = head & mask;

	for (i = 0; i < num; i++) {
		data[i] = ring->data[idx];
		idx     = (idx + 1) & mask;
	}

	ring->head = head + num;

	return num;
}

/* Enqueue data into the ring tail. Num_data is smaller than ring size. */
static inline uint32_t ring_st_enq_multi(ring_st_t *ring, const uint32_t data[],
					 uint32_t num_data)
{
	uint32_t head, tail, mask, size, idx;
	uint32_t num, i;

	head = ring->head;
	tail = ring->tail;
	mask = ring->mask;
	size = mask + 1;
	num  = size - (tail - head);

	/* Full */
	if (num == 0)
		return 0;

	if (num > num_data)
		num = num_data;

	idx = tail & mask;

	for (i = 0; i < num; i++) {
		ring->data[idx] = data[i];
		idx     = (idx + 1) & mask;
	}

	ring->tail = tail + num;

	return num;
}

/* Check if ring is empty */
static inline int ring_st_is_empty(ring_st_t *ring)
{
	return ring->head == ring->tail;
}

#ifdef __cplusplus
}
#endif

#endif
