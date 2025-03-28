/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2018 Linaro Limited
 * Copyright (c) 2025 Nokia
 */

#ifndef ODP_RING_ST_INTERNAL_H_
#define ODP_RING_ST_INTERNAL_H_

#include <odp/api/align.h>
#include <odp/api/hints.h>

#include <odp_ring_common.h>

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Single thread ring
 *
 * Basic ring for single thread usage. Operations must be synchronized by using
 * locks (or other means), when multiple threads use the same ring. */

struct ring_st_common {
	uint32_t head;
	uint32_t tail;
};

typedef struct {
	struct ring_st_common r;
} ring_st_u32_t;

typedef struct {
	struct ring_st_common r;
} ring_st_ptr_t;

#endif /* End of include guards */

#undef _ring_st_gen_t
#undef _ring_st_data_t
#undef _RING_ST_INIT
#undef _RING_ST_DEQ_MULTI
#undef _RING_ST_ENQ_MULTI
#undef _RING_ST_IS_EMPTY
#undef _RING_ST_LEN

/* This header should NOT be included directly. There are no include guards for
 * the following types and function definitions! */
#ifndef _ODP_RING_TYPE
#error Include type specific ring header instead of this common file.
#endif

#if _ODP_RING_TYPE == _ODP_RING_TYPE_U32
	#define _ring_st_gen_t		ring_st_u32_t
	#define _ring_st_data_t		uint32_t

	#define _RING_ST_INIT		ring_st_u32_init
	#define _RING_ST_DEQ_MULTI	ring_st_u32_deq_multi
	#define _RING_ST_ENQ_MULTI	ring_st_u32_enq_multi
	#define _RING_ST_IS_EMPTY	ring_st_u32_is_empty
	#define _RING_ST_LEN		ring_st_u32_len
#elif _ODP_RING_TYPE == _ODP_RING_TYPE_PTR
	#define _ring_st_gen_t		ring_st_ptr_t
	#define _ring_st_data_t		uintptr_t

	#define _RING_ST_INIT		ring_st_ptr_init
	#define _RING_ST_DEQ_MULTI	ring_st_ptr_deq_multi
	#define _RING_ST_ENQ_MULTI	ring_st_ptr_enq_multi
	#define _RING_ST_IS_EMPTY	ring_st_ptr_is_empty
	#define _RING_ST_LEN		ring_st_ptr_len
#endif

/* Initialize ring. Ring size must be a power of two. */
static inline void _RING_ST_INIT(_ring_st_gen_t *ring)
{
	ring->r.head = 0;
	ring->r.tail = 0;
}

/* Dequeue data from the ring head. Max_num is smaller than ring size.*/
static inline uint32_t _RING_ST_DEQ_MULTI(_ring_st_gen_t *ring,
					  _ring_st_data_t *ring_data,
					  uint32_t ring_mask,
					  _ring_st_data_t data[],
					  uint32_t max_num)
{
	uint32_t head, tail, idx;
	uint32_t num, i;

	head = ring->r.head;
	tail = ring->r.tail;
	num  = tail - head;

	/* Empty */
	if (num == 0)
		return 0;

	if (num > max_num)
		num = max_num;

	idx = head & ring_mask;

	for (i = 0; i < num; i++) {
		data[i] = ring_data[idx];
		idx     = (idx + 1) & ring_mask;
	}

	ring->r.head = head + num;

	return num;
}

/* Enqueue data into the ring tail. Num_data is smaller than ring size. */
static inline uint32_t _RING_ST_ENQ_MULTI(_ring_st_gen_t *ring,
					  _ring_st_data_t *ring_data,
					  uint32_t ring_mask,
					  const _ring_st_data_t data[],
					  uint32_t num_data)
{
	uint32_t head, tail, size, idx;
	uint32_t num, i;

	head = ring->r.head;
	tail = ring->r.tail;
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
		idx     = (idx + 1) & ring_mask;
	}

	ring->r.tail = tail + num;

	return num;
}

/* Check if ring is empty */
static inline int _RING_ST_IS_EMPTY(_ring_st_gen_t *ring)
{
	return ring->r.head == ring->r.tail;
}

/* Return current ring length */
static inline uint32_t _RING_ST_LEN(_ring_st_gen_t *ring)
{
	return ring->r.tail - ring->r.head;
}

#ifdef __cplusplus
}
#endif
