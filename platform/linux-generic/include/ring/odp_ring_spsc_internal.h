/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2018 Linaro Limited
 * Copyright (c) 2025 Nokia
 */

#ifndef ODP_RING_SPSC_INTERNAL_H_
#define ODP_RING_SPSC_INTERNAL_H_

#include <odp/api/atomic.h>

#include <odp/api/plat/atomic_inlines.h>

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Lock-free single-producer single-consumer ring
 *
 * Thread doing an operation may be different each time, but the same operation
 * (enq- or dequeue) must not be called concurrently. The next thread may call
 * the same operation only when it's sure that the previous thread have returned
 * from the call, or will never return back to finish the call when interrupted
 * during the call.
 *
 * Enqueue and dequeue operations can be done concurrently.
 */

struct ring_spsc_common {
	odp_atomic_u32_t head;
	odp_atomic_u32_t tail;

};

typedef struct {
	struct ring_spsc_common r;
} ring_spsc_u32_t;

typedef struct {
	struct ring_spsc_common r;
} ring_spsc_ptr_t;

#endif /* End of include guards */

#undef _ring_spsc_gen_t
#undef _ring_spsc_data_t
#undef _RING_SPSC_INIT
#undef _RING_SPSC_DEQ
#undef _RING_SPSC_DEQ_MULTI
#undef _RING_SPSC_ENQ
#undef _RING_SPSC_ENQ_MULTI
#undef _RING_SPSC_IS_EMPTY
#undef _RING_SPSC_LEN

/* This header should NOT be included directly. There are no include guards for
 * the following types and function definitions! */
#ifndef _ODP_RING_TYPE
#error Include type specific ring header instead of this common file.
#endif

#if _ODP_RING_TYPE == _ODP_RING_TYPE_U32
	#define _ring_spsc_gen_t	ring_spsc_u32_t
	#define _ring_spsc_data_t	uint32_t

	#define _RING_SPSC_INIT		ring_spsc_u32_init
	#define _RING_SPSC_DEQ		ring_spsc_u32_deq
	#define _RING_SPSC_DEQ_MULTI	ring_spsc_u32_deq_multi
	#define _RING_SPSC_ENQ		ring_spsc_u32_enq
	#define _RING_SPSC_ENQ_MULTI	ring_spsc_u32_enq_multi
	#define _RING_SPSC_IS_EMPTY	ring_spsc_u32_is_empty
	#define _RING_SPSC_LEN		ring_spsc_u32_len
#elif _ODP_RING_TYPE == _ODP_RING_TYPE_PTR
	#define _ring_spsc_gen_t	ring_spsc_ptr_t
	#define _ring_spsc_data_t	uintptr_t

	#define _RING_SPSC_INIT		ring_spsc_ptr_init
	#define _RING_SPSC_DEQ		ring_spsc_ptr_deq
	#define _RING_SPSC_DEQ_MULTI	ring_spsc_ptr_deq_multi
	#define _RING_SPSC_ENQ		ring_spsc_ptr_enq
	#define _RING_SPSC_ENQ_MULTI	ring_spsc_ptr_enq_multi
	#define _RING_SPSC_IS_EMPTY	ring_spsc_ptr_is_empty
	#define _RING_SPSC_LEN		ring_spsc_ptr_len
#endif

/* Initialize ring. Ring size must be a power of two. */
static inline void _RING_SPSC_INIT(_ring_spsc_gen_t *ring)
{
	odp_atomic_init_u32(&ring->r.head, 0);
	odp_atomic_init_u32(&ring->r.tail, 0);
}

/* Dequeue data from the ring head */
static inline uint32_t _RING_SPSC_DEQ(_ring_spsc_gen_t *ring,
				      _ring_spsc_data_t *ring_data,
				      uint32_t ring_mask, _ring_spsc_data_t *data)
{
	uint32_t head, tail;
	uint32_t num;

	tail = odp_atomic_load_acq_u32(&ring->r.tail);
	head = odp_atomic_load_u32(&ring->r.head);
	num  = tail - head;

	/* Empty */
	if (num == 0)
		return 0;

	*data = ring_data[head & ring_mask];

	odp_atomic_store_rel_u32(&ring->r.head, head + 1);

	return 1;
}

/* Dequeue data from the ring head. Max_num is smaller than ring size.*/
static inline uint32_t _RING_SPSC_DEQ_MULTI(_ring_spsc_gen_t *ring,
					    _ring_spsc_data_t *ring_data,
					    uint32_t ring_mask, _ring_spsc_data_t data[],
					    uint32_t max_num)
{
	uint32_t head, tail, idx;
	uint32_t num, i;

	tail = odp_atomic_load_acq_u32(&ring->r.tail);
	head = odp_atomic_load_u32(&ring->r.head);
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

	odp_atomic_store_rel_u32(&ring->r.head, head + num);

	return num;
}

/* Enqueue data into the ring tail */
static inline uint32_t _RING_SPSC_ENQ(_ring_spsc_gen_t *ring,
				      _ring_spsc_data_t *ring_data,
				      uint32_t ring_mask,
				      const _ring_spsc_data_t data)
{
	uint32_t head, tail, size;
	uint32_t num;

	head = odp_atomic_load_acq_u32(&ring->r.head);
	tail = odp_atomic_load_u32(&ring->r.tail);
	size = ring_mask + 1;
	num  = size - (tail - head);

	/* Full */
	if (num == 0)
		return 0;

	ring_data[tail & ring_mask] = data;

	odp_atomic_store_rel_u32(&ring->r.tail, tail + 1);

	return 1;
}

/* Enqueue data into the ring tail. Num_data is smaller than ring size. */
static inline uint32_t _RING_SPSC_ENQ_MULTI(_ring_spsc_gen_t *ring,
					    _ring_spsc_data_t *ring_data,
					    uint32_t ring_mask,
					    const _ring_spsc_data_t data[],
					    uint32_t num_data)
{
	uint32_t head, tail, size, idx;
	uint32_t num, i;

	head = odp_atomic_load_acq_u32(&ring->r.head);
	tail = odp_atomic_load_u32(&ring->r.tail);
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

	odp_atomic_store_rel_u32(&ring->r.tail, tail + num);

	return num;
}

/* Check if ring is empty */
static inline int _RING_SPSC_IS_EMPTY(_ring_spsc_gen_t *ring)
{
	uint32_t head = odp_atomic_load_u32(&ring->r.head);
	uint32_t tail = odp_atomic_load_u32(&ring->r.tail);

	return head == tail;
}

/* Return current ring length */
static inline uint32_t _RING_SPSC_LEN(_ring_spsc_gen_t *ring)
{
	uint32_t head = odp_atomic_load_u32(&ring->r.head);
	uint32_t tail = odp_atomic_load_u32(&ring->r.tail);

	return tail - head;
}

#ifdef __cplusplus
}
#endif
