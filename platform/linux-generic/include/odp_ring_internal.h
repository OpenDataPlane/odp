/* Copyright (c) 2016-2018, Linaro Limited
 * Copyright (c) 2019, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/* This header should NOT be included directly. There are no include guards for
 * the function definitions! */

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
#include <odp_ring_common.h>

/* Generic ring implementation
 *
 * Ring stores head and tail counters. Ring indexes are formed from these
 * counters with a mask (mask = ring_size - 1), which requires that ring size
 * must be a power of two. Also ring size must be larger than the maximum
 * number of data items that will be stored on it as write operations are
 * assumed to succeed eventually (after readers complete their current
 * operations). */

struct ring_common {
	/* Writer head and tail */
	odp_atomic_u32_t w_head;
	odp_atomic_u32_t w_tail;
	uint8_t pad[ODP_CACHE_LINE_SIZE - (2 * sizeof(odp_atomic_u32_t))];

	/* Reader head and tail */
	odp_atomic_u32_t r_head;
	odp_atomic_u32_t r_tail;
};

typedef struct ODP_ALIGNED_CACHE {
	struct ring_common r;
	uint32_t data[0];
} ring_u32_t;

typedef struct ODP_ALIGNED_CACHE {
	struct ring_common r;
	void *data[0];
} ring_ptr_t;

/* 32-bit CAS with memory order selection */
static inline int cas_mo_u32(odp_atomic_u32_t *atom, uint32_t *old_val,
			     uint32_t new_val, int mo_success, int mo_failure)
{
	return __atomic_compare_exchange_n(&atom->v, old_val, new_val,
					   0 /* strong */,
					   mo_success,
					   mo_failure);
}

#endif /* End of include guards */

#undef _ring_gen_t
#undef _ring_data_t
#undef _RING_INIT
#undef _RING_DEQ
#undef _RING_DEQ_MULTI
#undef _RING_ENQ
#undef _RING_ENQ_MULTI

/* Remap generic types and function names to ring data type specific ones. One
 * should never use the generic names (e.g. _RING_INIT) directly. */

#if _ODP_RING_TYPE == _ODP_RING_TYPE_U32
	#define _ring_gen_t ring_u32_t
	#define _ring_data_t uint32_t

	#define _RING_INIT ring_u32_init
	#define _RING_DEQ ring_u32_deq
	#define _RING_DEQ_MULTI ring_u32_deq_multi
	#define _RING_ENQ ring_u32_enq
	#define _RING_ENQ_MULTI ring_u32_enq_multi
#elif _ODP_RING_TYPE == _ODP_RING_TYPE_PTR
	#define _ring_gen_t ring_ptr_t
	#define _ring_data_t void *

	#define _RING_INIT ring_ptr_init
	#define _RING_DEQ ring_ptr_deq
	#define _RING_DEQ_MULTI ring_ptr_deq_multi
	#define _RING_ENQ ring_ptr_enq
	#define _RING_ENQ_MULTI ring_ptr_enq_multi
#endif

/* Initialize ring */
static inline void _RING_INIT(_ring_gen_t *ring)
{
	odp_atomic_init_u32(&ring->r.w_head, 0);
	odp_atomic_init_u32(&ring->r.w_tail, 0);
	odp_atomic_init_u32(&ring->r.r_head, 0);
	odp_atomic_init_u32(&ring->r.r_tail, 0);
}

/* Dequeue data from the ring head */
static inline uint32_t _RING_DEQ(_ring_gen_t *ring, uint32_t mask,
				 _ring_data_t *data)
{
	uint32_t head, tail, new_head;

	/* Load/CAS acquire of r_head ensures that w_tail load happens after
	 * r_head load, and thus head value is always behind or equal to tail
	 * value. */
	head = odp_atomic_load_acq_u32(&ring->r.r_head);

	/* Move reader head. This thread owns data at the new head. */
	do {
		tail = odp_atomic_load_acq_u32(&ring->r.w_tail);

		if (head == tail)
			return 0;

		new_head = head + 1;

	} while (odp_unlikely(cas_mo_u32(&ring->r.r_head, &head, new_head,
					 __ATOMIC_ACQUIRE,
					 __ATOMIC_ACQUIRE) == 0));

	/* Read data. */
	*data = ring->data[new_head & mask];

	/* Wait until other readers have updated the tail */
	while (odp_unlikely(odp_atomic_load_u32(&ring->r.r_tail) != head))
		odp_cpu_pause();

	/* Update the tail. Writers acquire it. */
	odp_atomic_store_rel_u32(&ring->r.r_tail, new_head);

	return 1;
}

/* Dequeue multiple data from the ring head. Num is smaller than ring size. */
static inline uint32_t _RING_DEQ_MULTI(_ring_gen_t *ring, uint32_t mask,
				       _ring_data_t data[], uint32_t num)
{
	uint32_t head, tail, new_head, i;

	/* Load/CAS acquire of r_head ensures that w_tail load happens after
	 * r_head load, and thus head value is always behind or equal to tail
	 * value. */
	head = odp_atomic_load_acq_u32(&ring->r.r_head);

	/* Move reader head. This thread owns data at the new head. */
	do {
		tail = odp_atomic_load_acq_u32(&ring->r.w_tail);

		/* Ring is empty */
		if (head == tail)
			return 0;

		/* Try to take all available */
		if ((tail - head) < num)
			num = tail - head;

		new_head = head + num;

	} while (odp_unlikely(cas_mo_u32(&ring->r.r_head, &head, new_head,
					 __ATOMIC_ACQUIRE,
					 __ATOMIC_ACQUIRE) == 0));

	/* Read data. */
	for (i = 0; i < num; i++)
		data[i] = ring->data[(head + 1 + i) & mask];

	/* Wait until other readers have updated the tail */
	while (odp_unlikely(odp_atomic_load_u32(&ring->r.r_tail) != head))
		odp_cpu_pause();

	/* Update the tail. Writers acquire it. */
	odp_atomic_store_rel_u32(&ring->r.r_tail, new_head);

	return num;
}

/* Enqueue data into the ring tail */
static inline void _RING_ENQ(_ring_gen_t *ring, uint32_t mask,
			     _ring_data_t data)
{
	uint32_t old_head, new_head;
	uint32_t size = mask + 1;

	/* Reserve a slot in the ring for writing */
	old_head = odp_atomic_fetch_inc_u32(&ring->r.w_head);
	new_head = old_head + 1;

	/* Wait for the last reader to finish. This prevents overwrite when
	 * a reader has been left behind (e.g. due to an interrupt) and is
	 * still reading the same slot. */
	while (odp_unlikely(new_head - odp_atomic_load_acq_u32(&ring->r.r_tail)
			    >= size))
		odp_cpu_pause();

	/* Write data */
	ring->data[new_head & mask] = data;

	/* Wait until other writers have updated the tail */
	while (odp_unlikely(odp_atomic_load_u32(&ring->r.w_tail) != old_head))
		odp_cpu_pause();

	/* Release the new writer tail, readers acquire it. */
	odp_atomic_store_rel_u32(&ring->r.w_tail, new_head);
}

/* Enqueue multiple data into the ring tail. Num is smaller than ring size. */
static inline void _RING_ENQ_MULTI(_ring_gen_t *ring, uint32_t mask,
				   _ring_data_t data[], uint32_t num)
{
	uint32_t old_head, new_head, i;
	uint32_t size = mask + 1;

	/* Reserve a slot in the ring for writing */
	old_head = odp_atomic_fetch_add_u32(&ring->r.w_head, num);
	new_head = old_head + 1;

	/* Wait for the last reader to finish. This prevents overwrite when
	 * a reader has been left behind (e.g. due to an interrupt) and is
	 * still reading these slots. */
	while (odp_unlikely(new_head - odp_atomic_load_acq_u32(&ring->r.r_tail)
			    >= size))
		odp_cpu_pause();

	/* Write data */
	for (i = 0; i < num; i++)
		ring->data[(new_head + i) & mask] = data[i];

	/* Wait until other writers have updated the tail */
	while (odp_unlikely(odp_atomic_load_u32(&ring->r.w_tail) != old_head))
		odp_cpu_pause();

	/* Release the new writer tail, readers acquire it. */
	odp_atomic_store_rel_u32(&ring->r.w_tail, old_head + num);
}

#ifdef __cplusplus
}
#endif
