/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2018 Linaro Limited
 * Copyright (c) 2019-2026 Nokia
 */

#ifndef ODP_RING_MPMC_RST_INTERNAL_H_
#define ODP_RING_MPMC_RST_INTERNAL_H_

#include <odp/api/align.h>
#include <odp/api/atomic.h>
#include <odp/api/cpu.h>
#include <odp/api/hints.h>

#include <odp/api/plat/atomic_inlines.h>
#include <odp/api/plat/cpu_inlines.h>

#include <odp_macros_internal.h>
#include <ring/odp_ring_common.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Restricted size multi-producer multi-consumer ring
 *
 * Ring stores head and tail counters. Ring indexes are formed from these
 * counters with a mask (mask = ring_size - 1), which requires that ring size
 * must be a power of two. Also ring size must be larger than the maximum
 * number of data items that will be stored on it as write operations are
 * assumed to succeed eventually (after readers complete their current
 * operations). */

struct ring_xpxc_rst_common {
	_ODP_CACHE_PAD

	/* Writer head and tail */
	struct ODP_ALIGNED_CACHE {
		odp_atomic_u32_t w_head;
		odp_atomic_u32_t w_tail;
	};

	_ODP_CACHE_PAD

	/* Reader head and tail */
	struct ODP_ALIGNED_CACHE {
		odp_atomic_u32_t r_head;
		odp_atomic_u32_t r_tail;
	};

	_ODP_CACHE_PAD
};

typedef struct ODP_ALIGNED_CACHE {
	struct ring_xpxc_rst_common r;
	uint32_t data[];
} ring_mpmc_rst_u32_t;

typedef struct ODP_ALIGNED_CACHE {
	struct ring_xpxc_rst_common r;
	uint64_t data[];
} ring_mpmc_rst_u64_t;

typedef struct ODP_ALIGNED_CACHE {
	struct ring_xpxc_rst_common r;
	void *data[];
} ring_mpmc_rst_ptr_t;

typedef struct ODP_ALIGNED_CACHE {
	struct ring_xpxc_rst_common r;
	uint32_t data[];
} ring_mpsc_rst_u32_t;

typedef struct ODP_ALIGNED_CACHE {
	struct ring_xpxc_rst_common r;
	uint64_t data[];
} ring_mpsc_rst_u64_t;

typedef struct ODP_ALIGNED_CACHE {
	struct ring_xpxc_rst_common r;
	void *data[];
} ring_mpsc_rst_ptr_t;

typedef struct ODP_ALIGNED_CACHE {
	struct ring_xpxc_rst_common r;
	uint32_t data[];
} ring_spmc_rst_u32_t;

typedef struct ODP_ALIGNED_CACHE {
	struct ring_xpxc_rst_common r;
	uint64_t data[];
} ring_spmc_rst_u64_t;

typedef struct ODP_ALIGNED_CACHE {
	struct ring_xpxc_rst_common r;
	void *data[];
} ring_spmc_rst_ptr_t;

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

#undef _ring_xpxc_rst_gen_t
#undef _ring_xpxc_rst_data_t
#undef _RING_XPXC_RST_INIT
#undef _RING_XPXC_RST_LEN

#undef _RING_MPMC_RST_DEQ
#undef _RING_MPMC_RST_DEQ_MULTI
#undef _RING_MPMC_RST_DEQ_BATCH
#undef _RING_MPMC_RST_ENQ
#undef _RING_MPMC_RST_ENQ_MULTI

#undef _RING_MPSC_RST_DEQ_MULTI
#undef _RING_MPSC_RST_DEQ_BATCH

#undef _RING_SPMC_RST_ENQ_MULTI

/* This header should NOT be included directly. There are no include guards for
 * the following types and function definitions! */
#if !defined(_ODP_RING_TYPE) || !defined(_ODP_RING_SYNC)
#error Include type specific ring header instead of this common file.
#endif

/* Remap generic types and function names to ring data type and synchronization
 * mode specific ones. One should never use the generic names (e.g.
 * _RING_XPXC_RST_INIT) directly. */

#if _ODP_RING_TYPE == _ODP_RING_TYPE_U32
	#if _ODP_RING_SYNC == _ODP_RING_SYNC_MPSC
		#define _ring_xpxc_rst_gen_t		ring_mpsc_rst_u32_t
		#define _ring_xpxc_rst_data_t		uint32_t

		#define _RING_XPXC_RST_INIT		ring_mpsc_rst_u32_init
		#define _RING_MPMC_RST_ENQ_MULTI	ring_mpsc_rst_u32_enq_multi
		#define _RING_MPSC_RST_DEQ_MULTI	ring_mpsc_rst_u32_deq_multi
		#define _RING_MPSC_RST_DEQ_BATCH	ring_mpsc_rst_u32_deq_batch
		#define _RING_XPXC_RST_LEN		ring_mpsc_rst_u32_len
	#elif _ODP_RING_SYNC == _ODP_RING_SYNC_SPMC
		#define _ring_xpxc_rst_gen_t		ring_spmc_rst_u32_t
		#define _ring_xpxc_rst_data_t		uint32_t

		#define _RING_XPXC_RST_INIT		ring_spmc_rst_u32_init
		#define _RING_SPMC_RST_ENQ_MULTI	ring_spmc_rst_u32_enq_multi
		#define _RING_MPMC_RST_DEQ_MULTI	ring_spmc_rst_u32_deq_multi
		#define _RING_MPMC_RST_DEQ_BATCH	ring_spmc_rst_u32_deq_batch
		#define _RING_XPXC_RST_LEN		ring_spmc_rst_u32_len
	#else
		#define _ring_xpxc_rst_gen_t		ring_mpmc_rst_u32_t
		#define _ring_xpxc_rst_data_t		uint32_t

		#define _RING_XPXC_RST_INIT		ring_mpmc_rst_u32_init
		#define _RING_MPMC_RST_DEQ		ring_mpmc_rst_u32_deq
		#define _RING_MPMC_RST_DEQ_MULTI	ring_mpmc_rst_u32_deq_multi
		#define _RING_MPMC_RST_DEQ_BATCH	ring_mpmc_rst_u32_deq_batch
		#define _RING_MPMC_RST_ENQ		ring_mpmc_rst_u32_enq
		#define _RING_MPMC_RST_ENQ_MULTI	ring_mpmc_rst_u32_enq_multi
		#define _RING_XPXC_RST_LEN		ring_mpmc_rst_u32_len
	#endif
#elif _ODP_RING_TYPE == _ODP_RING_TYPE_U64
	#if _ODP_RING_SYNC == _ODP_RING_SYNC_MPSC
		#define _ring_xpxc_rst_gen_t		ring_mpsc_rst_u64_t
		#define _ring_xpxc_rst_data_t		uint64_t

		#define _RING_XPXC_RST_INIT		ring_mpsc_rst_u64_init
		#define _RING_MPMC_RST_ENQ_MULTI	ring_mpsc_rst_u64_enq_multi
		#define _RING_MPSC_RST_DEQ_MULTI	ring_mpsc_rst_u64_deq_multi
		#define _RING_MPSC_RST_DEQ_BATCH	ring_mpsc_rst_u64_deq_batch
		#define _RING_XPXC_RST_LEN		ring_mpsc_rst_u64_len
	#elif _ODP_RING_SYNC == _ODP_RING_SYNC_SPMC
		#define _ring_xpxc_rst_gen_t		ring_spmc_rst_u64_t
		#define _ring_xpxc_rst_data_t		uint64_t

		#define _RING_XPXC_RST_INIT		ring_spmc_rst_u64_init
		#define _RING_SPMC_RST_ENQ_MULTI	ring_spmc_rst_u64_enq_multi
		#define _RING_MPMC_RST_DEQ_MULTI	ring_spmc_rst_u64_deq_multi
		#define _RING_MPMC_RST_DEQ_BATCH	ring_spmc_rst_u64_deq_batch
		#define _RING_XPXC_RST_LEN		ring_spmc_rst_u64_len
	#else
		#define _ring_xpxc_rst_gen_t		ring_mpmc_rst_u64_t
		#define _ring_xpxc_rst_data_t		uint64_t

		#define _RING_XPXC_RST_INIT		ring_mpmc_rst_u64_init
		#define _RING_MPMC_RST_DEQ		ring_mpmc_rst_u64_deq
		#define _RING_MPMC_RST_DEQ_MULTI	ring_mpmc_rst_u64_deq_multi
		#define _RING_MPMC_RST_DEQ_BATCH	ring_mpmc_rst_u64_deq_batch
		#define _RING_MPMC_RST_ENQ		ring_mpmc_rst_u64_enq
		#define _RING_MPMC_RST_ENQ_MULTI	ring_mpmc_rst_u64_enq_multi
		#define _RING_XPXC_RST_LEN		ring_mpmc_rst_u64_len
	#endif
#elif _ODP_RING_TYPE == _ODP_RING_TYPE_PTR
	#if _ODP_RING_SYNC == _ODP_RING_SYNC_MPSC
		#define _ring_xpxc_rst_gen_t		ring_mpsc_rst_ptr_t
		#define _ring_xpxc_rst_data_t		void *

		#define _RING_XPXC_RST_INIT		ring_mpsc_rst_ptr_init
		#define _RING_MPMC_RST_ENQ_MULTI	ring_mpsc_rst_ptr_enq_multi
		#define _RING_MPSC_RST_DEQ_MULTI	ring_mpsc_rst_ptr_deq_multi
		#define _RING_MPSC_RST_DEQ_BATCH	ring_mpsc_rst_ptr_deq_batch
		#define _RING_XPXC_RST_LEN		ring_mpsc_rst_ptr_len
	#elif _ODP_RING_SYNC == _ODP_RING_SYNC_SPMC
		#define _ring_xpxc_rst_gen_t		ring_spmc_rst_ptr_t
		#define _ring_xpxc_rst_data_t		void *

		#define _RING_XPXC_RST_INIT		ring_spmc_rst_ptr_init
		#define _RING_SPMC_RST_ENQ_MULTI	ring_spmc_rst_ptr_enq_multi
		#define _RING_MPMC_RST_DEQ_MULTI	ring_spmc_rst_ptr_deq_multi
		#define _RING_MPMC_RST_DEQ_BATCH	ring_spmc_rst_ptr_deq_batch
		#define _RING_XPXC_RST_LEN		ring_spmc_rst_ptr_len
	#else
		#define _ring_xpxc_rst_gen_t		ring_mpmc_rst_ptr_t
		#define _ring_xpxc_rst_data_t		void *

		#define _RING_XPXC_RST_INIT		ring_mpmc_rst_ptr_init
		#define _RING_MPMC_RST_DEQ		ring_mpmc_rst_ptr_deq
		#define _RING_MPMC_RST_DEQ_MULTI	ring_mpmc_rst_ptr_deq_multi
		#define _RING_MPMC_RST_DEQ_BATCH	ring_mpmc_rst_ptr_deq_batch
		#define _RING_MPMC_RST_ENQ		ring_mpmc_rst_ptr_enq
		#define _RING_MPMC_RST_ENQ_MULTI	ring_mpmc_rst_ptr_enq_multi
		#define _RING_XPXC_RST_LEN		ring_mpmc_rst_ptr_len
	#endif
#endif

/* Initialize ring */
static inline void _RING_XPXC_RST_INIT(_ring_xpxc_rst_gen_t *ring)
{
	odp_atomic_init_u32(&ring->r.w_head, 0);
	odp_atomic_init_u32(&ring->r.w_tail, 0);
	odp_atomic_init_u32(&ring->r.r_head, 0);
	odp_atomic_init_u32(&ring->r.r_tail, 0);
}

#ifdef _RING_MPMC_RST_DEQ
/* Dequeue data from the ring head */
static inline uint32_t _RING_MPMC_RST_DEQ(_ring_xpxc_rst_gen_t *ring, uint32_t mask,
					  _ring_xpxc_rst_data_t *data)
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
#endif

#ifdef _RING_MPMC_RST_DEQ_MULTI
/* Dequeue multiple data from the ring head. Num is smaller than ring size. */
static inline uint32_t _RING_MPMC_RST_DEQ_MULTI(_ring_xpxc_rst_gen_t *ring, uint32_t mask,
						_ring_xpxc_rst_data_t data[], uint32_t num)
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
#endif

#ifdef _RING_MPSC_RST_DEQ_MULTI
/* Single-consumer dequeue of multiple data items from the ring head. Num is
 * smaller than ring size. */
static inline uint32_t _RING_MPSC_RST_DEQ_MULTI(_ring_xpxc_rst_gen_t *ring, uint32_t mask,
						_ring_xpxc_rst_data_t data[], uint32_t num)
{
	uint32_t head, tail, new_head, i;

	/* Head value is always behind or equal to tail value */
	head = odp_atomic_load_u32(&ring->r.r_head);
	tail = odp_atomic_load_acq_u32(&ring->r.w_tail);

	/* Ring is empty */
	if (head == tail)
		return 0;

	/* Try to take all available */
	if ((tail - head) < num)
		num = tail - head;

	new_head = head + num;

	/* Reserve the slots. Relaxed store is enough as there are no other
	 * readers. Writers only read r_tail, which is updated below. */
	odp_atomic_store_u32(&ring->r.r_head, new_head);

	/* Read data. */
	for (i = 0; i < num; i++)
		data[i] = ring->data[(head + 1 + i) & mask];

	/* Update the tail. Writers acquire it. */
	odp_atomic_store_rel_u32(&ring->r.r_tail, new_head);

	return num;
}
#endif

#ifdef _RING_MPMC_RST_DEQ_BATCH
/* Dequeue batch of data (0 or num) from the ring head. Num is smaller than ring size. */
static inline uint32_t _RING_MPMC_RST_DEQ_BATCH(_ring_xpxc_rst_gen_t *ring, uint32_t mask,
						_ring_xpxc_rst_data_t data[], uint32_t num)
{
	uint32_t head, tail, new_head, i;

	/* Load/CAS acquire of r_head ensures that w_tail load happens after
	 * r_head load, and thus head value is always behind or equal to tail
	 * value. */
	head = odp_atomic_load_acq_u32(&ring->r.r_head);

	/* Move reader head. This thread owns data at the new head. */
	do {
		tail = odp_atomic_load_acq_u32(&ring->r.w_tail);

		/* Not enough data available */
		if ((tail - head) < num)
			return 0;

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
#endif

#ifdef _RING_MPSC_RST_DEQ_BATCH
/* Single-consumer batch dequeue of data items from the ring head. Num is
 * smaller than ring size. */
static inline uint32_t _RING_MPSC_RST_DEQ_BATCH(_ring_xpxc_rst_gen_t *ring, uint32_t mask,
						_ring_xpxc_rst_data_t data[], uint32_t num)
{
	uint32_t head, tail, new_head, i;

	/* Head value is always behind or equal to tail value */
	head = odp_atomic_load_u32(&ring->r.r_head);
	tail = odp_atomic_load_acq_u32(&ring->r.w_tail);

	/* Not enough data available */
	if ((tail - head) < num)
		return 0;

	new_head = head + num;

	odp_atomic_store_u32(&ring->r.r_head, new_head);

	/* Read data. */
	for (i = 0; i < num; i++)
		data[i] = ring->data[(head + 1 + i) & mask];

	/* Update the tail. Writers acquire it. */
	odp_atomic_store_rel_u32(&ring->r.r_tail, new_head);

	return num;
}
#endif

#ifdef _RING_MPMC_RST_ENQ
/* Enqueue data into the ring tail */
static inline void _RING_MPMC_RST_ENQ(_ring_xpxc_rst_gen_t *ring, uint32_t mask,
				      _ring_xpxc_rst_data_t data)
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
#endif

#ifdef _RING_MPMC_RST_ENQ_MULTI
/* Enqueue multiple data into the ring tail. Num is smaller than ring size. */
static inline void _RING_MPMC_RST_ENQ_MULTI(_ring_xpxc_rst_gen_t *ring, uint32_t mask,
					    _ring_xpxc_rst_data_t data[], uint32_t num)
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
#endif

#ifdef _RING_SPMC_RST_ENQ_MULTI
/* Single-producer enqueue of multiple data items into the ring tail. Num is
 * smaller than ring size. */
static inline void _RING_SPMC_RST_ENQ_MULTI(_ring_xpxc_rst_gen_t *ring, uint32_t mask,
					    _ring_xpxc_rst_data_t data[], uint32_t num)
{
	uint32_t old_head, new_head, i;
	uint32_t size = mask + 1;

	/* Reserve the slots for writing. Relaxed load and store are enough as
	 * there are no other writers. */
	old_head = odp_atomic_load_u32(&ring->r.w_head);
	odp_atomic_store_u32(&ring->r.w_head, old_head + num);
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

	/* Release the new writer tail, readers acquire it. */
	odp_atomic_store_rel_u32(&ring->r.w_tail, old_head + num);
}
#endif

static inline uint32_t _RING_XPXC_RST_LEN(_ring_xpxc_rst_gen_t *ring)
{
	uint32_t head = odp_atomic_load_u32(&ring->r.r_head);
	uint32_t tail = odp_atomic_load_u32(&ring->r.w_tail);

	return tail - head;
}

#ifdef __cplusplus
}
#endif
