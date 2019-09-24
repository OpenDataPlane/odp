/* Copyright (c) 2014-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2013 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Derived from FreeBSD's bufring.c
 *
 **************************************************************************
 *
 * Copyright (c) 2007,2008 Kip Macy kmacy@freebsd.org
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. The name of Kip Macy nor the names of other
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 ***************************************************************************/

#include <odp_api.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>
#include <odp_packet_io_ring_internal.h>
#include <odp_errno_define.h>
#include <odp_global_data.h>

#include <odp/api/plat/cpu_inlines.h>

#define RING_VAL_IS_POWER_2(x) ((((x) - 1) & (x)) == 0)

typedef struct {
	TAILQ_HEAD(, _ring) ring_list;
	/* Rings tailq lock */
	odp_rwlock_t qlock;
	odp_shm_t shm;
} global_data_t;

static global_data_t *global;

/*
 * the enqueue of pointers on the ring.
 */
#define ENQUEUE_PTRS() do { \
	const uint32_t size = r->prod.size; \
	uint32_t idx = prod_head & mask; \
	if (odp_likely(idx + n < size)) { \
		for (i = 0; i < (n & ((~(unsigned)0x3))); i += 4, idx += 4) { \
			r->ring[idx] = obj_table[i]; \
			r->ring[idx + 1] = obj_table[i + 1]; \
			r->ring[idx + 2] = obj_table[i + 2]; \
			r->ring[idx + 3] = obj_table[i + 3]; \
		} \
		switch (n & 0x3) { \
		case 3: \
		r->ring[idx++] = obj_table[i++]; \
		/* fallthrough */ \
		case 2: \
		r->ring[idx++] = obj_table[i++]; \
		/* fallthrough */ \
		case 1: \
		r->ring[idx++] = obj_table[i++]; \
		} \
	} else { \
		for (i = 0; idx < size; i++, idx++)\
			r->ring[idx] = obj_table[i]; \
		for (idx = 0; i < n; i++, idx++) \
			r->ring[idx] = obj_table[i]; \
	} \
} while (0)

/*
 * the actual copy of pointers on the ring to obj_table.
 */
#define DEQUEUE_PTRS() do { \
	uint32_t idx = cons_head & mask; \
	const uint32_t size = r->cons.size; \
	if (odp_likely(idx + n < size)) { \
		for (i = 0; i < (n & (~(unsigned)0x3)); i += 4, idx += 4) {\
			obj_table[i] = r->ring[idx]; \
			obj_table[i + 1] = r->ring[idx + 1]; \
			obj_table[i + 2] = r->ring[idx + 2]; \
			obj_table[i + 3] = r->ring[idx + 3]; \
		} \
		switch (n & 0x3) { \
		case 3: \
		obj_table[i++] = r->ring[idx++]; \
		/* fallthrough */ \
		case 2: \
		obj_table[i++] = r->ring[idx++]; \
		/* fallthrough */ \
		case 1: \
		obj_table[i++] = r->ring[idx++]; \
		} \
	} else { \
		for (i = 0; idx < size; i++, idx++) \
			obj_table[i] = r->ring[idx]; \
		for (idx = 0; i < n; i++, idx++) \
			obj_table[i] = r->ring[idx]; \
	} \
} while (0)


/* Initialize tailq_ring */
int _ring_tailq_init(void)
{	odp_shm_t shm;

	/* Allocate globally shared memory */
	shm = odp_shm_reserve("_odp_ring_global", sizeof(global_data_t),
			      ODP_CACHE_LINE_SIZE, 0);
	if (ODP_SHM_INVALID == shm) {
		ODP_ERR("Shm reserve failed for pktio ring\n");
		return -1;
	}

	global = odp_shm_addr(shm);
	memset(global, 0, sizeof(global_data_t));
	global->shm = shm;

	TAILQ_INIT(&global->ring_list);
	odp_rwlock_init(&global->qlock);

	return 0;
}

/* Terminate tailq_ring */
int _ring_tailq_term(void)
{
	if (odp_shm_free(global->shm)) {
		ODP_ERR("Shm free failed for pktio ring\n");
		return -1;
	}
	return 0;
}

/* create the ring */
_ring_t *
_ring_create(const char *name, unsigned count, unsigned flags)
{
	char ring_name[_RING_NAMESIZE];
	_ring_t *r;
	size_t ring_size;
	uint32_t shm_flag;
	odp_shm_t shm;

	if (flags & _RING_SHM_PROC)
		shm_flag = ODP_SHM_PROC | ODP_SHM_EXPORT;
	else
		shm_flag = 0;
	if (odp_global_ro.shm_single_va)
		shm_flag |= ODP_SHM_SINGLE_VA;

	/* count must be a power of 2 */
	if (!RING_VAL_IS_POWER_2(count) || (count > _RING_SZ_MASK)) {
		ODP_ERR("Requested size is invalid, must be power of 2,"
			"and do not exceed the size limit %u\n",
			_RING_SZ_MASK);
		__odp_errno = EINVAL;
		return NULL;
	}

	snprintf(ring_name, sizeof(ring_name), "%s", name);
	ring_size = count * sizeof(void *) + sizeof(_ring_t);

	odp_rwlock_write_lock(&global->qlock);
	/* reserve a memory zone for this ring.*/
	shm = odp_shm_reserve(ring_name, ring_size, ODP_CACHE_LINE_SIZE,
			      shm_flag);

	r = odp_shm_addr(shm);

	if (r != NULL) {
		/* init the ring structure */
		snprintf(r->name, sizeof(r->name), "%s", name);
		r->flags = flags;
		r->prod.size = count;
		r->cons.size = count;
		r->prod.mask = count - 1;
		r->cons.mask = count - 1;
		r->prod.head = 0;
		r->cons.head = 0;
		r->prod.tail = 0;
		r->cons.tail = 0;

		if (!(flags & _RING_NO_LIST))
			TAILQ_INSERT_TAIL(&global->ring_list, r, next);
	} else {
		__odp_errno = ENOMEM;
		ODP_ERR("Cannot reserve memory\n");
	}

	odp_rwlock_write_unlock(&global->qlock);
	return r;
}

int _ring_destroy(const char *name)
{
	odp_shm_t shm = odp_shm_lookup(name);

	if (shm != ODP_SHM_INVALID) {
		_ring_t *r = odp_shm_addr(shm);

		odp_rwlock_write_lock(&global->qlock);
		if (!(r->flags & _RING_NO_LIST))
			TAILQ_REMOVE(&global->ring_list, r, next);
		odp_rwlock_write_unlock(&global->qlock);

		return odp_shm_free(shm);
	}
	return 0;
}

/**
 * Enqueue several objects on the ring (multi-producers safe).
 */
int ___ring_mp_do_enqueue(_ring_t *r, void * const *obj_table,
			  unsigned n, enum _ring_queue_behavior behavior)
{
	uint32_t prod_head, prod_next;
	uint32_t cons_tail, free_entries;
	const unsigned max = n;
	int success;
	unsigned i;
	uint32_t mask = r->prod.mask;

	/* move prod.head atomically */
	do {
		/* Reset n to the initial burst count */
		n = max;

		prod_head = __atomic_load_n(&r->prod.head, __ATOMIC_ACQUIRE);
		cons_tail = __atomic_load_n(&r->cons.tail, __ATOMIC_ACQUIRE);
		/* The subtraction is done between two unsigned 32bits value
		 * (the result is always modulo 32 bits even if we have
		 * prod_head > cons_tail). So 'free_entries' is always between 0
		 * and size(ring)-1. */
		free_entries = (mask + cons_tail - prod_head);

		/* check that we have enough room in ring */
		if (odp_unlikely(n > free_entries)) {
			if (behavior == _RING_QUEUE_FIXED)
				return -ENOBUFS;
			/* No free entry available */
			if (odp_unlikely(free_entries == 0))
				return 0;

			n = free_entries;
		}

		prod_next = prod_head + n;
		success = __atomic_compare_exchange_n(&r->prod.head,
						      &prod_head,
						      prod_next,
						      false/*strong*/,
						      __ATOMIC_ACQUIRE,
						      __ATOMIC_RELAXED);
	} while (odp_unlikely(success == 0));

	/* write entries in ring */
	ENQUEUE_PTRS();

	/*
	 * If there are other enqueues in progress that preceded us,
	 * we need to wait for them to complete
	 */
	while (odp_unlikely(__atomic_load_n(&r->prod.tail, __ATOMIC_RELAXED) !=
			    prod_head))
		odp_cpu_pause();

	/* Release our entries and the memory they refer to */
	__atomic_store_n(&r->prod.tail, prod_next, __ATOMIC_RELEASE);
	return (behavior == _RING_QUEUE_FIXED) ? 0 : n;
}

/**
 * Dequeue several objects from a ring (multi-consumers safe).
 */

int ___ring_mc_do_dequeue(_ring_t *r, void **obj_table,
			  unsigned n, enum _ring_queue_behavior behavior)
{
	uint32_t cons_head, prod_tail;
	uint32_t cons_next, entries;
	const unsigned max = n;
	int success;
	unsigned i;
	uint32_t mask = r->prod.mask;

	/* move cons.head atomically */
	do {
		/* Restore n as it may change every loop */
		n = max;

		cons_head = __atomic_load_n(&r->cons.head, __ATOMIC_ACQUIRE);
		prod_tail = __atomic_load_n(&r->prod.tail, __ATOMIC_ACQUIRE);
		/* The subtraction is done between two unsigned 32bits value
		 * (the result is always modulo 32 bits even if we have
		 * cons_head > prod_tail). So 'entries' is always between 0
		 * and size(ring)-1. */
		entries = (prod_tail - cons_head);

		/* Set the actual entries for dequeue */
		if (n > entries) {
			if (behavior == _RING_QUEUE_FIXED)
				return -ENOENT;
			if (odp_unlikely(entries == 0))
				return 0;

			n = entries;
		}

		cons_next = cons_head + n;
		success = __atomic_compare_exchange_n(&r->cons.head,
						      &cons_head,
						      cons_next,
						      false/*strong*/,
						      __ATOMIC_ACQUIRE,
						      __ATOMIC_RELAXED);
	} while (odp_unlikely(success == 0));

	/* copy in table */
	DEQUEUE_PTRS();

	/*
	 * If there are other dequeues in progress that preceded us,
	 * we need to wait for them to complete
	 */
	while (odp_unlikely(__atomic_load_n(&r->cons.tail, __ATOMIC_RELAXED) !=
					    cons_head))
		odp_cpu_pause();

	/* Release our entries and the memory they refer to */
	__atomic_store_n(&r->cons.tail, cons_next, __ATOMIC_RELEASE);

	return behavior == _RING_QUEUE_FIXED ? 0 : n;
}

/**
 * Enqueue several objects on the ring (multi-producers safe).
 */
int _ring_mp_enqueue_bulk(_ring_t *r, void * const *obj_table,
			  unsigned n)
{
	return ___ring_mp_do_enqueue(r, obj_table, n,
					 _RING_QUEUE_FIXED);
}

/**
 * Dequeue several objects from a ring (multi-consumers safe).
 */
int _ring_mc_dequeue_bulk(_ring_t *r, void **obj_table, unsigned n)
{
	return ___ring_mc_do_dequeue(r, obj_table, n,
					 _RING_QUEUE_FIXED);
}

/**
 * Test if a ring is full.
 */
int _ring_full(const _ring_t *r)
{
	uint32_t prod_tail = r->prod.tail;
	uint32_t cons_tail = r->cons.tail;

	return (((cons_tail - prod_tail - 1) & r->prod.mask) == 0);
}

/**
 * Test if a ring is empty.
 */
int _ring_empty(const _ring_t *r)
{
	uint32_t prod_tail = r->prod.tail;
	uint32_t cons_tail = r->cons.tail;

	return !!(cons_tail == prod_tail);
}

/**
 * Return the number of entries in a ring.
 */
unsigned _ring_count(const _ring_t *r)
{
	uint32_t prod_tail = r->prod.tail;
	uint32_t cons_tail = r->cons.tail;

	return (prod_tail - cons_tail) & r->prod.mask;
}

/**
 * Return the number of free entries in a ring.
 */
unsigned _ring_free_count(const _ring_t *r)
{
	uint32_t prod_tail = r->prod.tail;
	uint32_t cons_tail = r->cons.tail;

	return (cons_tail - prod_tail - 1) & r->prod.mask;
}

/* dump the status of the ring on the console */
void _ring_dump(const _ring_t *r)
{
	ODP_DBG("ring <%s>@%p\n", r->name, r);
	ODP_DBG("  flags=%x\n", r->flags);
	ODP_DBG("  size=%" PRIu32 "\n", r->prod.size);
	ODP_DBG("  ct=%" PRIu32 "\n", r->cons.tail);
	ODP_DBG("  ch=%" PRIu32 "\n", r->cons.head);
	ODP_DBG("  pt=%" PRIu32 "\n", r->prod.tail);
	ODP_DBG("  ph=%" PRIu32 "\n", r->prod.head);
	ODP_DBG("  used=%u\n", _ring_count(r));
	ODP_DBG("  avail=%u\n", _ring_free_count(r));
}

/* dump the status of all rings on the console */
void _ring_list_dump(void)
{
	const _ring_t *mp = NULL;

	odp_rwlock_read_lock(&global->qlock);

	TAILQ_FOREACH(mp, &global->ring_list, next) {
		_ring_dump(mp);
	}

	odp_rwlock_read_unlock(&global->qlock);
}

/* search a ring from its name */
_ring_t *_ring_lookup(const char *name)
{
	_ring_t *r;

	odp_rwlock_read_lock(&global->qlock);
	TAILQ_FOREACH(r, &global->ring_list, next) {
		if (strncmp(name, r->name, _RING_NAMESIZE) == 0)
			break;
	}
	odp_rwlock_read_unlock(&global->qlock);

	return r;
}

/**
 * Enqueue several objects on the ring (multi-producers safe).
 */
int _ring_mp_enqueue_burst(_ring_t *r, void * const *obj_table,
			   unsigned n)
{
	return ___ring_mp_do_enqueue(r, obj_table, n,
					 _RING_QUEUE_VARIABLE);
}

/**
 * Dequeue several objects from a ring (multi-consumers safe).
 */
int _ring_mc_dequeue_burst(_ring_t *r, void **obj_table, unsigned n)
{
	return ___ring_mc_do_dequeue(r, obj_table, n,
					_RING_QUEUE_VARIABLE);
}
