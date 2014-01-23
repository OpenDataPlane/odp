/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
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

#include <odp_shared_memory.h>
#include <odp_internal.h>
#include <odp_spin_internal.h>
#include <odp_spinlock.h>
#include <odp_align.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <odp_ring.h>


/*
 * the enqueue of pointers on the ring.
 */
#define ENQUEUE_PTRS() do { \
	const uint32_t size = r->prod.size; \
	uint32_t idx = prod_head & mask; \
	if (odp_likely(idx + n < size)) { \
		for (i = 0; i < (n & ((~(unsigned)0x3))); i += 4, idx += 4) { \
			r->ring[idx] = obj_table[i]; \
			r->ring[idx+1] = obj_table[i+1]; \
			r->ring[idx+2] = obj_table[i+2]; \
			r->ring[idx+3] = obj_table[i+3]; \
		} \
		switch (n & 0x3) { \
		case 3: \
		r->ring[idx++] = obj_table[i++]; \
		case 2: \
		r->ring[idx++] = obj_table[i++]; \
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
			obj_table[i+1] = r->ring[idx+1]; \
			obj_table[i+2] = r->ring[idx+2]; \
			obj_table[i+3] = r->ring[idx+3]; \
		} \
		switch (n & 0x3) { \
		case 3: \
		obj_table[i++] = r->ring[idx++]; \
		case 2: \
		obj_table[i++] = r->ring[idx++]; \
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

/* create the ring */
odp_ring_t *
odp_ring_create(const char *name, unsigned count, unsigned flags)
{
	char ring_name[ODP_RING_NAMESIZE];
	odp_ring_t *r;
	size_t ring_size;

	/* count must be a power of 2 */
	if (!ODP_VAL_IS_POWER_2(count) || (count > ODP_RING_SZ_MASK)) {
		printf("Requested size is invalid, must be power of 2, and  do not exceed the size limit %u\n",
		       ODP_RING_SZ_MASK);
		return NULL;
	}

	snprintf(ring_name, sizeof(ring_name), "%s", name);
	ring_size = count*sizeof(void *)+sizeof(odp_ring_t);

	/* reserve a memory zone for this ring.*/
	r = odp_shm_reserve(ring_name, ring_size, ODP_CACHE_LINE_SIZE);

	if (r != NULL) {
		/* init the ring structure */
		snprintf(r->name, sizeof(r->name), "%s", name);
		r->flags = flags;
		r->prod.watermark = count;
		r->prod.sp_enqueue = !!(flags & RING_F_SP_ENQ);
		r->cons.sc_dequeue = !!(flags & RING_F_SC_DEQ);
		r->prod.size = count;
		r->cons.size = count;
		r->prod.mask = count-1;
		r->cons.mask = count-1;
		r->prod.head = 0;
		r->cons.head = 0;
		r->prod.tail = 0;
		r->cons.tail = 0;
	} else {
		printf("Cannot reserve memory\n");
	}

	return r;
}

/*
 * change the high water mark. If *count* is 0, water marking is
 * disabled
 */
int odp_ring_set_water_mark(odp_ring_t *r, unsigned count)
{
	if (count >= r->prod.size)
		return -EINVAL;

	/* if count is 0, disable the watermarking */
	if (count == 0)
		count = r->prod.size;

	r->prod.watermark = count;
	return 0;
}

/**
 * Enqueue several objects on the ring (multi-producers safe).
 */
int __odp_ring_mp_do_enqueue(odp_ring_t *r, void * const *obj_table,
			 unsigned n, enum odp_ring_queue_behavior behavior)
{
	uint32_t prod_head, prod_next;
	uint32_t cons_tail, free_entries;
	const unsigned max = n;
	int success;
	unsigned i;
	uint32_t mask = r->prod.mask;
	int ret;

	/* move prod.head atomically */
	do {
		/* Reset n to the initial burst count */
		n = max;

		prod_head = r->prod.head;
		cons_tail = r->cons.tail;
		/* The subtraction is done between two unsigned 32bits value
		 * (the result is always modulo 32 bits even if we have
		 * prod_head > cons_tail). So 'free_entries' is always between 0
		 * and size(ring)-1. */
		free_entries = (mask + cons_tail - prod_head);

		/* check that we have enough room in ring */
		if (odp_unlikely(n > free_entries)) {
			if (behavior == ODP_RING_QUEUE_FIXED) {
				return -ENOBUFS;
			} else {
				/* No free entry available */
				if (odp_unlikely(free_entries == 0))
					return 0;

				n = free_entries;
			}
		}

		prod_next = prod_head + n;
		success = odp_atomic32_cmpset(&r->prod.head, prod_head,
					      prod_next);
	} while (odp_unlikely(success == 0));

	/* write entries in ring */
	ENQUEUE_PTRS();
	odp_mem_barrier();

	/* if we exceed the watermark */
	if (odp_unlikely(((mask + 1) - free_entries + n) > r->prod.watermark)) {
		ret = (behavior == ODP_RING_QUEUE_FIXED) ? -EDQUOT :
				(int)(n | ODP_RING_QUOT_EXCEED);
	} else {
		ret = (behavior == ODP_RING_QUEUE_FIXED) ? 0 : n;
	}

	/*
	 * If there are other enqueues in progress that preceeded us,
	 * we need to wait for them to complete
	 */
	while (odp_unlikely(r->prod.tail != prod_head))
		odp_spin();

	r->prod.tail = prod_next;
	return ret;
}

/**
 * Dequeue several objects from a ring (multi-consumers safe).
 */

int __odp_ring_mc_do_dequeue(odp_ring_t *r, void **obj_table,
			 unsigned n, enum odp_ring_queue_behavior behavior)
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

		cons_head = r->cons.head;
		prod_tail = r->prod.tail;
		/* The subtraction is done between two unsigned 32bits value
		 * (the result is always modulo 32 bits even if we have
		 * cons_head > prod_tail). So 'entries' is always between 0
		 * and size(ring)-1. */
		entries = (prod_tail - cons_head);

		/* Set the actual entries for dequeue */
		if (n > entries) {
			if (behavior == ODP_RING_QUEUE_FIXED) {
				return -ENOENT;
			} else {
				if (odp_unlikely(entries == 0))
					return 0;

				n = entries;
			}
		}

		cons_next = cons_head + n;
		success = odp_atomic32_cmpset(&r->cons.head, cons_head,
					      cons_next);
	} while (odp_unlikely(success == 0));

	/* copy in table */
	DEQUEUE_PTRS();
	odp_mem_barrier();

	/*
	 * If there are other dequeues in progress that preceded us,
	 * we need to wait for them to complete
	 */
	while (odp_unlikely(r->cons.tail != cons_head))
		odp_spin();

	r->cons.tail = cons_next;

	return behavior == ODP_RING_QUEUE_FIXED ? 0 : n;
}


/**
 * Enqueue several objects on the ring (multi-producers safe).
 */
int odp_ring_mp_enqueue_bulk(odp_ring_t *r, void * const *obj_table,
				unsigned n)
{
	return __odp_ring_mp_do_enqueue(r, obj_table, n, ODP_RING_QUEUE_FIXED);
}

/**
 * Dequeue several objects from a ring (multi-consumers safe).
 */
int odp_ring_mc_dequeue_bulk(odp_ring_t *r, void **obj_table, unsigned n)
{
	return __odp_ring_mc_do_dequeue(r, obj_table, n, ODP_RING_QUEUE_FIXED);
}

/**
 * Test if a ring is full.
 */
int odp_ring_full(const odp_ring_t *r)
{
	uint32_t prod_tail = r->prod.tail;
	uint32_t cons_tail = r->cons.tail;
	return (((cons_tail - prod_tail - 1) & r->prod.mask) == 0);
}

/**
 * Test if a ring is empty.
 */
int odp_ring_empty(const odp_ring_t *r)
{
	uint32_t prod_tail = r->prod.tail;
	uint32_t cons_tail = r->cons.tail;
	return !!(cons_tail == prod_tail);
}

/**
 * Return the number of entries in a ring.
 */
unsigned odp_ring_count(const odp_ring_t *r)
{
	uint32_t prod_tail = r->prod.tail;
	uint32_t cons_tail = r->cons.tail;
	return (prod_tail - cons_tail) & r->prod.mask;
}

/**
 * Return the number of free entries in a ring.
 */
unsigned odp_ring_free_count(const odp_ring_t *r)
{
	uint32_t prod_tail = r->prod.tail;
	uint32_t cons_tail = r->cons.tail;
	return (cons_tail - prod_tail - 1) & r->prod.mask;
}

/* dump the status of the ring on the console */
void odp_ring_dump(const odp_ring_t *r)
{
	printf("ring <%s>@%p\n", r->name, r);
	printf("  flags=%x\n", r->flags);
	printf("  size=%"PRIu32"\n", r->prod.size);
	printf("  ct=%"PRIu32"\n", r->cons.tail);
	printf("  ch=%"PRIu32"\n", r->cons.head);
	printf("  pt=%"PRIu32"\n", r->prod.tail);
	printf("  ph=%"PRIu32"\n", r->prod.head);
	printf("  used=%u\n", odp_ring_count(r));
	printf("  avail=%u\n", odp_ring_free_count(r));
	if (r->prod.watermark == r->prod.size)
		printf("  watermark=0\n");
	else
		printf("  watermark=%"PRIu32"\n", r->prod.watermark);
}

/* search a ring from its name */
odp_ring_t *odp_ring_lookup(const char *name)
{
	odp_ring_t *r = odp_shm_lookup(name);

	return (strncmp(name, r->name, ODP_RING_NAMESIZE) == 0) ? r : NULL;
}
