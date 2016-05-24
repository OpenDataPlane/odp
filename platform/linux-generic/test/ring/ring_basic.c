/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP ring basic test
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <test_debug.h>
#include <odp_cunit_common.h>
#include <odp_packet_io_ring_internal.h>

#include "ring_suites.h"

/* labor functions declaration */
static void __do_basic_burst(_ring_t *r);
static void __do_basic_bulk(_ring_t *r);
static void __do_basic_watermark(_ring_t *r);

/* dummy object pointers for enqueue and dequeue testing */
static void **test_enq_data;
static void **test_deq_data;

/* create two rings: one for single thread usage scenario
 * and another for multiple thread usage scenario.
 * st - single thread usage scenario
 * mt - multiple thread usage scenario
 */
static const char *st_ring_name = "ST basic ring";
static const char *mt_ring_name = "MT basic ring";
static _ring_t *st_ring, *mt_ring;

int ring_test_basic_start(void)
{
	int i = 0;

	/* alloc dummy object pointers for enqueue testing */
	test_enq_data = malloc(RING_SIZE * 2 * sizeof(void *));
	if (NULL == test_enq_data) {
		LOG_ERR("failed to allocate basic test enqeue data\n");
		return -1;
	}

	for (i = 0; i < RING_SIZE * 2; i++)
		test_enq_data[i] = (void *)(unsigned long)i;

	/* alloc dummy object pointers for dequeue testing */
	test_deq_data = malloc(RING_SIZE * 2 * sizeof(void *));
	if (NULL == test_deq_data) {
		LOG_ERR("failed to allocate basic test dequeue data\n");
		free(test_enq_data); test_enq_data = NULL;
		return -1;
	}

	memset(test_deq_data, 0, RING_SIZE * 2 * sizeof(void *));
	return 0;
}

int ring_test_basic_end(void)
{
	free(test_enq_data);
	free(test_deq_data);
	return 0;
}

/* basic test cases */
void ring_test_basic_create(void)
{
	/* prove illegal size shall fail */
	st_ring = _ring_create(st_ring_name, ILLEGAL_SIZE, 0);
	CU_ASSERT(NULL == st_ring);
	CU_ASSERT(EINVAL == __odp_errno);

	/* create ring for single thread usage scenario */
	st_ring = _ring_create(st_ring_name, RING_SIZE,
			       _RING_F_SP_ENQ | _RING_F_SC_DEQ);

	CU_ASSERT(NULL != st_ring);
	CU_ASSERT(_ring_lookup(st_ring_name) == st_ring);

	/* create ring for multiple thread usage scenario */
	mt_ring = _ring_create(mt_ring_name, RING_SIZE,
			       _RING_SHM_PROC);

	CU_ASSERT(NULL != mt_ring);
	CU_ASSERT(_ring_lookup(mt_ring_name) == mt_ring);
}

void ring_test_basic_burst(void)
{
	/* two rounds to cover both single
	 * thread and multiple thread APIs
	 */
	__do_basic_burst(st_ring);
	__do_basic_burst(mt_ring);
}

void ring_test_basic_bulk(void)
{
	__do_basic_bulk(st_ring);
	__do_basic_bulk(mt_ring);
}

void ring_test_basic_watermark(void)
{
	__do_basic_watermark(st_ring);
	__do_basic_watermark(mt_ring);
}

/* labor functions definition */
static void __do_basic_burst(_ring_t *r)
{
	int result = 0;
	unsigned int count = 0;
	void * const *source = test_enq_data;
	void * const *dest = test_deq_data;
	void **enq = NULL, **deq = NULL;

	enq = test_enq_data; deq = test_deq_data;

	/* ring is empty */
	CU_ASSERT(1 == _ring_empty(r));

	/* enqueue 1 object */
	result = _ring_enqueue_burst(r, enq, 1);
	enq += 1;
	CU_ASSERT(1 == (result & _RING_SZ_MASK));

	/* enqueue 2 objects */
	result = _ring_enqueue_burst(r, enq, 2);
	enq += 2;
	CU_ASSERT(2 == (result & _RING_SZ_MASK));

	/* enqueue HALF_BULK objects */
	result = _ring_enqueue_burst(r, enq, HALF_BULK);
	enq += HALF_BULK;
	CU_ASSERT(HALF_BULK == (result & _RING_SZ_MASK));

	/* ring is neither empty nor full */
	CU_ASSERT(0 == _ring_full(r));
	CU_ASSERT(0 == _ring_empty(r));

	/* _ring_count() equals enqueued */
	count = (1 + 2 + HALF_BULK);
	CU_ASSERT(count == _ring_count(r));
	/* _ring_free_count() equals rooms left */
	count = (RING_SIZE - 1) - count;
	CU_ASSERT(count == _ring_free_count(r));

	/* exceed the size, enquene as many as possible */
	result = _ring_enqueue_burst(r, enq, HALF_BULK);
	enq += count;
	CU_ASSERT(count == (result & _RING_SZ_MASK));
	CU_ASSERT(1 == _ring_full(r));

	/* dequeue 1 object */
	result = _ring_dequeue_burst(r, deq, 1);
	deq += 1;
	CU_ASSERT(1 == (result & _RING_SZ_MASK));

	/* dequeue 2 objects */
	result = _ring_dequeue_burst(r, deq, 2);
	deq += 2;
	CU_ASSERT(2 == (result & _RING_SZ_MASK));

	/* dequeue HALF_BULK objects */
	result = _ring_dequeue_burst(r, deq, HALF_BULK);
	deq += HALF_BULK;
	CU_ASSERT(HALF_BULK == (result & _RING_SZ_MASK));

	/* _ring_free_count() equals dequeued */
	count = (1 + 2 + HALF_BULK);
	CU_ASSERT(count == _ring_free_count(r));
	/* _ring_count() equals remained left */
	count = (RING_SIZE - 1) - count;
	CU_ASSERT(count == _ring_count(r));

	/* underrun the size, dequeue as many as possible */
	result = _ring_dequeue_burst(r, deq, HALF_BULK);
	deq += count;
	CU_ASSERT(count == (result & _RING_SZ_MASK));
	CU_ASSERT(1 == _ring_empty(r));

	/* check data */
	CU_ASSERT(0 == memcmp(source, dest, deq - dest));

	/* reset dequeue data */
	memset(test_deq_data, 0, RING_SIZE * 2 * sizeof(void *));
}

/* incomplete ring API set: strange!
 * complement _ring_enqueue/dequeue_bulk to improve coverage
 */
static inline int __ring_enqueue_bulk(
	_ring_t *r, void * const *objects, unsigned bulk)
{
	if (r->prod.sp_enqueue)
		return _ring_sp_enqueue_bulk(r, objects, bulk);
	else
		return _ring_mp_enqueue_bulk(r, objects, bulk);
}

static inline int __ring_dequeue_bulk(
	_ring_t *r, void **objects, unsigned bulk)
{
	if (r->cons.sc_dequeue)
		return _ring_sc_dequeue_bulk(r, objects, bulk);
	else
		return _ring_mc_dequeue_bulk(r, objects, bulk);
}

static void __do_basic_bulk(_ring_t *r)
{
	int result = 0;
	unsigned int count = 0;
	void * const *source = test_enq_data;
	void * const *dest = test_deq_data;
	void **enq = NULL, **deq = NULL;

	enq = test_enq_data; deq = test_deq_data;

	/* ring is empty */
	CU_ASSERT(1 == _ring_empty(r));

	/* enqueue 1 object */
	result = __ring_enqueue_bulk(r, enq, 1);
	enq += 1;
	CU_ASSERT(0 == result);

	/* enqueue 2 objects */
	result = __ring_enqueue_bulk(r, enq, 2);
	enq += 2;
	CU_ASSERT(0 == result);

	/* enqueue HALF_BULK objects */
	result = __ring_enqueue_bulk(r, enq, HALF_BULK);
	enq += HALF_BULK;
	CU_ASSERT(0 == result);

	/* ring is neither empty nor full */
	CU_ASSERT(0 == _ring_full(r));
	CU_ASSERT(0 == _ring_empty(r));

	/* _ring_count() equals enqueued */
	count = (1 + 2 + HALF_BULK);
	CU_ASSERT(count == _ring_count(r));
	/* _ring_free_count() equals rooms left */
	count = (RING_SIZE - 1) - count;
	CU_ASSERT(count == _ring_free_count(r));

	/* exceed the size, enquene shall fail with -ENOBUFS */
	result = __ring_enqueue_bulk(r, enq, HALF_BULK);
	CU_ASSERT(-ENOBUFS == result);

	/* fullful the ring */
	result = __ring_enqueue_bulk(r, enq, count);
	enq += count;
	CU_ASSERT(0 == result);
	CU_ASSERT(1 == _ring_full(r));

	/* dequeue 1 object */
	result = __ring_dequeue_bulk(r, deq, 1);
	deq += 1;
	CU_ASSERT(0 == result);

	/* dequeue 2 objects */
	result = __ring_dequeue_bulk(r, deq, 2);
	deq += 2;
	CU_ASSERT(0 == result);

	/* dequeue HALF_BULK objects */
	result = __ring_dequeue_bulk(r, deq, HALF_BULK);
	deq += HALF_BULK;
	CU_ASSERT(0 == result);

	/* _ring_free_count() equals dequeued */
	count = (1 + 2 + HALF_BULK);
	CU_ASSERT(count == _ring_free_count(r));
	/* _ring_count() equals remained left */
	count = (RING_SIZE - 1) - count;
	CU_ASSERT(count == _ring_count(r));

	/* underrun the size, dequeue shall fail with -ENOENT */
	result = __ring_dequeue_bulk(r, deq, HALF_BULK);
	CU_ASSERT(-ENOENT == result);

	/* empty the queue */
	result = __ring_dequeue_bulk(r, deq, count);
	deq += count;
	CU_ASSERT(0 == result);
	CU_ASSERT(1 == _ring_empty(r));

	/* check data */
	CU_ASSERT(0 == memcmp(source, dest, deq - dest));

	/* reset dequeue data */
	memset(test_deq_data, 0, RING_SIZE * 2 * sizeof(void *));
}

void __do_basic_watermark(_ring_t *r)
{
	int result = 0;
	void * const *source = test_enq_data;
	void * const *dest = test_deq_data;
	void **enq = NULL, **deq = NULL;

	enq = test_enq_data; deq = test_deq_data;

	/* bulk = 3/4 watermark to trigger alarm on 2nd enqueue */
	const unsigned watermark = PIECE_BULK;
	const unsigned bulk = (watermark / 4) * 3;

	/* watermark cannot exceed ring size */
	result = _ring_set_water_mark(r, ILLEGAL_SIZE);
	CU_ASSERT(-EINVAL == result);

	/* set watermark */
	result = _ring_set_water_mark(r, watermark);
	CU_ASSERT(0 == result);

	/* 1st enqueue shall succeed */
	result = __ring_enqueue_bulk(r, enq, bulk);
	enq += bulk;
	CU_ASSERT(0 == result);

	/* 2nd enqueue shall succeed but return -EDQUOT */
	result = __ring_enqueue_bulk(r, enq, bulk);
	enq += bulk;
	CU_ASSERT(-EDQUOT == result);

	/* dequeue 1st bulk */
	result = __ring_dequeue_bulk(r, deq, bulk);
	deq += bulk;
	CU_ASSERT(0 == result);

	/* dequeue 2nd bulk */
	result = __ring_dequeue_bulk(r, deq, bulk);
	deq += bulk;
	CU_ASSERT(0 == result);

	/* check data */
	CU_ASSERT(0 == memcmp(source, dest, deq - dest));

	/* reset watermark */
	result = _ring_set_water_mark(r, 0);
	CU_ASSERT(0 == result);

	/* reset dequeue data */
	memset(test_deq_data, 0, RING_SIZE * 2 * sizeof(void *));
}
