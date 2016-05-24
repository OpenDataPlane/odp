/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP ring stress test
 */

#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <odp_api.h>
#include <odp/helper/linux.h>
#include <odp_packet_io_ring_internal.h>
#include <test_debug.h>
#include <odp_cunit_common.h>

#include "ring_suites.h"

/*
 * Since cunit framework cannot work with multi-threading, ask workers
 * to save their results for delayed assertion after thread collection.
 */
static int worker_results[MAX_WORKERS];

/*
 * Note : make sure that both enqueue and dequeue
 * operation starts at same time so to avoid data corruption
 * Its because atomic lock will protect only indexes, but if order of
 * read or write operation incorrect then data mismatch will happen
 * So its resposibility of application develop to take care of order of
 * data read or write.
 */
typedef enum {
	STRESS_1_1_PRODUCER_CONSUMER,
	STRESS_1_N_PRODUCER_CONSUMER,
	STRESS_N_1_PRODUCER_CONSUMER,
	STRESS_N_M_PRODUCER_CONSUMER
} stress_case_t;

/* worker function declarations */
static int stress_worker(void *_data);
static odp_atomic_u32_t *retrieve_consume_count(void);

/* global name for later look up in workers' context */
static const char *ring_name = "stress ring";
static const char *consume_count_name = "stress ring consume count";

int ring_test_stress_start(void)
{
	odp_shm_t shared;
	_ring_t *r_stress = NULL;

	/* multiple thread usage scenario, thread or process sharable */
	r_stress = _ring_create(ring_name, RING_SIZE, _RING_SHM_PROC);
	if (r_stress == NULL) {
		LOG_ERR("create ring failed for stress.\n");
		return -1;
	}

	/* atomic count for expected data pieces to be consumed
	 * by consumer threads.
	 */
	shared = odp_shm_reserve(consume_count_name,
				 sizeof(odp_atomic_u32_t),
				 sizeof(odp_atomic_u32_t),
				 ODP_SHM_PROC);
	if (shared == ODP_SHM_INVALID) {
		LOG_ERR("create expected consume count failed for stress.\n");
		return -1;
	}
	return 0;
}

int ring_test_stress_end(void)
{
	odp_shm_t shared;

	/* release consume atomic count */
	shared = odp_shm_lookup(consume_count_name);
	if (shared != ODP_SHM_INVALID)
		odp_shm_free(shared);
	return 0;
}

void ring_test_stress_1_1_producer_consumer(void)
{
	int i = 0;
	odp_cpumask_t cpus;
	pthrd_arg worker_param;
	odp_atomic_u32_t *consume_count = NULL;

	/* reset results for delayed assertion */
	memset(worker_results, 0, sizeof(worker_results));

	/* request 2 threads to run 1:1 stress */
	worker_param.numthrds = odp_cpumask_default_worker(&cpus, 2);
	worker_param.testcase = STRESS_1_1_PRODUCER_CONSUMER;

	/* not failure, insufficient resource */
	if (worker_param.numthrds < 2) {
		LOG_ERR("insufficient cpu for 1:1 "
			"producer/consumer stress.\n");
		return;
	}

	consume_count = retrieve_consume_count();
	CU_ASSERT(consume_count != NULL);

	/* in 1:1 test case, one producer thread produces one
	 * data piece to be consumed by one consumer thread.
	 */
	odp_atomic_init_u32(consume_count, 1);

	/* kick the workers */
	odp_cunit_thread_create(stress_worker, &worker_param);

	/* collect the results */
	odp_cunit_thread_exit(&worker_param);

	/* delayed assertion due to cunit limitation */
	for (i = 0; i < worker_param.numthrds; i++)
		CU_ASSERT(0 == worker_results[i]);
}

void ring_test_stress_N_M_producer_consumer(void)
{
	int i = 0;
	odp_cpumask_t cpus;
	pthrd_arg worker_param;
	odp_atomic_u32_t *consume_count = NULL;

	/* reset results for delayed assertion */
	memset(worker_results, 0, sizeof(worker_results));

	/* request MAX_WORKERS threads to run N:M stress */
	worker_param.numthrds =
		odp_cpumask_default_worker(&cpus, MAX_WORKERS);
	worker_param.testcase = STRESS_N_M_PRODUCER_CONSUMER;

	/* not failure, insufficient resource */
	if (worker_param.numthrds < 3) {
		LOG_ERR("insufficient cpu for N:M "
			"producer/consumer stress.\n");
		return;
	}

	consume_count = retrieve_consume_count();
	CU_ASSERT(consume_count != NULL);

	/* in N:M test case, producer threads are always
	 * greater or equal to consumer threads, thus produce
	 * enought "goods" to be consumed by consumer threads.
	 */
	odp_atomic_init_u32(consume_count,
			    (worker_param.numthrds) / 2);

	/* kick the workers */
	odp_cunit_thread_create(stress_worker, &worker_param);

	/* collect the results */
	odp_cunit_thread_exit(&worker_param);

	/* delayed assertion due to cunit limitation */
	for (i = 0; i < worker_param.numthrds; i++)
		CU_ASSERT(0 == worker_results[i]);
}

void ring_test_stress_1_N_producer_consumer(void)
{
}

void ring_test_stress_N_1_producer_consumer(void)
{
}

void ring_test_stress_ring_list_dump(void)
{
	/* improve code coverage */
	_ring_list_dump();
}

static odp_atomic_u32_t *retrieve_consume_count(void)
{
	odp_shm_t shared;

	shared = odp_shm_lookup(consume_count_name);
	if (shared == ODP_SHM_INVALID)
		return NULL;

	return (odp_atomic_u32_t *)odp_shm_addr(shared);
}

/* worker function for multiple producer instances */
static int do_producer(_ring_t *r)
{
	int i, result = 0;
	void **enq = NULL;

	/* allocate dummy object pointers for enqueue */
	enq = malloc(PIECE_BULK * 2 * sizeof(void *));
	if (NULL == enq) {
		LOG_ERR("insufficient memory for producer enqueue.\n");
		return 0; /* not failure, skip for insufficient memory */
	}

	/* data pattern to be evaluated later in consumer */
	for (i = 0; i < PIECE_BULK; i++)
		enq[i] = (void *)(unsigned long)i;

	do {
		result = _ring_mp_enqueue_bulk(r, enq, PIECE_BULK);
		if (0 == result) {
			free(enq);
			return 0;
		}
		usleep(10); /* wait for consumer threads */
	} while (!_ring_full(r));

	return 0;
}

/* worker function for multiple consumer instances */
static int do_consumer(_ring_t *r)
{
	int i, result = 0;
	void **deq = NULL;
	odp_atomic_u32_t *consume_count = NULL;
	const char *message = "test OK!";
	const char *mismatch = "data mismatch..lockless enq/deq failed.";

	/* allocate dummy object pointers for dequeue */
	deq = malloc(PIECE_BULK * 2 * sizeof(void *));
	if (NULL == deq) {
		LOG_ERR("insufficient memory for consumer dequeue.\n");
		return 0; /* not failure, skip for insufficient memory */
	}

	consume_count = retrieve_consume_count();
	if (consume_count == NULL) {
		LOG_ERR("cannot retrieve expected consume count.\n");
		return -1;
	}

	while (odp_atomic_load_u32(consume_count) > 0) {
		result = _ring_mc_dequeue_bulk(r, deq, PIECE_BULK);
		if (0 == result) {
			/* evaluate the data pattern */
			for (i = 0; i < PIECE_BULK; i++) {
				if (deq[i] != (void *)(unsigned long)i) {
					result = -1;
					message = mismatch;
					break;
				}
			}

			free(deq);
			LOG_ERR("%s\n", message);
			odp_atomic_dec_u32(consume_count);
			return result;
		}
		usleep(10); /* wait for producer threads */
	}
	return 0;
}

static int stress_worker(void *_data)
{
	pthrd_arg *worker_param = (pthrd_arg *)_data;
	_ring_t *r_stress = NULL;
	int *result = NULL;
	int worker_id = odp_thread_id();

	/* save the worker result for delayed assertion */
	result = &worker_results[(worker_id % worker_param->numthrds)];

	/* verify ring lookup in worker context */
	r_stress = _ring_lookup(ring_name);
	if (NULL == r_stress) {
		LOG_ERR("ring lookup %s not found\n", ring_name);
		return (*result = -1);
	}

	switch (worker_param->testcase) {
	case STRESS_1_1_PRODUCER_CONSUMER:
	case STRESS_N_M_PRODUCER_CONSUMER:
		/* interleaved producer/consumer */
		if (0 == (worker_id % 2))
			*result = do_producer(r_stress);
		else if (1 == (worker_id % 2))
			*result = do_consumer(r_stress);
		break;
	case STRESS_1_N_PRODUCER_CONSUMER:
	case STRESS_N_1_PRODUCER_CONSUMER:
	default:
		LOG_ERR("invalid or not-implemented stress type (%d)\n",
			worker_param->testcase);
		break;
	}
	return 0;
}
