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

/* There's even number of producer and consumer threads and each thread does
 * this many successful enq or deq operations */
#define NUM_BULK_OP ((RING_SIZE / PIECE_BULK) * 100)

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

/* global name for later look up in workers' context */
static const char *ring_name = "stress_ring";

/* barrier to run threads at the same time */
static odp_barrier_t barrier;

int ring_test_stress_start(void)
{
	_ring_t *r_stress = NULL;

	/* multiple thread usage scenario, thread or process sharable */
	r_stress = _ring_create(ring_name, RING_SIZE, _RING_SHM_PROC);
	if (r_stress == NULL) {
		LOG_ERR("create ring failed for stress.\n");
		return -1;
	}

	return 0;
}

int ring_test_stress_end(void)
{
	return 0;
}

void ring_test_stress_1_1_producer_consumer(void)
{
	int i = 0;
	odp_cpumask_t cpus;
	pthrd_arg worker_param;

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

	odp_barrier_init(&barrier, 2);

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

	/* force even number of threads */
	if (worker_param.numthrds & 0x1)
		worker_param.numthrds -= 1;

	odp_barrier_init(&barrier, worker_param.numthrds);

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

/* worker function for multiple producer instances */
static int do_producer(_ring_t *r)
{
	void *enq[PIECE_BULK];
	int i;
	int num = NUM_BULK_OP;

	/* data pattern to be evaluated later in consumer */
	for (i = 0; i < PIECE_BULK; i++)
		enq[i] = (void *)(uintptr_t)i;

	while (num)
		if (_ring_mp_enqueue_bulk(r, enq, PIECE_BULK) == 0)
			num--;

	return 0;
}

/* worker function for multiple consumer instances */
static int do_consumer(_ring_t *r)
{
	void *deq[PIECE_BULK];
	int i;
	int num = NUM_BULK_OP;

	while (num) {
		if (_ring_mc_dequeue_bulk(r, deq, PIECE_BULK) == 0) {
			num--;

			/* evaluate the data pattern */
			for (i = 0; i < PIECE_BULK; i++)
				CU_ASSERT(deq[i] == (void *)(uintptr_t)i);
		}
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

	odp_barrier_wait(&barrier);

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

	odp_barrier_wait(&barrier);

	return 0;
}
