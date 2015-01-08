/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 */

#include <assert.h>
#include <unistd.h>
#include <odp.h>
#include "odp_cunit_common.h"

/** @private Timeout range in milliseconds (ms) */
#define RANGE_MS 2000

/** @private Number of timers per thread */
#define NTIMERS 2000

/** @private Barrier for thread synchronisation */
static odp_barrier_t test_barrier;

/** @private Timeout buffer pool handle used by all threads */
static odp_buffer_pool_t tbp;

/** @private Timer pool handle used by all threads */
static odp_timer_pool_t tp;

/** @private min() function */
static int min(int a, int b)
{
	return a < b ? a : b;
}

/* @private Timer helper structure */
struct test_timer {
	odp_timer_t tim; /* Timer handle */
	odp_buffer_t buf; /* Timeout buffer */
	odp_buffer_t buf2; /* Copy of buffer handle */
	uint64_t tick; /* Expiration tick or TICK_INVALID */
};

#define TICK_INVALID (~(uint64_t)0)

/* @private Handle a received (timeout) buffer */
static void handle_tmo(odp_buffer_t buf, bool stale, uint64_t prev_tick)
{
	/* Use assert() for internal correctness checks of test program */
	assert(buf != ODP_BUFFER_INVALID);
	if (odp_buffer_type(buf) != ODP_BUFFER_TYPE_TIMEOUT) {
		/* Not a timeout buffer */
		CU_FAIL("Unexpected buffer type received");
		return;
	}
	/* Read the metadata from the timeout */
	odp_timeout_t tmo = odp_timeout_from_buf(buf);
	odp_timer_t tim = odp_timeout_timer(tmo);
	uint64_t tick = odp_timeout_tick(tmo);
	struct test_timer *ttp = odp_timeout_user_ptr(tmo);

	if (tim == ODP_TIMER_INVALID)
		CU_FAIL("odp_timeout_timer() invalid timer");
	if (ttp == NULL)
		CU_FAIL("odp_timeout_user_ptr() null user ptr");

	if (ttp->buf2 != buf)
		CU_FAIL("odp_timeout_user_ptr() wrong user ptr");
	if (ttp->tim != tim)
		CU_FAIL("odp_timeout_timer() wrong timer");
	if (stale) {
		if (odp_timeout_fresh(tmo))
			CU_FAIL("Wrong status (fresh) for stale timeout");
		/* Stale timeout => local timer must have invalid tick */
		if (ttp->tick != TICK_INVALID)
			CU_FAIL("Stale timeout for active timer");
	} else {
		if (!odp_timeout_fresh(tmo))
			CU_FAIL("Wrong status (stale) for fresh timeout");
		/* Fresh timeout => local timer must have matching tick */
		if (ttp->tick != tick) {
			printf("Wrong tick: expected %"PRIu64" actual %"PRIu64"\n",
			       ttp->tick, tick);
			CU_FAIL("odp_timeout_tick() wrong tick");
		}
		/* Check that timeout was delivered 'timely' */
		if (tick > odp_timer_current_tick(tp))
			CU_FAIL("Timeout delivered early");
		if (tick < prev_tick) {
			printf("Too late tick: %"PRIu64" prev_tick %"PRIu64"\n",
			       tick, prev_tick);
			CU_FAIL("Timeout delivered late");
		}
	}

	/* Use assert() for correctness check of test program itself */
	assert(ttp->buf == ODP_BUFFER_INVALID);
	ttp->buf = buf;
}

/* @private Worker thread entrypoint which performs timer alloc/set/cancel/free
 * tests */
static void *worker_entrypoint(void *arg)
{
	int thr = odp_thread_id();
	uint32_t i;
	unsigned seed = thr;
	(void)arg;

	odp_queue_t queue = odp_queue_create("timer_queue",
					     ODP_QUEUE_TYPE_POLL,
					     NULL);
	if (queue == ODP_QUEUE_INVALID)
		CU_FAIL_FATAL("Queue create failed");

	struct test_timer *tt = malloc(sizeof(struct test_timer) * NTIMERS);
	if (tt == NULL)
		perror("malloc"), abort();

	/* Prepare all timers */
	for (i = 0; i < NTIMERS; i++) {
		tt[i].tim = odp_timer_alloc(tp, queue, &tt[i]);
		if (tt[i].tim == ODP_TIMER_INVALID)
			CU_FAIL_FATAL("Failed to allocate timer");
		tt[i].buf = odp_buffer_alloc(tbp);
		if (tt[i].buf == ODP_BUFFER_INVALID)
			CU_FAIL_FATAL("Failed to allocate timeout buffer");
		tt[i].buf2 = tt[i].buf;
		tt[i].tick = TICK_INVALID;
	}

	odp_barrier_wait(&test_barrier);

	/* Initial set all timers with a random expiration time */
	uint32_t nset = 0;
	for (i = 0; i < NTIMERS; i++) {
		uint64_t tck = odp_timer_current_tick(tp) + 1 +
			       odp_timer_ns_to_tick(tp,
						    (rand_r(&seed) % RANGE_MS)
						    * 1000000ULL);
		odp_timer_set_t rc;
		rc = odp_timer_set_abs(tt[i].tim, tck, &tt[i].buf);
		if (rc != ODP_TIMER_SUCCESS) {
			CU_FAIL("Failed to set timer");
		} else {
			tt[i].tick = tck;
			nset++;
		}
	}

	/* Step through wall time, 1ms at a time and check for expired timers */
	uint32_t nrcv = 0;
	uint32_t nreset = 0;
	uint32_t ncancel = 0;
	uint32_t ntoolate = 0;
	uint32_t ms;
	uint64_t prev_tick = odp_timer_current_tick(tp);
	for (ms = 0; ms < 7 * RANGE_MS / 10; ms++) {
		odp_buffer_t buf;
		while ((buf = odp_queue_deq(queue)) != ODP_BUFFER_INVALID) {
			/* Subtract one from prev_tick to allow for timeouts
			 * to be delivered a tick late */
			handle_tmo(buf, false, prev_tick - 1);
			nrcv++;
		}
		prev_tick = odp_timer_current_tick(tp);
		i = rand_r(&seed) % NTIMERS;
		if (tt[i].buf == ODP_BUFFER_INVALID &&
		    (rand_r(&seed) % 2 == 0)) {
			/* Timer active, cancel it */
			int rc = odp_timer_cancel(tt[i].tim, &tt[i].buf);
			if (rc != 0)
				/* Cancel failed, timer already expired */
				ntoolate++;
			tt[i].tick = TICK_INVALID;
			ncancel++;
		} else {
			if (tt[i].buf != ODP_BUFFER_INVALID)
				/* Timer inactive => set */
				nset++;
			else
				/* Timer active => reset */
				nreset++;
			uint64_t tck = 1 + odp_timer_ns_to_tick(tp,
				       (rand_r(&seed) % RANGE_MS) * 1000000ULL);
			odp_timer_set_t rc;
			uint64_t cur_tick;
			/* Loop until we manage to read cur_tick and set a
			 * relative timer in the same tick */
			do {
				cur_tick = odp_timer_current_tick(tp);
				rc = odp_timer_set_rel(tt[i].tim,
						       tck, &tt[i].buf);
			} while (cur_tick != odp_timer_current_tick(tp));
			if (rc == ODP_TIMER_TOOEARLY ||
			    rc == ODP_TIMER_TOOLATE) {
				CU_FAIL("Failed to set timer (tooearly/toolate)");
			} else if (rc != ODP_TIMER_SUCCESS) {
				/* Set/reset failed, timer already expired */
				ntoolate++;
			}
			/* Save expected expiration tick */
			tt[i].tick = cur_tick + tck;
		}
		if (usleep(1000/*1ms*/) < 0)
			perror("usleep"), abort();
	}

	/* Cancel and free all timers */
	uint32_t nstale = 0;
	for (i = 0; i < NTIMERS; i++) {
		(void)odp_timer_cancel(tt[i].tim, &tt[i].buf);
		tt[i].tick = TICK_INVALID;
		if (tt[i].buf == ODP_BUFFER_INVALID)
			/* Cancel too late, timer already expired and
			 * timoeut buffer enqueued */
			nstale++;
		if (odp_timer_free(tt[i].tim) != ODP_BUFFER_INVALID)
			CU_FAIL("odp_timer_free");
	}

	printf("Thread %u: %u timers set\n", thr, nset);
	printf("Thread %u: %u timers reset\n", thr, nreset);
	printf("Thread %u: %u timers cancelled\n", thr, ncancel);
	printf("Thread %u: %u timers reset/cancelled too late\n",
	       thr, ntoolate);
	printf("Thread %u: %u timeouts received\n", thr, nrcv);
	printf("Thread %u: %u stale timeout(s) after odp_timer_free()\n",
	       thr, nstale);

	/* Delay some more to ensure timeouts for expired timers can be
	 * received */
	usleep(1000/*1ms*/);
	while (nstale != 0) {
		odp_buffer_t buf = odp_queue_deq(queue);
		if (buf != ODP_BUFFER_INVALID) {
			handle_tmo(buf, true, 0/*Dont' care for stale tmo's*/);
			nstale--;
		} else {
			CU_FAIL("Failed to receive stale timeout");
			break;
		}
	}
	/* Check if there any more (unexpected) buffers */
	odp_buffer_t buf = odp_queue_deq(queue);
	if (buf != ODP_BUFFER_INVALID)
		CU_FAIL("Unexpected buffer received");

	printf("Thread %u: exiting\n", thr);
	return NULL;
}

/* @private Timer test case entrypoint */
static void test_odp_timer_all(void)
{
	odp_buffer_pool_param_t params;
	odp_timer_pool_param_t tparam;
	/* This is a stressfull test - need to reserve some cpu cycles
	 * @TODO move to test/performance */
	int num_workers = min(odp_sys_cpu_count()-1, MAX_WORKERS);

	/* Create timeout buffer pools */
	params.buf_size  = 0;
	params.buf_align = ODP_CACHE_LINE_SIZE;
	params.num_bufs  = (NTIMERS + 1) * num_workers;
	params.buf_type  = ODP_BUFFER_TYPE_TIMEOUT;
	tbp = odp_buffer_pool_create("tmo_pool", ODP_SHM_INVALID, &params);
	if (tbp == ODP_BUFFER_POOL_INVALID)
		CU_FAIL_FATAL("Timeout buffer pool create failed");

#define NAME "timer_pool"
#define RES (10 * ODP_TIME_MSEC / 3)
#define MIN (10 * ODP_TIME_MSEC / 3)
#define MAX (1000000 * ODP_TIME_MSEC)
	/* Create a timer pool */
	tparam.res_ns = RES;
	tparam.min_tmo = MIN;
	tparam.max_tmo = MAX;
	tparam.num_timers = num_workers * NTIMERS;
	tparam.private = 0;
	tparam.clk_src = ODP_CLOCK_CPU;
	tp = odp_timer_pool_create(NAME, &tparam);
	if (tp == ODP_TIMER_POOL_INVALID)
		CU_FAIL_FATAL("Timer pool create failed");

	/* Start all created timer pools */
	odp_timer_pool_start();

	odp_timer_pool_info_t tpinfo;
	if (odp_timer_pool_info(tp, &tpinfo) != 0)
		CU_FAIL("odp_timer_pool_info");
	CU_ASSERT(strcmp(tpinfo.name, NAME) == 0);
	CU_ASSERT(tpinfo.param.res_ns == RES);
	CU_ASSERT(tpinfo.param.min_tmo == MIN);
	CU_ASSERT(tpinfo.param.max_tmo == MAX);
	printf("Timer pool\n");
	printf("----------\n");
	printf("  name: %s\n", tpinfo.name);
	printf("  resolution: %"PRIu64" ns (%"PRIu64" us)\n",
	       tpinfo.param.res_ns, tpinfo.param.res_ns / 1000);
	printf("  min tmo: %"PRIu64" ns\n", tpinfo.param.min_tmo);
	printf("  max tmo: %"PRIu64" ns\n", tpinfo.param.max_tmo);
	printf("\n");

	printf("#timers..: %u\n", NTIMERS);
	printf("Tmo range: %u ms (%"PRIu64" ticks)\n", RANGE_MS,
	       odp_timer_ns_to_tick(tp, 1000000ULL * RANGE_MS));
	printf("\n");

	uint64_t tick;
	for (tick = 0; tick < 1000000000000ULL; tick += 1000000ULL) {
		uint64_t ns = odp_timer_tick_to_ns(tp, tick);
		uint64_t t2 = odp_timer_ns_to_tick(tp, ns);
		if (tick != t2)
			CU_FAIL("Invalid conversion tick->ns->tick");
	}

	/* Initialize barrier used by worker threads for synchronization */
	odp_barrier_init(&test_barrier, num_workers);

	/* Create and start worker threads */
	pthrd_arg thrdarg;
	thrdarg.testcase = 0;
	thrdarg.numthrds = num_workers;
	odp_cunit_thread_create(worker_entrypoint, &thrdarg);

	/* Wait for worker threads to exit */
	odp_cunit_thread_exit(&thrdarg);

	/* Check some statistics after the test */
	if (odp_timer_pool_info(tp, &tpinfo) != 0)
		CU_FAIL("odp_timer_pool_info");
	CU_ASSERT(tpinfo.param.num_timers == (unsigned)num_workers * NTIMERS);
	CU_ASSERT(tpinfo.cur_timers == 0);
	CU_ASSERT(tpinfo.hwm_timers == (unsigned)num_workers * NTIMERS);

	/* Destroy timer pool, all timers must have been freed */
	odp_timer_pool_destroy(tp);

	CU_PASS("ODP timer test");
}

CU_TestInfo test_odp_timer[] = {
	{"test_odp_timer_all",  test_odp_timer_all},
	CU_TEST_INFO_NULL,
};

CU_SuiteInfo odp_testsuites[] = {
	{"Timer", NULL, NULL, NULL, NULL, test_odp_timer},
	CU_SUITE_INFO_NULL,
};
