/* Copyright (c) 2015-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "config.h"

/* For rand_r and nanosleep */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <time.h>
#include <odp.h>
#include <odp/helper/odph_api.h>
#include "odp_cunit_common.h"
#include "test_debug.h"

#define MAX(a, b) (((a) > (b)) ? (a) : (b))

/* Timeout range in milliseconds (ms) */
#define RANGE_MS 2000

/* Number of timers per thread */
#define NTIMERS 2000

#define NAME "timer_pool"
#define RES (10 * ODP_TIME_MSEC_IN_NS / 3)
#define MIN_TMO (10 * ODP_TIME_MSEC_IN_NS / 3)
#define MAX_TMO (1000000 * ODP_TIME_MSEC_IN_NS)
#define USER_PTR ((void *)0xdead)
#define TICK_INVALID (~(uint64_t)0)

/* Barrier for thread synchronisation */
static odp_barrier_t test_barrier;

/* Timeout pool handle used by all threads */
static odp_pool_t tbp;

/* Timer pool handle used by all threads */
static odp_timer_pool_t tp;

/* Count of timeouts delivered too late */
static odp_atomic_u32_t ndelivtoolate;

/* Sum of all allocated timers from all threads. Thread-local
 * caches may make this number lower than the capacity of the pool  */
static odp_atomic_u32_t timers_allocated;

/* Timer resolution in nsec */
static uint64_t resolution_ns;

/* Timer helper structure */
struct test_timer {
	odp_timer_t tim; /* Timer handle */
	odp_event_t ev;  /* Timeout event */
	odp_event_t ev2; /* Copy of event handle */
	uint64_t tick; /* Expiration tick or TICK_INVALID */
};

static void timer_test_timeout_pool_alloc(void)
{
	odp_pool_t pool;
	const int num = 3;
	odp_timeout_t tmo[num];
	odp_event_t ev;
	int index;
	odp_bool_t wrong_type = false, wrong_subtype = false;
	odp_pool_param_t params;

	odp_pool_param_init(&params);
	params.type    = ODP_POOL_TIMEOUT;
	params.tmo.num = num;

	pool = odp_pool_create("timeout_pool_alloc", &params);
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	odp_pool_print(pool);

	/* Try to allocate num items from the pool */
	for (index = 0; index < num; index++) {
		odp_event_subtype_t subtype;

		tmo[index] = odp_timeout_alloc(pool);

		if (tmo[index] == ODP_TIMEOUT_INVALID)
			break;

		ev = odp_timeout_to_event(tmo[index]);
		if (odp_event_type(ev) != ODP_EVENT_TIMEOUT)
			wrong_type = true;
		if (odp_event_subtype(ev) != ODP_EVENT_NO_SUBTYPE)
			wrong_subtype = true;
		if (odp_event_types(ev, &subtype) != ODP_EVENT_TIMEOUT)
			wrong_type = true;
		if (subtype != ODP_EVENT_NO_SUBTYPE)
			wrong_subtype = true;
	}

	/* Check that the pool had at least num items */
	CU_ASSERT(index == num);
	/* index points out of buffer[] or it point to an invalid buffer */
	index--;

	/* Check that the pool had correct buffers */
	CU_ASSERT(!wrong_type);
	CU_ASSERT(!wrong_subtype);

	for (; index >= 0; index--)
		odp_timeout_free(tmo[index]);

	CU_ASSERT(odp_pool_destroy(pool) == 0);
}

static void timer_test_timeout_pool_free(void)
{
	odp_pool_t pool;
	odp_timeout_t tmo;
	odp_pool_param_t params;

	odp_pool_param_init(&params);
	params.type    = ODP_POOL_TIMEOUT;
	params.tmo.num = 1;

	pool = odp_pool_create("timeout_pool_free", &params);
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);
	odp_pool_print(pool);

	/* Allocate the only timeout from the pool */
	tmo = odp_timeout_alloc(pool);
	CU_ASSERT_FATAL(tmo != ODP_TIMEOUT_INVALID);

	/* Pool should have only one timeout */
	CU_ASSERT_FATAL(odp_timeout_alloc(pool) == ODP_TIMEOUT_INVALID)

	odp_timeout_free(tmo);

	/* Check that the timeout was returned back to the pool */
	tmo = odp_timeout_alloc(pool);
	CU_ASSERT_FATAL(tmo != ODP_TIMEOUT_INVALID);

	odp_timeout_free(tmo);
	CU_ASSERT(odp_pool_destroy(pool) == 0);
}

static void timer_test_queue_type(odp_queue_type_t queue_type)
{
	odp_pool_t pool;
	const int num = 10;
	odp_timeout_t tmo;
	odp_event_t ev;
	odp_queue_param_t queue_param;
	odp_timer_pool_param_t tparam;
	odp_timer_pool_t tp;
	odp_queue_t queue;
	odp_timer_t tim;
	int i, ret, num_tmo;
	uint64_t tick_base, tick;
	uint64_t res_ns, period_ns, period_tick, test_period;
	uint64_t diff_period, diff_test;
	odp_pool_param_t params;
	odp_timer_capability_t timer_capa;
	odp_time_t t0, t1, t2;

	odp_pool_param_init(&params);
	params.type    = ODP_POOL_TIMEOUT;
	params.tmo.num = num;

	pool = odp_pool_create("timeout_pool", &params);
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	if (odp_timer_capability(ODP_CLOCK_CPU, &timer_capa))
		CU_FAIL_FATAL("Timer capability failed")

	res_ns = 20 * ODP_TIME_MSEC_IN_NS;

	if (timer_capa.highest_res_ns > res_ns)
		res_ns = timer_capa.highest_res_ns;

	tparam.res_ns     = res_ns;
	tparam.min_tmo    = 5 * res_ns;
	tparam.max_tmo    = 10000 * tparam.min_tmo;
	tparam.num_timers = num + 1;
	tparam.priv       = 0;
	tparam.clk_src    = ODP_CLOCK_CPU;

	LOG_DBG("\nTimer pool parameters:\n");
	LOG_DBG("  res_ns  %" PRIu64 "\n", tparam.res_ns);
	LOG_DBG("  min_tmo %" PRIu64 "\n", tparam.min_tmo);
	LOG_DBG("  max_tmo %" PRIu64 "\n", tparam.max_tmo);

	tp = odp_timer_pool_create("timer_pool", &tparam);
	if (tp == ODP_TIMER_POOL_INVALID)
		CU_FAIL_FATAL("Timer pool create failed");

	odp_timer_pool_start();

	odp_queue_param_init(&queue_param);
	if (queue_type == ODP_QUEUE_TYPE_SCHED) {
		queue_param.type = ODP_QUEUE_TYPE_SCHED;
		queue_param.sched.prio  = ODP_SCHED_PRIO_DEFAULT;
		queue_param.sched.sync  = ODP_SCHED_SYNC_ATOMIC;
		queue_param.sched.group = ODP_SCHED_GROUP_ALL;
	}

	queue = odp_queue_create("timer_queue", &queue_param);
	if (queue == ODP_QUEUE_INVALID)
		CU_FAIL_FATAL("Queue create failed");

	period_ns   = 4 * tparam.min_tmo;
	period_tick = odp_timer_ns_to_tick(tp, period_ns);
	test_period = num * period_ns;

	LOG_DBG("  period_ns %" PRIu64 "\n", period_ns);
	LOG_DBG("  period_tick %" PRIu64 "\n\n", period_tick);

	tick_base = odp_timer_current_tick(tp);
	t0 = odp_time_local();
	t1 = t0;
	t2 = t0;

	for (i = 0; i < num; i++) {
		tmo = odp_timeout_alloc(pool);
		CU_ASSERT_FATAL(tmo != ODP_TIMEOUT_INVALID);
		ev  = odp_timeout_to_event(tmo);
		CU_ASSERT_FATAL(ev != ODP_EVENT_INVALID);

		tim = odp_timer_alloc(tp, queue, USER_PTR);
		CU_ASSERT_FATAL(tim != ODP_TIMER_INVALID);

		tick = tick_base + ((i + 1) * period_tick);
		ret = odp_timer_set_abs(tim, tick, &ev);

		LOG_DBG("abs timer tick %" PRIu64 "\n", tick);
		if (ret == ODP_TIMER_TOOEARLY)
			LOG_DBG("Too early %" PRIu64 "\n", tick);
		else if (ret == ODP_TIMER_TOOLATE)
			LOG_DBG("Too late %" PRIu64 "\n", tick);
		else if (ret == ODP_TIMER_NOEVENT)
			LOG_DBG("No event %" PRIu64 "\n", tick);

		CU_ASSERT(ret == ODP_TIMER_SUCCESS);
	}

	num_tmo = 0;

	do {
		if (queue_type == ODP_QUEUE_TYPE_SCHED)
			ev = odp_schedule(NULL, ODP_SCHED_NO_WAIT);
		else
			ev = odp_queue_deq(queue);

		t2 = odp_time_local();
		diff_test = odp_time_diff_ns(t2, t0);

		if (ev != ODP_EVENT_INVALID) {
			diff_period = odp_time_diff_ns(t2, t1);
			t1 = t2;
			tmo = odp_timeout_from_event(ev);
			tim = odp_timeout_timer(tmo);
			tick = odp_timeout_tick(tmo);

			CU_ASSERT(diff_period > (period_ns - (4 * res_ns)));
			CU_ASSERT(diff_period < (period_ns + (4 * res_ns)));

			LOG_DBG("timeout tick %" PRIu64 ", "
				"timeout period %" PRIu64 "\n",
				tick, diff_period);

			odp_timeout_free(tmo);
			CU_ASSERT(odp_timer_free(tim) == ODP_EVENT_INVALID);

			num_tmo++;
		}

	} while (diff_test < (2 * test_period) && num_tmo < num);

	LOG_DBG("test period %" PRIu64 "\n", diff_test);

	CU_ASSERT(num_tmo == num);
	CU_ASSERT(diff_test > (test_period - period_ns));
	CU_ASSERT(diff_test < (test_period + period_ns));

	/* Scalable scheduler needs this pause sequence. Otherwise, it gets
	 * stuck on terminate. */
	if (queue_type == ODP_QUEUE_TYPE_SCHED) {
		odp_schedule_pause();
		while (1) {
			ev = odp_schedule(NULL, ODP_SCHED_NO_WAIT);
			if (ev == ODP_EVENT_INVALID)
				break;

			CU_FAIL("Drop extra event\n");
			odp_event_free(ev);
		}
	}

	odp_timer_pool_destroy(tp);

	CU_ASSERT(odp_queue_destroy(queue) == 0);
	CU_ASSERT(odp_pool_destroy(pool) == 0);
}

static void timer_test_plain_queue(void)
{
	timer_test_queue_type(ODP_QUEUE_TYPE_PLAIN);
}

static void timer_test_sched_queue(void)
{
	timer_test_queue_type(ODP_QUEUE_TYPE_SCHED);
}

static void timer_test_odp_timer_cancel(void)
{
	odp_pool_t pool;
	odp_pool_param_t params;
	odp_timer_pool_param_t tparam;
	odp_timer_pool_t tp;
	odp_queue_t queue;
	odp_timer_t tim;
	odp_event_t ev;
	odp_timeout_t tmo;
	odp_timer_set_t rc;
	uint64_t tick;
	odp_timer_capability_t timer_capa;

	odp_pool_param_init(&params);
	params.type    = ODP_POOL_TIMEOUT;
	params.tmo.num = 1;

	pool = odp_pool_create("tmo_pool_for_cancel", &params);

	if (pool == ODP_POOL_INVALID)
		CU_FAIL_FATAL("Timeout pool create failed");

	if (odp_timer_capability(ODP_CLOCK_CPU, &timer_capa))
		CU_FAIL_FATAL("Get timer capability failed")

	tparam.res_ns	  = MAX(100 * ODP_TIME_MSEC_IN_NS,
				timer_capa.highest_res_ns);
	tparam.min_tmo    = 1   * ODP_TIME_SEC_IN_NS;
	tparam.max_tmo    = 10  * ODP_TIME_SEC_IN_NS;
	tparam.num_timers = 1;
	tparam.priv       = 0;
	tparam.clk_src    = ODP_CLOCK_CPU;
	tp = odp_timer_pool_create(NULL, &tparam);
	if (tp == ODP_TIMER_POOL_INVALID)
		CU_FAIL_FATAL("Timer pool create failed");

	/* Start all created timer pools */
	odp_timer_pool_start();

	queue = odp_queue_create("timer_queue", NULL);
	if (queue == ODP_QUEUE_INVALID)
		CU_FAIL_FATAL("Queue create failed");

	tim = odp_timer_alloc(tp, queue, USER_PTR);
	if (tim == ODP_TIMER_INVALID)
		CU_FAIL_FATAL("Failed to allocate timer");
	LOG_DBG("Timer handle: %" PRIu64 "\n", odp_timer_to_u64(tim));

	ev = odp_timeout_to_event(odp_timeout_alloc(pool));
	if (ev == ODP_EVENT_INVALID)
		CU_FAIL_FATAL("Failed to allocate timeout");

	tick = odp_timer_ns_to_tick(tp, 2 * ODP_TIME_SEC_IN_NS);

	rc = odp_timer_set_rel(tim, tick, &ev);
	if (rc != ODP_TIMER_SUCCESS)
		CU_FAIL_FATAL("Failed to set timer (relative time)");

	ev = ODP_EVENT_INVALID;
	if (odp_timer_cancel(tim, &ev) != 0)
		CU_FAIL_FATAL("Failed to cancel timer (relative time)");

	if (ev == ODP_EVENT_INVALID)
		CU_FAIL_FATAL("Cancel did not return event");

	tmo = odp_timeout_from_event(ev);
	if (tmo == ODP_TIMEOUT_INVALID)
		CU_FAIL_FATAL("Cancel did not return timeout");
	LOG_DBG("Timeout handle: %" PRIu64 "\n", odp_timeout_to_u64(tmo));

	if (odp_timeout_timer(tmo) != tim)
		CU_FAIL("Cancel invalid tmo.timer");

	if (odp_timeout_user_ptr(tmo) != USER_PTR)
		CU_FAIL("Cancel invalid tmo.user_ptr");

	odp_timeout_free(tmo);

	ev = odp_timer_free(tim);
	if (ev != ODP_EVENT_INVALID)
		CU_FAIL_FATAL("Free returned event");

	odp_timer_pool_destroy(tp);

	if (odp_queue_destroy(queue) != 0)
		CU_FAIL_FATAL("Failed to destroy queue");

	if (odp_pool_destroy(pool) != 0)
		CU_FAIL_FATAL("Failed to destroy pool");
}

/* Handle a received (timeout) event */
static void handle_tmo(odp_event_t ev, bool stale, uint64_t prev_tick)
{
	odp_event_subtype_t subtype;
	odp_timeout_t tmo;
	odp_timer_t tim;
	uint64_t tick;
	struct test_timer *ttp;

	CU_ASSERT_FATAL(ev != ODP_EVENT_INVALID); /* Internal error */
	if (odp_event_type(ev) != ODP_EVENT_TIMEOUT) {
		/* Not a timeout event */
		CU_FAIL("Unexpected event type received");
		return;
	}
	if (odp_event_subtype(ev) != ODP_EVENT_NO_SUBTYPE) {
		/* Not a timeout event */
		CU_FAIL("Unexpected event subtype received");
		return;
	}
	if (odp_event_types(ev, &subtype) != ODP_EVENT_TIMEOUT) {
		/* Not a timeout event */
		CU_FAIL("Unexpected event type received");
		return;
	}
	if (subtype != ODP_EVENT_NO_SUBTYPE) {
		/* Not a timeout event */
		CU_FAIL("Unexpected event subtype received");
		return;
	}

	/* Read the metadata from the timeout */
	tmo  = odp_timeout_from_event(ev);
	tim  = odp_timeout_timer(tmo);
	tick = odp_timeout_tick(tmo);
	ttp  = odp_timeout_user_ptr(tmo);

	if (tim == ODP_TIMER_INVALID)
		CU_FAIL("odp_timeout_timer() invalid timer");

	if (ttp == NULL) {
		CU_FAIL("odp_timeout_user_ptr() null user ptr");
		return;
	}

	if (ttp->ev2 != ev)
		CU_FAIL("odp_timeout_user_ptr() wrong user ptr");

	if (ttp->tim != tim)
		CU_FAIL("odp_timeout_timer() wrong timer");

	if (!odp_timeout_fresh(tmo))
		CU_FAIL("Wrong status (stale) for fresh timeout");

	if (!stale) {
		/* tmo tick cannot be smaller than pre-calculated tick */
		if (tick < ttp->tick) {
			LOG_DBG("Too small tick: pre-calculated %" PRIu64
				" timeout %" PRIu64 "\n",
				ttp->tick, tick);
			CU_FAIL("odp_timeout_tick() too small tick");
		}

		if (tick > odp_timer_current_tick(tp))
			CU_FAIL("Timeout delivered early");

		if (tick < prev_tick) {
			LOG_DBG("Too late tick: %" PRIu64
				" prev_tick %" PRIu64"\n",
				tick, prev_tick);
			/* We don't report late timeouts using CU_FAIL */
			odp_atomic_inc_u32(&ndelivtoolate);
		}
	}

	/* Internal error */
	CU_ASSERT_FATAL(ttp->ev == ODP_EVENT_INVALID);
	ttp->ev = ev;
}

/* Worker thread entrypoint which performs timer alloc/set/cancel/free
 * tests */
static int worker_entrypoint(void *arg TEST_UNUSED)
{
	int thr = odp_thread_id();
	uint32_t i, allocated;
	unsigned seed = thr;
	int rc;
	odp_queue_t queue;
	struct test_timer *tt;
	uint32_t nset;
	uint64_t tck;
	uint32_t nrcv;
	uint32_t nreset;
	uint32_t ncancel;
	uint32_t ntoolate;
	uint32_t ms;
	uint64_t prev_tick, nsec;
	odp_event_t ev;
	struct timespec ts;
	uint32_t nstale;
	odp_timer_set_t timer_rc;

	queue = odp_queue_create("timer_queue", NULL);
	if (queue == ODP_QUEUE_INVALID)
		CU_FAIL_FATAL("Queue create failed");

	tt = malloc(sizeof(struct test_timer) * NTIMERS);
	if (!tt)
		CU_FAIL_FATAL("malloc failed");

	/* Prepare all timers */
	for (i = 0; i < NTIMERS; i++) {
		tt[i].ev = odp_timeout_to_event(odp_timeout_alloc(tbp));
		if (tt[i].ev == ODP_EVENT_INVALID) {
			LOG_DBG("Failed to allocate timeout (%" PRIu32 "/%d)\n",
				i, NTIMERS);
			break;
		}
		tt[i].tim = odp_timer_alloc(tp, queue, &tt[i]);
		if (tt[i].tim == ODP_TIMER_INVALID) {
			LOG_DBG("Failed to allocate timer (%" PRIu32 "/%d)\n",
				i, NTIMERS);
			odp_event_free(tt[i].ev);
			break;
		}
		tt[i].ev2 = tt[i].ev;
		tt[i].tick = TICK_INVALID;
	}
	allocated = i;
	if (allocated == 0)
		CU_FAIL_FATAL("unable to alloc a timer");
	odp_atomic_fetch_add_u32(&timers_allocated, allocated);

	odp_barrier_wait(&test_barrier);

	/* Initial set all timers with a random expiration time */
	nset = 0;
	for (i = 0; i < allocated; i++) {
		nsec = MIN_TMO + (rand_r(&seed) % RANGE_MS) * 1000000ULL;
		tck = odp_timer_current_tick(tp) +
		      odp_timer_ns_to_tick(tp, nsec);
		timer_rc = odp_timer_set_abs(tt[i].tim, tck, &tt[i].ev);
		if (timer_rc == ODP_TIMER_TOOEARLY) {
			LOG_ERR("Missed tick, setting timer\n");
		} else if (timer_rc != ODP_TIMER_SUCCESS) {
			LOG_ERR("Failed to set timer: %d\n", timer_rc);
			CU_FAIL("Failed to set timer");
		} else {
			tt[i].tick = tck;
			nset++;
		}
	}

	/* Step through wall time, 1ms at a time and check for expired timers */
	nrcv = 0;
	nreset = 0;
	ncancel = 0;
	ntoolate = 0;
	prev_tick = odp_timer_current_tick(tp);

	for (ms = 0; ms < 7 * RANGE_MS / 10 && allocated > 0; ms++) {
		while ((ev = odp_queue_deq(queue)) != ODP_EVENT_INVALID) {
			/* Subtract one from prev_tick to allow for timeouts
			 * to be delivered a tick late */
			handle_tmo(ev, false, prev_tick - 1);
			nrcv++;
		}
		prev_tick = odp_timer_current_tick(tp);
		i = rand_r(&seed) % allocated;
		if (tt[i].ev == ODP_EVENT_INVALID &&
		    (rand_r(&seed) % 2 == 0)) {
			/* Timer active, cancel it */
			rc = odp_timer_cancel(tt[i].tim, &tt[i].ev);
			if (rc != 0) {
				/* Cancel failed, timer already expired */
				ntoolate++;
				LOG_DBG("Failed to cancel timer, probably already expired\n");
			} else {
				tt[i].tick = TICK_INVALID;
				ncancel++;
			}
		} else {
			odp_timer_set_t rc;
			uint64_t cur_tick;
			uint64_t tck;

			if (tt[i].ev != ODP_EVENT_INVALID)
				/* Timer inactive => set */
				nset++;
			else
				/* Timer active => reset */
				nreset++;

			nsec = MIN_TMO +
			       (rand_r(&seed) % RANGE_MS) * 1000000ULL;
			tck  = odp_timer_ns_to_tick(tp, nsec);

			cur_tick = odp_timer_current_tick(tp);
			rc = odp_timer_set_rel(tt[i].tim, tck, &tt[i].ev);

			if (rc == ODP_TIMER_TOOEARLY) {
				CU_FAIL("Failed to set timer: TOO EARLY");
			} else if (rc == ODP_TIMER_TOOLATE) {
				CU_FAIL("Failed to set timer: TOO LATE");
			} else if (rc == ODP_TIMER_NOEVENT) {
				/* Set/reset failed, timer already expired */
				ntoolate++;
			} else if (rc == ODP_TIMER_SUCCESS) {
				/* Save expected expiration tick on success */
				tt[i].tick = cur_tick + tck;
				/* ODP timer owns the event now */
				tt[i].ev = ODP_EVENT_INVALID;
			} else {
				CU_FAIL("Failed to set timer: bad return code");
			}
		}
		ts.tv_sec = 0;
		ts.tv_nsec = 1000000; /* 1ms */
		if (nanosleep(&ts, NULL) < 0)
			CU_FAIL_FATAL("nanosleep failed");
	}

	/* Cancel and free all timers */
	nstale = 0;
	for (i = 0; i < allocated; i++) {
		(void)odp_timer_cancel(tt[i].tim, &tt[i].ev);
		tt[i].tick = TICK_INVALID;
		if (tt[i].ev == ODP_EVENT_INVALID)
			/* Cancel too late, timer already expired and
			 * timeout enqueued */
			nstale++;
	}

	LOG_DBG("Thread %u: %" PRIu32 " timers set\n", thr, nset);
	LOG_DBG("Thread %u: %" PRIu32 " timers reset\n", thr, nreset);
	LOG_DBG("Thread %u: %" PRIu32 " timers cancelled\n", thr, ncancel);
	LOG_DBG("Thread %u: %" PRIu32 " timers reset/cancelled too late\n",
		thr, ntoolate);
	LOG_DBG("Thread %u: %" PRIu32 " timeouts received\n", thr, nrcv);
	LOG_DBG("Thread %u: %" PRIu32
		" stale timeout(s) after odp_timer_cancel()\n",
		thr, nstale);

	/* Delay some more to ensure timeouts for expired timers can be
	 * received. Can not use busy loop here to make background timer
	 * thread finish their work. */
	ts.tv_sec = 0;
	ts.tv_nsec = (3 * RANGE_MS / 10 + 50) * ODP_TIME_MSEC_IN_NS;
	if (nanosleep(&ts, NULL) < 0)
		CU_FAIL_FATAL("nanosleep failed");

	while (nstale != 0) {
		ev = odp_queue_deq(queue);
		if (ev != ODP_EVENT_INVALID) {
			handle_tmo(ev, true, 0/*Don't care for stale tmo's*/);
			nstale--;
		} else {
			CU_FAIL("Failed to receive stale timeout");
			break;
		}
	}

	for (i = 0; i < allocated; i++) {
		if (odp_timer_free(tt[i].tim) != ODP_EVENT_INVALID)
			CU_FAIL("odp_timer_free");
	}

	/* Check if there any more (unexpected) events */
	ev = odp_queue_deq(queue);
	if (ev != ODP_EVENT_INVALID)
		CU_FAIL("Unexpected event received");

	rc = odp_queue_destroy(queue);
	CU_ASSERT(rc == 0);
	for (i = 0; i < allocated; i++) {
		if (tt[i].ev != ODP_EVENT_INVALID)
			odp_event_free(tt[i].ev);
	}

	free(tt);
	LOG_DBG("Thread %u: exiting\n", thr);
	return CU_get_number_of_failures();
}

/* Timer test case entrypoint */
static void timer_test_odp_timer_all(void)
{
	int rc;
	odp_pool_param_t params;
	odp_timer_pool_param_t tparam;
	odp_cpumask_t unused;
	odp_timer_pool_info_t tpinfo;
	uint64_t ns, tick, ns2;
	pthrd_arg thrdarg;
	odp_timer_capability_t timer_capa;

	/* Reserve at least one core for running other processes so the timer
	 * test hopefully can run undisturbed and thus get better timing
	 * results. */
	int num_workers = odp_cpumask_default_worker(&unused, 0);

	/* force to max CPU count */
	if (num_workers > MAX_WORKERS)
		num_workers = MAX_WORKERS;

	/* On a single-CPU machine run at least one thread */
	if (num_workers < 1)
		num_workers = 1;

	/* Create timeout pools */
	odp_pool_param_init(&params);
	params.type    = ODP_POOL_TIMEOUT;
	params.tmo.num = (NTIMERS + 1) * num_workers;

	tbp = odp_pool_create("tmo_pool", &params);
	if (tbp == ODP_POOL_INVALID)
		CU_FAIL_FATAL("Timeout pool create failed");

	/* Create a timer pool */
	if (odp_timer_capability(ODP_CLOCK_CPU, &timer_capa))
		CU_FAIL("Error: get timer capacity failed.\n");

	resolution_ns = MAX(RES, timer_capa.highest_res_ns);
	tparam.res_ns = resolution_ns;
	tparam.min_tmo = MIN_TMO;
	tparam.max_tmo = MAX_TMO;
	tparam.num_timers = num_workers * NTIMERS;
	tparam.priv = 0;
	tparam.clk_src = ODP_CLOCK_CPU;
	tp = odp_timer_pool_create(NAME, &tparam);
	if (tp == ODP_TIMER_POOL_INVALID)
		CU_FAIL_FATAL("Timer pool create failed");

	/* Start all created timer pools */
	odp_timer_pool_start();

	if (odp_timer_pool_info(tp, &tpinfo) != 0)
		CU_FAIL("odp_timer_pool_info");
	CU_ASSERT(strcmp(tpinfo.name, NAME) == 0);
	CU_ASSERT(tpinfo.param.res_ns == MAX(RES,
					     timer_capa.highest_res_ns));
	CU_ASSERT(tpinfo.param.min_tmo == MIN_TMO);
	CU_ASSERT(tpinfo.param.max_tmo == MAX_TMO);
	CU_ASSERT(strcmp(tpinfo.name, NAME) == 0);

	LOG_DBG("Timer pool handle: %" PRIu64 "\n", odp_timer_pool_to_u64(tp));
	LOG_DBG("Resolution:   %" PRIu64 "\n", tparam.res_ns);
	LOG_DBG("Min timeout:  %" PRIu64 "\n", tparam.min_tmo);
	LOG_DBG("Max timeout:  %" PRIu64 "\n", tparam.max_tmo);
	LOG_DBG("Num timers..: %u\n", tparam.num_timers);
	LOG_DBG("Tmo range: %u ms (%" PRIu64 " ticks)\n", RANGE_MS,
		odp_timer_ns_to_tick(tp, 1000000ULL * RANGE_MS));

	tick = odp_timer_ns_to_tick(tp, 0);
	CU_ASSERT(tick == 0);
	ns2  = odp_timer_tick_to_ns(tp, tick);
	CU_ASSERT(ns2 == 0);

	for (ns = resolution_ns; ns < MAX_TMO; ns += resolution_ns) {
		tick = odp_timer_ns_to_tick(tp, ns);
		ns2  = odp_timer_tick_to_ns(tp, tick);

		if (ns2 < ns - resolution_ns) {
			LOG_DBG("FAIL ns:%" PRIu64 " tick:%" PRIu64 " ns2:%"
				PRIu64 "\n", ns, tick, ns2);
			CU_FAIL("tick conversion: nsec too small\n");
		}

		if (ns2 > ns + resolution_ns) {
			LOG_DBG("FAIL ns:%" PRIu64 " tick:%" PRIu64 " ns2:%"
				PRIu64 "\n", ns, tick, ns2);
			CU_FAIL("tick conversion: nsec too large\n");
		}
	}

	/* Initialize barrier used by worker threads for synchronization */
	odp_barrier_init(&test_barrier, num_workers);

	/* Initialize the shared timeout counter */
	odp_atomic_init_u32(&ndelivtoolate, 0);

	/* Initialize the number of finally allocated elements */
	odp_atomic_init_u32(&timers_allocated, 0);

	/* Create and start worker threads */
	thrdarg.testcase = 0;
	thrdarg.numthrds = num_workers;
	odp_cunit_thread_create(worker_entrypoint, &thrdarg);

	/* Wait for worker threads to exit */
	odp_cunit_thread_exit(&thrdarg);
	LOG_DBG("Number of timeouts delivered/received too late: %" PRIu32 "\n",
		odp_atomic_load_u32(&ndelivtoolate));

	/* Check some statistics after the test */
	if (odp_timer_pool_info(tp, &tpinfo) != 0)
		CU_FAIL("odp_timer_pool_info");
	CU_ASSERT(tpinfo.param.num_timers == (unsigned)num_workers * NTIMERS);
	CU_ASSERT(tpinfo.cur_timers == 0);
	CU_ASSERT(tpinfo.hwm_timers == odp_atomic_load_u32(&timers_allocated));

	/* Destroy timer pool, all timers must have been freed */
	odp_timer_pool_destroy(tp);

	/* Destroy timeout pool, all timeouts must have been freed */
	rc = odp_pool_destroy(tbp);
	CU_ASSERT(rc == 0);

	CU_PASS("ODP timer test");
}

odp_testinfo_t timer_suite[] = {
	ODP_TEST_INFO(timer_test_timeout_pool_alloc),
	ODP_TEST_INFO(timer_test_timeout_pool_free),
	ODP_TEST_INFO(timer_test_plain_queue),
	ODP_TEST_INFO(timer_test_sched_queue),
	ODP_TEST_INFO(timer_test_odp_timer_cancel),
	ODP_TEST_INFO(timer_test_odp_timer_all),
	ODP_TEST_INFO_NULL,
};

odp_suiteinfo_t timer_suites[] = {
	{"Timer", NULL, NULL, timer_suite},
	ODP_SUITE_INFO_NULL,
};

int main(int argc, char *argv[])
{
	/* parse common options: */
	if (odp_cunit_parse_options(argc, argv))
		return -1;

	int ret = odp_cunit_register(timer_suites);

	if (ret == 0)
		ret = odp_cunit_run();

	return ret;
}
