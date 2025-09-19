/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023-2025 Nokia
 */

/**
 * @example odp_bench_timer.c
 *
 * Microbenchmark application for timer API functions
 *
 * @cond _ODP_HIDE_FROM_DOXYGEN_
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* Needed for sigaction */
#endif

#include <odp_api.h>
#include <odp/helper/odph_api.h>

#include <bench_common.h>
#include <export_results.h>

#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

/* Number of API function calls per test case */
#define REPEAT_COUNT 1000

/* Default number of rounds per test case */
#define ROUNDS 1000u

/* User area size in bytes */
#define UAREA_SIZE 8

/* Timer duration in nsec */
#define TIMER_NSEC 50000000

/* Maximum number of results to be held */
#define TEST_MAX_BENCH 20

#define BENCH_INFO(run_fn, init_fn, term_fn) \
	{.name = #run_fn, .run = run_fn, .init = init_fn, .term = term_fn}

#define BENCH_INFO_TM(run_fn, init_fn, term_fn) \
	{.name = #run_fn, .run = run_fn, .init = init_fn, .term = term_fn}

typedef enum {
	M_TPUT,
	M_LATENCY
} meas_mode_t;

typedef struct {
	/* Command line options */
	struct {
		/* Clock source to be used */
		int clk_src;
		/* Measure time vs CPU cycles */
		int time;
		/* Benchmark index to run indefinitely */
		int bench_idx;
		/* Rounds per test case */
		uint32_t rounds;
		/* Measurement mode */
		meas_mode_t mode;

	} opt;

	/* Common benchmark suite data */
	struct {
		union {
			/* Basic suite for avg */
			bench_suite_t b;
			/* TM suite for min/max/avg */
			bench_tm_suite_t t;
		};

		/* Loop breaker */
		odp_atomic_u32_t *exit;
		/* Pointer to suite return value */
		int *retval;
		/* Suite args */
		void *args;
		/* Suite runner */
		int (*suite_fn)(void *args);
		/* Data exporter */
		int (*export_fn)(void *data);
		/* Dummy storage */
		uint64_t dummy;
	} suite;

	odp_timer_start_t start_param;
	odp_timer_pool_t timer_pool;
	odp_timer_t timer;
	odp_queue_t queue;
	odp_pool_t pool;
	odp_timeout_t timeout;
	odp_event_t event;
	uint64_t timer_nsec;
	uint64_t tick;
	uint64_t nsec;
	double tick_hz;
	int plain_queue;

	/* Test case input / output data */
	uint64_t      a1[REPEAT_COUNT];
	odp_event_t   ev[REPEAT_COUNT];
	odp_timeout_t tmo[REPEAT_COUNT];
	odp_timer_t   tim_src[REPEAT_COUNT];
	odp_timer_t   tim_dst[REPEAT_COUNT];

	/* CPU mask as string */
	char cpumask_str[ODP_CPUMASK_STR_SIZE];

	/* Array for storing results */
	union{
		/* Basic suite results */
		double b[TEST_MAX_BENCH];
		/* TM suite results */
		bench_tm_result_t t[TEST_MAX_BENCH];
	} result;

} gbl_args_t;

static gbl_args_t *gbl_args;

static void sig_handler(int signo ODP_UNUSED)
{
	if (gbl_args == NULL)
		return;
	odp_atomic_store_u32(gbl_args->suite.exit, 1);
}

static int setup_sig_handler(void)
{
	struct sigaction action;

	memset(&action, 0, sizeof(action));
	action.sa_handler = sig_handler;

	/* No additional signals blocked. By default, the signal which triggered
	 * the handler is blocked. */
	if (sigemptyset(&action.sa_mask))
		return -1;

	if (sigaction(SIGINT, &action, NULL))
		return -1;

	return 0;
}

static void cancel_timers(void)
{
	odp_timer_t *tim = gbl_args->tim_src;
	odp_event_t ev;
	int ret;

	for (int i = 0; i < REPEAT_COUNT; i++) {
		ret = odp_timer_cancel(tim[i], &ev);

		if (ret == ODP_TIMER_FAIL)
			ODPH_ABORT("Failed to cancel timer, ret: %d, index: %d\n", ret, i);
	}
}

static void start_timers(void)
{
	odp_timer_t *tim = gbl_args->tim_src;
	const odp_timer_start_t *start = &gbl_args->start_param;
	int ret;

	for (int i = 0; i < REPEAT_COUNT; i++) {
		ret = odp_timer_start(tim[i], start);

		if (ret != ODP_TIMER_SUCCESS)
			ODPH_ABORT("Failed to start timer, ret: %d, index: %d\n", ret, i);
	}
}

static int timer_current_tick(void)
{
	int i;
	odp_timer_pool_t timer_pool = gbl_args->timer_pool;
	uint64_t *a1 = gbl_args->a1;

	for (i = 0; i < REPEAT_COUNT; i++)
		a1[i] = odp_timer_current_tick(timer_pool);

	return i;
}

static int timer_current_tick_tm(bench_tm_result_t *res, int repeat_count)
{
	int i;
	odp_timer_pool_t timer_pool = gbl_args->timer_pool;
	uint64_t *a1 = gbl_args->a1;
	const uint8_t id1 = bench_tm_func_register(res, "odp_timer_current_tick()");
	bench_tm_stamp_t s1, s2;

	for (i = 0; i < repeat_count; i++) {
		bench_tm_now(res, &s1);
		a1[i] = odp_timer_current_tick(timer_pool);
		bench_tm_now(res, &s2);
		bench_tm_func_record(&s2, &s1, res, id1);
	}

	return i;
}

static int timer_tick_to_ns(void)
{
	int i;
	odp_timer_pool_t timer_pool = gbl_args->timer_pool;
	uint64_t *a1 = gbl_args->a1;
	uint64_t tick = gbl_args->tick;

	for (i = 0; i < REPEAT_COUNT; i++)
		a1[i] = odp_timer_tick_to_ns(timer_pool, tick);

	return i;
}

static int timer_tick_to_ns_tm(bench_tm_result_t *res, int repeat_count)
{
	int i;
	odp_timer_pool_t timer_pool = gbl_args->timer_pool;
	uint64_t *a1 = gbl_args->a1;
	uint64_t tick = gbl_args->tick;
	const uint8_t id1 = bench_tm_func_register(res, "odp_timer_tick_to_ns()");
	bench_tm_stamp_t s1, s2;

	for (i = 0; i < repeat_count; i++) {
		bench_tm_now(res, &s1);
		a1[i] = odp_timer_tick_to_ns(timer_pool, tick);
		bench_tm_now(res, &s2);
		bench_tm_func_record(&s2, &s1, res, id1);
	}

	return i;
}

static int timer_ns_to_tick(void)
{
	int i;
	odp_timer_pool_t timer_pool = gbl_args->timer_pool;
	uint64_t *a1 = gbl_args->a1;
	uint64_t nsec = gbl_args->nsec;

	for (i = 0; i < REPEAT_COUNT; i++)
		a1[i] = odp_timer_ns_to_tick(timer_pool, nsec);

	return i;
}

static int timer_ns_to_tick_tm(bench_tm_result_t *res, int repeat_count)
{
	int i;
	odp_timer_pool_t timer_pool = gbl_args->timer_pool;
	uint64_t *a1 = gbl_args->a1;
	uint64_t nsec = gbl_args->nsec;
	const uint8_t id1 = bench_tm_func_register(res, "odp_timer_ns_to_tick()");
	bench_tm_stamp_t s1, s2;

	for (i = 0; i < repeat_count; i++) {
		bench_tm_now(res, &s1);
		a1[i] = odp_timer_ns_to_tick(timer_pool, nsec);
		bench_tm_now(res, &s2);
		bench_tm_func_record(&s2, &s1, res, id1);
	}

	return i;
}

static int timeout_to_event(void)
{
	int i;
	odp_event_t *ev = gbl_args->ev;
	odp_timeout_t timeout = gbl_args->timeout;

	for (i = 0; i < REPEAT_COUNT; i++)
		ev[i] = odp_timeout_to_event(timeout);

	gbl_args->suite.dummy += odp_event_to_u64(ev[0]);

	return i;
}

static int timeout_to_event_tm(bench_tm_result_t *res, int repeat_count)
{
	int i;
	odp_event_t *ev = gbl_args->ev;
	odp_timeout_t timeout = gbl_args->timeout;
	const uint8_t id1 = bench_tm_func_register(res, "odp_timeout_to_event()");
	bench_tm_stamp_t s1, s2;

	for (i = 0; i < repeat_count; i++) {
		bench_tm_now(res, &s1);
		ev[i] = odp_timeout_to_event(timeout);
		bench_tm_now(res, &s2);
		bench_tm_func_record(&s2, &s1, res, id1);
	}

	gbl_args->suite.dummy += odp_event_to_u64(ev[0]);

	return i;
}

static int timeout_from_event(void)
{
	int i;
	odp_event_t ev = gbl_args->event;
	odp_timeout_t *tmo = gbl_args->tmo;

	for (i = 0; i < REPEAT_COUNT; i++)
		tmo[i] = odp_timeout_from_event(ev);

	gbl_args->suite.dummy += odp_timeout_to_u64(tmo[0]);

	return i;
}

static int timeout_from_event_tm(bench_tm_result_t *res, int repeat_count)
{
	int i;
	odp_event_t ev = gbl_args->event;
	odp_timeout_t *tmo = gbl_args->tmo;
	const uint8_t id1 = bench_tm_func_register(res, "odp_timeout_from_event()");
	bench_tm_stamp_t s1, s2;

	for (i = 0; i < repeat_count; i++) {
		bench_tm_now(res, &s1);
		tmo[i] = odp_timeout_from_event(ev);
		bench_tm_now(res, &s2);
		bench_tm_func_record(&s2, &s1, res, id1);
	}

	gbl_args->suite.dummy += odp_timeout_to_u64(tmo[0]);

	return i;
}

static int timeout_timer(void)
{
	int i;
	odp_timeout_t timeout = gbl_args->timeout;
	odp_timer_t *tim = gbl_args->tim_dst;

	for (i = 0; i < REPEAT_COUNT; i++)
		tim[i] = odp_timeout_timer(timeout);

	gbl_args->suite.dummy += odp_timer_to_u64(tim[0]);

	return i;
}

static int timeout_timer_tm(bench_tm_result_t *res, int repeat_count)
{
	int i;
	odp_timeout_t timeout = gbl_args->timeout;
	odp_timer_t *tim = gbl_args->tim_dst;
	const uint8_t id1 = bench_tm_func_register(res, "odp_timeout_timer()");
	bench_tm_stamp_t s1, s2;

	for (i = 0; i < repeat_count; i++) {
		bench_tm_now(res, &s1);
		tim[i] = odp_timeout_timer(timeout);
		bench_tm_now(res, &s2);
		bench_tm_func_record(&s2, &s1, res, id1);
	}

	gbl_args->suite.dummy += odp_timer_to_u64(tim[0]);

	return i;
}

static int timeout_tick(void)
{
	int i;
	odp_timeout_t timeout = gbl_args->timeout;
	uint64_t *a1 = gbl_args->a1;

	for (i = 0; i < REPEAT_COUNT; i++)
		a1[i] = odp_timeout_tick(timeout);

	return i;
}

static int timeout_tick_tm(bench_tm_result_t *res, int repeat_count)
{
	int i;
	odp_timeout_t timeout = gbl_args->timeout;
	uint64_t *a1 = gbl_args->a1;
	const uint8_t id1 = bench_tm_func_register(res, "odp_timeout_tick()");
	bench_tm_stamp_t s1, s2;

	for (i = 0; i < repeat_count; i++) {
		bench_tm_now(res, &s1);
		a1[i] = odp_timeout_tick(timeout);
		bench_tm_now(res, &s2);
		bench_tm_func_record(&s2, &s1, res, id1);
	}

	return i;
}

static int timeout_user_ptr(void)
{
	int i;
	odp_timeout_t timeout = gbl_args->timeout;
	uint64_t *a1 = gbl_args->a1;

	for (i = 0; i < REPEAT_COUNT; i++)
		a1[i] = (uintptr_t)odp_timeout_user_ptr(timeout);

	return i;
}

static int timeout_user_ptr_tm(bench_tm_result_t *res, int repeat_count)
{
	int i;
	odp_timeout_t timeout = gbl_args->timeout;
	uint64_t *a1 = gbl_args->a1;
	const uint8_t id1 = bench_tm_func_register(res, "odp_timeout_user_ptr()");
	bench_tm_stamp_t s1, s2;

	for (i = 0; i < repeat_count; i++) {
		bench_tm_now(res, &s1);
		a1[i] = (uintptr_t)odp_timeout_user_ptr(timeout);
		bench_tm_now(res, &s2);
		bench_tm_func_record(&s2, &s1, res, id1);
	}

	return i;
}

static int timeout_user_area(void)
{
	int i;
	odp_timeout_t timeout = gbl_args->timeout;
	uint64_t *a1 = gbl_args->a1;

	for (i = 0; i < REPEAT_COUNT; i++)
		a1[i] = (uintptr_t)odp_timeout_user_area(timeout);

	return i;
}

static int timeout_user_area_tm(bench_tm_result_t *res, int repeat_count)
{
	int i;
	odp_timeout_t timeout = gbl_args->timeout;
	uint64_t *a1 = gbl_args->a1;
	const uint8_t id1 = bench_tm_func_register(res, "odp_timeout_user_area()");
	bench_tm_stamp_t s1, s2;

	for (i = 0; i < repeat_count; i++) {
		bench_tm_now(res, &s1);
		a1[i] = (uintptr_t)odp_timeout_user_area(timeout);
		bench_tm_now(res, &s2);
		bench_tm_func_record(&s2, &s1, res, id1);
	}

	return i;
}

static int timeout_to_u64(void)
{
	int i;
	odp_timeout_t timeout = gbl_args->timeout;
	uint64_t *a1 = gbl_args->a1;

	for (i = 0; i < REPEAT_COUNT; i++)
		a1[i] = odp_timeout_to_u64(timeout);

	return i;
}

static int timeout_to_u64_tm(bench_tm_result_t *res, int repeat_count)
{
	int i;
	odp_timeout_t timeout = gbl_args->timeout;
	uint64_t *a1 = gbl_args->a1;
	const uint8_t id1 = bench_tm_func_register(res, "odp_timeout_to_u64()");
	bench_tm_stamp_t s1, s2;

	for (i = 0; i < repeat_count; i++) {
		bench_tm_now(res, &s1);
		a1[i] = odp_timeout_to_u64(timeout);
		bench_tm_now(res, &s2);
		bench_tm_func_record(&s2, &s1, res, id1);
	}

	return i;
}

static int timer_to_u64(void)
{
	int i;
	odp_timer_t timer = gbl_args->timer;
	uint64_t *a1 = gbl_args->a1;

	for (i = 0; i < REPEAT_COUNT; i++)
		a1[i] = odp_timer_to_u64(timer);

	return i;
}

static int timer_to_u64_tm(bench_tm_result_t *res, int repeat_count)
{
	int i;
	odp_timer_t timer = gbl_args->timer;
	uint64_t *a1 = gbl_args->a1;
	const uint8_t id1 = bench_tm_func_register(res, "odp_timer_to_u64()");
	bench_tm_stamp_t s1, s2;

	for (i = 0; i < repeat_count; i++) {
		bench_tm_now(res, &s1);
		a1[i] = odp_timer_to_u64(timer);
		bench_tm_now(res, &s2);
		bench_tm_func_record(&s2, &s1, res, id1);
	}

	return i;
}

static int timer_pool_to_u64(void)
{
	int i;
	odp_timer_pool_t tp = gbl_args->timer_pool;
	uint64_t *a1 = gbl_args->a1;

	for (i = 0; i < REPEAT_COUNT; i++)
		a1[i] = odp_timer_pool_to_u64(tp);

	return i;
}

static int timer_pool_to_u64_tm(bench_tm_result_t *res, int repeat_count)
{
	int i;
	odp_timer_pool_t tp = gbl_args->timer_pool;
	uint64_t *a1 = gbl_args->a1;
	const uint8_t id1 = bench_tm_func_register(res, "odp_timer_pool_to_u64()");
	bench_tm_stamp_t s1, s2;

	for (i = 0; i < repeat_count; i++) {
		bench_tm_now(res, &s1);
		a1[i] = odp_timer_pool_to_u64(tp);
		bench_tm_now(res, &s2);
		bench_tm_func_record(&s2, &s1, res, id1);
	}

	return i;
}

static int timer_start(void)
{
	int i, ret;
	odp_timer_t *tim = gbl_args->tim_src;
	const odp_timer_start_t *start = &gbl_args->start_param;

	for (i = 0; i < REPEAT_COUNT; i++) {
		ret = odp_timer_start(tim[i], start);

		ODPH_ASSERT(ret == ODP_TIMER_SUCCESS);
	}

	return i;
}

static int timer_start_tm(bench_tm_result_t *res, int repeat_count)
{
	int i, ret;
	odp_timer_t *tim = gbl_args->tim_src;
	const odp_timer_start_t *start = &gbl_args->start_param;
	const uint8_t id1 = bench_tm_func_register(res, "odp_timer_start()");
	bench_tm_stamp_t s1, s2;

	for (i = 0; i < repeat_count; i++) {
		bench_tm_now(res, &s1);
		ret = odp_timer_start(tim[i], start);

		ODPH_ASSERT(ret == ODP_TIMER_SUCCESS);

		bench_tm_now(res, &s2);
		bench_tm_func_record(&s2, &s1, res, id1);
	}

	return i;
}

static int timer_cancel(void)
{
	int i, ret;
	odp_timer_t *tim = gbl_args->tim_src;
	odp_event_t ev;

	for (i = 0; i < REPEAT_COUNT; i++) {
		ret = odp_timer_cancel(tim[i], &ev);

		ODPH_ASSERT(ret == ODP_TIMER_SUCCESS);
	}

	return i;
}

static int timer_cancel_tm(bench_tm_result_t *res, int repeat_count)
{
	int i, ret;
	odp_timer_t *tim = gbl_args->tim_src;
	odp_event_t ev;
	const uint8_t id1 = bench_tm_func_register(res, "odp_timer_cancel()");
	bench_tm_stamp_t s1, s2;

	for (i = 0; i < repeat_count; i++) {
		bench_tm_now(res, &s1);
		ret = odp_timer_cancel(tim[i], &ev);

		ODPH_ASSERT(ret == ODP_TIMER_SUCCESS);

		bench_tm_now(res, &s2);
		bench_tm_func_record(&s2, &s1, res, id1);
	}

	return i;
}

static int timer_start_cancel(void)
{
	int i, ret;
	odp_timer_t *tim = gbl_args->tim_src;
	const odp_timer_start_t *start = &gbl_args->start_param;
	odp_event_t ev;

	for (i = 0; i < REPEAT_COUNT; i++) {
		ret = odp_timer_start(tim[i], start);

		ODPH_ASSERT(ret == ODP_TIMER_SUCCESS);

		ret = odp_timer_cancel(tim[i], &ev);

		ODPH_ASSERT(ret == ODP_TIMER_SUCCESS);
	}

	return i;
}

static int timer_start_cancel_tm(bench_tm_result_t *res, int repeat_count)
{
	int i, ret;
	odp_timer_t *tim = gbl_args->tim_src;
	const odp_timer_start_t *start = &gbl_args->start_param;
	odp_event_t ev;
	const uint8_t id1 = bench_tm_func_register(res, "odp_timer_start()/_cancel()");
	bench_tm_stamp_t s1, s2;

	for (i = 0; i < repeat_count; i++) {
		bench_tm_now(res, &s1);
		ret = odp_timer_start(tim[i], start);

		ODPH_ASSERT(ret == ODP_TIMER_SUCCESS);

		ret = odp_timer_cancel(tim[i], &ev);

		ODPH_ASSERT(ret == ODP_TIMER_SUCCESS);

		bench_tm_now(res, &s2);
		bench_tm_func_record(&s2, &s1, res, id1);
	}

	return i;
}

static int bench_timer_tm_export(void *data)
{
	gbl_args_t *gbl_args = data;
	bench_tm_result_t *res;
	uint64_t num;
	int ret = 0;
	const char *unit = gbl_args->opt.time ? "nsec" : "cpu cycles";

	if (test_common_write("function name,min %s per function call,"
			      "average %s per function call,"
			      "max %s per function call\n", unit, unit, unit)) {
		ret = -1;
		goto exit;
	}

	for (uint32_t i = 0; i < gbl_args->suite.t.num_bench; i++) {
		res = &gbl_args->suite.t.result[i];

		for (int j = 0; j < res->num; j++) {
			num = res->func[j].num ? res->func[j].num : 1;
			if (test_common_write("%s,%" PRIu64 ",%" PRIu64 ",%" PRIu64 "\n",
					      res->func[j].name,
					      bench_tm_to_u64(res, &res->func[j].min),
					      bench_tm_to_u64(res, &res->func[j].tot) / num,
					      bench_tm_to_u64(res, &res->func[j].max))) {
				ret = -1;
				goto exit;
			}
		}
	}

exit:
	test_common_write_term();

	return ret;
}

static int bench_timer_export(void *data)
{
	gbl_args_t *gbl_args = data;
	int ret = 0;

	if (test_common_write("%s", gbl_args->opt.time ?
			      "function name,average nsec per function call\n" :
			      "function name,average cpu cycles per function call\n")) {
		ret = -1;
		goto exit;
	}

	for (int i = 0; i < gbl_args->suite.b.num_bench; i++) {
		if (test_common_write("odp_%s,%f\n",
				      gbl_args->suite.b.bench[i].name,
				      gbl_args->suite.b.result[i])) {
			ret = -1;
			goto exit;
		}
	}

exit:
	test_common_write_term();

	return ret;
}

bench_info_t test_suite[] = {
	BENCH_INFO(timer_current_tick, NULL, NULL),
	BENCH_INFO(timer_tick_to_ns, NULL, NULL),
	BENCH_INFO(timer_ns_to_tick, NULL, NULL),
	BENCH_INFO(timeout_to_event, NULL, NULL),
	BENCH_INFO(timeout_from_event, NULL, NULL),
	BENCH_INFO(timeout_timer, NULL, NULL),
	BENCH_INFO(timeout_tick, NULL, NULL),
	BENCH_INFO(timeout_user_ptr, NULL, NULL),
	BENCH_INFO(timeout_user_area, NULL, NULL),
	BENCH_INFO(timeout_to_u64, NULL, NULL),
	BENCH_INFO(timer_to_u64, NULL, NULL),
	BENCH_INFO(timer_pool_to_u64, NULL, NULL),
	BENCH_INFO(timer_start, NULL, cancel_timers),
	BENCH_INFO(timer_cancel, start_timers, NULL),
	BENCH_INFO(timer_start_cancel, NULL, NULL),
};

ODP_STATIC_ASSERT(ODPH_ARRAY_SIZE(test_suite) < TEST_MAX_BENCH,
		  "Result array is too small to hold all the results");

bench_tm_info_t test_suite_tm[] = {
	BENCH_INFO_TM(timer_current_tick_tm, NULL, NULL),
	BENCH_INFO_TM(timer_tick_to_ns_tm, NULL, NULL),
	BENCH_INFO_TM(timer_ns_to_tick_tm, NULL, NULL),
	BENCH_INFO_TM(timeout_to_event_tm, NULL, NULL),
	BENCH_INFO_TM(timeout_from_event_tm, NULL, NULL),
	BENCH_INFO_TM(timeout_timer_tm, NULL, NULL),
	BENCH_INFO_TM(timeout_tick_tm, NULL, NULL),
	BENCH_INFO_TM(timeout_user_ptr_tm, NULL, NULL),
	BENCH_INFO_TM(timeout_user_area_tm, NULL, NULL),
	BENCH_INFO_TM(timeout_to_u64_tm, NULL, NULL),
	BENCH_INFO_TM(timer_to_u64_tm, NULL, NULL),
	BENCH_INFO_TM(timer_pool_to_u64_tm, NULL, NULL),
	BENCH_INFO_TM(timer_start_tm, NULL, cancel_timers),
	BENCH_INFO_TM(timer_cancel_tm, start_timers, NULL),
	BENCH_INFO_TM(timer_start_cancel_tm, NULL, NULL),
};

ODP_STATIC_ASSERT(ODPH_ARRAY_SIZE(test_suite_tm) < TEST_MAX_BENCH,
		  "Result array is too small to hold all the results");

/* Print usage information */
static void usage(void)
{
	printf("\n"
	       "ODP timer API micro benchmarks\n"
	       "\n"
	       "Options:\n"
	       "  -s, --clk_src           Clock source select (default 0):\n"
	       "                            0: ODP_CLOCK_DEFAULT\n"
	       "                            1: ODP_CLOCK_SRC_1, ...\n"
	       "  -t, --time <opt>        Time measurement. 0: measure CPU cycles (default), 1: measure time\n"
	       "  -i, --index <idx>       Benchmark index to run indefinitely.\n"
	       "  -r, --rounds <num>      Run each test case 'num' times (default %u).\n"
	       "  -m, --mode <mode>       Measurement mode. 0: measure throughput, track average execution\n"
	       "                          time (default), 1: measure latency, track function minimum and\n"
	       "                          maximum in addition to average execution time.\n"
	       "  -h, --help              Display help and exit.\n\n"
	       "\n", ROUNDS);
}

/* Parse command line arguments */
static int parse_args(int argc, char *argv[])
{
	int opt;
	static const struct option longopts[] = {
		{"clk_src", required_argument, NULL, 's'},
		{"time", required_argument, NULL, 't'},
		{"index", required_argument, NULL, 'i'},
		{"rounds", required_argument, NULL, 'r'},
		{"mode", required_argument, NULL, 'm'},
		{"help", no_argument, NULL, 'h'},
		{NULL, 0, NULL, 0}
	};

	static const char *shortopts =  "s:t:i:r:m:h";

	gbl_args->opt.clk_src = ODP_CLOCK_DEFAULT;
	gbl_args->opt.time = 0; /* Measure CPU cycles */
	gbl_args->opt.bench_idx = 0; /* Run all benchmarks */
	gbl_args->opt.rounds = ROUNDS;
	gbl_args->opt.mode = M_TPUT;

	while (1) {
		opt = getopt_long(argc, argv, shortopts, longopts, NULL);

		if (opt == -1)
			break; /* No more options */

		switch (opt) {
		case 's':
			gbl_args->opt.clk_src = atoi(optarg);
			break;
		case 't':
			gbl_args->opt.time = atoi(optarg);
			break;
		case 'i':
			gbl_args->opt.bench_idx = atoi(optarg);
			break;
		case 'r':
			gbl_args->opt.rounds = atoi(optarg);
			break;
		case 'm':
			gbl_args->opt.mode = atoi(optarg);
			break;
		case 'h':
			usage();
			return 1;
		default:
			ODPH_ERR("Bad option. Use -h for help.\n");
			return -1;
		}
	}

	if (gbl_args->opt.rounds < 1) {
		ODPH_ERR("Invalid test cycle repeat count: %u\n", gbl_args->opt.rounds);
		return -1;
	}

	if (gbl_args->opt.bench_idx < 0 ||
	    gbl_args->opt.bench_idx > (int)ODPH_ARRAY_SIZE(test_suite)) {
		ODPH_ERR("Bad bench index %i\n", gbl_args->opt.bench_idx);
		return -1;
	}

	if (gbl_args->opt.mode != M_TPUT && gbl_args->opt.mode != M_LATENCY) {
		printf("Invalid measurement mode: %d\n", gbl_args->opt.mode);
		exit(EXIT_FAILURE);
	}

	optind = 1; /* Reset 'extern optind' from the getopt lib */

	return 0;
}

/* Print system and application info */
static void print_info(void)
{
	odp_sys_info_print();

	printf("\n"
	       "odp_bench_timer options\n"
	       "-----------------------\n");

	printf("CPU mask:          %s\n", gbl_args->cpumask_str);
	printf("Clock source:      %i\n", gbl_args->opt.clk_src);
	printf("Measurement unit:  %s\n", gbl_args->opt.time ? "nsec" : "CPU cycles");
	printf("Test rounds:       %u\n", gbl_args->opt.rounds);
	printf("Timer duration:    %" PRIu64 " nsec\n", gbl_args->timer_nsec);
	printf("Timer tick freq:   %.2f Hz\n", gbl_args->tick_hz);
	printf("Measurement mode:  %s\n", gbl_args->opt.mode == M_TPUT ? "throughput" : "latency");
	printf("\n");
}

static int create_timers(void)
{
	odp_pool_capability_t pool_capa;
	odp_timer_capability_t timer_capa;
	odp_timer_clk_src_t clk_src;
	odp_timer_pool_param_t tp_param;
	odp_timer_pool_t tp;
	odp_pool_t pool;
	odp_pool_param_t pool_param;
	odp_timeout_t tmo;
	odp_queue_param_t queue_param;
	odp_queue_t queue;
	odp_timer_t timer, *tim_src = gbl_args->tim_src;
	uint64_t t1, t2, diff, tick1, tick2;
	const uint32_t num_timers = REPEAT_COUNT + 1;

	if (odp_pool_capability(&pool_capa)) {
		ODPH_ERR("Pool capa failed\n");
		return -1;
	}

	clk_src = gbl_args->opt.clk_src;
	if (odp_timer_capability(clk_src, &timer_capa)) {
		ODPH_ERR("Timer capa failed\n");
		return -1;
	}

	if (timer_capa.max_timers != 0 && timer_capa.max_timers < num_timers) {
		ODPH_ERR("Not enough timers supported\n");
		return -1;
	}

	odp_timer_pool_param_init(&tp_param);
	tp_param.clk_src    = clk_src;
	tp_param.res_ns     = timer_capa.max_res.res_ns;
	tp_param.min_tmo    = timer_capa.max_res.min_tmo;
	tp_param.max_tmo    = timer_capa.max_res.max_tmo;
	tp_param.num_timers = num_timers;

	tp = odp_timer_pool_create("bench_timer", &tp_param);

	if (tp == ODP_TIMER_POOL_INVALID) {
		ODPH_ERR("Timer pool create failed\n");
		return -1;
	}

	if (odp_timer_pool_start_multi(&tp, 1) != 1) {
		ODPH_ERR("Timer pool start failed\n");
		return -1;
	}

	gbl_args->timer_pool = tp;

	gbl_args->timer_nsec = TIMER_NSEC;
	if (TIMER_NSEC < tp_param.min_tmo)
		gbl_args->timer_nsec = tp_param.min_tmo;
	else if (TIMER_NSEC > tp_param.max_tmo)
		gbl_args->timer_nsec = tp_param.max_tmo;

	odp_pool_param_init(&pool_param);
	pool_param.type           = ODP_POOL_TIMEOUT;
	pool_param.tmo.num        = 10;
	pool_param.tmo.uarea_size = UAREA_SIZE;
	if (UAREA_SIZE > pool_capa.tmo.max_uarea_size)
		pool_param.tmo.uarea_size = pool_capa.tmo.max_uarea_size;

	pool = odp_pool_create("bench_timer", &pool_param);

	if (pool == ODP_POOL_INVALID) {
		ODPH_ERR("Timeout pool create failed\n");
		return -1;
	}

	gbl_args->pool = pool;

	tmo = odp_timeout_alloc(pool);

	if (tmo == ODP_TIMEOUT_INVALID) {
		ODPH_ERR("Timeout alloc failed\n");
		return -1;
	}

	gbl_args->timeout = tmo;
	gbl_args->tick = odp_timer_current_tick(tp);
	gbl_args->nsec = odp_timer_tick_to_ns(tp, gbl_args->tick);

	/* Measure timer tick frequency for test information */
	t1 = odp_time_global_strict_ns();
	tick1 = odp_timer_current_tick(tp);

	odp_time_wait_ns(200 * ODP_TIME_MSEC_IN_NS);

	tick2 = odp_timer_current_tick(tp);
	t2 = odp_time_global_strict_ns();
	diff = t2 - t1;

	if (diff)
		gbl_args->tick_hz = (tick2 - tick1) / ((double)diff / ODP_TIME_SEC_IN_NS);

	odp_queue_param_init(&queue_param);
	queue_param.type        = ODP_QUEUE_TYPE_SCHED;
	queue_param.sched.prio  = odp_schedule_default_prio();
	queue_param.sched.sync  = ODP_SCHED_SYNC_ATOMIC;
	queue_param.sched.group = ODP_SCHED_GROUP_ALL;

	if (timer_capa.queue_type_sched == 0) {
		queue_param.type = ODP_QUEUE_TYPE_PLAIN;
		gbl_args->plain_queue = 1;
	}

	queue = odp_queue_create("bench_timer", &queue_param);
	if (queue == ODP_QUEUE_INVALID) {
		ODPH_ERR("Queue create failed\n");
		return -1;
	}

	gbl_args->queue = queue;

	timer = odp_timer_alloc(tp, queue, (void *)(uintptr_t)0xdeadbeef);
	if (timer == ODP_TIMER_INVALID) {
		ODPH_ERR("Timer alloc failed\n");
		return -1;
	}

	gbl_args->timer = timer;

	for (int i = 0; i < REPEAT_COUNT; i++) {
		tim_src[i] = odp_timer_alloc(tp, queue, NULL);

		if (tim_src[i] == ODP_TIMER_INVALID) {
			ODPH_ERR("Timer alloc failed\n");
			return -1;
		}
	}

	return 0;
}

static int wait_timer(void)
{
	odp_timer_start_t *start_param = &gbl_args->start_param;
	odp_timer_t timer = gbl_args->timer;
	odp_timer_pool_t tp = gbl_args->timer_pool;
	uint64_t wait_nsec = 2 * gbl_args->timer_nsec;
	uint64_t sched_wait = odp_schedule_wait_time(wait_nsec);
	odp_event_t ev;
	uint64_t start;

	start_param->tick_type = ODP_TIMER_TICK_REL;
	start_param->tick      = odp_timer_ns_to_tick(tp, gbl_args->timer_nsec);
	start_param->tmo_ev    = odp_timeout_to_event(gbl_args->timeout);

	if (odp_timer_start(timer, start_param) != ODP_TIMER_SUCCESS) {
		ODPH_ERR("Timer start failed\n");
		return -1;
	}

	gbl_args->timeout = ODP_TIMEOUT_INVALID;
	gbl_args->event = ODP_EVENT_INVALID;

	/* Wait for timeout */
	if (gbl_args->plain_queue) {
		start = odp_time_global_ns();
		while (1) {
			ev = odp_queue_deq(gbl_args->queue);

			if (ev != ODP_EVENT_INVALID)
				break;

			if ((odp_time_global_ns() - start) > wait_nsec) {
				ODPH_ERR("Timeout event missing\n");
				return -1;
			}
		}

		gbl_args->event = ev;
	} else {
		ev = odp_schedule(NULL, sched_wait);

		if (ev == ODP_EVENT_INVALID) {
			ODPH_ERR("Timeout event missing\n");
			return -1;
		}

		gbl_args->event = ev;

		/* Free schedule context */
		if (odp_schedule(NULL, ODP_SCHED_NO_WAIT) != ODP_EVENT_INVALID) {
			ODPH_ERR("Extra timeout event\n");
			return -1;
		}
	}

	if (odp_event_type(gbl_args->event) != ODP_EVENT_TIMEOUT) {
		ODPH_ERR("Bad event type\n");
		return -1;
	}

	gbl_args->timeout = odp_timeout_from_event(gbl_args->event);

	return 0;
}

static void init_suite(gbl_args_t *gbl_args)
{
	if (gbl_args->opt.mode == M_LATENCY) {
		bench_tm_suite_init(&gbl_args->suite.t);
		gbl_args->suite.t.bench = test_suite_tm;
		gbl_args->suite.t.num_bench = ODPH_ARRAY_SIZE(test_suite_tm);
		gbl_args->suite.t.rounds = REPEAT_COUNT;
		gbl_args->suite.t.bench_idx = gbl_args->opt.bench_idx;
		gbl_args->suite.t.measure_time = !!gbl_args->opt.time;
		gbl_args->suite.exit = &gbl_args->suite.t.exit_worker;
		gbl_args->suite.retval = &gbl_args->suite.t.retval;
		gbl_args->suite.args = &gbl_args->suite.t;
		gbl_args->suite.suite_fn = bench_tm_run;
		gbl_args->suite.export_fn = bench_timer_tm_export;
		gbl_args->suite.t.result = gbl_args->result.t;
	} else {
		bench_suite_init(&gbl_args->suite.b);
		gbl_args->suite.b.bench = test_suite;
		gbl_args->suite.b.num_bench = ODPH_ARRAY_SIZE(test_suite);
		gbl_args->suite.b.indef_idx = gbl_args->opt.bench_idx;
		gbl_args->suite.b.rounds = gbl_args->opt.rounds;
		gbl_args->suite.b.repeat_count = REPEAT_COUNT;
		gbl_args->suite.b.measure_time = !!gbl_args->opt.time;
		gbl_args->suite.exit = &gbl_args->suite.b.exit_worker;
		gbl_args->suite.retval = &gbl_args->suite.b.retval;
		gbl_args->suite.args = &gbl_args->suite.b;
		gbl_args->suite.suite_fn = bench_run;
		gbl_args->suite.export_fn = bench_timer_export;
		gbl_args->suite.b.result = gbl_args->result.b;
	}
}

static void drain_timeouts(void)
{
	const int is_plain = gbl_args->plain_queue;
	odp_queue_t q = gbl_args->queue;
	odp_event_t ev;
	const uint64_t wait = odp_schedule_wait_time(2 * gbl_args->timer_nsec);

	while (true) {
		ev = is_plain ? odp_queue_deq(q) : odp_schedule(NULL, wait);

		if (ev == ODP_EVENT_INVALID)
			break;

		/* The used tmo event will be freed in tester teardown. */
	}
}

int main(int argc, char *argv[])
{
	odph_helper_options_t helper_options;
	test_common_options_t common_options;
	odph_thread_t worker_thread;
	odph_thread_common_param_t thr_common;
	odph_thread_param_t thr_param;
	int cpu, i;
	odp_shm_t shm;
	odp_cpumask_t cpumask, default_mask;
	odp_instance_t instance;
	odp_init_t init_param;
	int ret = 0;

	/* Let helper collect its own arguments (e.g. --odph_proc) */
	argc = odph_parse_options(argc, argv);
	if (odph_options(&helper_options)) {
		ODPH_ERR("Reading ODP helper options failed\n");
		exit(EXIT_FAILURE);
	}

	argc = test_common_parse_options(argc, argv);
	if (test_common_options(&common_options)) {
		ODPH_ERR("Reading test options failed\n");
		exit(EXIT_FAILURE);
	}

	odp_init_param_init(&init_param);
	init_param.mem_model = helper_options.mem_model;

	/* Init ODP before calling anything else */
	if (odp_init_global(&instance, &init_param, NULL)) {
		ODPH_ERR("Global init failed\n");
		exit(EXIT_FAILURE);
	}

	/* Init this thread */
	if (odp_init_local(instance, ODP_THREAD_CONTROL)) {
		ODPH_ERR("Local init failed\n");
		exit(EXIT_FAILURE);
	}

	if (setup_sig_handler()) {
		ODPH_ERR("Signal handler setup failed\n");
		exit(EXIT_FAILURE);
	}

	odp_schedule_config(NULL);

	/* Reserve memory for args from shared mem */
	shm = odp_shm_reserve("shm_args", sizeof(gbl_args_t), ODP_CACHE_LINE_SIZE, 0);
	if (shm == ODP_SHM_INVALID) {
		ODPH_ERR("Shared mem reserve failed\n");
		exit(EXIT_FAILURE);
	}

	gbl_args = odp_shm_addr(shm);
	if (gbl_args == NULL) {
		ODPH_ERR("Shared mem alloc failed\n");
		exit(EXIT_FAILURE);
	}

	memset(gbl_args, 0, sizeof(gbl_args_t));
	gbl_args->timer_pool = ODP_TIMER_POOL_INVALID;
	gbl_args->timer = ODP_TIMER_INVALID;
	gbl_args->queue = ODP_QUEUE_INVALID;
	gbl_args->pool = ODP_POOL_INVALID;
	gbl_args->timeout = ODP_TIMEOUT_INVALID;

	for (i = 0; i < REPEAT_COUNT; i++) {
		gbl_args->a1[i] = i;
		gbl_args->ev[i] = ODP_EVENT_INVALID;
		gbl_args->tmo[i] = ODP_TIMEOUT_INVALID;
		gbl_args->tim_src[i] = ODP_TIMER_INVALID;
		gbl_args->tim_dst[i] = ODP_TIMER_INVALID;
	}

	/* Parse and store the application arguments */
	ret = parse_args(argc, argv);
	if (ret)
		goto exit;

	init_suite(gbl_args);

	/* Get default worker cpumask */
	if (odp_cpumask_default_worker(&default_mask, 1) != 1) {
		ODPH_ERR("Unable to allocate worker thread\n");
		ret = -1;
		goto exit;
	}

	(void)odp_cpumask_to_str(&default_mask, gbl_args->cpumask_str,
				 sizeof(gbl_args->cpumask_str));

	/* Create timers and other resources */
	ret = create_timers();
	if (ret)
		goto exit;

	print_info();

	/* Start one timer and wait for the timeout event. Timer expiration fills in
	 * timeout event metadata. */
	ret = wait_timer();
	if (ret)
		goto exit;

	memset(&worker_thread, 0, sizeof(odph_thread_t));

	/* Create worker thread */
	cpu = odp_cpumask_first(&default_mask);

	odp_cpumask_zero(&cpumask);
	odp_cpumask_set(&cpumask, cpu);

	odph_thread_common_param_init(&thr_common);
	thr_common.instance = instance;
	thr_common.cpumask = &cpumask;
	thr_common.share_param = 1;

	odph_thread_param_init(&thr_param);
	thr_param.start = gbl_args->suite.suite_fn;
	thr_param.arg = gbl_args->suite.args;
	thr_param.thr_type = ODP_THREAD_WORKER;

	odph_thread_create(&worker_thread, &thr_common, &thr_param, 1);

	odph_thread_join(&worker_thread, 1);
	/* Drain those timeouts that were not successfully cancelled for some reason. */
	drain_timeouts();

	if (gbl_args->suite.dummy)
		printf("(dummy result: 0x%" PRIx64 ")\n\n", gbl_args->suite.dummy);

	ret = *gbl_args->suite.retval;

	if (ret == 0 && common_options.is_export) {
		if (gbl_args->suite.export_fn(gbl_args)) {
			ODPH_ERR("Error: Export failed\n");
			ret = -1;
		}
	}

exit:
	if (gbl_args->timeout != ODP_TIMEOUT_INVALID)
		odp_timeout_free(gbl_args->timeout);

	if (gbl_args->pool != ODP_POOL_INVALID)
		odp_pool_destroy(gbl_args->pool);

	if (gbl_args->timer != ODP_TIMER_INVALID) {
		if (odp_timer_free(gbl_args->timer)) {
			ODPH_ERR("Timer free failed\n");
			exit(EXIT_FAILURE);
		}
	}

	for (i = 0; i < REPEAT_COUNT; i++) {
		if (gbl_args->tim_src[i] != ODP_TIMER_INVALID) {
			if (odp_timer_free(gbl_args->tim_src[i])) {
				ODPH_ERR("Timer free failed\n");
				exit(EXIT_FAILURE);
			}
		}
	}

	if (gbl_args->timer_pool != ODP_TIMER_POOL_INVALID)
		odp_timer_pool_destroy(gbl_args->timer_pool);

	if (gbl_args->queue != ODP_QUEUE_INVALID) {
		if (odp_queue_destroy(gbl_args->queue)) {
			ODPH_ERR("Queue destroy failed\n");
			exit(EXIT_FAILURE);
		}
	}

	if (odp_shm_free(shm)) {
		ODPH_ERR("Shared mem free failed\n");
		exit(EXIT_FAILURE);
	}

	if (odp_term_local()) {
		ODPH_ERR("Local term failed\n");
		exit(EXIT_FAILURE);
	}

	if (odp_term_global(instance)) {
		ODPH_ERR("Global term failed\n");
		exit(EXIT_FAILURE);
	}

	if (ret < 0)
		return EXIT_FAILURE;

	return EXIT_SUCCESS;
}
