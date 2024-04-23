/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2015-2018 Linaro Limited
 * Copyright (c) 2019-2024 Nokia
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <time.h>

#include <odp_api.h>
#include <odp/helper/odph_api.h>
#include "odp_cunit_common.h"

#define BUSY_LOOP_CNT		30000000    /* used for t > min resolution */
#define MIN_TIME_RATE		32000
#define MAX_TIME_RATE		15000000000
#define DELAY_TOLERANCE		40000000	    /* deviation for delay */
#define WAIT_SECONDS		3
#define MAX_WORKERS		32
#define TEST_ROUNDS		1024
#define TIME_SAMPLES		2
#define TIME_TOLERANCE_NS	1000000
#define TIME_TOLERANCE_CI_NS	40000000
#define TIME_TOLERANCE_1CPU_NS	40000000
#define GLOBAL_SHM_NAME		"GlobalTimeTest"
#define YEAR_IN_NS		(365 * 24 * ODP_TIME_HOUR_IN_NS)

static uint64_t local_res;
static uint64_t global_res;

typedef odp_time_t time_cb(void);
typedef uint64_t time_res_cb(void);
typedef odp_time_t time_from_ns_cb(uint64_t ns);
typedef uint64_t time_nsec_cb(void);

typedef struct {
	uint32_t num_threads;
	odp_barrier_t test_barrier;
	odp_time_t time[MAX_WORKERS + 1][TIME_SAMPLES];
	odp_queue_t queue[MAX_WORKERS];
	uint32_t num_queues;
	odp_atomic_u32_t event_count;
} global_shared_mem_t;

static global_shared_mem_t *global_mem;
static odp_instance_t *instance;

static int time_global_init(odp_instance_t *inst)
{
	odp_shm_t global_shm;
	odp_init_t init_param;
	odph_helper_options_t helper_options;
	uint32_t workers_count, max_threads;

	if (odph_options(&helper_options)) {
		ODPH_ERR("odph_options() failed\n");
		return -1;
	}

	odp_init_param_init(&init_param);
	init_param.mem_model = helper_options.mem_model;

	if (0 != odp_init_global(inst, &init_param, NULL)) {
		ODPH_ERR("odp_init_global() failed\n");
		return -1;
	}
	if (0 != odp_init_local(*inst, ODP_THREAD_CONTROL)) {
		ODPH_ERR("odp_init_local() failed\n");
		return -1;
	}

	global_shm = odp_shm_reserve(GLOBAL_SHM_NAME,
				     sizeof(global_shared_mem_t),
				     ODP_CACHE_LINE_SIZE, 0);
	if (global_shm == ODP_SHM_INVALID) {
		ODPH_ERR("Unable reserve memory for global_shm\n");
		return -1;
	}

	global_mem = odp_shm_addr(global_shm);
	memset(global_mem, 0, sizeof(global_shared_mem_t));

	global_mem->num_threads = MAX_WORKERS;

	workers_count = odp_cpumask_default_worker(NULL, 0);

	max_threads = (workers_count >= MAX_WORKERS) ?
			MAX_WORKERS : workers_count;

	if (max_threads < global_mem->num_threads) {
		printf("Requested num of threads is too large\n");
		printf("reducing from %" PRIu32 " to %" PRIu32 "\n",
		       global_mem->num_threads,
		       max_threads);
		global_mem->num_threads = max_threads;
	}

	printf("Num of threads used = %" PRIu32 "\n",
	       global_mem->num_threads);

	instance = inst;

	return 0;
}

static int time_global_term(odp_instance_t inst)
{
	odp_shm_t shm;

	shm = odp_shm_lookup(GLOBAL_SHM_NAME);
	if (0 != odp_shm_free(shm)) {
		ODPH_ERR("odp_shm_free() failed\n");
		return -1;
	}

	if (0 != odp_term_local()) {
		ODPH_ERR("odp_term_local() failed\n");
		return -1;
	}

	if (0 != odp_term_global(inst)) {
		ODPH_ERR("odp_term_global() failed\n");
		return -1;
	}

	return 0;
}

static void time_test_constants(void)
{
	uint64_t ns;

	CU_ASSERT(ODP_TIME_USEC_IN_NS == 1000);

	ns = ODP_TIME_HOUR_IN_NS;
	CU_ASSERT(ns == 60 * ODP_TIME_MIN_IN_NS);
	ns = ODP_TIME_MIN_IN_NS;
	CU_ASSERT(ns == 60 * ODP_TIME_SEC_IN_NS);
	ns = ODP_TIME_SEC_IN_NS;
	CU_ASSERT(ns == 1000 * ODP_TIME_MSEC_IN_NS);
	ns = ODP_TIME_MSEC_IN_NS;
	CU_ASSERT(ns == 1000 * ODP_TIME_USEC_IN_NS);

	ns = ODP_TIME_SEC_IN_NS / 1000;
	CU_ASSERT(ns == ODP_TIME_MSEC_IN_NS);
	ns /= 1000;
	CU_ASSERT(ns == ODP_TIME_USEC_IN_NS);
}

static void time_test_startup_time(void)
{
	odp_time_startup_t startup;
	uint64_t ns1, ns2, ns3;
	odp_time_t time;

	memset(&startup, 0, sizeof(odp_time_startup_t));

	odp_time_startup(&startup);
	ns1 = startup.global_ns;
	ns2 = odp_time_to_ns(startup.global);

	CU_ASSERT(UINT64_MAX - ns1 >= 10 * YEAR_IN_NS);
	CU_ASSERT(UINT64_MAX - ns2 >= 10 * YEAR_IN_NS);

	time = odp_time_global();
	ns3  = odp_time_to_ns(time);
	CU_ASSERT(odp_time_cmp(time, startup.global) > 0);

	time = odp_time_global_from_ns(10 * YEAR_IN_NS);
	time = odp_time_sum(startup.global, time);
	CU_ASSERT(odp_time_cmp(time, startup.global) > 0);

	printf("\n");
	printf("    Startup time in nsec: %" PRIu64 "\n", ns1);
	printf("    Startup time to nsec: %" PRIu64 "\n", ns2);
	printf("    Nsec since startup:   %" PRIu64 "\n\n", ns3 - startup.global_ns);
}

static void time_test_res(time_res_cb time_res, uint64_t *res)
{
	uint64_t rate;

	rate = time_res();
	CU_ASSERT(rate > MIN_TIME_RATE);
	CU_ASSERT(rate < MAX_TIME_RATE);

	*res = ODP_TIME_SEC_IN_NS / rate;
	if (ODP_TIME_SEC_IN_NS % rate)
		(*res)++;
}

static void time_test_local_res(void)
{
	time_test_res(odp_time_local_res, &local_res);
}

static void time_test_global_res(void)
{
	time_test_res(odp_time_global_res, &global_res);
}

/* check that related conversions come back to the same value */
static void time_test_conversion(time_from_ns_cb time_from_ns, uint64_t res)
{
	uint64_t ns1, ns2;
	odp_time_t time;
	uint64_t upper_limit, lower_limit;

	ns1 = 100;
	time = time_from_ns(ns1);

	ns2 = odp_time_to_ns(time);

	/* need to check within arithmetic tolerance that the same
	 * value in ns is returned after conversions */
	upper_limit = ns1 + res;
	lower_limit = ns1 - res;
	CU_ASSERT((ns2 <= upper_limit) && (ns2 >= lower_limit));

	ns1 = 60 * 11 * ODP_TIME_SEC_IN_NS;
	time = time_from_ns(ns1);

	ns2 = odp_time_to_ns(time);

	/* need to check within arithmetic tolerance that the same
	 * value in ns is returned after conversions */
	upper_limit = ns1 + res;
	lower_limit = ns1 - res;
	CU_ASSERT((ns2 <= upper_limit) && (ns2 >= lower_limit));

	/* test on 0 */
	ns1 = odp_time_to_ns(ODP_TIME_NULL);
	CU_ASSERT(ns1 == 0);
}

static void time_test_local_conversion(void)
{
	time_test_conversion(odp_time_local_from_ns, local_res);
}

static void time_test_global_conversion(void)
{
	time_test_conversion(odp_time_global_from_ns, global_res);
}

static void time_test_monotony(void)
{
	volatile uint64_t count = 0;
	odp_time_t l_t1, l_t2, l_t3;
	odp_time_t ls_t1, ls_t2, ls_t3;
	odp_time_t g_t1, g_t2, g_t3;
	odp_time_t gs_t1, gs_t2, gs_t3;
	uint64_t l_ns1, l_ns2, l_ns3;
	uint64_t ls_ns1, ls_ns2, ls_ns3;
	uint64_t g_ns1, g_ns2, g_ns3;
	uint64_t gs_ns1, gs_ns2, gs_ns3;
	uint64_t ns1, ns2, ns3;
	uint64_t s_ns1, s_ns2, s_ns3;
	uint64_t limit;

	l_t1   = odp_time_local();
	ls_t1  = odp_time_local_strict();
	l_ns1  = odp_time_local_ns();
	ls_ns1 = odp_time_local_strict_ns();

	g_t1   = odp_time_global();
	gs_t1  = odp_time_global_strict();
	g_ns1  = odp_time_global_ns();
	gs_ns1 = odp_time_global_strict_ns();

	while (count < BUSY_LOOP_CNT) {
		count++;
	};

	l_t2   = odp_time_local();
	ls_t2  = odp_time_local_strict();
	l_ns2  = odp_time_local_ns();
	ls_ns2 = odp_time_local_strict_ns();

	g_t2   = odp_time_global();
	gs_t2  = odp_time_global_strict();
	g_ns2  = odp_time_global_ns();
	gs_ns2 = odp_time_global_strict_ns();

	count = 0;
	while (count < BUSY_LOOP_CNT) {
		count++;
	};

	l_t3   = odp_time_local();
	ls_t3  = odp_time_local_strict();
	l_ns3  = odp_time_local_ns();
	ls_ns3 = odp_time_local_strict_ns();

	g_t3   = odp_time_global();
	gs_t3  = odp_time_global_strict();
	g_ns3  = odp_time_global_ns();
	gs_ns3 = odp_time_global_strict_ns();

	/* Local time tests
	 * ---------------- */

	ns1 = odp_time_to_ns(l_t1);
	ns2 = odp_time_to_ns(l_t2);
	ns3 = odp_time_to_ns(l_t3);

	s_ns1 = odp_time_to_ns(ls_t1);
	s_ns2 = odp_time_to_ns(ls_t2);
	s_ns3 = odp_time_to_ns(ls_t3);

	/* Time should not wrap in at least 10 years from ODP start. Ignoring delay from start up
	 * and other test cases, which should be few seconds. */
	limit = 10 * YEAR_IN_NS;
	CU_ASSERT(UINT64_MAX - ns1    > limit);
	CU_ASSERT(UINT64_MAX - s_ns1  > limit);
	CU_ASSERT(UINT64_MAX - l_ns1  > limit);
	CU_ASSERT(UINT64_MAX - ls_ns1 > limit);

	/* Time stamp */
	CU_ASSERT(ns2 > ns1);
	CU_ASSERT(ns3 > ns2);

	/* Strict time stamp */
	CU_ASSERT(s_ns2 > s_ns1);
	CU_ASSERT(s_ns3 > s_ns2);

	/* Nsec time */
	CU_ASSERT(l_ns2 > l_ns1);
	CU_ASSERT(l_ns3 > l_ns2);

	/* Strict nsec time */
	CU_ASSERT(ls_ns2 > ls_ns1);
	CU_ASSERT(ls_ns3 > ls_ns2);

	/* Strict time stamp order is maintained */
	CU_ASSERT(ls_ns1 >= s_ns1);
	CU_ASSERT(ls_ns2 >= s_ns2);
	CU_ASSERT(ls_ns3 >= s_ns3);

	/* Time in nanoseconds have the same time base. Allow less than 100 msec error
	 * between time stamp converted to nsec and nsec time. */
	CU_ASSERT((ls_ns1 - s_ns1) < (100 * ODP_TIME_MSEC_IN_NS));
	CU_ASSERT((ls_ns2 - s_ns2) < (100 * ODP_TIME_MSEC_IN_NS));
	CU_ASSERT((ls_ns3 - s_ns3) < (100 * ODP_TIME_MSEC_IN_NS));

	/* Global time tests
	 * ----------------- */

	ns1 = odp_time_to_ns(g_t1);
	ns2 = odp_time_to_ns(g_t2);
	ns3 = odp_time_to_ns(g_t3);

	s_ns1 = odp_time_to_ns(gs_t1);
	s_ns2 = odp_time_to_ns(gs_t2);
	s_ns3 = odp_time_to_ns(gs_t3);

	/* Time should not wrap in at least 10 years from ODP start. Ignoring delay from start up
	 * and other test cases, which should be few seconds. */
	limit = 10 * YEAR_IN_NS;
	CU_ASSERT(UINT64_MAX - ns1    > limit);
	CU_ASSERT(UINT64_MAX - s_ns1  > limit);
	CU_ASSERT(UINT64_MAX - g_ns1  > limit);
	CU_ASSERT(UINT64_MAX - gs_ns1 > limit);

	/* Time stamp */
	CU_ASSERT(ns2 > ns1);
	CU_ASSERT(ns3 > ns2);

	/* Strict time stamp */
	CU_ASSERT(s_ns2 > s_ns1);
	CU_ASSERT(s_ns3 > s_ns2);

	/* Nsec time */
	CU_ASSERT(g_ns2 > g_ns1);
	CU_ASSERT(g_ns3 > g_ns2);

	/* Strict nsec time */
	CU_ASSERT(gs_ns2 > gs_ns1);
	CU_ASSERT(gs_ns3 > gs_ns2);

	/* Strict time stamp order is maintained */
	CU_ASSERT(gs_ns1 >= s_ns1);
	CU_ASSERT(gs_ns2 >= s_ns2);
	CU_ASSERT(gs_ns3 >= s_ns3);

	/* Time in nanoseconds have the same time base. Allow less than 100 msec error
	 * between time stamp converted to nsec and nsec time. */
	CU_ASSERT((gs_ns1 - s_ns1) < (100 * ODP_TIME_MSEC_IN_NS));
	CU_ASSERT((gs_ns2 - s_ns2) < (100 * ODP_TIME_MSEC_IN_NS));
	CU_ASSERT((gs_ns3 - s_ns3) < (100 * ODP_TIME_MSEC_IN_NS));

	/* Tight error margin cannot be used due to possible OS interrupts during the test.
	 * Record all time stamp values into the log to help debugging their relative order and
	 * accuracy. */
	printf("\n    Time stamp values in nsec:\n");
	printf("    odp_time_local():            %" PRIu64 "\n", odp_time_to_ns(l_t1));
	printf("    odp_time_local_strict():     %" PRIu64 "\n", odp_time_to_ns(ls_t1));
	printf("    odp_time_local_ns():         %" PRIu64 "\n", l_ns1);
	printf("    odp_time_local_strict_ns():  %" PRIu64 "\n", ls_ns1);
	printf("    odp_time_global():           %" PRIu64 "\n", odp_time_to_ns(g_t1));
	printf("    odp_time_global_strict():    %" PRIu64 "\n", odp_time_to_ns(gs_t1));
	printf("    odp_time_global_ns():        %" PRIu64 "\n", g_ns1);
	printf("    odp_time_global_strict_ns(): %" PRIu64 "\n\n", gs_ns1);
}

static void time_test_cmp(time_cb time_cur, time_from_ns_cb time_from_ns)
{
	/* volatile to stop optimization of busy loop */
	volatile int count = 0;
	odp_time_t t1, t2, t3;

	t1 = time_cur();

	while (count < BUSY_LOOP_CNT) {
		count++;
	};

	t2 = time_cur();

	while (count < BUSY_LOOP_CNT * 2) {
		count++;
	};

	t3 = time_cur();

	CU_ASSERT(odp_time_cmp(t2, t1) > 0);
	CU_ASSERT(odp_time_cmp(t3, t2) > 0);
	CU_ASSERT(odp_time_cmp(t3, t1) > 0);
	CU_ASSERT(odp_time_cmp(t1, t2) < 0);
	CU_ASSERT(odp_time_cmp(t2, t3) < 0);
	CU_ASSERT(odp_time_cmp(t1, t3) < 0);
	CU_ASSERT(odp_time_cmp(t1, t1) == 0);
	CU_ASSERT(odp_time_cmp(t2, t2) == 0);
	CU_ASSERT(odp_time_cmp(t3, t3) == 0);

	t2 = time_from_ns(60 * 10 * ODP_TIME_SEC_IN_NS);
	t1 = time_from_ns(3);

	CU_ASSERT(odp_time_cmp(t2, t1) > 0);
	CU_ASSERT(odp_time_cmp(t1, t2) < 0);

	t1 = time_from_ns(0);
	CU_ASSERT(odp_time_cmp(t1, ODP_TIME_NULL) == 0);
}

static void time_test_local_cmp(void)
{
	time_test_cmp(odp_time_local, odp_time_local_from_ns);
}

static void time_test_global_cmp(void)
{
	time_test_cmp(odp_time_global, odp_time_global_from_ns);
}

static void time_test_local_strict_cmp(void)
{
	time_test_cmp(odp_time_local_strict, odp_time_local_from_ns);
}

static void time_test_global_strict_cmp(void)
{
	time_test_cmp(odp_time_global_strict, odp_time_global_from_ns);
}

/* check that a time difference gives a reasonable result */
static void time_test_diff(time_cb time_cur,
			   time_from_ns_cb time_from_ns,
			   uint64_t res)
{
	/* volatile to stop optimization of busy loop */
	volatile int count = 0;
	odp_time_t diff, t1, t2;
	uint64_t ns1, ns2, ns;
	uint64_t nsdiff, diff_ns;
	uint64_t upper_limit, lower_limit;

	/* test timestamp diff */
	t1 = time_cur();

	while (count < BUSY_LOOP_CNT) {
		count++;
	};

	t2 = time_cur();
	CU_ASSERT(odp_time_cmp(t2, t1) > 0);

	diff = odp_time_diff(t2, t1);
	CU_ASSERT(odp_time_cmp(diff, ODP_TIME_NULL) > 0);

	diff_ns = odp_time_diff_ns(t2, t1);
	CU_ASSERT(diff_ns > 0);

	ns1 = odp_time_to_ns(t1);
	ns2 = odp_time_to_ns(t2);
	ns = ns2 - ns1;
	nsdiff = odp_time_to_ns(diff);

	upper_limit = ns + 2 * res;
	lower_limit = ns - 2 * res;
	CU_ASSERT((nsdiff <= upper_limit) && (nsdiff >= lower_limit));
	CU_ASSERT((diff_ns <= upper_limit) && (diff_ns >= lower_limit));

	/* test timestamp and interval diff */
	ns1 = 54;
	t1 = time_from_ns(ns1);
	ns = ns2 - ns1;

	diff = odp_time_diff(t2, t1);
	CU_ASSERT(odp_time_cmp(diff, ODP_TIME_NULL) > 0);

	diff_ns = odp_time_diff_ns(t2, t1);
	CU_ASSERT(diff_ns > 0);

	nsdiff = odp_time_to_ns(diff);

	upper_limit = ns + 2 * res;
	lower_limit = ns - 2 * res;
	CU_ASSERT((nsdiff <= upper_limit) && (nsdiff >= lower_limit));
	CU_ASSERT((diff_ns <= upper_limit) && (diff_ns >= lower_limit));

	/* test interval diff */
	ns2 = 60 * 10 * ODP_TIME_SEC_IN_NS;
	ns = ns2 - ns1;

	t2 = time_from_ns(ns2);
	diff = odp_time_diff(t2, t1);
	CU_ASSERT(odp_time_cmp(diff, ODP_TIME_NULL) > 0);

	diff_ns = odp_time_diff_ns(t2, t1);
	CU_ASSERT(diff_ns > 0);

	nsdiff = odp_time_to_ns(diff);

	upper_limit = ns + 2 * res;
	lower_limit = ns - 2 * res;
	CU_ASSERT((nsdiff <= upper_limit) && (nsdiff >= lower_limit));
	CU_ASSERT((diff_ns <= upper_limit) && (diff_ns >= lower_limit));

	/* same time has to diff to 0 */
	diff = odp_time_diff(t2, t2);
	CU_ASSERT(odp_time_cmp(diff, ODP_TIME_NULL) == 0);

	diff = odp_time_diff(t2, ODP_TIME_NULL);
	CU_ASSERT(odp_time_cmp(t2, diff) == 0);

	diff_ns = odp_time_diff_ns(t2, t2);
	CU_ASSERT(diff_ns == 0);
}

static void time_test_local_diff(void)
{
	time_test_diff(odp_time_local, odp_time_local_from_ns, local_res);
}

static void time_test_global_diff(void)
{
	time_test_diff(odp_time_global, odp_time_global_from_ns, global_res);
}

static void time_test_local_strict_diff(void)
{
	time_test_diff(odp_time_local_strict, odp_time_local_from_ns, local_res);
}

static void time_test_global_strict_diff(void)
{
	time_test_diff(odp_time_global_strict, odp_time_global_from_ns, global_res);
}

/* check that a time sum gives a reasonable result */
static void time_test_sum(time_cb time_cur,
			  time_from_ns_cb time_from_ns,
			  uint64_t res)
{
	odp_time_t sum, t1, t2;
	uint64_t nssum, ns1, ns2, ns, diff;
	uint64_t upper_limit, lower_limit;

	/* sum timestamp and interval */
	t1 = time_cur();
	ns2 = 103;
	t2 = time_from_ns(ns2);
	ns1 = odp_time_to_ns(t1);
	ns = ns1 + ns2;

	sum = odp_time_sum(t2, t1);
	CU_ASSERT(odp_time_cmp(sum, ODP_TIME_NULL) > 0);
	nssum = odp_time_to_ns(sum);

	upper_limit = ns + 2 * res;
	lower_limit = ns - 2 * res;
	CU_ASSERT((nssum <= upper_limit) && (nssum >= lower_limit));

	/* sum intervals */
	ns1 = 60 * 13 * ODP_TIME_SEC_IN_NS;
	t1 = time_from_ns(ns1);
	ns = ns1 + ns2;

	sum = odp_time_sum(t2, t1);
	CU_ASSERT(odp_time_cmp(sum, ODP_TIME_NULL) > 0);
	nssum = odp_time_to_ns(sum);

	upper_limit = ns + 2 * res;
	lower_limit = ns - 2 * res;
	CU_ASSERT((nssum <= upper_limit) && (nssum >= lower_limit));

	/* test on 0 */
	sum = odp_time_sum(t2, ODP_TIME_NULL);
	CU_ASSERT(odp_time_cmp(t2, sum) == 0);

	/* test add nsec */
	ns = ODP_TIME_SEC_IN_NS;
	upper_limit = ns + 2 * res;
	lower_limit = ns - 2 * res;

	t1 = time_cur();
	t2 = odp_time_add_ns(t1, ns);

	CU_ASSERT(odp_time_cmp(t2, t1) > 0);

	diff = odp_time_diff_ns(t2, t1);
	CU_ASSERT((diff <= upper_limit) && (diff >= lower_limit));

	t1 = ODP_TIME_NULL;
	t2 = odp_time_add_ns(t1, ns);

	CU_ASSERT(odp_time_cmp(t2, t1) > 0);

	diff = odp_time_diff_ns(t2, t1);
	CU_ASSERT((diff <= upper_limit) && (diff >= lower_limit));
}

static void time_test_local_sum(void)
{
	time_test_sum(odp_time_local, odp_time_local_from_ns, local_res);
}

static void time_test_global_sum(void)
{
	time_test_sum(odp_time_global, odp_time_global_from_ns, global_res);
}

static void time_test_local_strict_sum(void)
{
	time_test_sum(odp_time_local_strict, odp_time_local_from_ns, local_res);
}

static void time_test_global_strict_sum(void)
{
	time_test_sum(odp_time_global_strict, odp_time_global_from_ns, global_res);
}

static void time_test_wait_until(time_cb time_cur, time_from_ns_cb time_from_ns)
{
	int i;
	odp_time_t lower_limit, upper_limit;
	odp_time_t start_time, end_time, wait;
	odp_time_t second = time_from_ns(ODP_TIME_SEC_IN_NS);

	start_time = time_cur();
	wait = start_time;
	for (i = 0; i < WAIT_SECONDS; i++) {
		wait = odp_time_sum(wait, second);
		odp_time_wait_until(wait);
	}
	end_time = time_cur();

	wait = odp_time_diff(end_time, start_time);
	lower_limit = time_from_ns(WAIT_SECONDS * ODP_TIME_SEC_IN_NS -
				   DELAY_TOLERANCE);
	upper_limit = time_from_ns(WAIT_SECONDS * ODP_TIME_SEC_IN_NS +
				   DELAY_TOLERANCE);

	if (odp_time_cmp(wait, lower_limit) < 0) {
		ODPH_ERR("Exceed lower limit: wait is %" PRIu64 ", lower_limit %" PRIu64 "\n",
			 odp_time_to_ns(wait), odp_time_to_ns(lower_limit));
		CU_FAIL("Exceed lower limit\n");
	}

	if (odp_time_cmp(wait, upper_limit) > 0) {
		ODPH_ERR("Exceed upper limit: wait is %" PRIu64 ", upper_limit %" PRIu64 "\n",
			 odp_time_to_ns(wait), odp_time_to_ns(lower_limit));
		CU_FAIL("Exceed upper limit\n");
	}
}

static void time_test_local_wait_until(void)
{
	time_test_wait_until(odp_time_local, odp_time_local_from_ns);
}

static void time_test_global_wait_until(void)
{
	time_test_wait_until(odp_time_global, odp_time_global_from_ns);
}

static void time_test_wait_ns(void)
{
	int i;
	odp_time_t lower_limit, upper_limit;
	odp_time_t start_time, end_time, diff;

	start_time = odp_time_local();
	for (i = 0; i < WAIT_SECONDS; i++)
		odp_time_wait_ns(ODP_TIME_SEC_IN_NS);
	end_time = odp_time_local();

	diff = odp_time_diff(end_time, start_time);

	lower_limit = odp_time_local_from_ns(WAIT_SECONDS * ODP_TIME_SEC_IN_NS -
					     DELAY_TOLERANCE);
	upper_limit = odp_time_local_from_ns(WAIT_SECONDS * ODP_TIME_SEC_IN_NS +
					     DELAY_TOLERANCE);

	if (odp_time_cmp(diff, lower_limit) < 0) {
		ODPH_ERR("Exceed lower limit: diff is %" PRIu64 ", lower_limit %" PRIu64 "\n",
			 odp_time_to_ns(diff), odp_time_to_ns(lower_limit));
		CU_FAIL("Exceed lower limit\n");
	}

	if (odp_time_cmp(diff, upper_limit) > 0) {
		ODPH_ERR("Exceed upper limit: diff is %" PRIu64 ", upper_limit %" PRIu64 "\n",
			 odp_time_to_ns(diff), odp_time_to_ns(upper_limit));
		CU_FAIL("Exceed upper limit\n");
	}
}

/* Check that ODP time is within +-5% of system time */
static void check_time_diff(double t_odp, double t_system,
			    const char *test, int id)
{
	if (t_odp > t_system * 1.05) {
		CU_FAIL("ODP time too high");
		ODPH_ERR("ODP time too high (%s/%d): t_odp: %f, t_system: %f\n",
			 test, id, t_odp, t_system);
	}
	if (t_odp < t_system * 0.95) {
		CU_FAIL("ODP time too low");
		ODPH_ERR("ODP time too low (%s/%d): t_odp: %f, t_system: %f\n",
			 test, id, t_odp, t_system);
	}
}

static void time_test_accuracy(time_cb time_cur,
			       time_cb time_cur_strict, time_from_ns_cb time_from_ns)
{
	int i;
	odp_time_t t1[2], t2[2], wait;
	struct timespec ts1, ts2, tsdiff;
	double sec_c;
	odp_time_t sec = time_from_ns(ODP_TIME_SEC_IN_NS);

	i = clock_gettime(CLOCK_MONOTONIC, &ts1);
	CU_ASSERT(i == 0);
	t1[0] = time_cur_strict();
	t1[1] = time_cur();

	wait = odp_time_sum(t1[0], sec);
	for (i = 0; i < 5; i++) {
		odp_time_wait_until(wait);
		wait = odp_time_add_ns(wait, ODP_TIME_SEC_IN_NS);
	}

	i = clock_gettime(CLOCK_MONOTONIC, &ts2);
	CU_ASSERT(i == 0);
	t2[0] = time_cur_strict();
	t2[1] = time_cur();

	if (ts2.tv_nsec < ts1.tv_nsec) {
		tsdiff.tv_nsec = 1000000000L + ts2.tv_nsec - ts1.tv_nsec;
		tsdiff.tv_sec = ts2.tv_sec - 1 - ts1.tv_sec;
	} else {
		tsdiff.tv_nsec = ts2.tv_nsec - ts1.tv_nsec;
		tsdiff.tv_sec = ts2.tv_sec - ts1.tv_sec;
	}
	sec_c = ((double)(tsdiff.tv_nsec) / 1000000000L) + tsdiff.tv_sec;

	for (i = 0; i < 2; i++) {
		odp_time_t diff  = odp_time_diff(t2[i], t1[i]);
		double sec_t = ((double)odp_time_to_ns(diff)) / ODP_TIME_SEC_IN_NS;

		check_time_diff(sec_t, sec_c, __func__, i);
	}
}

static void time_test_local_accuracy(void)
{
	time_test_accuracy(odp_time_local, odp_time_local_strict, odp_time_local_from_ns);
}

static void time_test_global_accuracy(void)
{
	time_test_accuracy(odp_time_global, odp_time_global_strict, odp_time_global_from_ns);
}

static void time_test_accuracy_nsec(void)
{
	uint64_t t1[4], t2[4];
	struct timespec ts1, ts2, tsdiff;
	double sec_c;
	int i, ret;

	ret = clock_gettime(CLOCK_MONOTONIC, &ts1);
	CU_ASSERT(ret == 0);
	t1[0] = odp_time_global_strict_ns();
	t1[1] = odp_time_local_strict_ns();
	t1[2] = odp_time_global_ns();
	t1[3] = odp_time_local_ns();

	for (i = 0; i < 5; i++)
		odp_time_wait_ns(ODP_TIME_SEC_IN_NS);

	ret = clock_gettime(CLOCK_MONOTONIC, &ts2);
	CU_ASSERT(ret == 0);
	t2[0] = odp_time_global_strict_ns();
	t2[1] = odp_time_local_strict_ns();
	t2[2] = odp_time_global_ns();
	t2[3] = odp_time_local_ns();

	if (ts2.tv_nsec < ts1.tv_nsec) {
		tsdiff.tv_nsec = 1000000000L + ts2.tv_nsec - ts1.tv_nsec;
		tsdiff.tv_sec = ts2.tv_sec - 1 - ts1.tv_sec;
	} else {
		tsdiff.tv_nsec = ts2.tv_nsec - ts1.tv_nsec;
		tsdiff.tv_sec = ts2.tv_sec - ts1.tv_sec;
	}
	sec_c = ((double)(tsdiff.tv_nsec) / 1000000000L) + tsdiff.tv_sec;

	for (i = 0; i < 4; i++) {
		uint64_t diff  = t2[i] - t1[i];
		double sec_t = ((double)diff) / ODP_TIME_SEC_IN_NS;

		check_time_diff(sec_t, sec_c, __func__, i);
	}
}

static int time_test_global_sync_thr(void *arg ODP_UNUSED)
{
	int tid = odp_thread_id();
	odp_shm_t global_shm = odp_shm_lookup(GLOBAL_SHM_NAME);
	global_shared_mem_t *global_mem = odp_shm_addr(global_shm);

	if (!global_mem)
		return 1;

	odp_barrier_wait(&global_mem->test_barrier);
	global_mem->time[tid][0] = odp_time_global();
	odp_time_wait_ns(ODP_TIME_MSEC_IN_NS * 100);
	odp_barrier_wait(&global_mem->test_barrier);
	global_mem->time[tid][1] = odp_time_global();

	return 0;
}

static void time_test_global_sync(const int ctrl)
{
	odp_cpumask_t cpumask;
	odph_thread_common_param_t thr_common;
	odph_thread_param_t thr_param;
	odph_thread_t thread_tbl[MAX_WORKERS];
	uint64_t tolerance = odp_cunit_ci() ? TIME_TOLERANCE_CI_NS : TIME_TOLERANCE_NS;
	const int num = ctrl ? 2 : global_mem->num_threads;

	if (num < 2) {
		printf(" number of threads is less than two, test skipped. ");
		return;
	}

	odp_barrier_init(&global_mem->test_barrier, num);

	odph_thread_param_init(&thr_param);
	thr_param.start = time_test_global_sync_thr;

	odph_thread_common_param_init(&thr_common);
	thr_common.instance = *instance;

	int thr = 0;

	if (ctrl) {
		/* Test sync between one control and one worker thread. */
		int control_cpu;
		int worker_cpu;

		odp_cpumask_default_control(&cpumask, 1);
		thr_common.cpumask = &cpumask;
		thr_param.thr_type = ODP_THREAD_CONTROL;
		control_cpu = odp_cpumask_first(&cpumask);

		int r = odph_thread_create(&thread_tbl[thr++],
					   &thr_common, &thr_param, 1);
		CU_ASSERT_FATAL(r == 1);
		odp_cpumask_default_worker(&cpumask, 1);
		worker_cpu = odp_cpumask_first(&cpumask);
		if (control_cpu == worker_cpu) {
			printf(" single CPU, relaxing tolerance. ");
			tolerance = TIME_TOLERANCE_1CPU_NS;
		}
	} else {
		/* Test sync between num worker threads. */
		odp_cpumask_default_worker(&cpumask, num);
	}

	int cpu = odp_cpumask_first(&cpumask);

	while (cpu >= 0) {
		odp_cpumask_t cpumask_one;

		/*
		 * Delay for more than the tolerance, so that we notice if the
		 * thread's view of global time is affected.
		 */
		odp_time_wait_ns(tolerance * 2);

		odp_cpumask_zero(&cpumask_one);
		odp_cpumask_set(&cpumask_one, cpu);
		thr_common.cpumask = &cpumask_one;
		thr_param.thr_type = ODP_THREAD_WORKER;

		int r = odph_thread_create(&thread_tbl[thr++],
					   &thr_common, &thr_param, 1);
		CU_ASSERT_FATAL(r == 1);

		cpu = odp_cpumask_next(&cpumask, cpu);
	}

	odph_thread_join_result_t res[num];

	int ret = odph_thread_join_result(thread_tbl, res, num);

	CU_ASSERT(ret == num);

	for (int i = 0; i < num; i++)
		CU_ASSERT(!res[i].is_sig && res[i].ret == 0);

	for (int s = 0; s < TIME_SAMPLES; s++) {
		int min_idx = 0, max_idx = 0;
		uint64_t min = UINT64_MAX, max = 0;
		double avg = 0;

		for (int i = 1; i < num + 1; i++) {
			uint64_t t = odp_time_to_ns(global_mem->time[i][s]);

			if (t < min) {
				min = t;
				min_idx = i;
			}
		}

		printf("\nround %d\nthread time diffs: ", s);

		for (int i = 1; i < num + 1; i++) {
			uint64_t t = odp_time_to_ns(global_mem->time[i][s]) - min;

			printf("%" PRIu64 " ", t);

			if (t > max) {
				max = t;
				max_idx = i;
			}

			avg += t;
		}

		/* The min result itself is not included in the average. */
		avg /= num - 1;
		printf("\nmin: %" PRIu64 " (tid %d)  max diff: %" PRIu64
		       " (tid %d)  avg diff: %g", min, min_idx, max, max_idx, avg);
		CU_ASSERT(max < tolerance);
	}

	printf("\n");
}

static void time_test_global_sync_workers(void)
{
	time_test_global_sync(0);
}

static void time_test_global_sync_control(void)
{
	time_test_global_sync(1);
}

static odp_queue_t select_dst_queue(int thread_id, const odp_queue_t queue[], uint32_t num)
{
	uint8_t rand_u8;
	int rand_id = 0;

	if (num == 1)
		return queue[0];

	do {
		odp_random_data(&rand_u8, 1, ODP_RANDOM_BASIC);
		rand_id = rand_u8 % num;
	} while (rand_id == thread_id);

	return queue[rand_id];
}

static int run_time_global_thread(void *arg)
{
	global_shared_mem_t *gbl = arg;
	const int thread_id = odp_thread_id();
	const odp_queue_t src_queue = gbl->queue[thread_id % gbl->num_queues];
	const odp_queue_t *queues = gbl->queue;
	const uint32_t num_queues = gbl->num_queues;
	odp_atomic_u32_t *event_count = &gbl->event_count;

	odp_barrier_wait(&gbl->test_barrier);

	while (odp_atomic_load_u32(event_count) < TEST_ROUNDS) {
		odp_time_t *ts;
		odp_time_t cur_time;
		odp_buffer_t buf;
		odp_queue_t dst_queue;
		odp_event_t ev = odp_queue_deq(src_queue);

		if (ev == ODP_EVENT_INVALID) {
			odp_cpu_pause();
			continue;
		}

		cur_time = odp_time_global();

		buf = odp_buffer_from_event(ev);
		ts = odp_buffer_addr(buf);

		CU_ASSERT(odp_time_cmp(cur_time, *ts) >= 0);

		*ts = cur_time;

		dst_queue = select_dst_queue(thread_id, queues, num_queues);

		CU_ASSERT_FATAL(odp_queue_enq(dst_queue, ev) == 0);

		odp_atomic_inc_u32(event_count);
	}
	return 0;
}

static void time_test_global_mt(void)
{
	odp_cpumask_t cpumask;
	odp_pool_t pool;
	odp_pool_param_t pool_param;
	odp_pool_capability_t pool_capa;
	odp_queue_param_t queue_param;
	odp_queue_capability_t queue_capa;
	odph_thread_t thread_tbl[MAX_WORKERS];
	odph_thread_common_param_t thr_common;
	odph_thread_param_t thr_param;
	odp_time_t cur_time;
	uint32_t i;
	int num_workers = odp_cpumask_default_worker(&cpumask, global_mem->num_threads);
	uint32_t num_events = num_workers;
	uint32_t num_queues = num_workers;

	CU_ASSERT_FATAL(odp_pool_capability(&pool_capa) == 0);
	CU_ASSERT_FATAL(odp_queue_capability(&queue_capa) == 0);

	if (pool_capa.buf.max_num && num_events > pool_capa.buf.max_num)
		num_events = pool_capa.buf.max_num;

	if (queue_capa.plain.max_size && num_events > queue_capa.plain.max_size)
		num_events = queue_capa.plain.max_size;

	if (queue_capa.plain.max_num < num_queues)
		num_queues = queue_capa.plain.max_num;
	CU_ASSERT_FATAL(num_queues > 0);

	odp_pool_param_init(&pool_param);
	pool_param.buf.size = sizeof(odp_time_t);
	pool_param.buf.num = num_events;
	pool_param.type = ODP_POOL_BUFFER;

	pool = odp_pool_create("test event pool", &pool_param);
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	odp_queue_param_init(&queue_param);
	queue_param.size = num_events;
	queue_param.type = ODP_QUEUE_TYPE_PLAIN;

	for (i = 0; i < num_queues; i++) {
		global_mem->queue[i]  = odp_queue_create(NULL, &queue_param);
		CU_ASSERT_FATAL(global_mem->queue[i] != ODP_QUEUE_INVALID);
	}
	global_mem->num_queues = num_queues;

	odp_atomic_init_u32(&global_mem->event_count, 0);

	for (i = 0; i < num_events; i++) {
		odp_time_t *ts;
		odp_buffer_t buf = odp_buffer_alloc(pool);

		if (buf == ODP_BUFFER_INVALID)
			break;

		ts = odp_buffer_addr(buf);
		*ts = odp_time_global();

		CU_ASSERT_FATAL(odp_queue_enq(global_mem->queue[i % num_queues],
					      odp_buffer_to_event(buf)) == 0);
	}
	CU_ASSERT_FATAL(i > 0);
	CU_ASSERT(i == num_events);

	odp_barrier_init(&global_mem->test_barrier, num_workers);

	odph_thread_param_init(&thr_param);
	thr_param.start    = run_time_global_thread;
	thr_param.arg      = global_mem;
	thr_param.thr_type = ODP_THREAD_WORKER;

	odph_thread_common_param_init(&thr_common);
	thr_common.instance = *instance;
	thr_common.cpumask = &cpumask;
	thr_common.share_param = 1;

	CU_ASSERT_FATAL(odph_thread_create(thread_tbl, &thr_common, &thr_param, num_workers) ==
			num_workers);

	odph_thread_join_result_t res[num_workers];

	int ret = odph_thread_join_result(thread_tbl, res, num_workers);

	CU_ASSERT(ret == num_workers);

	for (i = 0; i < (uint32_t)num_workers; i++)
		CU_ASSERT(!res[i].is_sig && res[i].ret == 0);

	cur_time = odp_time_global_strict();

	for (i = 0; i < num_queues; i++) {
		odp_queue_t queue = global_mem->queue[i];

		while (1) {
			odp_buffer_t buf;
			odp_time_t *ts;
			odp_event_t ev = odp_queue_deq(queue);

			if (ev == ODP_EVENT_INVALID)
				break;

			buf = odp_buffer_from_event(ev);
			ts = odp_buffer_addr(buf);

			CU_ASSERT(odp_time_cmp(cur_time, *ts) >= 0);
			odp_buffer_free(buf);
		};

		CU_ASSERT(odp_queue_destroy(queue) == 0);
	}

	CU_ASSERT(odp_pool_destroy(pool) == 0);
}

odp_testinfo_t time_suite_time[] = {
	ODP_TEST_INFO(time_test_constants),
	ODP_TEST_INFO(time_test_startup_time),
	ODP_TEST_INFO(time_test_local_res),
	ODP_TEST_INFO(time_test_local_conversion),
	ODP_TEST_INFO(time_test_local_cmp),
	ODP_TEST_INFO(time_test_local_diff),
	ODP_TEST_INFO(time_test_local_sum),
	ODP_TEST_INFO(time_test_global_mt),
	ODP_TEST_INFO(time_test_global_res),
	ODP_TEST_INFO(time_test_global_conversion),
	ODP_TEST_INFO(time_test_global_cmp),
	ODP_TEST_INFO(time_test_global_diff),
	ODP_TEST_INFO(time_test_global_sum),
	ODP_TEST_INFO(time_test_wait_ns),
	ODP_TEST_INFO(time_test_monotony),
	ODP_TEST_INFO(time_test_local_wait_until),
	ODP_TEST_INFO(time_test_global_wait_until),
	ODP_TEST_INFO(time_test_local_accuracy),
	ODP_TEST_INFO(time_test_global_accuracy),
	ODP_TEST_INFO(time_test_accuracy_nsec),
	ODP_TEST_INFO(time_test_local_strict_diff),
	ODP_TEST_INFO(time_test_local_strict_sum),
	ODP_TEST_INFO(time_test_local_strict_cmp),
	ODP_TEST_INFO(time_test_global_strict_diff),
	ODP_TEST_INFO(time_test_global_strict_sum),
	ODP_TEST_INFO(time_test_global_strict_cmp),
	ODP_TEST_INFO(time_test_global_sync_workers),
	ODP_TEST_INFO(time_test_global_sync_control),
	ODP_TEST_INFO_NULL
};

odp_suiteinfo_t time_suites[] = {
		{"Time", NULL, NULL, time_suite_time},
		ODP_SUITE_INFO_NULL
};

int main(int argc, char *argv[])
{
	int ret;

	/* parse common options: */
	if (odp_cunit_parse_options(&argc, argv))
		return -1;

	odp_cunit_register_global_init(time_global_init);
	odp_cunit_register_global_term(time_global_term);

	ret = odp_cunit_register(time_suites);

	if (ret == 0)
		ret = odp_cunit_run();

	return ret;
}
