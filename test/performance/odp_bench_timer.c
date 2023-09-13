/* Copyright (c) 2023, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* Needed for sigaction */
#endif

#include <odp_api.h>
#include <odp/helper/odph_api.h>

#include "bench_common.h"

#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

/* Number of API function calls per test case */
#define REPEAT_COUNT 1000

/* Default number of rounds per test case */
#define ROUNDS 1000u

/** User area size in bytes */
#define UAREA_SIZE 8

/** Timer duration in nsec */
#define TIMER_NSEC 50000000

#define BENCH_INFO(run_fn, max, alt_name) \
	{.name = #run_fn, .run = run_fn, .max_rounds = max, .desc = alt_name}

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

	} opt;

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

	/* Benchmark functions */
	bench_info_t *bench;

	/* Number of benchmark functions */
	int num_bench;

	/* Break worker loop if set to 1 */
	odp_atomic_u32_t exit_thread;

	/* Test case input / output data */
	uint64_t      a1[REPEAT_COUNT];
	odp_event_t   ev[REPEAT_COUNT];
	odp_timeout_t tmo[REPEAT_COUNT];
	odp_timer_t   tim[REPEAT_COUNT];

	/* Dummy result */
	uint64_t dummy;

	/* Benchmark run failed */
	int bench_failed;

	/* CPU mask as string */
	char cpumask_str[ODP_CPUMASK_STR_SIZE];

} gbl_args_t;

static gbl_args_t *gbl_args;

static void sig_handler(int signo ODP_UNUSED)
{
	if (gbl_args == NULL)
		return;
	odp_atomic_store_u32(&gbl_args->exit_thread, 1);
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

/* Run given benchmark indefinitely */
static void run_indef(gbl_args_t *args, int idx)
{
	const char *desc;
	const bench_info_t *bench = &args->bench[idx];

	desc = bench->desc != NULL ? bench->desc : bench->name;

	printf("Running odp_%s test indefinitely\n", desc);

	while (!odp_atomic_load_u32(&gbl_args->exit_thread)) {
		int ret;

		ret = bench->run();

		if (!ret)
			ODPH_ABORT("Benchmark %s failed\n", desc);
	}
}

static int run_benchmarks(void *arg)
{
	int i, j;
	uint64_t c1, c2;
	odp_time_t t1, t2;
	gbl_args_t *args = arg;
	const int meas_time = args->opt.time;

	printf("\nAverage %s per function call\n", meas_time ? "time (nsec)" : "CPU cycles");
	printf("-------------------------------------------------\n");

	/* Run each test twice. Results from the first warm-up round are ignored. */
	for (i = 0; i < 2; i++) {
		uint64_t total = 0;
		uint32_t round = 1;

		for (j = 0; j < gbl_args->num_bench; round++) {
			int ret;
			const char *desc;
			const bench_info_t *bench = &args->bench[j];
			uint32_t max_rounds = args->opt.rounds;

			if (bench->max_rounds && max_rounds > bench->max_rounds)
				max_rounds = bench->max_rounds;

			/* Run selected test indefinitely */
			if (args->opt.bench_idx) {
				if ((j + 1) != args->opt.bench_idx) {
					j++;
					continue;
				}

				run_indef(args, j);
				return 0;
			}

			desc = bench->desc != NULL ? bench->desc : bench->name;

			if (meas_time)
				t1 = odp_time_local();
			else
				c1 = odp_cpu_cycles();

			ret = bench->run();

			if (meas_time)
				t2 = odp_time_local();
			else
				c2 = odp_cpu_cycles();

			if (!ret) {
				ODPH_ERR("Benchmark odp_%s failed\n", desc);
				args->bench_failed = -1;
				return -1;
			}

			if (meas_time)
				total += odp_time_diff_ns(t2, t1);
			else
				total += odp_cpu_cycles_diff(c2, c1);

			for (i = 0; i < REPEAT_COUNT; i++)
				args->dummy += args->a1[i];

			if (round >= max_rounds) {
				double result;

				/* Each benchmark runs internally REPEAT_COUNT times. */
				result = ((double)total) / (max_rounds * REPEAT_COUNT);

				/* No print from warm-up round */
				if (i > 0)
					printf("[%02d] odp_%-26s: %12.2f\n", j + 1, desc, result);

				j++;
				total = 0;
				round = 1;
			}
		}
	}

	/* Print dummy result to prevent compiler to optimize it away*/
	printf("\n(dummy result: 0x%" PRIx64 ")\n\n", args->dummy);

	return 0;
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

static int timeout_to_event(void)
{
	int i;
	odp_event_t *ev = gbl_args->ev;
	odp_timeout_t timeout = gbl_args->timeout;

	for (i = 0; i < REPEAT_COUNT; i++)
		ev[i] = odp_timeout_to_event(timeout);

	gbl_args->dummy += odp_event_to_u64(ev[0]);

	return i;
}

static int timeout_from_event(void)
{
	int i;
	odp_event_t ev = gbl_args->event;
	odp_timeout_t *tmo = gbl_args->tmo;

	for (i = 0; i < REPEAT_COUNT; i++)
		tmo[i] = odp_timeout_from_event(ev);

	gbl_args->dummy += odp_timeout_to_u64(tmo[0]);

	return i;
}

static int timeout_fresh(void)
{
	int i;
	odp_timeout_t timeout = gbl_args->timeout;
	uint64_t *a1 = gbl_args->a1;

	for (i = 0; i < REPEAT_COUNT; i++)
		a1[i] = odp_timeout_fresh(timeout);

	return i;
}

static int timeout_timer(void)
{
	int i;
	odp_timeout_t timeout = gbl_args->timeout;
	odp_timer_t *tim = gbl_args->tim;

	for (i = 0; i < REPEAT_COUNT; i++)
		tim[i] = odp_timeout_timer(timeout);

	gbl_args->dummy += odp_timer_to_u64(tim[0]);

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

static int timeout_user_ptr(void)
{
	int i;
	odp_timeout_t timeout = gbl_args->timeout;
	uint64_t *a1 = gbl_args->a1;

	for (i = 0; i < REPEAT_COUNT; i++)
		a1[i] = (uintptr_t)odp_timeout_user_ptr(timeout);

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

static int timeout_to_u64(void)
{
	int i;
	odp_timeout_t timeout = gbl_args->timeout;
	uint64_t *a1 = gbl_args->a1;

	for (i = 0; i < REPEAT_COUNT; i++)
		a1[i] = odp_timeout_to_u64(timeout);

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

static int timer_pool_to_u64(void)
{
	int i;
	odp_timer_pool_t tp = gbl_args->timer_pool;
	uint64_t *a1 = gbl_args->a1;

	for (i = 0; i < REPEAT_COUNT; i++)
		a1[i] = odp_timer_pool_to_u64(tp);

	return i;
}

bench_info_t test_suite[] = {
	BENCH_INFO(timer_current_tick, 0, NULL),
	BENCH_INFO(timer_tick_to_ns, 0, NULL),
	BENCH_INFO(timer_ns_to_tick, 0, NULL),
	BENCH_INFO(timeout_to_event, 0, NULL),
	BENCH_INFO(timeout_from_event, 0, NULL),
	BENCH_INFO(timeout_fresh, 0, NULL),
	BENCH_INFO(timeout_timer, 0, NULL),
	BENCH_INFO(timeout_tick, 0, NULL),
	BENCH_INFO(timeout_user_ptr, 0, NULL),
	BENCH_INFO(timeout_user_area, 0, NULL),
	BENCH_INFO(timeout_to_u64, 0, NULL),
	BENCH_INFO(timer_to_u64, 0, NULL),
	BENCH_INFO(timer_pool_to_u64, 0, NULL),
};

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
	       "  -h, --help              Display help and exit.\n\n"
	       "\n", ROUNDS);
}

/* Parse command line arguments */
static int parse_args(int argc, char *argv[])
{
	int opt;
	int long_index;
	static const struct option longopts[] = {
		{"clk_src", required_argument, NULL, 's'},
		{"time", required_argument, NULL, 't'},
		{"index", required_argument, NULL, 'i'},
		{"rounds", required_argument, NULL, 'r'},
		{"help", no_argument, NULL, 'h'},
		{NULL, 0, NULL, 0}
	};

	static const char *shortopts =  "s:t:i:r:h";

	gbl_args->opt.clk_src = ODP_CLOCK_DEFAULT;
	gbl_args->opt.time = 0; /* Measure CPU cycles */
	gbl_args->opt.bench_idx = 0; /* Run all benchmarks */
	gbl_args->opt.rounds = ROUNDS;

	while (1) {
		opt = getopt_long(argc, argv, shortopts, longopts, &long_index);

		if (opt == -1)
			break;	/* No more options */

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

	if (gbl_args->opt.bench_idx < 0 || gbl_args->opt.bench_idx > gbl_args->num_bench) {
		ODPH_ERR("Bad bench index %i\n", gbl_args->opt.bench_idx);
		return -1;
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
	printf("\n");
}

static int create_timer(void)
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
	odp_timer_t timer;
	uint64_t t1, t2, diff, tick1, tick2;

	if (odp_pool_capability(&pool_capa)) {
		ODPH_ERR("Pool capa failed\n");
		return -1;
	}

	clk_src = gbl_args->opt.clk_src;
	if (odp_timer_capability(clk_src, &timer_capa)) {
		ODPH_ERR("Timer capa failed\n");
		return -1;
	}

	odp_timer_pool_param_init(&tp_param);
	tp_param.clk_src    = clk_src;
	tp_param.res_ns     = timer_capa.max_res.res_ns;
	tp_param.min_tmo    = timer_capa.max_res.min_tmo;
	tp_param.max_tmo    = timer_capa.max_res.max_tmo;
	tp_param.num_timers = 10;

	tp = odp_timer_pool_create("bench_timer", &tp_param);

	if (tp == ODP_TIMER_POOL_INVALID) {
		ODPH_ERR("Timer pool create failed\n");
		return -1;
	}

	gbl_args->timer_pool = tp;

	odp_timer_pool_start();

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

	return 0;
}

static int wait_timer(void)
{
	odp_timer_start_t start_param;
	odp_timer_t timer = gbl_args->timer;
	odp_timer_pool_t tp = gbl_args->timer_pool;
	uint64_t wait_nsec = 2 * gbl_args->timer_nsec;
	uint64_t sched_wait = odp_schedule_wait_time(wait_nsec);
	odp_event_t ev;
	uint64_t start;

	start_param.tick_type = ODP_TIMER_TICK_REL;
	start_param.tick      = odp_timer_ns_to_tick(tp, gbl_args->timer_nsec);
	start_param.tmo_ev    = odp_timeout_to_event(gbl_args->timeout);

	if (odp_timer_start(timer, &start_param) != ODP_TIMER_SUCCESS) {
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

int main(int argc, char *argv[])
{
	odph_helper_options_t helper_options;
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
	odp_atomic_init_u32(&gbl_args->exit_thread, 0);
	gbl_args->timer_pool = ODP_TIMER_POOL_INVALID;
	gbl_args->timer = ODP_TIMER_INVALID;
	gbl_args->queue = ODP_QUEUE_INVALID;
	gbl_args->pool = ODP_POOL_INVALID;
	gbl_args->timeout = ODP_TIMEOUT_INVALID;

	gbl_args->bench = test_suite;
	gbl_args->num_bench = sizeof(test_suite) / sizeof(test_suite[0]);

	for (i = 0; i < REPEAT_COUNT; i++) {
		gbl_args->a1[i] = i;
		gbl_args->ev[i] = ODP_EVENT_INVALID;
		gbl_args->tmo[i] = ODP_TIMEOUT_INVALID;
		gbl_args->tim[i] = ODP_TIMER_INVALID;
	}

	/* Parse and store the application arguments */
	ret = parse_args(argc, argv);
	if (ret)
		goto exit;

	/* Get default worker cpumask */
	if (odp_cpumask_default_worker(&default_mask, 1) != 1) {
		ODPH_ERR("Unable to allocate worker thread\n");
		ret = -1;
		goto exit;
	}

	(void)odp_cpumask_to_str(&default_mask, gbl_args->cpumask_str,
				 sizeof(gbl_args->cpumask_str));

	/* Create timer and other resources */
	ret = create_timer();
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
	thr_param.start = run_benchmarks;
	thr_param.arg = gbl_args;
	thr_param.thr_type = ODP_THREAD_WORKER;

	odph_thread_create(&worker_thread, &thr_common, &thr_param, 1);

	odph_thread_join(&worker_thread, 1);

	ret = gbl_args->bench_failed;

exit:
	if (gbl_args->timeout != ODP_TIMEOUT_INVALID)
		odp_timeout_free(gbl_args->timeout);

	if (gbl_args->pool != ODP_POOL_INVALID)
		odp_pool_destroy(gbl_args->pool);

	if (gbl_args->timer != ODP_TIMER_INVALID)
		odp_timer_free(gbl_args->timer);

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
