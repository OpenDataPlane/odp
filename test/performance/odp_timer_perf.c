/* Copyright (c) 2019, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <signal.h>
#include <stdlib.h>
#include <getopt.h>

#include <odp_api.h>
#include <odp/helper/odph_api.h>

#define MAX_TIMER_POOLS 32
#define MAX_TIMERS      10000
#define START_NS        (100 * ODP_TIME_MSEC_IN_NS)

typedef struct test_options_t {
	uint32_t num_cpu;
	uint32_t num_tp;
	uint32_t num_timer;
	uint64_t res_ns;
	uint64_t period_ns;

} test_options_t;

typedef struct time_stat_t {
	uint64_t num;
	uint64_t sum_ns;
	uint64_t max_ns;

} time_stat_t;

typedef struct test_stat_t {
	uint64_t rounds;
	uint64_t events;
	uint64_t nsec;
	uint64_t cycles;

	time_stat_t before;
	time_stat_t after;

} test_stat_t;

typedef struct thread_arg_t {
	void *global;

} thread_arg_t;

typedef struct timer_ctx_t {
	uint64_t target_ns;
	int last;

} timer_ctx_t;

typedef struct test_global_t {
	test_options_t test_options;
	odp_atomic_u32_t exit_test;
	odp_barrier_t barrier;
	odp_cpumask_t cpumask;
	odp_timer_pool_t tp[MAX_TIMER_POOLS];
	odp_pool_t pool[MAX_TIMER_POOLS];
	odp_queue_t queue[MAX_TIMER_POOLS];
	odp_timer_t timer[MAX_TIMER_POOLS][MAX_TIMERS];
	timer_ctx_t timer_ctx[MAX_TIMER_POOLS][MAX_TIMERS];
	odph_thread_t thread_tbl[ODP_THREAD_COUNT_MAX];
	test_stat_t stat[ODP_THREAD_COUNT_MAX];
	thread_arg_t thread_arg[ODP_THREAD_COUNT_MAX];

} test_global_t;

test_global_t test_global;

static void print_usage(void)
{
	printf("\n"
	       "Scheduler performance test\n"
	       "\n"
	       "Usage: odp_sched_perf [options]\n"
	       "\n"
	       "  -c, --num_cpu          Number of CPUs (worker threads). 0: all available CPUs. Default: 1\n"
	       "  -n, --num_tp           Number of timer pools. Default: 1\n"
	       "  -t, --num_timer        Number of timers per timer pool. Default: 10\n"
	       "  -r, --res_ns           Resolution in nsec.     Default:  10000000\n"
	       "  -p, --period_ns        Timeout period in nsec. Default: 100000000\n"
	       "  -h, --help             This help\n"
	       "\n");
}

static int parse_options(int argc, char *argv[], test_options_t *test_options)
{
	int opt;
	int long_index;
	int ret = 0;

	static const struct option longopts[] = {
		{"num_cpu",   required_argument, NULL, 'c'},
		{"num_tp   ", required_argument, NULL, 'n'},
		{"num_timer", required_argument, NULL, 't'},
		{"res_ns",    required_argument, NULL, 'r'},
		{"period_ns", required_argument, NULL, 'p'},
		{"help",      no_argument,       NULL, 'h'},
		{NULL, 0, NULL, 0}
	};

	static const char *shortopts = "+c:n:t:r:p:h";

	test_options->num_cpu   = 1;
	test_options->num_tp    = 1;
	test_options->num_timer = 10;
	test_options->res_ns    = 10 * ODP_TIME_MSEC_IN_NS;
	test_options->period_ns = 100 * ODP_TIME_MSEC_IN_NS;

	while (1) {
		opt = getopt_long(argc, argv, shortopts, longopts, &long_index);

		if (opt == -1)
			break;

		switch (opt) {
		case 'c':
			test_options->num_cpu = atoi(optarg);
			break;
		case 'n':
			test_options->num_tp = atoi(optarg);
			break;
		case 't':
			test_options->num_timer = atoi(optarg);
			break;
		case 'r':
			test_options->res_ns = atoll(optarg);
			break;
		case 'p':
			test_options->period_ns = atoll(optarg);
			break;
		case 'h':
			/* fall through */
		default:
			print_usage();
			ret = -1;
			break;
		}
	}

	if (test_options->num_timer > MAX_TIMERS) {
		printf("Error: too many timers. Max %u\n", MAX_TIMERS);
		ret = -1;
	}

	return ret;
}

static int set_num_cpu(test_global_t *global)
{
	int ret;
	test_options_t *test_options = &global->test_options;
	int num_cpu = test_options->num_cpu;

	/* One thread used for the main thread */
	if (num_cpu > ODP_THREAD_COUNT_MAX - 1) {
		printf("Error: Too many workers. Maximum is %i.\n",
		       ODP_THREAD_COUNT_MAX - 1);
		return -1;
	}

	ret = odp_cpumask_default_worker(&global->cpumask, num_cpu);

	if (num_cpu && ret != num_cpu) {
		printf("Error: Too many workers. Max supported %i\n.", ret);
		return -1;
	}

	/* Zero: all available workers */
	if (num_cpu == 0) {
		num_cpu = ret;
		test_options->num_cpu = num_cpu;
	}

	/* Main thread + all workers */
	odp_barrier_init(&global->barrier, num_cpu + 1);

	return 0;
}

static int create_timer_pools(test_global_t *global)
{
	odp_timer_capability_t timer_capa;
	odp_timer_pool_param_t timer_pool_param;
	odp_timer_pool_t tp;
	odp_queue_param_t queue_param;
	odp_queue_t queue;
	odp_pool_param_t pool_param;
	odp_pool_t pool;
	uint64_t max_tmo_ns;
	uint32_t i, j;
	uint32_t max_timers;
	test_options_t *test_options = &global->test_options;
	uint32_t num_cpu   = test_options->num_cpu;
	uint32_t num_tp    = test_options->num_tp;
	uint32_t num_timer = test_options->num_timer;
	uint64_t res_ns    = test_options->res_ns;
	uint64_t period_ns = test_options->period_ns;

	max_tmo_ns = START_NS + (num_timer * period_ns);

	printf("\nTimer performance test\n");
	printf("  num cpu          %u\n", num_cpu);
	printf("  num timer pool   %u\n", num_tp);
	printf("  num timer        %u\n", num_timer);
	printf("  resolution       %" PRIu64 " nsec\n", res_ns);
	printf("  period           %" PRIu64 " nsec\n", period_ns);
	printf("  first timer at   %.2f sec\n", (double)START_NS /
	       ODP_TIME_SEC_IN_NS);
	printf("  test duration    %.2f sec\n", (double)max_tmo_ns /
	       ODP_TIME_SEC_IN_NS);
	printf("\n");

	for (i = 0; i < MAX_TIMER_POOLS; i++) {
		global->tp[i]    = ODP_TIMER_POOL_INVALID;
		global->pool[i]  = ODP_POOL_INVALID;
		global->queue[i] = ODP_QUEUE_INVALID;

		for (j = 0; j < MAX_TIMERS; j++)
			global->timer[i][j] = ODP_TIMER_INVALID;
	}

	if (odp_timer_capability(ODP_CLOCK_CPU, &timer_capa)) {
		printf("Error: timer capability failed\n");
		return -1;
	}

	if (res_ns < timer_capa.max_res.res_ns) {
		printf("Error: too high resolution\n");
		return -1;
	}

	if (START_NS < timer_capa.max_res.min_tmo) {
		printf("Error: too short min timeout\n");
		return -1;
	}

	if (max_tmo_ns > timer_capa.max_res.max_tmo) {
		printf("Error: too long max timeout\n");
		return -1;
	}

	max_timers = timer_capa.max_timers;
	if (max_timers && num_timer > max_timers) {
		printf("Error: too many timers (max %u)\n", max_timers);
		return -1;
	}

	if (num_tp > timer_capa.max_pools) {
		printf("Error: too many timer pools (max %u)\n",
		       timer_capa.max_pools);
		return -1;
	}

	memset(&timer_pool_param, 0, sizeof(odp_timer_pool_param_t));

	timer_pool_param.res_ns     = res_ns;
	timer_pool_param.min_tmo    = START_NS;
	timer_pool_param.max_tmo    = max_tmo_ns;
	timer_pool_param.num_timers = num_timer;
	timer_pool_param.priv       = 0;
	timer_pool_param.clk_src    = ODP_CLOCK_CPU;

	odp_pool_param_init(&pool_param);
	pool_param.type    = ODP_POOL_TIMEOUT;
	pool_param.tmo.num = num_timer;

	odp_queue_param_init(&queue_param);
	queue_param.type        = ODP_QUEUE_TYPE_SCHED;
	queue_param.sched.prio  = ODP_SCHED_PRIO_DEFAULT;
	queue_param.sched.sync  = ODP_SCHED_SYNC_ATOMIC;
	queue_param.sched.group = ODP_SCHED_GROUP_ALL;

	for (i = 0; i < num_tp; i++) {
		tp = odp_timer_pool_create(NULL, &timer_pool_param);
		global->tp[i] = tp;
		if (tp == ODP_TIMER_POOL_INVALID) {
			printf("Error: timer pool create failed (%u)\n", i);
			return -1;
		}

		pool = odp_pool_create(NULL, &pool_param);
		global->pool[i] = pool;
		if (pool == ODP_POOL_INVALID) {
			printf("Error: pool create failed (%u)\n", i);
			return -1;
		}

		queue = odp_queue_create(NULL, &queue_param);
		global->queue[i] = queue;
		if (queue == ODP_QUEUE_INVALID) {
			printf("Error: queue create failed (%u)\n", i);
			return -1;
		}
	}

	odp_timer_pool_start();

	return 0;
}

static int set_timers(test_global_t *global)
{
	odp_timer_pool_info_t timer_pool_info;
	odp_timer_pool_t tp;
	odp_timer_t timer;
	odp_pool_t pool;
	odp_queue_t queue;
	odp_time_t time;
	uint64_t tick_cur, nsec, time_ns;
	uint64_t max_tmo_ns;
	uint32_t i, j;
	test_options_t *test_options = &global->test_options;
	uint32_t num_tp    = test_options->num_tp;
	uint32_t num_timer = test_options->num_timer;
	uint64_t period_ns = test_options->period_ns;

	max_tmo_ns = START_NS + (num_timer * period_ns);

	for (i = 0; i < num_tp; i++) {
		tp    = global->tp[i];
		pool  = global->pool[i];
		queue = global->queue[i];

		nsec     = max_tmo_ns;
		tick_cur = odp_timer_current_tick(tp);
		time     = odp_time_global();
		time_ns  = odp_time_to_ns(time);

		for (j = 0; j < num_timer; j++) {
			uint64_t tick_ns;
			odp_timeout_t timeout;
			odp_event_t ev;
			int status;
			timer_ctx_t *ctx = &global->timer_ctx[i][j];

			/* Set timers backwards, the last timer is set first */
			if (j == 0)
				ctx->last = 1;

			ctx->target_ns = time_ns + nsec;

			timeout = odp_timeout_alloc(pool);
			ev = odp_timeout_to_event(timeout);

			timer = odp_timer_alloc(tp, queue, ctx);
			global->timer[i][j] = timer;

			tick_ns = odp_timer_ns_to_tick(tp, nsec);
			nsec    = nsec - period_ns;

			status = odp_timer_set_abs(timer, tick_cur + tick_ns,
						   &ev);

			if (status != ODP_TIMER_SUCCESS) {
				printf("Error: Timer set %i/%i (ret %i)\n",
				       i, j, status);
				return -1;
			}
		}

		if (odp_timer_pool_info(tp, &timer_pool_info)) {
			printf("Error: timer pool info failed\n");
			return -1;
		}

		printf("Timer pool info [%i]:\n", i);
		printf("  cur_timers       %u\n", timer_pool_info.cur_timers);
		printf("  hwm_timers       %u\n", timer_pool_info.hwm_timers);
		printf("\n");
	}

	return 0;
}

static int destroy_timer_pool(test_global_t *global)
{
	odp_timer_pool_t tp;
	odp_pool_t pool;
	odp_queue_t queue;
	odp_timer_t timer;
	odp_event_t ev;
	uint32_t i, j;
	test_options_t *test_options = &global->test_options;
	uint32_t num_timer = test_options->num_timer;
	uint32_t num_tp = test_options->num_tp;

	for (i = 0; i < num_tp; i++) {
		for (j = 0; j < num_timer; j++) {
			timer = global->timer[i][j];

			if (timer == ODP_TIMER_INVALID)
				break;

			ev = odp_timer_free(timer);

			if (ev != ODP_EVENT_INVALID) {
				printf("Event from timer free %i/%i\n", i, j);
				odp_event_free(ev);
			}
		}

		queue = global->queue[i];
		if (queue != ODP_QUEUE_INVALID)
			odp_queue_destroy(queue);

		pool = global->pool[i];
		if (pool != ODP_POOL_INVALID)
			odp_pool_destroy(pool);

		tp = global->tp[i];
		if (tp != ODP_TIMER_POOL_INVALID)
			odp_timer_pool_destroy(tp);
	}

	return 0;
}

static int test_worker(void *arg)
{
	int thr;
	uint32_t exit_test;
	odp_event_t ev;
	odp_timeout_t tmo;
	uint64_t c2, diff, nsec, time_ns, target_ns;
	odp_time_t t1, t2, time;
	time_stat_t before, after;
	timer_ctx_t *ctx;
	thread_arg_t *thread_arg = arg;
	test_global_t *global = thread_arg->global;
	test_options_t *test_options = &global->test_options;
	uint32_t num_tp = test_options->num_tp;
	uint64_t cycles = 0;
	uint64_t events = 0;
	uint64_t rounds = 0;
	uint64_t c1 = 0;
	int meas = 1;
	int ret = 0;

	memset(&before, 0, sizeof(time_stat_t));
	memset(&after, 0, sizeof(time_stat_t));

	thr = odp_thread_id();

	/* Start all workers at the same time */
	odp_barrier_wait(&global->barrier);

	t1 = odp_time_local();

	while (1) {
		if (meas) {
			c1   = odp_cpu_cycles();
			meas = 0;
		}

		ev = odp_schedule(NULL, ODP_SCHED_NO_WAIT);
		rounds++;

		exit_test = odp_atomic_load_u32(&global->exit_test);
		if (odp_likely(ev == ODP_EVENT_INVALID && exit_test < num_tp))
			continue;

		c2      = odp_cpu_cycles();
		diff    = odp_cpu_cycles_diff(c2, c1);
		cycles += diff;

		if (ev == ODP_EVENT_INVALID && exit_test >= num_tp)
			break;

		time = odp_time_global();
		time_ns = odp_time_to_ns(time);
		events++;
		meas = 1;

		tmo  = odp_timeout_from_event(ev);
		ctx  = odp_timeout_user_ptr(tmo);
		odp_timeout_free(tmo);

		target_ns = ctx->target_ns;
		if (time_ns < target_ns) {
			diff = target_ns - time_ns;
			before.num++;
			before.sum_ns += diff;
			if (diff > before.max_ns)
				before.max_ns = diff;

			ODPH_DBG("before %" PRIu64 "\n", diff);
		} else {
			diff = time_ns - target_ns;
			after.num++;
			after.sum_ns += diff;
			if (diff > after.max_ns)
				after.max_ns = diff;

			ODPH_DBG("after %" PRIu64 "\n", time_ns - target_ns);
		}

		if (ctx->last)
			odp_atomic_inc_u32(&global->exit_test);
	}

	t2   = odp_time_local();
	nsec = odp_time_diff_ns(t2, t1);

	/* Update stats*/
	global->stat[thr].events = events;
	global->stat[thr].cycles = cycles;
	global->stat[thr].rounds = rounds;
	global->stat[thr].nsec   = nsec;
	global->stat[thr].before = before;
	global->stat[thr].after  = after;

	return ret;
}

static int start_workers(test_global_t *global, odp_instance_t instance)
{
	odph_thread_common_param_t thr_common;
	int i, ret;
	test_options_t *test_options = &global->test_options;
	int num_cpu   = test_options->num_cpu;
	odph_thread_param_t thr_param[num_cpu];

	memset(global->thread_tbl, 0, sizeof(global->thread_tbl));
	memset(thr_param, 0, sizeof(thr_param));
	memset(&thr_common, 0, sizeof(thr_common));

	thr_common.instance = instance;
	thr_common.cpumask  = &global->cpumask;

	for (i = 0; i < num_cpu; i++) {
		thr_param[i].start    = test_worker;
		thr_param[i].arg      = &global->thread_arg[i];
		thr_param[i].thr_type = ODP_THREAD_WORKER;

		global->thread_arg[i].global = global;
	}

	ret = odph_thread_create(global->thread_tbl, &thr_common, thr_param,
				 num_cpu);

	if (ret != num_cpu) {
		printf("Error: thread create failed %i\n", ret);
		return -1;
	}

	return 0;
}

static void print_stat(test_global_t *global)
{
	int i;
	time_stat_t before, after;
	double time_ave = 0.0;
	double round_ave = 0.0;
	double before_ave = 0.0;
	double after_ave = 0.0;
	uint64_t time_sum = 0;
	uint64_t event_sum = 0;
	uint64_t round_sum = 0;
	uint64_t cycle_sum = 0;
	int num = 0;

	memset(&before, 0, sizeof(time_stat_t));
	memset(&after, 0, sizeof(time_stat_t));

	printf("\n");
	printf("RESULTS - schedule() cycles per thread:\n");
	printf("----------------------------------------------\n");
	printf("        1      2      3      4      5      6      7      8      9     10");

	for (i = 0; i < ODP_THREAD_COUNT_MAX; i++) {
		if (global->stat[i].rounds) {
			if ((num % 10) == 0)
				printf("\n   ");

			printf("%6.1f ", (double)global->stat[i].cycles /
			       global->stat[i].rounds);
			num++;
		}
	}

	printf("\n\n");

	for (i = 0; i < ODP_THREAD_COUNT_MAX; i++) {
		event_sum += global->stat[i].events;
		round_sum += global->stat[i].rounds;
		cycle_sum += global->stat[i].cycles;
		time_sum  += global->stat[i].nsec;
		before.num += global->stat[i].before.num;
		before.sum_ns += global->stat[i].before.sum_ns;
		after.num += global->stat[i].after.num;
		after.sum_ns += global->stat[i].after.sum_ns;

		if (global->stat[i].before.max_ns > before.max_ns)
			before.max_ns = global->stat[i].before.max_ns;

		if (global->stat[i].after.max_ns > after.max_ns)
			after.max_ns = global->stat[i].after.max_ns;
	}

	if (num) {
		time_ave  = ((double)time_sum / num) / ODP_TIME_SEC_IN_NS;
		round_ave = (double)round_sum / num;
	}

	if (before.num)
		before_ave = (double)before.sum_ns / before.num;

	if (after.num)
		after_ave = (double)after.sum_ns / after.num;

	printf("TOTAL (%i workers)\n", num);
	printf("  events:             %" PRIu64 "\n", event_sum);
	printf("  ave time:           %.2f sec\n", time_ave);
	printf("  ave rounds per sec: %.2fM\n",
	       (round_ave / time_ave) / 1000000.0);
	printf("  num before:         %" PRIu64 "\n", before.num);
	printf("  ave before:         %.1f nsec\n", before_ave);
	printf("  max before:         %" PRIu64 " nsec\n", before.max_ns);
	printf("  num after:          %" PRIu64 "\n", after.num);
	printf("  ave after:          %.1f nsec\n", after_ave);
	printf("  max after:          %" PRIu64 " nsec\n", after.max_ns);
	printf("\n");
}

static void sig_handler(int signo)
{
	(void)signo;

	odp_atomic_add_u32(&test_global.exit_test, MAX_TIMER_POOLS);
}

int main(int argc, char **argv)
{
	odp_instance_t instance;
	odp_init_t init;
	test_global_t *global;

	global = &test_global;
	memset(global, 0, sizeof(test_global_t));
	odp_atomic_init_u32(&global->exit_test, 0);

	signal(SIGINT, sig_handler);

	if (parse_options(argc, argv, &global->test_options))
		return -1;

	/* List features not to be used */
	odp_init_param_init(&init);
	init.not_used.feat.cls      = 1;
	init.not_used.feat.crypto   = 1;
	init.not_used.feat.ipsec    = 1;
	init.not_used.feat.tm       = 1;

	/* Init ODP before calling anything else */
	if (odp_init_global(&instance, &init, NULL)) {
		printf("Error: Global init failed.\n");
		return -1;
	}

	/* Init this thread */
	if (odp_init_local(instance, ODP_THREAD_CONTROL)) {
		printf("Error: Local init failed.\n");
		return -1;
	}

	odp_schedule_config(NULL);

	if (set_num_cpu(global))
		return -1;

	if (create_timer_pools(global))
		return -1;

	/* Start worker threads */
	start_workers(global, instance);

	/* Wait until workers have started.
	 * Scheduler calls from workers may be needed to run timer pools in
	 * a software implementation. Wait 1 msec to ensure that timer pools
	 * are running before setting timers. */
	odp_barrier_wait(&global->barrier);
	odp_time_wait_ns(ODP_TIME_MSEC_IN_NS);

	/* Set timers. Force workers to exit on failure. */
	if (set_timers(global))
		odp_atomic_add_u32(&global->exit_test, MAX_TIMER_POOLS);

	/* Wait workers to exit */
	odph_thread_join(global->thread_tbl, global->test_options.num_cpu);

	print_stat(global);

	destroy_timer_pool(global);

	if (odp_term_local()) {
		printf("Error: term local failed.\n");
		return -1;
	}

	if (odp_term_global(instance)) {
		printf("Error: term global failed.\n");
		return -1;
	}

	return 0;
}
