/* Copyright (c) 2019-2022, Nokia
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

#define MODE_SCHED_OVERH  0
#define MODE_SET_CANCEL   1
#define MAX_TIMER_POOLS   32
#define MAX_TIMERS        10000
#define START_NS          (100 * ODP_TIME_MSEC_IN_NS)

typedef struct test_options_t {
	uint32_t num_cpu;
	uint32_t num_tp;
	uint32_t num_timer;
	uint64_t res_ns;
	uint64_t period_ns;
	int      shared;
	int      mode;
	uint64_t test_rounds;

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

	uint64_t cancels;
	uint64_t sets;

	time_stat_t before;
	time_stat_t after;

} test_stat_t;

typedef struct test_stat_sum_t {
	uint64_t rounds;
	uint64_t events;
	uint64_t nsec;
	uint64_t cycles;

	uint64_t cancels;
	uint64_t sets;

	time_stat_t before;
	time_stat_t after;

	double   time_ave;
	uint32_t num;

} test_stat_sum_t;

typedef struct thread_arg_t {
	void *global;
	int   worker_idx;

} thread_arg_t;

typedef struct timer_ctx_t {
	uint64_t target_ns;
	uint32_t tp_idx;
	uint32_t timer_idx;
	int last;

} timer_ctx_t;

typedef struct timer_pool_t {
	odp_timer_pool_t tp;
	uint64_t start_tick;
	uint64_t period_tick;

} timer_pool_t;

typedef struct test_global_t {
	test_options_t test_options;
	odp_atomic_u32_t exit_test;
	odp_atomic_u32_t timers_started;
	odp_barrier_t barrier;
	odp_cpumask_t cpumask;
	timer_pool_t timer_pool[MAX_TIMER_POOLS];
	odp_pool_t pool[MAX_TIMER_POOLS];
	odp_queue_t queue[MAX_TIMER_POOLS];
	odp_timer_t timer[MAX_TIMER_POOLS][MAX_TIMERS];
	timer_ctx_t timer_ctx[MAX_TIMER_POOLS][MAX_TIMERS];
	odph_thread_t thread_tbl[ODP_THREAD_COUNT_MAX];
	test_stat_t stat[ODP_THREAD_COUNT_MAX];
	thread_arg_t thread_arg[ODP_THREAD_COUNT_MAX];
	test_stat_sum_t stat_sum;

} test_global_t;

test_global_t *test_global;

static void print_usage(void)
{
	printf("\n"
	       "Timer performance test\n"
	       "\n"
	       "Usage: odp_timer_perf [options]\n"
	       "\n"
	       "  -c, --num_cpu          Number of CPUs (worker threads). 0: all available CPUs. Default: 1\n"
	       "  -n, --num_tp           Number of timer pools. Default: 1\n"
	       "  -t, --num_timer        Number of timers per timer pool. Default: 10\n"
	       "  -r, --res_ns           Resolution in nsec.     Default:  10000000\n"
	       "  -p, --period_ns        Timeout period in nsec. Default: 100000000\n"
	       "  -s, --shared           Shared vs private timer pool. Currently, private pools can be\n"
	       "                         tested only with single CPU. Default: 1\n"
	       "                           0: Private timer pools\n"
	       "                           1: Shared timer pools\n"
	       "  -m, --mode             Select test mode. Default: 0\n"
	       "                           0: Measure odp_schedule() overhead when using timers\n"
	       "                           1: Measure timer set + cancel performance\n"
	       "  -R, --rounds           Number of test rounds in timer set + cancel test.\n"
	       "                           Default: 100000\n"
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
		{"shared",    required_argument, NULL, 's'},
		{"mode",      required_argument, NULL, 'm'},
		{"rounds",    required_argument, NULL, 'R'},
		{"help",      no_argument,       NULL, 'h'},
		{NULL, 0, NULL, 0}
	};

	static const char *shortopts = "+c:n:t:r:p:s:m:R:h";

	test_options->num_cpu   = 1;
	test_options->num_tp    = 1;
	test_options->num_timer = 10;
	test_options->res_ns    = 10 * ODP_TIME_MSEC_IN_NS;
	test_options->period_ns = 100 * ODP_TIME_MSEC_IN_NS;
	test_options->shared    = 1;
	test_options->mode      = 0;
	test_options->test_rounds = 100000;

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
		case 's':
			test_options->shared = atoi(optarg);
			break;
		case 'm':
			test_options->mode = atoi(optarg);
			break;
		case 'R':
			test_options->test_rounds = atoll(optarg);
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
		ODPH_ERR("Too many timers. Max %u\n", MAX_TIMERS);
		ret = -1;
	}

	return ret;
}

static int set_num_cpu(test_global_t *global)
{
	int ret;
	test_options_t *test_options = &global->test_options;
	int num_cpu = test_options->num_cpu;
	int shared = test_options->shared;

	/* One thread used for the main thread */
	if (num_cpu > ODP_THREAD_COUNT_MAX - 1) {
		ODPH_ERR("Too many workers. Maximum is %i.\n", ODP_THREAD_COUNT_MAX - 1);
		return -1;
	}

	ret = odp_cpumask_default_worker(&global->cpumask, num_cpu);

	if (num_cpu && ret != num_cpu) {
		ODPH_ERR("Too many workers. Max supported %i\n.", ret);
		return -1;
	}

	if (shared == 0 && num_cpu != 1) {
		ODPH_ERR("Private pool test supports only single CPU\n.");
		return -1;
	}

	/* Zero: all available workers */
	if (num_cpu == 0) {
		num_cpu = ret;
		test_options->num_cpu = num_cpu;
	}

	if (shared) /* Main thread + all workers */
		odp_barrier_init(&global->barrier, num_cpu + 1);
	else /* Only the main thread */
		odp_barrier_init(&global->barrier, 1);

	return 0;
}

static int create_timer_pools(test_global_t *global)
{
	odp_timer_capability_t timer_capa;
	odp_timer_res_capability_t timer_res_capa;
	odp_timer_pool_param_t timer_pool_param;
	odp_timer_pool_t tp;
	odp_queue_param_t queue_param;
	odp_queue_t queue;
	odp_pool_param_t pool_param;
	odp_pool_t pool;
	uint64_t max_tmo_ns, min_tmo_ns;
	uint32_t i, j;
	uint32_t max_timers;
	int priv;
	test_options_t *test_options = &global->test_options;
	uint32_t num_cpu   = test_options->num_cpu;
	uint32_t num_tp    = test_options->num_tp;
	uint32_t num_timer = test_options->num_timer;
	uint64_t res_ns    = test_options->res_ns;
	uint64_t period_ns = test_options->period_ns;
	int mode = test_options->mode;
	char tp_name[] = "timer_pool_00";

	max_tmo_ns = START_NS + (num_timer * period_ns);
	min_tmo_ns = START_NS / 2;

	priv = 0;
	if (test_options->shared == 0)
		priv = 1;

	printf("\nTimer performance test\n");
	printf("  mode             %i\n", mode);
	printf("  num cpu          %u\n", num_cpu);
	printf("  private pool     %i\n", priv);
	printf("  num timer pool   %u\n", num_tp);
	printf("  num timer        %u\n", num_timer);
	printf("  resolution       %" PRIu64 " nsec\n", res_ns);
	printf("  period           %" PRIu64 " nsec\n", period_ns);
	printf("  max timeout      %" PRIu64 " nsec\n", max_tmo_ns);
	printf("  min timeout      %" PRIu64 " nsec\n", min_tmo_ns);
	printf("  first timer at   %.2f sec\n", (double)START_NS / ODP_TIME_SEC_IN_NS);
	if (mode == MODE_SCHED_OVERH)
		printf("  test duration    %.2f sec\n", (double)max_tmo_ns / ODP_TIME_SEC_IN_NS);
	else
		printf("  test rounds      %" PRIu64 "\n", test_options->test_rounds);

	for (i = 0; i < MAX_TIMER_POOLS; i++) {
		global->timer_pool[i].tp = ODP_TIMER_POOL_INVALID;
		global->pool[i]  = ODP_POOL_INVALID;
		global->queue[i] = ODP_QUEUE_INVALID;

		for (j = 0; j < MAX_TIMERS; j++)
			global->timer[i][j] = ODP_TIMER_INVALID;
	}

	if (odp_timer_capability(ODP_CLOCK_DEFAULT, &timer_capa)) {
		ODPH_ERR("Timer capability failed\n");
		return -1;
	}

	memset(&timer_res_capa, 0, sizeof(odp_timer_res_capability_t));
	timer_res_capa.res_ns = res_ns;
	if (odp_timer_res_capability(ODP_CLOCK_DEFAULT, &timer_res_capa)) {
		ODPH_ERR("Timer resolution capability failed\n");
		return -1;
	}

	if (res_ns < timer_capa.max_res.res_ns) {
		ODPH_ERR("Too high resolution\n");
		return -1;
	}

	if (min_tmo_ns < timer_res_capa.min_tmo) {
		ODPH_ERR("Too short min timeout\n");
		return -1;
	}

	if (max_tmo_ns > timer_res_capa.max_tmo) {
		ODPH_ERR("Too long max timeout\n");
		return -1;
	}

	max_timers = timer_capa.max_timers;
	if (max_timers && num_timer > max_timers) {
		ODPH_ERR("Too many timers (max %u)\n", max_timers);
		return -1;
	}

	if (num_tp > timer_capa.max_pools) {
		ODPH_ERR("Too many timer pools (max %u)\n", timer_capa.max_pools);
		return -1;
	}

	odp_timer_pool_param_init(&timer_pool_param);
	timer_pool_param.res_ns     = res_ns;
	timer_pool_param.min_tmo    = min_tmo_ns;
	timer_pool_param.max_tmo    = max_tmo_ns;
	timer_pool_param.num_timers = num_timer;
	timer_pool_param.priv       = priv;
	timer_pool_param.clk_src    = ODP_CLOCK_DEFAULT;

	odp_pool_param_init(&pool_param);
	pool_param.type    = ODP_POOL_TIMEOUT;
	pool_param.tmo.num = num_timer;

	odp_queue_param_init(&queue_param);
	queue_param.type        = ODP_QUEUE_TYPE_SCHED;
	queue_param.sched.prio  = odp_schedule_default_prio();
	queue_param.sched.sync  = ODP_SCHED_SYNC_ATOMIC;
	queue_param.sched.group = ODP_SCHED_GROUP_ALL;

	for (i = 0; i < num_tp; i++) {
		if (num_tp < 100) {
			tp_name[11] = '0' + i / 10;
			tp_name[12] = '0' + i % 10;
		}

		tp = odp_timer_pool_create(tp_name, &timer_pool_param);
		global->timer_pool[i].tp = tp;
		if (tp == ODP_TIMER_POOL_INVALID) {
			ODPH_ERR("Timer pool create failed (%u)\n", i);
			return -1;
		}

		pool = odp_pool_create(tp_name, &pool_param);
		global->pool[i] = pool;
		if (pool == ODP_POOL_INVALID) {
			ODPH_ERR("Pool create failed (%u)\n", i);
			return -1;
		}

		queue = odp_queue_create(tp_name, &queue_param);
		global->queue[i] = queue;
		if (queue == ODP_QUEUE_INVALID) {
			ODPH_ERR("Queue create failed (%u)\n", i);
			return -1;
		}

		global->timer_pool[i].period_tick = odp_timer_ns_to_tick(tp,
									 test_options->period_ns);
		global->timer_pool[i].start_tick = odp_timer_ns_to_tick(tp, START_NS);
	}

	odp_timer_pool_start();

	printf("  start            %" PRIu64 " tick\n",  global->timer_pool[0].start_tick);
	printf("  period           %" PRIu64 " ticks\n", global->timer_pool[0].period_tick);
	printf("\n");

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
		tp    = global->timer_pool[i].tp;
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
			odp_timer_start_t start_param;

			/* Set timers backwards, the last timer is set first */
			if (j == 0)
				ctx->last = 1;

			ctx->target_ns = time_ns + nsec;
			ctx->tp_idx    = i;
			ctx->timer_idx = j;

			timeout = odp_timeout_alloc(pool);
			ev = odp_timeout_to_event(timeout);

			timer = odp_timer_alloc(tp, queue, ctx);
			global->timer[i][j] = timer;

			tick_ns = odp_timer_ns_to_tick(tp, nsec);
			nsec    = nsec - period_ns;

			start_param.tick_type = ODP_TIMER_TICK_ABS;
			start_param.tick = tick_cur + tick_ns;
			start_param.tmo_ev = ev;

			status = odp_timer_start(timer, &start_param);
			if (status != ODP_TIMER_SUCCESS) {
				ODPH_ERR("Timer set %i/%i (ret %i)\n", i, j, status);
				return -1;
			}
		}

		if (odp_timer_pool_info(tp, &timer_pool_info)) {
			ODPH_ERR("Timer pool info failed\n");
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
				if (test_options->mode == MODE_SCHED_OVERH)
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

		tp = global->timer_pool[i].tp;
		if (tp != ODP_TIMER_POOL_INVALID)
			odp_timer_pool_destroy(tp);
	}

	return 0;
}

static int sched_mode_worker(void *arg)
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

static void cancel_timers(test_global_t *global, uint32_t worker_idx)
{
	uint32_t i, j;
	odp_timer_t timer;
	odp_event_t ev;
	test_options_t *test_options = &global->test_options;
	uint32_t num_tp = test_options->num_tp;
	uint32_t num_timer = test_options->num_timer;
	uint32_t num_worker = test_options->num_cpu;

	for (i = 0; i < num_tp; i++) {
		for (j = 0; j < num_timer; j++) {
			if ((j % num_worker) != worker_idx)
				continue;

			timer = global->timer[i][j];
			if (timer == ODP_TIMER_INVALID)
				continue;

			if (odp_timer_cancel(timer, &ev) == 0)
				odp_event_free(ev);
		}
	}
}

static int set_cancel_mode_worker(void *arg)
{
	uint64_t tick, start_tick, period_tick, nsec;
	uint64_t c1, c2, diff;
	int thr, status;
	uint32_t i, j, worker_idx;
	odp_event_t ev;
	odp_time_t t1, t2;
	odp_timer_t timer;
	odp_timer_pool_t tp;
	odp_timeout_t tmo;
	odp_timer_start_t start_param;
	thread_arg_t *thread_arg = arg;
	test_global_t *global = thread_arg->global;
	test_options_t *test_options = &global->test_options;
	uint32_t num_tp = test_options->num_tp;
	uint32_t num_timer = test_options->num_timer;
	uint32_t num_worker = test_options->num_cpu;
	int ret = 0;
	int started = 0;
	uint64_t test_rounds = test_options->test_rounds;
	uint64_t num_tmo = 0;
	uint64_t num_cancel = 0;
	uint64_t num_set = 0;

	thr = odp_thread_id();
	worker_idx = thread_arg->worker_idx;
	t1 = ODP_TIME_NULL;
	c1 = 0;

	/* Start all workers at the same time */
	odp_barrier_wait(&global->barrier);

	while (1) {
		ev = odp_schedule(NULL, ODP_SCHED_NO_WAIT);

		if (odp_unlikely(ev != ODP_EVENT_INVALID)) {
			/* Timeout, set timer again. When start_tick is large enough, this should
			 * not happen. */
			timer_ctx_t *ctx;

			tmo   = odp_timeout_from_event(ev);
			ctx   = odp_timeout_user_ptr(tmo);
			i     = ctx->tp_idx;
			j     = ctx->timer_idx;
			timer = global->timer[i][j];
			start_tick  = global->timer_pool[i].start_tick;
			period_tick = global->timer_pool[i].period_tick;
			tick = start_tick + j * period_tick;

			start_param.tick_type = ODP_TIMER_TICK_REL;
			start_param.tick = tick;
			start_param.tmo_ev = ev;

			status = odp_timer_start(timer, &start_param);
			num_tmo++;
			num_set++;

			if (status != ODP_TIMER_SUCCESS) {
				ODPH_ERR("Timer set (tmo) failed (ret %i)\n", status);
				ret = -1;
				break;
			}

			continue;
		}

		if (odp_unlikely(odp_atomic_load_u32(&global->exit_test)))
			break;

		if (odp_unlikely(started == 0)) {
			/* Run schedule loop while waiting for timers to be created */
			if (odp_atomic_load_acq_u32(&global->timers_started) == 0)
				continue;

			/* Start measurements */
			started = 1;
			t1 = odp_time_local();
			c1 = odp_cpu_cycles();
		}

		/* Cancel and set timers again */
		for (i = 0; i < num_tp; i++) {
			tp = global->timer_pool[i].tp;
			if (tp == ODP_TIMER_POOL_INVALID)
				continue;

			start_tick  = global->timer_pool[i].start_tick;
			period_tick = global->timer_pool[i].period_tick;

			tick = odp_timer_current_tick(tp) + start_tick;

			for (j = 0; j < num_timer; j++) {
				if ((j % num_worker) != worker_idx)
					continue;

				timer = global->timer[i][j];
				if (timer == ODP_TIMER_INVALID)
					continue;

				status = odp_timer_cancel(timer, &ev);
				num_cancel++;

				if (status < 0)
					continue;

				start_param.tick_type = ODP_TIMER_TICK_ABS;
				start_param.tick = tick + j * period_tick;
				start_param.tmo_ev = ev;

				status = odp_timer_start(timer, &start_param);
				num_set++;

				if (status != ODP_TIMER_SUCCESS) {
					ODPH_ERR("Timer (%u/%u) set failed (ret %i)\n", i, j,
						 status);
					ret = -1;
					break;
				}
			}
		}

		if (test_rounds) {
			test_rounds--;
			if (test_rounds == 0)
				break;
		}
	}

	t2   = odp_time_local();
	c2   = odp_cpu_cycles();
	nsec = odp_time_diff_ns(t2, t1);
	diff = odp_cpu_cycles_diff(c2, c1);

	/* Cancel all timers that belong to this thread */
	cancel_timers(global, worker_idx);

	/* Update stats */
	global->stat[thr].events = num_tmo;
	global->stat[thr].rounds = test_options->test_rounds - test_rounds;
	global->stat[thr].nsec   = nsec;
	global->stat[thr].cycles = diff;

	global->stat[thr].cancels = num_cancel;
	global->stat[thr].sets    = num_set;

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
	odph_thread_common_param_init(&thr_common);

	thr_common.instance = instance;
	thr_common.cpumask  = &global->cpumask;

	for (i = 0; i < num_cpu; i++) {
		odph_thread_param_init(&thr_param[i]);

		if (test_options->mode == MODE_SCHED_OVERH)
			thr_param[i].start = sched_mode_worker;
		else
			thr_param[i].start = set_cancel_mode_worker;

		thr_param[i].arg      = &global->thread_arg[i];
		thr_param[i].thr_type = ODP_THREAD_WORKER;
	}

	ret = odph_thread_create(global->thread_tbl, &thr_common, thr_param,
				 num_cpu);

	if (ret != num_cpu) {
		ODPH_ERR("Thread create failed %i\n", ret);
		return -1;
	}

	return 0;
}

static void sum_stat(test_global_t *global)
{
	int i;
	test_stat_sum_t *sum = &global->stat_sum;

	memset(sum, 0, sizeof(test_stat_sum_t));

	for (i = 0; i < ODP_THREAD_COUNT_MAX; i++) {
		if (global->stat[i].rounds == 0)
			continue;

		sum->num++;
		sum->events  += global->stat[i].events;
		sum->rounds  += global->stat[i].rounds;
		sum->cycles  += global->stat[i].cycles;
		sum->nsec    += global->stat[i].nsec;
		sum->cancels += global->stat[i].cancels;
		sum->sets    += global->stat[i].sets;

		sum->before.num    += global->stat[i].before.num;
		sum->before.sum_ns += global->stat[i].before.sum_ns;
		sum->after.num     += global->stat[i].after.num;
		sum->after.sum_ns  += global->stat[i].after.sum_ns;

		if (global->stat[i].before.max_ns > sum->before.max_ns)
			sum->before.max_ns = global->stat[i].before.max_ns;

		if (global->stat[i].after.max_ns > sum->after.max_ns)
			sum->after.max_ns = global->stat[i].after.max_ns;
	}

	if (sum->num)
		sum->time_ave = ((double)sum->nsec / sum->num) / ODP_TIME_SEC_IN_NS;
}

static void print_stat_sched_mode(test_global_t *global)
{
	int i;
	test_stat_sum_t *sum = &global->stat_sum;
	double round_ave = 0.0;
	double before_ave = 0.0;
	double after_ave = 0.0;
	int num = 0;

	printf("\n");
	printf("RESULTS - schedule() cycles per thread:\n");
	printf("----------------------------------------------\n");
	printf("        1      2      3      4      5      6      7      8      9     10");

	for (i = 0; i < ODP_THREAD_COUNT_MAX; i++) {
		if (global->stat[i].rounds) {
			if ((num % 10) == 0)
				printf("\n   ");

			printf("%6.1f ", (double)global->stat[i].cycles / global->stat[i].rounds);
			num++;
		}
	}

	printf("\n\n");

	if (sum->num)
		round_ave = (double)sum->rounds / sum->num;

	if (sum->before.num)
		before_ave = (double)sum->before.sum_ns / sum->before.num;

	if (sum->after.num)
		after_ave = (double)sum->after.sum_ns / sum->after.num;

	printf("TOTAL (%i workers)\n", sum->num);
	printf("  events:             %" PRIu64 "\n", sum->events);
	printf("  ave time:           %.2f sec\n", sum->time_ave);
	printf("  ave rounds per sec: %.2fM\n", (round_ave / sum->time_ave) / 1000000.0);
	printf("  num before:         %" PRIu64 "\n", sum->before.num);
	printf("  ave before:         %.1f nsec\n", before_ave);
	printf("  max before:         %" PRIu64 " nsec\n", sum->before.max_ns);
	printf("  num after:          %" PRIu64 "\n", sum->after.num);
	printf("  ave after:          %.1f nsec\n", after_ave);
	printf("  max after:          %" PRIu64 " nsec\n", sum->after.max_ns);
	printf("\n");
}

static void print_stat_set_cancel_mode(test_global_t *global)
{
	int i;
	test_stat_sum_t *sum = &global->stat_sum;
	double set_ave = 0.0;
	int num = 0;

	printf("\n");
	printf("RESULTS - timer cancel + set cycles per thread:\n");
	printf("-----------------------------------------------\n");
	printf("        1      2      3      4      5      6      7      8      9     10");

	for (i = 0; i < ODP_THREAD_COUNT_MAX; i++) {
		if (global->stat[i].rounds) {
			if ((num % 10) == 0)
				printf("\n   ");

			printf("%6.1f ", (double)global->stat[i].cycles / global->stat[i].sets);
			num++;
		}
	}

	if (sum->num)
		set_ave = (double)sum->sets / sum->num;

	printf("\n\n");
	printf("TOTAL (%i workers)\n", sum->num);
	printf("  rounds:              %" PRIu64 "\n", sum->rounds);
	printf("  timeouts:            %" PRIu64 "\n", sum->events);
	printf("  timer cancels:       %" PRIu64 "\n", sum->cancels);
	printf("  cancels failed:      %" PRIu64 "\n", sum->cancels - sum->sets);
	printf("  timer sets:          %" PRIu64 "\n", sum->sets);
	printf("  ave time:            %.2f sec\n", sum->time_ave);
	printf("  cancel+set per cpu:  %.2fM per sec\n", (set_ave / sum->time_ave) / 1000000.0);
	printf("\n");
}

static void sig_handler(int signo)
{
	(void)signo;

	if (test_global == NULL)
		return;
	odp_atomic_add_u32(&test_global->exit_test, MAX_TIMER_POOLS);
}

int main(int argc, char **argv)
{
	odph_helper_options_t helper_options;
	odp_instance_t instance;
	odp_init_t init;
	odp_shm_t shm;
	test_global_t *global;
	test_options_t *test_options;
	int i, shared, mode;

	signal(SIGINT, sig_handler);

	/* Let helper collect its own arguments (e.g. --odph_proc) */
	argc = odph_parse_options(argc, argv);
	if (odph_options(&helper_options)) {
		ODPH_ERR("Reading ODP helper options failed.\n");
		exit(EXIT_FAILURE);
	}

	/* List features not to be used */
	odp_init_param_init(&init);
	init.not_used.feat.cls      = 1;
	init.not_used.feat.compress = 1;
	init.not_used.feat.crypto   = 1;
	init.not_used.feat.ipsec    = 1;
	init.not_used.feat.tm       = 1;

	init.mem_model = helper_options.mem_model;

	/* Init ODP before calling anything else */
	if (odp_init_global(&instance, &init, NULL)) {
		ODPH_ERR("Global init failed.\n");
		return -1;
	}

	/* Init this thread */
	if (odp_init_local(instance, ODP_THREAD_CONTROL)) {
		ODPH_ERR("Local init failed.\n");
		return -1;
	}

	shm = odp_shm_reserve("timer_perf_global", sizeof(test_global_t), ODP_CACHE_LINE_SIZE, 0);
	if (shm == ODP_SHM_INVALID) {
		ODPH_ERR("Shared mem reserve failed.\n");
		exit(EXIT_FAILURE);
	}

	global = odp_shm_addr(shm);
	if (global == NULL) {
		ODPH_ERR("Shared mem alloc failed\n");
		exit(EXIT_FAILURE);
	}
	test_global = global;

	memset(global, 0, sizeof(test_global_t));
	odp_atomic_init_u32(&global->exit_test, 0);
	odp_atomic_init_u32(&global->timers_started, 0);

	for (i = 0; i < ODP_THREAD_COUNT_MAX; i++) {
		global->thread_arg[i].global = global;
		global->thread_arg[i].worker_idx = i;
	}

	if (parse_options(argc, argv, &global->test_options))
		return -1;

	test_options = &global->test_options;
	shared = test_options->shared;
	mode   = test_options->mode;

	odp_sys_info_print();

	odp_schedule_config(NULL);

	if (set_num_cpu(global))
		return -1;

	if (create_timer_pools(global))
		return -1;

	if (shared) {
		/* Start worker threads */
		start_workers(global, instance);

		/* Wait until workers have started.
		 * Scheduler calls from workers may be needed to run timer
		 * pools in a software implementation. Wait 1 msec to ensure
		 * that timer pools are running before setting timers. */
		odp_barrier_wait(&global->barrier);
		odp_time_wait_ns(ODP_TIME_MSEC_IN_NS);
	}

	/* Set timers. Force workers to exit on failure. */
	if (set_timers(global))
		odp_atomic_add_u32(&global->exit_test, MAX_TIMER_POOLS);
	else
		odp_atomic_store_rel_u32(&global->timers_started, 1);

	if (!shared) {
		/* Test private pools on the master thread */
		if (mode == MODE_SCHED_OVERH) {
			if (sched_mode_worker(&global->thread_arg[0])) {
				ODPH_ERR("Sched_mode_worker failed\n");
				return -1;
			}
		} else {
			if (set_cancel_mode_worker(&global->thread_arg[0])) {
				ODPH_ERR("Set_cancel_mode_worker failed\n");
				return -1;
			}
		}
	} else {
		/* Wait workers to exit */
		odph_thread_join(global->thread_tbl,
				 global->test_options.num_cpu);
	}

	sum_stat(global);

	if (mode == MODE_SCHED_OVERH)
		print_stat_sched_mode(global);
	else
		print_stat_set_cancel_mode(global);

	destroy_timer_pool(global);

	if (odp_shm_free(shm)) {
		ODPH_ERR("Shared mem free failed.\n");
		exit(EXIT_FAILURE);
	}

	if (odp_term_local()) {
		ODPH_ERR("Term local failed.\n");
		return -1;
	}

	if (odp_term_global(instance)) {
		ODPH_ERR("Term global failed.\n");
		return -1;
	}

	return 0;
}
