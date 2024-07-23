/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022-2024 Nokia
 */

/**
 * @example odp_stress.c
 *
 * Test application that can be used to stress CPU, memory, and HW accelerators.
 *
 * @cond _ODP_HIDE_FROM_DOXYGEN_
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

#define MODE_MEMCPY   0x1
#define MODE_COPY_U32 0x2
#define MODE_SQRT_U32 0x4
#define MODE_SQRT_F32 0x8

typedef struct test_options_t {
	uint32_t num_cpu;
	uint64_t period_ns;
	uint64_t rounds;
	uint64_t mem_size;
	int      mode;
	int      group_mode;

} test_options_t;

typedef struct test_stat_t {
	uint64_t rounds;
	uint64_t tot_nsec;
	uint64_t work_nsec;
	uint64_t dummy_sum;

} test_stat_t;

typedef struct test_stat_sum_t {
	uint64_t rounds;
	uint64_t tot_nsec;
	uint64_t work_nsec;

} test_stat_sum_t;

typedef struct thread_arg_t {
	void *global;
	int   worker_idx;

} thread_arg_t;

typedef struct test_global_t {
	test_options_t test_options;
	odp_atomic_u32_t exit_test;
	odp_barrier_t barrier;
	odp_cpumask_t cpumask;
	odp_timer_pool_t timer_pool;
	odp_pool_t tmo_pool;
	uint64_t period_ticks;
	void *worker_mem;
	odp_timer_t timer[ODP_THREAD_COUNT_MAX];
	odp_queue_t tmo_queue[ODP_THREAD_COUNT_MAX];
	odp_schedule_group_t group[ODP_THREAD_COUNT_MAX];
	odph_thread_t thread_tbl[ODP_THREAD_COUNT_MAX];
	test_stat_t stat[ODP_THREAD_COUNT_MAX];
	thread_arg_t thread_arg[ODP_THREAD_COUNT_MAX];
	test_stat_sum_t stat_sum;
	odp_atomic_u64_t tot_rounds;

} test_global_t;

test_global_t *test_global;

/* 250 random numbers: values between 100 and 20000 */
static const uint32_t pseudo_rand[] = {
	14917,  9914,  5313,  4092, 16041,  7757, 17247, 14804,  3255,  7675,
	13149,  7288,  5665,  7095,  9594,  1296,  2058,  6013, 17779, 11788,
	14855,   760, 16891,  2483, 10937, 16385, 13593, 10674,  4080,  2392,
	12218, 11475,  6009,  5798,  7582,  8358,  4520, 14655, 10555,  6598,
	10598, 16097, 16634, 17102, 16296, 17142,  5748, 11079, 14569, 10961,
	16693, 17775, 19155, 14102, 16132, 19561,  8746,  4521,  8280,   355,
	10655, 14539,  5641,  2343, 19213,  9187,   570, 15096,   780,  1711,
	 8007,  8128, 17416, 14123,  4713, 13774, 11450,  9031,  1194, 16531,
	 9349,  3496, 19130, 19458, 12412,  9168,  9508, 10607,  5952, 19375,
	14934, 18276, 12116,   510, 14272, 10362,  4095,  6789,  1600, 18509,
	 9274,  2815,  3175,  1122,  6495,  7991, 18831, 17550,  7056, 16185,
	18594, 19178, 10028,  1182, 13410, 16173,  3548,  8013,  6099,  2619,
	 7359,  6889, 15227,  4910, 12341, 18904,   671,  5851,  9836, 18105,
	13624,  8138,  5751, 15590, 17415, 15330,   697, 11439,  7008, 10676,
	 9863, 17163, 10885,  5581,  8078,  4689,  9870, 18370, 19323,  8831,
	11444,  3602, 10125,  6244, 13171, 19335, 15635, 19684, 17581,  9513,
	 8444, 13724,  5243,  9987, 19886,  5087, 17292, 16294, 19627, 14985,
	 1999,  9889,  1311,  5589, 10084,   911,   301,  2260, 15305,  8265,
	  409,  1732,  1463, 17680, 15038,  2440,  4239,  9554, 14045,   924,
	13997,  3472, 18304,  4848, 10601, 18604,  6459, 19394,  2962, 11218,
	 5405,  9869,   133,  2512, 13440,  4350,   625,  6580,  5082, 12908,
	11517,  8919,   354, 14216,  3190, 15515,  1277,  1028,   507,  9525,
	10115,   811,  1268, 17587,  5192,  7240, 17371,  4902, 19908,  1027,
	 3475,  8658, 11782, 13701, 13034,   154,  4940, 12679, 14067,  2707,
	10180,  4669, 17756,  6602,  6727,   818,  8644,   580, 16988, 19127
};

static void print_usage(void)
{
	printf("\n"
	       "Stress test options:\n"
	       "\n"
	       "  -c, --num_cpu          Number of CPUs (worker threads). 0: all available CPUs. Default: 1\n"
	       "  -p, --period_ns        Timeout period in nsec. Default: 100 ms\n"
	       "  -r, --rounds           Number of timeout rounds. Default: 2\n"
	       "  -m, --mode             Test mode flags, multiple may be selected. Default: 0x1\n"
	       "                           0:   No stress, just wait for timeouts\n"
	       "                           0x1: memcpy()\n"
	       "                           0x2: Memory copy loop\n"
	       "                           0x4: Integer square root\n"
	       "                           0x8: Floating point square root\n"
	       "  -s, --mem_size         Memory size per worker in bytes. Default: 2048\n"
	       "  -g, --group_mode       Select schedule group mode: Default: 1\n"
	       "                           0: Use GROUP_ALL group. Scheduler load balances timeout events.\n"
	       "                           1: Create a group per CPU. Dedicated timeout event per CPU.\n"
	       "  -h, --help             This help\n"
	       "\n");
}

static int parse_options(int argc, char *argv[], test_options_t *test_options)
{
	int opt;
	int long_index;
	int ret = 0;

	static const struct option longopts[] = {
		{"num_cpu",      required_argument, NULL, 'c'},
		{"period_ns",    required_argument, NULL, 'p'},
		{"rounds",       required_argument, NULL, 'r'},
		{"mode",         required_argument, NULL, 'm'},
		{"mem_size",     required_argument, NULL, 's'},
		{"group_mode",   required_argument, NULL, 'g'},
		{"help",         no_argument,       NULL, 'h'},
		{NULL, 0, NULL, 0}
	};

	static const char *shortopts = "+c:p:r:m:s:g:h";

	test_options->num_cpu     = 1;
	test_options->period_ns   = 100 * ODP_TIME_MSEC_IN_NS;
	test_options->rounds      = 2;
	test_options->mode        = MODE_MEMCPY;
	test_options->mem_size    = 2048;
	test_options->group_mode  = 1;

	while (1) {
		opt = getopt_long(argc, argv, shortopts, longopts, &long_index);

		if (opt == -1)
			break;

		switch (opt) {
		case 'c':
			test_options->num_cpu = atoi(optarg);
			break;
		case 'p':
			test_options->period_ns = atoll(optarg);
			break;
		case 'r':
			test_options->rounds = atoll(optarg);
			break;
		case 'm':
			test_options->mode = strtoul(optarg, NULL, 0);
			break;
		case 's':
			test_options->mem_size = atoll(optarg);
			break;
		case 'g':
			test_options->group_mode = atoi(optarg);
			break;
		case 'h':
			/* fall through */
		default:
			print_usage();
			ret = -1;
			break;
		}
	}

	if (test_options->mode) {
		if (test_options->mem_size < sizeof(uint32_t)) {
			ODPH_ERR("Too small memory size. Minimum is %zu bytes.\n",
				 sizeof(uint32_t));
			return -1;
		}
	}

	return ret;
}

static int set_num_cpu(test_global_t *global)
{
	int ret;
	test_options_t *test_options = &global->test_options;
	int num_cpu = test_options->num_cpu;

	/* One thread used for the main thread */
	if (num_cpu < 0 || num_cpu > ODP_THREAD_COUNT_MAX - 1) {
		ODPH_ERR("Bad number of workers. Maximum is %i.\n", ODP_THREAD_COUNT_MAX - 1);
		return -1;
	}

	ret = odp_cpumask_default_worker(&global->cpumask, num_cpu);

	if (num_cpu && ret != num_cpu) {
		ODPH_ERR("Too many workers. Max supported %i\n.", ret);
		return -1;
	}

	/* Zero: all available workers */
	if (num_cpu == 0) {
		num_cpu = ret;
		test_options->num_cpu = num_cpu;
	}

	odp_barrier_init(&global->barrier, num_cpu + 1);

	return 0;
}

static int join_group(test_global_t *global, int worker_idx, int thr)
{
	odp_thrmask_t thrmask;
	odp_schedule_group_t group;

	odp_thrmask_zero(&thrmask);
	odp_thrmask_set(&thrmask, thr);
	group = global->group[worker_idx];

	if (odp_schedule_group_join(group, &thrmask)) {
		ODPH_ERR("Thread %i failed to join group %i\n", thr, worker_idx);
		return -1;
	}

	return 0;
}

static int worker_thread(void *arg)
{
	int thr, timer_ret;
	uint32_t exit_test;
	odp_event_t ev;
	odp_timeout_t tmo;
	odp_timer_t timer;
	uint64_t tot_nsec, work_sum, max_nsec, i;
	odp_timer_start_t start_param;
	odp_time_t t1, t2, max_time;
	odp_time_t work_t1, work_t2;
	uint8_t *src = NULL, *dst = NULL;
	uint32_t *src_u32 = NULL, *dst_u32 = NULL;
	thread_arg_t *thread_arg = arg;
	int worker_idx = thread_arg->worker_idx;
	test_global_t *global = thread_arg->global;
	test_options_t *test_options = &global->test_options;
	const int group_mode = test_options->group_mode;
	const int mode = test_options->mode;
	const int data_mode = mode & (MODE_SQRT_U32 | MODE_SQRT_F32);
	const uint64_t mem_size = test_options->mem_size;
	const uint64_t copy_size = mem_size / 2;
	const uint64_t num_words = mem_size / sizeof(uint32_t);
	const uint64_t copy_words = num_words / 2;
	uint64_t rounds = 0;
	uint64_t dummy_sum = 0;
	int ret = 0;
	uint32_t done = 0;
	uint64_t wait = ODP_SCHED_WAIT;
	uint64_t tot_rounds = test_options->rounds * test_options->num_cpu;

	thr = odp_thread_id();
	max_nsec = 2 * test_options->rounds * test_options->period_ns;
	max_time = odp_time_local_from_ns(max_nsec);
	printf("Thread %i starting on CPU %i\n", thr, odp_cpu_id());

	if (group_mode == 0) {
		/* Timeout events are load balanced. Using this
		 * period to poll exit status. */
		wait = odp_schedule_wait_time(100 * ODP_TIME_MSEC_IN_NS);
	} else {
		if (join_group(global, worker_idx, thr)) {
			/* Join failed, exit after barrier */
			wait = ODP_SCHED_NO_WAIT;
			done = 1;
		}
	}

	if (mode) {
		src = (uint8_t *)global->worker_mem + worker_idx * mem_size;
		dst = src + copy_size;
		src_u32 = (uint32_t *)(uintptr_t)src;
		dst_u32 = (uint32_t *)(uintptr_t)dst;
	}

	start_param.tick_type = ODP_TIMER_TICK_REL;
	start_param.tick = global->period_ticks;

	/* Start all workers at the same time */
	odp_barrier_wait(&global->barrier);

	work_sum = 0;
	t1 = odp_time_local();
	max_time = odp_time_sum(t1, max_time);

	while (1) {
		ev = odp_schedule(NULL, wait);

		exit_test  = odp_atomic_load_u32(&global->exit_test);
		exit_test += done;

		if (ev == ODP_EVENT_INVALID) {
			odp_time_t cur_time = odp_time_local();

			if (odp_time_cmp(cur_time, max_time) > 0)
				exit_test += 1;

			if (exit_test) {
				/* Exit loop without schedule context */
				break;
			}

			continue;
		}

		rounds++;

		if (group_mode) {
			if (rounds >= test_options->rounds)
				done = 1;
		} else {
			if (odp_atomic_fetch_inc_u64(&global->tot_rounds) >= (tot_rounds - 1))
				done = 1;
		}

		if (done == 0) {
			tmo = odp_timeout_from_event(ev);
			timer = odp_timeout_timer(tmo);
			start_param.tmo_ev = ev;

			timer_ret = odp_timer_start(timer, &start_param);

			if (timer_ret != ODP_TIMER_SUCCESS) {
				ODPH_ERR("Timer start failed (%" PRIu64 ")\n", rounds);
				done = 1;
			}
		}

		/* Do work */
		if (mode) {
			work_t1 = odp_time_local();

			if (mode & MODE_MEMCPY)
				memcpy(dst, src, copy_size);

			if (mode & MODE_COPY_U32)
				for (i = 0; i < copy_words; i++)
					dst_u32[i] = src_u32[i];

			if (data_mode) {
				for (i = 0; i < num_words; i++) {
					if (mode & MODE_SQRT_U32)
						dummy_sum += odph_stress_sqrt_u32(src_u32[i]);

					if (mode & MODE_SQRT_F32)
						dummy_sum += odph_stress_sqrt_f32(src_u32[i]);
				}
			}

			work_t2 = odp_time_local();
			work_sum += odp_time_diff_ns(work_t2, work_t1);
		}

		if (done) {
			/* Stop timer and do not wait events */
			wait = ODP_SCHED_NO_WAIT;
			odp_event_free(ev);
		}
	}

	t2 = odp_time_local();
	tot_nsec = odp_time_diff_ns(t2, t1);

	/* Update stats*/
	global->stat[thr].rounds    = rounds;
	global->stat[thr].tot_nsec  = tot_nsec;
	global->stat[thr].work_nsec = work_sum;
	global->stat[thr].dummy_sum = dummy_sum;

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
		thr_param[i].start = worker_thread;
		thr_param[i].arg      = &global->thread_arg[i];
		thr_param[i].thr_type = ODP_THREAD_WORKER;
	}

	ret = odph_thread_create(global->thread_tbl, &thr_common, thr_param, num_cpu);

	if (ret != num_cpu) {
		ODPH_ERR("Thread create failed %i\n", ret);
		return -1;
	}

	return 0;
}

static int create_timers(test_global_t *global)
{
	odp_timer_capability_t timer_capa;
	odp_timer_res_capability_t timer_res_capa;
	odp_timer_pool_param_t timer_pool_param;
	odp_timer_pool_t tp;
	odp_pool_param_t pool_param;
	odp_pool_t pool;
	double duration;
	test_options_t *test_options = &global->test_options;
	uint32_t num_cpu   = test_options->num_cpu;
	uint64_t period_ns = test_options->period_ns;
	uint64_t res_ns = period_ns / 1000;

	if (odp_timer_capability(ODP_CLOCK_DEFAULT, &timer_capa)) {
		ODPH_ERR("Timer capability failed\n");
		return -1;
	}

	if (timer_capa.queue_type_sched == 0) {
		ODPH_ERR("Timer does not support sched queues\n");
		return -1;
	}

	memset(&timer_res_capa, 0, sizeof(odp_timer_res_capability_t));
	timer_res_capa.max_tmo = 2 * period_ns;
	if (odp_timer_res_capability(ODP_CLOCK_DEFAULT, &timer_res_capa)) {
		ODPH_ERR("Timer resolution capability failed. Too long period.\n");
		return -1;
	}

	if (res_ns < timer_res_capa.res_ns)
		res_ns = timer_res_capa.res_ns;

	duration = test_options->rounds * (double)period_ns / ODP_TIME_SEC_IN_NS;

	printf("  num timers          %u\n", num_cpu);
	printf("  resolution          %" PRIu64 " nsec\n", res_ns);
	printf("  period              %" PRIu64 " nsec\n", period_ns);
	printf("  test duration       %.2f sec\n", duration);
	if (test_options->group_mode == 0)
		printf("  force stop after    %.2f sec\n", 2 * duration);
	printf("\n");

	odp_pool_param_init(&pool_param);
	pool_param.type    = ODP_POOL_TIMEOUT;
	pool_param.tmo.num = num_cpu;

	pool = odp_pool_create("Timeout pool", &pool_param);
	global->tmo_pool = pool;
	if (pool == ODP_POOL_INVALID) {
		ODPH_ERR("Pool create failed\n");
		return -1;
	}

	odp_timer_pool_param_init(&timer_pool_param);
	timer_pool_param.res_ns     = res_ns;
	timer_pool_param.min_tmo    = period_ns / 2;
	timer_pool_param.max_tmo    = 2 * period_ns;
	timer_pool_param.num_timers = 2 * num_cpu; /* extra for stop events */
	timer_pool_param.clk_src    = ODP_CLOCK_DEFAULT;

	tp = odp_timer_pool_create("Stress timers", &timer_pool_param);
	global->timer_pool = tp;
	if (tp == ODP_TIMER_POOL_INVALID) {
		ODPH_ERR("Timer pool create failed\n");
		return -1;
	}

	if (odp_timer_pool_start_multi(&tp, 1) != 1) {
		ODPH_ERR("Timer pool start failed\n");
		return -1;
	}

	global->period_ticks = odp_timer_ns_to_tick(tp, period_ns);

	return 0;
}

static int create_queues(test_global_t *global)
{
	odp_schedule_capability_t sched_capa;
	odp_thrmask_t thrmask;
	odp_queue_param_t queue_param;
	uint32_t i;
	test_options_t *test_options = &global->test_options;
	uint32_t num_cpu = test_options->num_cpu;

	if (odp_schedule_capability(&sched_capa)) {
		ODPH_ERR("Schedule capability failed\n");
		return -1;
	}

	if (test_options->group_mode) {
		if ((sched_capa.max_groups - 1) < num_cpu) {
			ODPH_ERR("Too many workers. Not enough schedule groups.\n");
			return -1;
		}

		odp_thrmask_zero(&thrmask);

		/* A group per worker thread */
		for (i = 0; i < num_cpu; i++) {
			global->group[i] = odp_schedule_group_create(NULL, &thrmask);

			if (global->group[i] == ODP_SCHED_GROUP_INVALID) {
				ODPH_ERR("Schedule group create failed (%u)\n", i);
				return -1;
			}
		}
	}

	odp_queue_param_init(&queue_param);
	queue_param.type = ODP_QUEUE_TYPE_SCHED;
	queue_param.sched.sync = ODP_SCHED_SYNC_PARALLEL;
	queue_param.sched.group = ODP_SCHED_GROUP_ALL;

	for (i = 0; i < num_cpu; i++) {
		if (test_options->group_mode)
			queue_param.sched.group = global->group[i];

		global->tmo_queue[i] = odp_queue_create(NULL, &queue_param);

		if (global->tmo_queue[i] == ODP_QUEUE_INVALID) {
			ODPH_ERR("Timeout dest queue create failed (%u)\n", i);
			return -1;
		}
	}

	return 0;
}

static int start_timers(test_global_t *global)
{
	odp_timer_start_t start_param;
	uint32_t i;
	test_options_t *test_options = &global->test_options;
	uint32_t num_cpu = test_options->num_cpu;
	odp_timeout_t tmo[num_cpu];
	odp_timer_t timer[num_cpu];

	for (i = 0; i < num_cpu; i++) {
		tmo[i] = odp_timeout_alloc(global->tmo_pool);

		if (tmo[i] == ODP_TIMEOUT_INVALID) {
			ODPH_ERR("Timeout alloc failed (%u)\n", i);
			return -1;
		}
	}

	for (i = 0; i < num_cpu; i++) {
		timer[i] = odp_timer_alloc(global->timer_pool, global->tmo_queue[i], NULL);

		if (timer[i] == ODP_TIMER_INVALID) {
			ODPH_ERR("Timer alloc failed (%u)\n", i);
			return -1;
		}

		global->timer[i] = timer[i];
	}

	start_param.tick_type = ODP_TIMER_TICK_REL;
	start_param.tick = global->period_ticks;

	for (i = 0; i < num_cpu; i++) {
		start_param.tmo_ev = odp_timeout_to_event(tmo[i]);

		if (odp_timer_start(timer[i], &start_param) != ODP_TIMER_SUCCESS) {
			ODPH_ERR("Timer start failed (%u)\n", i);
			return -1;
		}
	}

	return 0;
}

static void destroy_timers(test_global_t *global)
{
	uint32_t i;
	test_options_t *test_options = &global->test_options;
	uint32_t num_cpu = test_options->num_cpu;

	for (i = 0; i < num_cpu; i++) {
		odp_timer_t timer = global->timer[i];

		if (timer == ODP_TIMER_INVALID)
			continue;

		if (odp_timer_free(timer))
			ODPH_ERR("Timer free failed (%u)\n", i);
	}

	if (global->timer_pool != ODP_TIMER_POOL_INVALID)
		odp_timer_pool_destroy(global->timer_pool);

	for (i = 0; i < num_cpu; i++) {
		odp_queue_t queue = global->tmo_queue[i];

		if (queue == ODP_QUEUE_INVALID)
			continue;

		if (odp_queue_destroy(queue))
			ODPH_ERR("Queue destroy failed (%u)\n", i);
	}

	if (test_options->group_mode) {
		for (i = 0; i < num_cpu; i++) {
			odp_schedule_group_t group = global->group[i];

			if (group == ODP_SCHED_GROUP_INVALID)
				continue;

			if (odp_schedule_group_destroy(group))
				ODPH_ERR("Schedule group destroy failed (%u)\n", i);
		}
	}

	if (global->tmo_pool != ODP_POOL_INVALID)
		odp_pool_destroy(global->tmo_pool);
}

static void sig_handler(int signo)
{
	(void)signo;

	if (test_global == NULL)
		return;

	odp_atomic_add_u32(&test_global->exit_test, 1);
}

static void stop_workers(test_global_t *global)
{
	uint32_t i;
	odp_timeout_t tmo;
	odp_event_t ev;
	odp_queue_t queue;
	test_options_t *test_options = &global->test_options;
	uint32_t num_cpu = test_options->num_cpu;

	odp_atomic_add_u32(&test_global->exit_test, 1);

	for (i = 0; i < num_cpu; i++) {
		queue = global->tmo_queue[i];
		if (queue == ODP_QUEUE_INVALID)
			continue;

		tmo = odp_timeout_alloc(global->tmo_pool);

		if (tmo == ODP_TIMEOUT_INVALID)
			continue;

		ev = odp_timeout_to_event(tmo);
		if (odp_queue_enq(queue, ev)) {
			ODPH_ERR("Enqueue failed %u\n", i);
			odp_event_free(ev);
		}
	}
}

static void sum_stat(test_global_t *global)
{
	uint32_t i;
	test_options_t *test_options = &global->test_options;
	uint32_t num_cpu = test_options->num_cpu;
	test_stat_sum_t *sum = &global->stat_sum;

	memset(sum, 0, sizeof(test_stat_sum_t));

	for (i = 1; i < num_cpu + 1 ; i++) {
		sum->rounds    += global->stat[i].rounds;
		sum->tot_nsec  += global->stat[i].tot_nsec;
		sum->work_nsec += global->stat[i].work_nsec;
	}
}

static void print_stat(test_global_t *global)
{
	uint32_t i;
	test_options_t *test_options = &global->test_options;
	uint32_t num_cpu = test_options->num_cpu;
	int mode = test_options->mode;
	test_stat_sum_t *sum = &global->stat_sum;
	double sec_ave, work_ave, perc;
	double round_ave = 0.0;
	double rate_ave = 0.0;
	double rate_tot = 0.0;
	double cpu_load = 0.0;
	const double mega = 1000000.0;
	const double giga = 1000000000.0;
	uint32_t num = 0;

	if (num_cpu == 0)
		return;

	sec_ave  = (sum->tot_nsec / giga) / num_cpu;
	work_ave = (sum->work_nsec / giga) / num_cpu;

	printf("\n");
	printf("CPU load from work (percent) per thread:\n");
	printf("----------------------------------------------\n");
	printf("        1      2      3      4      5      6      7      8      9     10");

	for (i = 1; i < num_cpu + 1; i++) {
		if (global->stat[i].tot_nsec == 0)
			continue;

		if ((num % 10) == 0)
			printf("\n   ");

		perc = 100.0 * ((double)global->stat[i].work_nsec) / global->stat[i].tot_nsec;

		printf("%6.2f ", perc);
		num++;
	}

	if (sec_ave > 0.0) {
		round_ave = (double)sum->rounds / num_cpu;
		cpu_load  = 100.0 * (work_ave / sec_ave);

		if (mode) {
			uint64_t data_bytes;

			if (mode == MODE_MEMCPY || mode == MODE_COPY_U32 ||
			    mode == (MODE_COPY_U32 | MODE_MEMCPY))
				data_bytes = sum->rounds * test_options->mem_size / 2;
			else
				data_bytes = sum->rounds * test_options->mem_size;

			rate_ave = data_bytes / (sum->work_nsec / giga);
			rate_tot = rate_ave * num_cpu;
		}
	}

	printf("\n\n");
	printf("TOTAL (%i workers)\n", num_cpu);
	printf("  ave time:           %.2f sec\n", sec_ave);
	printf("  ave work:           %.2f sec\n", work_ave);
	printf("  ave CPU load:       %.2f\n", cpu_load);
	printf("  ave rounds per sec: %.2f\n", round_ave / sec_ave);
	printf("  ave data rate:      %.2f MB/sec\n", rate_ave / mega);
	printf("  total data rate:    %.2f MB/sec\n", rate_tot / mega);
	printf("\n");
}

int main(int argc, char **argv)
{
	odph_helper_options_t helper_options;
	odp_instance_t instance;
	odp_init_t init;
	odp_shm_t shm, shm_global;
	odp_schedule_config_t sched_config;
	test_global_t *global;
	test_options_t *test_options;
	int i, mode;
	uint32_t num_cpu;
	uint64_t mem_size;
	odp_shm_t shm_work = ODP_SHM_INVALID;

	signal(SIGINT, sig_handler);

	/* Let helper collect its own arguments (e.g. --odph_proc) */
	argc = odph_parse_options(argc, argv);
	if (odph_options(&helper_options)) {
		ODPH_ERR("Reading ODP helper options failed.\n");
		exit(EXIT_FAILURE);
	}

	odp_init_param_init(&init);
	init.mem_model = helper_options.mem_model;

	if (odp_init_global(&instance, &init, NULL)) {
		ODPH_ERR("Global init failed.\n");
		exit(EXIT_FAILURE);
	}

	if (odp_init_local(instance, ODP_THREAD_CONTROL)) {
		ODPH_ERR("Local init failed.\n");
		exit(EXIT_FAILURE);
	}

	shm = odp_shm_reserve("Stress global", sizeof(test_global_t), ODP_CACHE_LINE_SIZE, 0);
	shm_global = shm;
	if (shm == ODP_SHM_INVALID) {
		ODPH_ERR("SHM reserve failed.\n");
		exit(EXIT_FAILURE);
	}

	global = odp_shm_addr(shm);
	if (global == NULL) {
		ODPH_ERR("SHM addr failed\n");
		exit(EXIT_FAILURE);
	}
	test_global = global;

	memset(global, 0, sizeof(test_global_t));
	odp_atomic_init_u32(&global->exit_test, 0);
	odp_atomic_init_u64(&global->tot_rounds, 0);

	global->timer_pool = ODP_TIMER_POOL_INVALID;
	global->tmo_pool   = ODP_POOL_INVALID;

	for (i = 0; i < ODP_THREAD_COUNT_MAX; i++) {
		global->timer[i] = ODP_TIMER_INVALID;
		global->tmo_queue[i] = ODP_QUEUE_INVALID;
		global->group[i] = ODP_SCHED_GROUP_INVALID;

		global->thread_arg[i].global = global;
		global->thread_arg[i].worker_idx = i;
	}

	if (parse_options(argc, argv, &global->test_options))
		exit(EXIT_FAILURE);

	test_options = &global->test_options;
	mode = test_options->mode;

	odp_sys_info_print();

	odp_schedule_config_init(&sched_config);
	sched_config.sched_group.all     = 1;
	sched_config.sched_group.control = 0;
	sched_config.sched_group.worker  = 0;

	odp_schedule_config(&sched_config);

	if (set_num_cpu(global))
		exit(EXIT_FAILURE);

	num_cpu = test_options->num_cpu;

	/* Memory for workers */
	if (mode) {
		uint64_t num_words;
		uint32_t *word;
		uint32_t num_rand = ODPH_ARRAY_SIZE(pseudo_rand);

		mem_size = test_options->mem_size * num_cpu;

		shm = odp_shm_reserve("Test memory", mem_size, ODP_CACHE_LINE_SIZE, 0);
		shm_work = shm;
		if (shm == ODP_SHM_INVALID) {
			ODPH_ERR("SHM reserve failed.\n");
			exit(EXIT_FAILURE);
		}

		global->worker_mem = odp_shm_addr(shm);
		if (global->worker_mem == NULL) {
			ODPH_ERR("SHM addr failed\n");
			exit(EXIT_FAILURE);
		}

		num_words = mem_size / sizeof(uint32_t);
		word = (uint32_t *)global->worker_mem;

		for (uint64_t j = 0; j < num_words; j++)
			word[j] = pseudo_rand[j % num_rand];

	}

	printf("\n");
	printf("Test parameters\n");
	printf("  num workers         %u\n", num_cpu);
	printf("  mode                0x%x\n", mode);
	printf("  group mode          %i\n", test_options->group_mode);
	printf("  mem size per worker %" PRIu64 " bytes\n", test_options->mem_size);

	if (create_timers(global))
		exit(EXIT_FAILURE);

	if (create_queues(global))
		exit(EXIT_FAILURE);

	/* Start worker threads */
	start_workers(global, instance);

	/* Wait until all workers are ready */
	odp_barrier_wait(&global->barrier);

	if (start_timers(global)) {
		/* Stop all workers, if some timer did not start */
		ODPH_ERR("Timers did not start. Stopping workers.\n");
		stop_workers(global);
	}

	/* Wait workers to exit */
	odph_thread_join(global->thread_tbl, num_cpu);

	sum_stat(global);

	print_stat(global);

	destroy_timers(global);

	if (mode) {
		if (odp_shm_free(shm_work)) {
			ODPH_ERR("SHM free failed.\n");
			exit(EXIT_FAILURE);
		}
	}

	if (odp_shm_free(shm_global)) {
		ODPH_ERR("SHM free failed.\n");
		exit(EXIT_FAILURE);
	}

	if (odp_term_local()) {
		ODPH_ERR("Term local failed.\n");
		exit(EXIT_FAILURE);
	}

	if (odp_term_global(instance)) {
		ODPH_ERR("Term global failed.\n");
		exit(EXIT_FAILURE);
	}

	return 0;
}
