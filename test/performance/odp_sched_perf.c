/* Copyright (c) 2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>
#include <getopt.h>

#include <odp_api.h>
#include <odp/helper/odph_api.h>

#define MAX_QUEUES_PER_CPU  1024
#define MAX_QUEUES          (ODP_THREAD_COUNT_MAX * MAX_QUEUES_PER_CPU)

typedef struct test_options_t {
	uint32_t num_cpu;
	uint32_t num_queue;
	uint32_t num_event;
	uint32_t num_round;
	uint32_t max_burst;
	int      queue_type;
	uint32_t tot_queue;
	uint32_t tot_event;

} test_options_t;

typedef struct test_stat_t {
	uint64_t rounds;
	uint64_t enqueues;
	uint64_t events;
	uint64_t nsec;
	uint64_t cycles;

} test_stat_t;

typedef struct test_global_t {
	test_options_t test_options;

	odp_barrier_t barrier;
	odp_pool_t pool;
	odp_cpumask_t cpumask;
	odp_queue_t queue[MAX_QUEUES];
	odph_odpthread_t thread_tbl[ODP_THREAD_COUNT_MAX];
	test_stat_t stat[ODP_THREAD_COUNT_MAX];

} test_global_t;

test_global_t test_global;

static void print_usage(void)
{
	printf("\n"
	       "Scheduler performance test\n"
	       "\n"
	       "Usage: odp_sched_perf [options]\n"
	       "\n"
	       "  -c, --num_cpu          Number of CPUs (worker threads). 0: all available CPUs. Default: 1.\n"
	       "  -q, --num_queue        Number of queues per CPU. Default: 1.\n"
	       "  -e, --num_event        Number of events per queue\n"
	       "  -r, --num_round        Number of rounds\n"
	       "  -b, --burst            Maximum number of events per operation\n"
	       "  -t, --type             Queue type. 0: parallel, 1: atomic, 2: ordered. Default: 0.\n"
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
		{"num_queue", required_argument, NULL, 'q'},
		{"num_event", required_argument, NULL, 'e'},
		{"num_round", required_argument, NULL, 'r'},
		{"burst",     required_argument, NULL, 'b'},
		{"type",      required_argument, NULL, 't'},
		{"help",      no_argument,       NULL, 'h'},
		{NULL, 0, NULL, 0}
	};

	static const char *shortopts = "+c:q:e:r:b:t:h";

	test_options->num_cpu    = 1;
	test_options->num_queue  = 1;
	test_options->num_event  = 100;
	test_options->num_round  = 100000;
	test_options->max_burst  = 100;
	test_options->queue_type = 0;

	while (1) {
		opt = getopt_long(argc, argv, shortopts, longopts, &long_index);

		if (opt == -1)
			break;

		switch (opt) {
		case 'c':
			test_options->num_cpu = atoi(optarg);
			break;
		case 'q':
			test_options->num_queue = atoi(optarg);
			break;
		case 'e':
			test_options->num_event = atoi(optarg);
			break;
		case 'r':
			test_options->num_round = atoi(optarg);
			break;
		case 'b':
			test_options->max_burst = atoi(optarg);
			break;
		case 't':
			test_options->queue_type = atoi(optarg);
			break;
		case 'h':
			/* fall through */
		default:
			print_usage();
			ret = -1;
			break;
		}
	}

	if (test_options->num_queue > MAX_QUEUES_PER_CPU) {
		printf("Error: Too many queues per worker. Max supported %i\n.",
		       MAX_QUEUES_PER_CPU);
		ret = -1;
	}

	test_options->tot_queue = test_options->num_queue *
				  test_options->num_cpu;
	test_options->tot_event = test_options->tot_queue *
				  test_options->num_event;

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

	odp_barrier_init(&global->barrier, num_cpu);

	return 0;
}

static int create_pool(test_global_t *global)
{
	odp_pool_capability_t pool_capa;
	odp_pool_param_t pool_param;
	odp_pool_t pool;
	test_options_t *test_options = &global->test_options;
	uint32_t num_cpu   = test_options->num_cpu;
	uint32_t num_queue = test_options->num_queue;
	uint32_t num_event = test_options->num_event;
	uint32_t num_round = test_options->num_round;
	uint32_t max_burst = test_options->max_burst;
	uint32_t tot_queue = test_options->tot_queue;
	uint32_t tot_event = test_options->tot_event;

	printf("\nScheduler performance test\n");
	printf("  num cpu          %u\n", num_cpu);
	printf("  queues per cpu   %u\n", num_queue);
	printf("  events per queue %u\n", num_event);
	printf("  max burst size   %u\n", max_burst);
	printf("  num queues       %u\n", tot_queue);
	printf("  num events       %u\n", tot_event);
	printf("  num rounds       %u\n", num_round);

	if (odp_pool_capability(&pool_capa)) {
		printf("Error: Pool capa failed.\n");
		return -1;
	}

	if (tot_event > pool_capa.buf.max_num) {
		printf("Max events supported %u\n", pool_capa.buf.max_num);
		return -1;
	}

	odp_pool_param_init(&pool_param);
	pool_param.type = ODP_POOL_BUFFER;
	pool_param.buf.num = tot_event;

	pool = odp_pool_create("sched perf", &pool_param);

	if (pool == ODP_POOL_INVALID) {
		printf("Error: Pool create failed.\n");
		return -1;
	}

	global->pool = pool;

	return 0;
}

static int create_queues(test_global_t *global)
{
	odp_queue_capability_t queue_capa;
	odp_queue_param_t queue_param;
	odp_queue_t queue;
	odp_buffer_t buf;
	odp_schedule_sync_t sync;
	const char *type_str;
	uint32_t i, j;
	test_options_t *test_options = &global->test_options;
	uint32_t num_event = test_options->num_event;
	uint32_t tot_queue = test_options->tot_queue;
	int type = test_options->queue_type;
	odp_pool_t pool = global->pool;

	if (type == 0) {
		type_str = "parallel";
		sync = ODP_SCHED_SYNC_PARALLEL;
	} else if (type == 1) {
		type_str = "atomic";
		sync = ODP_SCHED_SYNC_ATOMIC;
	} else {
		type_str = "ordered";
		sync = ODP_SCHED_SYNC_ORDERED;
	}

	printf("  queue type       %s\n\n", type_str);

	if (odp_queue_capability(&queue_capa)) {
		printf("Error: Queue capa failed.\n");
		return -1;
	}

	if (tot_queue > queue_capa.sched.max_num) {
		printf("Max queues supported %u\n", queue_capa.sched.max_num);
		return -1;
	}

	if (queue_capa.sched.max_size &&
	    num_event > queue_capa.sched.max_size) {
		printf("Max events per queue %u\n", queue_capa.sched.max_size);
		return -1;
	}

	odp_queue_param_init(&queue_param);
	queue_param.type = ODP_QUEUE_TYPE_SCHED;
	queue_param.sched.prio  = ODP_SCHED_PRIO_DEFAULT;
	queue_param.sched.sync  = sync;
	queue_param.sched.group = ODP_SCHED_GROUP_ALL;
	queue_param.size = num_event;

	for (i = 0; i < tot_queue; i++) {
		queue = odp_queue_create(NULL, &queue_param);

		global->queue[i] = queue;

		if (queue == ODP_QUEUE_INVALID) {
			printf("Error: Queue create failed %u\n", i);
			return -1;
		}
	}

	for (i = 0; i < tot_queue; i++) {
		queue = global->queue[i];

		for (j = 0; j < num_event; j++) {
			buf = odp_buffer_alloc(pool);

			if (buf == ODP_BUFFER_INVALID) {
				printf("Error: Alloc failed %u/%u\n", i, j);
				return -1;
			}

			if (odp_queue_enq(queue, odp_buffer_to_event(buf))) {
				printf("Error: Enqueue failed %u/%u\n", i, j);
				return -1;
			}
		}
	}

	return 0;
}

static int destroy_queues(test_global_t *global)
{
	uint32_t i;
	odp_event_t ev;
	uint64_t wait;
	test_options_t *test_options = &global->test_options;
	uint32_t tot_queue = test_options->tot_queue;

	wait = odp_schedule_wait_time(200 * ODP_TIME_MSEC_IN_NS);

	while ((ev = odp_schedule(NULL, wait)) != ODP_EVENT_INVALID)
		odp_event_free(ev);

	for (i = 0; i < tot_queue; i++) {
		if (global->queue[i] != ODP_QUEUE_INVALID) {
			if (odp_queue_destroy(global->queue[i])) {
				printf("Error: Queue destroy failed %u\n", i);
				return -1;
			}
		}
	}

	return 0;
}

static int test_sched(void *arg)
{
	int num, num_enq, ret, thr;
	uint32_t i, rounds;
	uint64_t c1, c2, cycles, nsec;
	uint64_t events, enqueues;
	odp_time_t t1, t2;
	odp_queue_t queue;
	test_global_t *global = arg;
	test_options_t *test_options = &global->test_options;
	uint32_t num_round = test_options->num_round;
	uint32_t max_burst = test_options->max_burst;
	odp_event_t ev[max_burst];

	thr = odp_thread_id();

	for (i = 0; i < max_burst; i++)
		ev[i] = ODP_EVENT_INVALID;

	enqueues = 0;
	events = 0;
	ret = 0;

	/* Start all workers at the same time */
	odp_barrier_wait(&global->barrier);

	t1 = odp_time_local();
	c1 = odp_cpu_cycles();

	for (rounds = 0; rounds < num_round; rounds++) {
		num = odp_schedule_multi(&queue, ODP_SCHED_NO_WAIT,
					 ev, max_burst);

		if (odp_likely(num > 0)) {
			events += num;
			i = 0;

			while (num) {
				num_enq = odp_queue_enq_multi(queue, &ev[i],
							      num);

				if (num_enq < 0) {
					printf("Error: Enqueue failed. Round %u\n",
					       rounds);
					ret = -1;
					break;
				}

				num -= num_enq;
				i   += num_enq;
				enqueues++;
			}

			if (odp_unlikely(ret))
				break;

			continue;
		}

		/* <0 not specified as an error but checking anyway */
		if (num < 0) {
			printf("Error: Sched failed. Round %u\n", rounds);
			ret = -1;
			break;
		}
	}

	c2 = odp_cpu_cycles();
	t2 = odp_time_local();

	nsec   = odp_time_diff_ns(t2, t1);
	cycles = odp_cpu_cycles_diff(c2, c1);

	/* Update stats*/
	global->stat[thr].rounds   = rounds;
	global->stat[thr].enqueues = enqueues;
	global->stat[thr].events   = events;
	global->stat[thr].nsec     = nsec;
	global->stat[thr].cycles   = cycles;

	/* Pause scheduling before thread exit */
	odp_schedule_pause();

	while (1) {
		ev[0] = odp_schedule(&queue, ODP_SCHED_NO_WAIT);

		if (ev[0] == ODP_EVENT_INVALID)
			break;

		odp_queue_enq(queue, ev[0]);
	}

	return ret;
}

static int start_workers(test_global_t *global, odp_instance_t instance)
{
	odph_odpthread_params_t thr_params;
	test_options_t *test_options = &global->test_options;
	int num_cpu = test_options->num_cpu;

	memset(&thr_params, 0, sizeof(thr_params));
	thr_params.thr_type = ODP_THREAD_WORKER;
	thr_params.instance = instance;
	thr_params.start    = test_sched;
	thr_params.arg      = global;

	if (odph_odpthreads_create(global->thread_tbl, &global->cpumask,
				   &thr_params) != num_cpu)
		return -1;

	return 0;
}

static void print_stat(test_global_t *global)
{
	int i, num;
	double rounds_ave, enqueues_ave, events_ave, nsec_ave, cycles_ave;
	test_options_t *test_options = &global->test_options;
	int num_cpu = test_options->num_cpu;
	uint64_t rounds_sum = 0;
	uint64_t enqueues_sum = 0;
	uint64_t events_sum = 0;
	uint64_t nsec_sum = 0;
	uint64_t cycles_sum = 0;

	/* Averages */
	for (i = 0; i < ODP_THREAD_COUNT_MAX; i++) {
		rounds_sum   += global->stat[i].rounds;
		enqueues_sum += global->stat[i].enqueues;
		events_sum   += global->stat[i].events;
		nsec_sum     += global->stat[i].nsec;
		cycles_sum   += global->stat[i].cycles;
	}

	if (rounds_sum == 0) {
		printf("No results.\n");
		return;
	}

	rounds_ave   = rounds_sum / num_cpu;
	enqueues_ave = enqueues_sum / num_cpu;
	events_ave   = events_sum / num_cpu;
	nsec_ave     = nsec_sum / num_cpu;
	cycles_ave   = cycles_sum / num_cpu;
	num = 0;

	printf("RESULTS - per thread (Million events per sec):\n");
	printf("----------------------------------------------\n");
	printf("        1      2      3      4      5      6      7      8      9     10");

	for (i = 0; i < ODP_THREAD_COUNT_MAX; i++) {
		if (global->stat[i].rounds) {
			if ((num % 10) == 0)
				printf("\n   ");

			printf("%6.1f ", (1000.0 * global->stat[i].events) /
			       global->stat[i].nsec);
			num++;
		}
	}
	printf("\n\n");

	printf("RESULTS - average over %i threads:\n", num_cpu);
	printf("----------------------------------\n");
	printf("  schedule calls:           %.3f\n", rounds_ave);
	printf("  enqueue calls:            %.3f\n", enqueues_ave);
	printf("  duration:                 %.3f msec\n", nsec_ave / 1000000);
	printf("  num cycles:               %.3f M\n", cycles_ave / 1000000);
	printf("  cycles per round:         %.3f\n",
	       cycles_ave / rounds_ave);
	printf("  cycles per event:         %.3f\n",
	       cycles_ave / events_ave);
	printf("  ave events received:      %.3f\n",
	       events_ave / rounds_ave);
	printf("  rounds per sec:           %.3f M\n",
	       (1000.0 * rounds_ave) / nsec_ave);
	printf("  events per sec:           %.3f M\n\n",
	       (1000.0 * events_ave) / nsec_ave);
}

int main(int argc, char **argv)
{
	odp_instance_t instance;
	odp_init_t init;
	test_global_t *global;

	global = &test_global;
	memset(global, 0, sizeof(test_global_t));
	global->pool = ODP_POOL_INVALID;

	if (parse_options(argc, argv, &global->test_options))
		return -1;

	/* List features not to be used */
	odp_init_param_init(&init);
	init.not_used.feat.cls      = 1;
	init.not_used.feat.crypto   = 1;
	init.not_used.feat.ipsec    = 1;
	init.not_used.feat.timer    = 1;
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

	if (set_num_cpu(global))
		return -1;

	if (create_pool(global))
		return -1;

	if (create_queues(global))
		return -1;

	/* Start workers */
	start_workers(global, instance);

	/* Wait workers to exit */
	odph_odpthreads_join(global->thread_tbl);

	if (destroy_queues(global))
		return -1;

	print_stat(global);

	if (odp_pool_destroy(global->pool)) {
		printf("Error: Pool destroy failed.\n");
		return -1;
	}

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
