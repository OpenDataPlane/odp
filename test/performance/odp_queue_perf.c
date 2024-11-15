/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2018 Linaro Limited
 * Copyright (c) 2021-2024 Nokia
 */

/**
 * @example odp_queue_perf.c
 *
 * Performance test application for plain queues
 *
 * @cond _ODP_HIDE_FROM_DOXYGEN_
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>
#include <getopt.h>

#include <odp_api.h>
#include <odp/helper/odph_api.h>

#include <export_results.h>

#define MAX_QUEUES (32 * 1024)

typedef enum {
	TEST_MODE_LOOP = 0,
	TEST_MODE_PAIR,
} test_mode_t;

typedef struct test_options_t {
	uint32_t num_queue;
	uint32_t num_event;
	uint32_t num_round;
	uint32_t max_burst;
	uint32_t num_cpu;
	odp_nonblocking_t nonblock;
	test_mode_t mode;
	odp_bool_t private_queues;
	odp_bool_t single;

} test_options_t;

typedef struct test_stat_t {
	uint64_t rounds;
	uint64_t events;
	uint64_t nsec;
	uint64_t cycles;
	uint64_t deq_retry;
	uint64_t enq_retry;

} test_stat_t;

typedef struct test_global_t test_global_t;

typedef struct {
	test_global_t  *global;
	odp_barrier_t  *barrier;
	test_options_t *options;
	test_stat_t     stats;
	uint32_t        src_queue_id[MAX_QUEUES];
	uint32_t        dst_queue_id[MAX_QUEUES];
	uint32_t        num_queues;
} thread_args_t;

typedef struct test_global_t {
	odp_barrier_t    barrier;
	test_options_t   options;
	odp_instance_t   instance;
	odp_shm_t        shm;
	odp_pool_t       pool;
	odp_atomic_u32_t workers_finished;
	odp_queue_t      queue[MAX_QUEUES];
	odph_thread_t    thread_tbl[ODP_THREAD_COUNT_MAX];
	thread_args_t    thread_args[ODP_THREAD_COUNT_MAX];
	test_common_options_t common_options;

} test_global_t;

static void print_usage(void)
{
	printf("\n"
	       "Plain queue performance test\n"
	       "\n"
	       "Usage: odp_queue_perf [options]\n"
	       "\n"
	       "  -m, --mode <arg>       Test mode:\n"
	       "                         0: Loop: events are enqueued back to the same queue they\n"
	       "                            were dequeued from (default)\n"
	       "                         1: Pair: queues are paired and events are always moved\n"
	       "                            between the queues when doing dequeue/enqueue. Requires\n"
	       "                            an even number of both queues and workers.\n"
	       "  -c, --num_cpu          Number of worker threads (default 1)\n"
	       "  -q, --num_queue        Number of queues (default 1)\n"
	       "  -e, --num_event        Number of events per queue (default 1)\n"
	       "  -b, --burst_size       Maximum number of events per operation (default 1)\n"
	       "  -p, --private          Use separate queues for each worker\n"
	       "  -r, --num_round        Number of rounds\n"
	       "  -l, --lockfree         Lock-free queues\n"
	       "  -w, --waitfree         Wait-free queues\n"
	       "  -s, --single           Single producer/consumer queues\n"
	       "  -h, --help             This help\n"
	       "\n");
}

static int parse_options(int argc, char *argv[], test_options_t *test_options)
{
	int opt, long_index, num_cpu;
	int ret = 0;

	static const struct option longopts[] = {
		{"num_cpu",    required_argument, NULL, 'c'},
		{"num_queue",  required_argument, NULL, 'q'},
		{"num_event",  required_argument, NULL, 'e'},
		{"burst_size", required_argument, NULL, 'b'},
		{"mode",       required_argument, NULL, 'm'},
		{"private",    no_argument,       NULL, 'p'},
		{"num_round",  required_argument, NULL, 'r'},
		{"lockfree",   no_argument,       NULL, 'l'},
		{"waitfree",   no_argument,       NULL, 'w'},
		{"single",     no_argument,       NULL, 's'},
		{"help",       no_argument,       NULL, 'h'},
		{NULL, 0, NULL, 0}
	};

	static const char *shortopts = "+c:q:e:b:m:pr:lwsh";

	test_options->num_cpu   = 1;
	test_options->num_queue = 1;
	test_options->num_event = 1;
	test_options->max_burst = 1;
	test_options->mode      = TEST_MODE_LOOP;
	test_options->num_round = 1000;
	test_options->nonblock  = ODP_BLOCKING;
	test_options->single    = false;
	test_options->private_queues = false;

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
		case 'b':
			test_options->max_burst = atoi(optarg);
			break;
		case 'm':
			if (atoi(optarg) == TEST_MODE_PAIR)
				test_options->mode = TEST_MODE_PAIR;
			break;
		case 'r':
			test_options->num_round = atoi(optarg);
			break;
		case 'l':
			test_options->nonblock = ODP_NONBLOCKING_LF;
			break;
		case 'w':
			test_options->nonblock = ODP_NONBLOCKING_WF;
			break;
		case 'p':
			test_options->private_queues = true;
			break;
		case 's':
			test_options->single = true;
			break;
		case 'h':
			/* fall through */
		default:
			print_usage();
			ret = -1;
			break;
		}
	}

	if (test_options->num_queue > MAX_QUEUES || test_options->num_queue == 0) {
		ODPH_ERR("Invalid number of queues %u. Test maximum %u.\n",
			 test_options->num_queue, MAX_QUEUES);
		return -1;
	}

	num_cpu = test_options->num_cpu;
	if (num_cpu == 0)
		num_cpu = odp_cpumask_default_worker(NULL, 0);

	if (test_options->private_queues) {
		if ((int)test_options->num_queue < num_cpu) {
			ODPH_ERR("Not enough queues for %d workers.\n", num_cpu);
			return -1;
		}
		if (test_options->num_queue % num_cpu)
			ODPH_ERR("Warn: %" PRIu32 " queues shared unevenly amongst %" PRIu32 " "
				 "workers.\n", test_options->num_queue, num_cpu);
	}

	if (test_options->single && !test_options->private_queues) {
		if ((test_options->mode == TEST_MODE_LOOP && num_cpu != 1) ||
		    (test_options->mode == TEST_MODE_PAIR && num_cpu != 2)) {
			ODPH_ERR("Multiple producers/consumers not allowed with single prod/cons queues.\n");
			return -1;
		}
	}

	if (test_options->mode == TEST_MODE_PAIR && (test_options->num_queue % 2 || num_cpu % 2)) {
		ODPH_ERR("Pair mode requires an even number of queues and workers.\n");
		return -1;
	}

	return ret;
}

static int create_queues(test_global_t *global)
{
	odp_pool_capability_t pool_capa;
	odp_queue_capability_t queue_capa;
	odp_pool_param_t pool_param;
	odp_queue_param_t queue_param;
	odp_pool_t pool;
	uint32_t i, j, max_size, max_num;
	test_options_t *test_options = &global->options;
	odp_nonblocking_t nonblock = test_options->nonblock;
	uint32_t num_queue = test_options->num_queue;
	uint32_t num_event = test_options->num_event;
	uint32_t num_round = test_options->num_round;
	uint32_t tot_event = num_queue * num_event;
	uint32_t queue_size = test_options->mode == TEST_MODE_PAIR ? 2 * num_event : num_event;
	int ret = 0;
	odp_queue_t *queue = global->queue;
	odp_event_t event[tot_event];

	printf("\nTesting %s queues\n",
	       nonblock == ODP_BLOCKING ? "NORMAL" :
	       (nonblock == ODP_NONBLOCKING_LF ? "LOCKFREE" :
	       (nonblock == ODP_NONBLOCKING_WF ? "WAITFREE" : "???")));
	printf("  mode                 %s\n", test_options->mode == TEST_MODE_LOOP ?
						"loop" : "pair");
	printf("  private queues       %s\n", test_options->private_queues ? "yes" : "no");
	printf("  single prod/cons     %s\n", test_options->single ? "yes" : "no");
	printf("  num rounds           %u\n", num_round);
	printf("  num queues           %u\n", num_queue);
	printf("  num events per queue %u\n", num_event);
	printf("  queue size           %u\n", queue_size);
	printf("  max burst size       %u\n", test_options->max_burst);

	for (i = 0; i < num_queue; i++)
		queue[i] = ODP_QUEUE_INVALID;

	for (i = 0; i < tot_event; i++)
		event[i] = ODP_EVENT_INVALID;

	if (odp_queue_capability(&queue_capa)) {
		ODPH_ERR("Queue capa failed.\n");
		return -1;
	}

	if (odp_pool_capability(&pool_capa)) {
		ODPH_ERR("Pool capa failed.\n");
		return -1;
	}

	if (nonblock == ODP_BLOCKING) {
		if (num_queue > queue_capa.plain.max_num) {
			ODPH_ERR("Max queues supported %u.\n", queue_capa.plain.max_num);
			return -1;
		}

		max_size = queue_capa.plain.max_size;
		if (max_size && queue_size > max_size) {
			ODPH_ERR("Max queue size supported %u.\n", max_size);
			return -1;
		}
	} else if (nonblock == ODP_NONBLOCKING_LF) {
		if (queue_capa.plain.lockfree.max_num == 0) {
			ODPH_ERR("Lockfree queues not supported.\n");
			return -1;
		}

		if (num_queue > queue_capa.plain.lockfree.max_num) {
			ODPH_ERR("Max lockfree queues supported %u.\n",
				 queue_capa.plain.lockfree.max_num);
			return -1;
		}

		max_size = queue_capa.plain.lockfree.max_size;
		if (max_size && queue_size > max_size) {
			ODPH_ERR("Max lockfree queue size supported %u.\n", max_size);
			return -1;
		}
	} else if (nonblock == ODP_NONBLOCKING_WF) {
		if (queue_capa.plain.waitfree.max_num == 0) {
			ODPH_ERR("Waitfree queues not supported.\n");
			return -1;
		}

		if (num_queue > queue_capa.plain.waitfree.max_num) {
			ODPH_ERR("Max waitfree queues supported %u.\n",
				 queue_capa.plain.waitfree.max_num);
			return -1;
		}

		max_size = queue_capa.plain.waitfree.max_size;
		if (max_size && queue_size > max_size) {
			ODPH_ERR("Max waitfree queue size supported %u.\n", max_size);
			return -1;
		}
	} else {
		ODPH_ERR("Bad queue blocking type.\n");
		return -1;
	}

	max_num = pool_capa.buf.max_num;

	if (max_num && tot_event > max_num) {
		ODPH_ERR("Max events supported %u.\n", max_num);
		return -1;
	}

	odp_pool_param_init(&pool_param);
	pool_param.type = ODP_POOL_BUFFER;
	pool_param.buf.num = tot_event;

	pool = odp_pool_create("queue perf pool", &pool_param);

	if (pool == ODP_POOL_INVALID) {
		ODPH_ERR("Pool create failed.\n");
		return -1;
	}

	global->pool = pool;

	odp_queue_param_init(&queue_param);
	queue_param.type        = ODP_QUEUE_TYPE_PLAIN;
	queue_param.nonblocking = nonblock;
	queue_param.size        = queue_size;

	if (test_options->single) {
		queue_param.enq_mode = ODP_QUEUE_OP_MT_UNSAFE;
		queue_param.deq_mode = ODP_QUEUE_OP_MT_UNSAFE;
	}

	for (i = 0; i < num_queue; i++) {
		queue[i] = odp_queue_create(NULL, &queue_param);

		if (queue[i] == ODP_QUEUE_INVALID) {
			ODPH_ERR("Queue create failed %u.\n", i);
			return -1;
		}
	}

	for (i = 0; i < tot_event; i++) {
		event[i] = odp_buffer_to_event(odp_buffer_alloc(pool));

		if (event[i] == ODP_EVENT_INVALID) {
			ODPH_ERR("Event alloc failed %u.\n", i);
			ret = -1;
			goto free_events;
		}
	}

	for (i = 0; i < num_queue; i++) {
		for (j = 0; j < num_event; j++) {
			uint32_t id = i * num_event + j;

			if (odp_queue_enq(queue[i], event[id])) {
				ODPH_ERR("Queue enq failed %u/%u.\n", i, j);
				ret = -1;
				goto free_events;
			}

			event[id] = ODP_EVENT_INVALID;
		}
	}

free_events:
	/* Free events that were not stored into queues */
	for (i = 0; i < tot_event; i++) {
		if (event[i] != ODP_EVENT_INVALID)
			odp_event_free(event[i]);
	}

	if (ret)
		ODPH_ERR("Initializing test queues failed.\n");

	return ret;
}

static int destroy_queues(test_global_t *global)
{
	odp_event_t ev;
	uint32_t i, j;
	int ret = 0;
	test_options_t *test_options = &global->options;
	uint32_t num_queue = test_options->num_queue;
	uint32_t num_event = test_options->num_event;
	odp_queue_t *queue = global->queue;
	odp_pool_t pool    = global->pool;

	for (i = 0; i < num_queue; i++) {
		if (queue[i] == ODP_QUEUE_INVALID)
			break;

		for (j = 0; j < num_event; j++) {
			ev = odp_queue_deq(queue[i]);

			if (ev != ODP_EVENT_INVALID)
				odp_event_free(ev);
		}

		if (odp_queue_destroy(queue[i])) {
			ODPH_ERR("Queue destroy failed %u.\n", i);
			ret = -1;
			break;
		}
	}

	if (pool != ODP_POOL_INVALID && odp_pool_destroy(pool)) {
		ODPH_ERR("Pool destroy failed.\n");
		ret = -1;
	}

	return ret;
}

static int run_test(void *arg)
{
	uint64_t c1, c2, cycles, nsec;
	odp_time_t t1, t2;
	uint32_t rounds;
	int num_ev;
	thread_args_t *thr_args = arg;
	test_global_t *global = thr_args->global;
	test_stat_t *stat = &thr_args->stats;
	odp_queue_t src_queue, dst_queue;
	uint64_t num_deq_retry = 0;
	uint64_t num_enq_retry = 0;
	uint64_t events = 0;
	const uint32_t num_queue = thr_args->num_queues;
	const uint32_t num_round = thr_args->options->num_round;
	const uint32_t num_workers = thr_args->options->num_cpu;
	const uint32_t max_burst = thr_args->options->max_burst;
	uint32_t queue_idx = 0;
	odp_event_t ev[max_burst];
	odp_queue_t src_queue_tbl[MAX_QUEUES];
	odp_queue_t dst_queue_tbl[MAX_QUEUES];

	for (uint32_t i = 0; i < num_queue; i++) {
		src_queue_tbl[i] = global->queue[thr_args->src_queue_id[i]];
		dst_queue_tbl[i] = global->queue[thr_args->dst_queue_id[i]];
	}

	/* Start all workers at the same time */
	odp_barrier_wait(thr_args->barrier);

	t1 = odp_time_local_strict();
	c1 = odp_cpu_cycles();

	for (rounds = 0; rounds < num_round; rounds++) {
		int num_enq = 0;

		do {
			src_queue = src_queue_tbl[queue_idx];
			dst_queue = dst_queue_tbl[queue_idx];

			queue_idx++;
			if (queue_idx == num_queue)
				queue_idx = 0;

			num_ev = odp_queue_deq_multi(src_queue, ev, max_burst);

			if (odp_unlikely(num_ev < 0))
				ODPH_ABORT("odp_queue_deq_multi() failed\n");

			if (odp_unlikely(num_ev == 0))
				num_deq_retry++;

		} while (num_ev == 0);

		while (num_enq < num_ev) {
			int num = odp_queue_enq_multi(dst_queue, &ev[num_enq], num_ev - num_enq);

			if (odp_unlikely(num < 0))
				ODPH_ABORT("odp_queue_enq_multi() failed\n");

			num_enq += num;

			if (odp_unlikely(num_enq != num_ev))
				num_enq_retry++;
		}
		events += num_ev;
	}

	c2 = odp_cpu_cycles();
	t2 = odp_time_local_strict();

	odp_atomic_inc_u32(&global->workers_finished);

	/* Keep forwarding events in pair mode until all workers have completed */
	while (thr_args->options->mode == TEST_MODE_PAIR &&
	       odp_atomic_load_u32(&global->workers_finished) < num_workers) {
		int num_enq = 0;

		src_queue = src_queue_tbl[queue_idx];
		dst_queue = dst_queue_tbl[queue_idx];

		queue_idx++;
		if (queue_idx == num_queue)
			queue_idx = 0;

		num_ev = odp_queue_deq_multi(src_queue, ev, max_burst);

		while (num_enq < num_ev) {
			int num = odp_queue_enq_multi(dst_queue, &ev[num_enq], num_ev - num_enq);

			if (odp_unlikely(num < 0))
				ODPH_ABORT("odp_queue_enq_multi() failed\n");

			num_enq += num;
		}
	}

	nsec   = odp_time_diff_ns(t2, t1);
	cycles = odp_cpu_cycles_diff(c2, c1);

	stat->rounds = rounds;
	stat->events = events;
	stat->nsec   = nsec;
	stat->cycles = cycles;
	stat->deq_retry = num_deq_retry;
	stat->enq_retry = num_enq_retry;

	return 0;
}

static void map_queues_to_threads(test_global_t *global)
{
	test_options_t *opt = &global->options;

	if (opt->mode == TEST_MODE_LOOP) {
		if (!opt->private_queues) {
			for (uint32_t i = 0; i < opt->num_queue; i++) {
				for (uint32_t j = 0; j < opt->num_cpu; j++) {
					thread_args_t *thread_args = &global->thread_args[j];

					thread_args->src_queue_id[i] = i;
					thread_args->dst_queue_id[i] = i;
					thread_args->num_queues++;
				}
			}
			return;
		}

		for (uint32_t i = 0; i < opt->num_queue; i++) {
			thread_args_t *thread_args = &global->thread_args[i % opt->num_cpu];
			uint32_t queue_idx = thread_args->num_queues;

			thread_args->src_queue_id[queue_idx] = i;
			thread_args->dst_queue_id[queue_idx] = i;
			thread_args->num_queues++;
		}
		return;
	}
	/* Pair mode. Always an even number of both queues and CPUs. */
	if (!opt->private_queues) {
		for (uint32_t i = 0; i < opt->num_queue; i += 2) {
			for (uint32_t j = 0; j < opt->num_cpu; j++) {
				thread_args_t *thread_args = &global->thread_args[j];
				uint32_t num_queues = thread_args->num_queues;

				if (j % 2 == 0) {
					thread_args->src_queue_id[num_queues] = i;
					thread_args->dst_queue_id[num_queues] = i + 1;
				} else {
					thread_args->src_queue_id[num_queues] = i + 1;
					thread_args->dst_queue_id[num_queues] = i;
				}
				thread_args->num_queues++;
			}
		}
		return;
	}

	for (uint32_t i = 0; i < opt->num_queue; i += 2) {
		uint32_t num_queues;
		uint32_t thread_a_idx = i % opt->num_cpu;
		thread_args_t *thread_a_args = &global->thread_args[thread_a_idx];
		thread_args_t *thread_b_args = &global->thread_args[thread_a_idx + 1];

		num_queues = thread_a_args->num_queues;
		thread_a_args->src_queue_id[num_queues] = i;
		thread_a_args->dst_queue_id[num_queues] = i + 1;
		thread_a_args->num_queues++;

		num_queues = thread_b_args->num_queues;
		thread_b_args->src_queue_id[num_queues] = i + 1;
		thread_b_args->dst_queue_id[num_queues] = i;
		thread_b_args->num_queues++;
	}
}

static void print_queue_mappings(test_global_t *global)
{
	printf("Worker-queue mappings\n");
	printf("---------------------\n");

	for (uint32_t i = 0; i < global->options.num_cpu; i++) {
		thread_args_t *thread_args = &global->thread_args[i];
		uint32_t num_queues = thread_args->num_queues;

		printf("Worker %u:\n", i);

		printf("  src queue idx:");
		for (uint32_t j = 0; j < num_queues; j++)
			printf(" %" PRIu32 "", thread_args->src_queue_id[j]);
		printf("\n  dst queue idx:");
		for (uint32_t j = 0; j < num_queues; j++)
			printf(" %" PRIu32 "", thread_args->dst_queue_id[j]);
		printf("\n\n");
	}
}

static void init_thread_args(test_global_t *global)
{
	for (uint32_t i = 0; i < global->options.num_cpu; i++) {
		thread_args_t *thread_args = &global->thread_args[i];

		thread_args->global = global;
		thread_args->barrier = &global->barrier;
		thread_args->options = &global->options;
	}

	map_queues_to_threads(global);

	print_queue_mappings(global);
}

static int start_workers(test_global_t *global)
{
	odph_thread_common_param_t thr_common;
	odph_thread_param_t thr_param[ODP_THREAD_COUNT_MAX];
	odp_cpumask_t cpumask;
	int ret;
	test_options_t *test_options = &global->options;
	int num_cpu = test_options->num_cpu;

	ret = odp_cpumask_default_worker(&cpumask, num_cpu);

	if (num_cpu && ret != num_cpu) {
		ODPH_ERR("Too many workers. Max supported %i\n.", ret);
		return -1;
	}

	/* Zero: all available workers */
	if (num_cpu == 0) {
		num_cpu = ret;
		test_options->num_cpu = num_cpu;
	}

	printf("  num workers          %u\n\n", num_cpu);

	odp_barrier_init(&global->barrier, num_cpu);

	odph_thread_common_param_init(&thr_common);
	thr_common.instance = global->instance;
	thr_common.cpumask = &cpumask;

	init_thread_args(global);

	for (int i = 0; i < num_cpu; i++) {
		odph_thread_param_init(&thr_param[i]);
		thr_param[i].start = run_test;
		thr_param[i].arg = &global->thread_args[i];
		thr_param[i].thr_type = ODP_THREAD_WORKER;
	}

	if (odph_thread_create(global->thread_tbl, &thr_common, thr_param,
			       num_cpu) != num_cpu)
		return -1;

	return 0;
}

static int output_results(test_global_t *global)
{
	int i, num;
	double rounds_ave, events_ave, nsec_ave, cycles_ave;
	test_stat_t *stats;
	test_options_t *test_options = &global->options;
	int num_cpu = test_options->num_cpu;
	uint64_t rounds_sum = 0;
	uint64_t events_sum = 0;
	uint64_t nsec_sum = 0;
	uint64_t cycles_sum = 0;
	uint64_t deq_retry_sum = 0;
	uint64_t enq_retry_sum = 0;

	/* Averages */
	for (i = 0; i < ODP_THREAD_COUNT_MAX; i++) {
		stats = &global->thread_args[i].stats;
		rounds_sum    += stats->rounds;
		events_sum    += stats->events;
		nsec_sum      += stats->nsec;
		cycles_sum    += stats->cycles;
		deq_retry_sum += stats->deq_retry;
		enq_retry_sum += stats->enq_retry;
	}

	if (rounds_sum == 0) {
		printf("No results.\n");
		return 0;
	}

	rounds_ave   = rounds_sum / num_cpu;
	events_ave   = events_sum / num_cpu;
	nsec_ave     = nsec_sum / num_cpu;
	cycles_ave   = cycles_sum / num_cpu;
	num = 0;

	printf("RESULTS - per thread (Million events per sec):\n");
	printf("----------------------------------------------\n");
	printf("        1      2      3      4      5      6      7      8      9     10");

	for (i = 0; i < ODP_THREAD_COUNT_MAX; i++) {
		stats = &global->thread_args[i].stats;
		if (stats->rounds) {
			if ((num % 10) == 0)
				printf("\n   ");

			printf("%6.1f ", (1000.0 * stats->events) / stats->nsec);
			num++;
		}
	}
	printf("\n\n");

	printf("RESULTS - per thread average (%i threads):\n", num_cpu);
	printf("------------------------------------------\n");
	printf("  duration:                 %.3f msec\n", nsec_ave / 1000000);
	printf("  num cycles:               %.3f M\n", cycles_ave / 1000000);
	printf("  events per dequeue:       %.3f\n",
	       events_ave / rounds_ave);
	printf("  cycles per event:         %.3f\n",
	       cycles_ave / events_ave);
	printf("  dequeue retries:          %" PRIu64 "\n", deq_retry_sum);
	printf("  enqueue retries:          %" PRIu64 "\n", enq_retry_sum);
	printf("  events per sec:           %.3f M\n\n",
	       (1000.0 * events_ave) / nsec_ave);

	printf("TOTAL events per sec:       %.3f M\n\n",
	       (1000.0 * events_sum) / nsec_ave);

	if (global->common_options.is_export) {
		if (test_common_write("cycles per event,events per sec (M),TOTAL events per sec (M),"
				      "dequeue retries,enqueue retries\n")) {
			test_common_write_term();
			return -1;
		}
		if (test_common_write("%f,%f,%f,%" PRIu64 ",%" PRIu64 "\n",
				      cycles_ave / events_ave,
				      (1000.0 * events_ave) / nsec_ave,
				      (1000.0 * events_sum) / nsec_ave,
				      deq_retry_sum,
				      enq_retry_sum)) {
			test_common_write_term();
			return -1;
		}
		test_common_write_term();
	}

	return 0;
}

int main(int argc, char **argv)
{
	odph_helper_options_t helper_options;
	odp_instance_t instance;
	odp_init_t init;
	odp_shm_t shm;
	test_global_t *global;
	test_common_options_t common_options;

	/* Let helper collect its own arguments (e.g. --odph_proc) */
	argc = odph_parse_options(argc, argv);
	if (odph_options(&helper_options)) {
		ODPH_ERR("Reading ODP helper options failed.\n");
		exit(EXIT_FAILURE);
	}

	argc = test_common_parse_options(argc, argv);
	if (test_common_options(&common_options)) {
		ODPH_ERR("Reading test options failed.\n");
		exit(EXIT_FAILURE);
	}

	/* List features not to be used */
	odp_init_param_init(&init);
	init.not_used.feat.cls      = 1;
	init.not_used.feat.compress = 1;
	init.not_used.feat.crypto   = 1;
	init.not_used.feat.ipsec    = 1;
	init.not_used.feat.schedule = 1;
	init.not_used.feat.timer    = 1;
	init.not_used.feat.tm       = 1;

	init.mem_model = helper_options.mem_model;

	/* Init ODP before calling anything else */
	if (odp_init_global(&instance, &init, NULL)) {
		ODPH_ERR("Global init failed.\n");
		return -1;
	}

	/* Init this thread */
	if (odp_init_local(instance, ODP_THREAD_WORKER)) {
		ODPH_ERR("Local init failed.\n");
		return -1;
	}

	shm = odp_shm_reserve("queue_perf_global", sizeof(test_global_t), ODP_CACHE_LINE_SIZE, 0);
	if (shm == ODP_SHM_INVALID) {
		ODPH_ERR("Shared memory reserve failed.\n");
		exit(EXIT_FAILURE);
	}

	global = odp_shm_addr(shm);
	if (global == NULL) {
		ODPH_ERR("Shared memory address read failed.\n");
		exit(EXIT_FAILURE);
	}

	memset(global, 0, sizeof(test_global_t));
	global->common_options = common_options;
	odp_atomic_init_u32(&global->workers_finished, 0);

	if (parse_options(argc, argv, &global->options))
		return -1;

	odp_sys_info_print();

	global->instance = instance;

	if (create_queues(global))
		goto destroy;

	if (start_workers(global)) {
		ODPH_ERR("Test start failed.\n");
		return -1;
	}

	/* Wait workers to exit */
	odph_thread_join(global->thread_tbl, global->options.num_cpu);

	if (output_results(global)) {
		ODPH_ERR("Outputting results failed.\n");
		exit(EXIT_FAILURE);
	}

destroy:
	if (destroy_queues(global)) {
		ODPH_ERR("Destroy queues failed.\n");
		return -1;
	}

	if (odp_shm_free(shm)) {
		ODPH_ERR("Shared memory free failed.\n");
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
