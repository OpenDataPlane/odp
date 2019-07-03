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

#define MAX_QUEUES (32 * 1024)

typedef struct test_options_t {
	uint32_t num_queue;
	uint32_t num_event;
	uint32_t num_round;
	uint32_t max_burst;
	odp_nonblocking_t nonblock;
	int single;
	int num_cpu;

} test_options_t;

typedef struct test_stat_t {
	uint64_t rounds;
	uint64_t events;
	uint64_t nsec;
	uint64_t cycles;
	uint64_t deq_retry;

} test_stat_t;

typedef struct test_global_t {
	odp_barrier_t    barrier;
	test_options_t   options;
	odp_instance_t   instance;
	odp_shm_t        shm;
	odp_pool_t       pool;
	odp_queue_t      queue[MAX_QUEUES];
	odph_odpthread_t thread_tbl[ODP_THREAD_COUNT_MAX];
	test_stat_t      stat[ODP_THREAD_COUNT_MAX];

} test_global_t;

static test_global_t test_global;

static void print_usage(void)
{
	printf("\n"
	       "Plain queue performance test\n"
	       "\n"
	       "Usage: odp_queue_perf [options]\n"
	       "\n"
	       "  -c, --num_cpu          Number of worker threads. Default: 1\n"
	       "  -q, --num_queue        Number of queues. Default: 1\n"
	       "  -e, --num_event        Number of events per queue. Default: 1\n"
	       "  -b, --burst_size       Maximum number of events per operation. Default: 1\n"
	       "  -r, --num_round        Number of rounds\n"
	       "  -l, --lockfree         Lockfree queues\n"
	       "  -w, --waitfree         Waitfree queues\n"
	       "  -s, --single           Single producer, single consumer\n"
	       "  -h, --help             This help\n"
	       "\n");
}

static int parse_options(int argc, char *argv[], test_options_t *test_options)
{
	int opt;
	int long_index;
	int ret = 0;

	static const struct option longopts[] = {
		{"num_cpu",    required_argument, NULL, 'c'},
		{"num_queue",  required_argument, NULL, 'q'},
		{"num_event",  required_argument, NULL, 'e'},
		{"burst_size", required_argument, NULL, 'b'},
		{"num_round",  required_argument, NULL, 'r'},
		{"lockfree",   no_argument,       NULL, 'l'},
		{"waitfree",   no_argument,       NULL, 'w'},
		{"single",     no_argument,       NULL, 's'},
		{"help",       no_argument,       NULL, 'h'},
		{NULL, 0, NULL, 0}
	};

	static const char *shortopts = "+c:q:e:b:r:lwsh";

	test_options->num_cpu   = 1;
	test_options->num_queue = 1;
	test_options->num_event = 1;
	test_options->max_burst = 1;
	test_options->num_round = 1000;
	test_options->nonblock  = ODP_BLOCKING;
	test_options->single    = 0;

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
		case 'r':
			test_options->num_round = atoi(optarg);
			break;
		case 'l':
			test_options->nonblock = ODP_NONBLOCKING_LF;
			break;
		case 'w':
			test_options->nonblock = ODP_NONBLOCKING_WF;
			break;
		case 's':
			test_options->single = 1;
			break;
		case 'h':
			/* fall through */
		default:
			print_usage();
			ret = -1;
			break;
		}
	}

	if (test_options->num_queue > MAX_QUEUES) {
		printf("Too many queues %u. Test maximum %u.\n",
		       test_options->num_queue, MAX_QUEUES);
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
	int ret = 0;
	odp_queue_t *queue = global->queue;
	odp_event_t event[tot_event];

	printf("\nTesting %s queues\n",
	       nonblock == ODP_BLOCKING ? "NORMAL" :
	       (nonblock == ODP_NONBLOCKING_LF ? "LOCKFREE" :
	       (nonblock == ODP_NONBLOCKING_WF ? "WAITFREE" : "???")));
	printf("  num rounds           %u\n", num_round);
	printf("  num queues           %u\n", num_queue);
	printf("  num events per queue %u\n", num_event);
	printf("  max burst size       %u\n", test_options->max_burst);

	for (i = 0; i < num_queue; i++)
		queue[i] = ODP_QUEUE_INVALID;

	for (i = 0; i < tot_event; i++)
		event[i] = ODP_EVENT_INVALID;

	if (odp_queue_capability(&queue_capa)) {
		printf("Error: Queue capa failed.\n");
		return -1;
	}

	if (odp_pool_capability(&pool_capa)) {
		printf("Error: Pool capa failed.\n");
		return -1;
	}

	if (nonblock == ODP_BLOCKING) {
		if (num_queue > queue_capa.plain.max_num) {
			printf("Max queues supported %u\n",
			       queue_capa.plain.max_num);
			return -1;
		}

		max_size = queue_capa.plain.max_size;
		if (max_size && num_event > max_size) {
			printf("Max queue size supported %u\n", max_size);
			return -1;
		}
	} else if (nonblock == ODP_NONBLOCKING_LF) {
		if (queue_capa.plain.lockfree.max_num == 0) {
			printf("Lockfree queues not supported\n");
			return -1;
		}

		if (num_queue > queue_capa.plain.lockfree.max_num) {
			printf("Max lockfree queues supported %u\n",
			       queue_capa.plain.lockfree.max_num);
			return -1;
		}

		max_size = queue_capa.plain.lockfree.max_size;
		if (max_size && num_event > max_size) {
			printf("Max lockfree queue size supported %u\n",
			       max_size);
			return -1;
		}
	} else if (nonblock == ODP_NONBLOCKING_WF) {
		if (queue_capa.plain.waitfree.max_num == 0) {
			printf("Waitfree queues not supported\n");
			return -1;
		}

		if (num_queue > queue_capa.plain.waitfree.max_num) {
			printf("Max waitfree queues supported %u\n",
			       queue_capa.plain.waitfree.max_num);
			return -1;
		}

		max_size = queue_capa.plain.waitfree.max_size;
		if (max_size && num_event > max_size) {
			printf("Max waitfree queue size supported %u\n",
			       max_size);
			return -1;
		}
	} else {
		printf("Error: Bad queue blocking type\n");
		return -1;
	}

	max_num = pool_capa.buf.max_num;

	if (max_num && tot_event > max_num) {
		printf("Error: max events supported %u\n", max_num);
		return -1;
	}

	odp_pool_param_init(&pool_param);
	pool_param.type = ODP_POOL_BUFFER;
	pool_param.buf.num = tot_event;

	pool = odp_pool_create("queue perf pool", &pool_param);

	if (pool == ODP_POOL_INVALID) {
		printf("Error: Pool create failed.\n");
		return -1;
	}

	global->pool = pool;

	odp_queue_param_init(&queue_param);
	queue_param.type        = ODP_QUEUE_TYPE_PLAIN;
	queue_param.nonblocking = nonblock;
	queue_param.size        = num_event;

	if (test_options->single) {
		queue_param.enq_mode = ODP_QUEUE_OP_MT_UNSAFE;
		queue_param.deq_mode = ODP_QUEUE_OP_MT_UNSAFE;
	}

	for (i = 0; i < num_queue; i++) {
		queue[i] = odp_queue_create(NULL, &queue_param);

		if (queue[i] == ODP_QUEUE_INVALID) {
			printf("Error: Queue create failed %u.\n", i);
			return -1;
		}
	}

	for (i = 0; i < tot_event; i++) {
		event[i] = odp_buffer_to_event(odp_buffer_alloc(pool));

		if (event[i] == ODP_EVENT_INVALID) {
			printf("Error: Event alloc failed %u.\n", i);
			ret = -1;
			goto free_events;
		}
	}

	for (i = 0; i < num_queue; i++) {
		for (j = 0; j < num_event; j++) {
			uint32_t id = i * num_event + j;

			if (odp_queue_enq(queue[i], event[id])) {
				printf("Error: Queue enq failed %u/%u\n", i, j);
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
		if (queue[i] == ODP_QUEUE_INVALID) {
			printf("Error: Invalid queue handle (i: %u).\n", i);
			break;
		}

		for (j = 0; j < num_event; j++) {
			ev = odp_queue_deq(queue[i]);

			if (ev != ODP_EVENT_INVALID)
				odp_event_free(ev);
		}

		if (odp_queue_destroy(queue[i])) {
			printf("Error: Queue destroy failed %u.\n", i);
			ret = -1;
			break;
		}
	}

	if (pool != ODP_POOL_INVALID && odp_pool_destroy(pool)) {
		printf("Error: Pool destroy failed.\n");
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
	test_stat_t *stat;
	test_global_t *global = arg;
	test_options_t *test_options = &global->options;
	odp_queue_t queue;
	uint64_t num_retry = 0;
	uint64_t events = 0;
	uint32_t num_queue = test_options->num_queue;
	uint32_t num_round = test_options->num_round;
	int thr = odp_thread_id();
	int ret = 0;
	uint32_t i = 0;
	uint32_t max_burst = test_options->max_burst;
	odp_event_t ev[max_burst];

	stat = &global->stat[thr];

	/* Start all workers at the same time */
	odp_barrier_wait(&global->barrier);

	t1 = odp_time_local();
	c1 = odp_cpu_cycles();

	for (rounds = 0; rounds < num_round; rounds++) {
		do {
			queue = global->queue[i++];

			if (i == num_queue)
				i = 0;

			num_ev = odp_queue_deq_multi(queue, ev, max_burst);

			if (odp_unlikely(num_ev <= 0))
				num_retry++;

		} while (num_ev <= 0);

		if (odp_queue_enq_multi(queue, ev, num_ev) != num_ev) {
			printf("Error: Queue enq failed %u\n", i);
			ret = -1;
			goto error;
		}

		events += num_ev;
	}

	c2 = odp_cpu_cycles();
	t2 = odp_time_local();

	nsec   = odp_time_diff_ns(t2, t1);
	cycles = odp_cpu_cycles_diff(c2, c1);

	stat->rounds = rounds;
	stat->events = events;
	stat->nsec   = nsec;
	stat->cycles = cycles;
	stat->deq_retry = num_retry;

error:
	return ret;
}

static int start_workers(test_global_t *global)
{
	odph_odpthread_params_t thr_params;
	odp_cpumask_t cpumask;
	int ret;
	test_options_t *test_options = &global->options;
	int num_cpu = test_options->num_cpu;

	memset(&thr_params, 0, sizeof(thr_params));
	thr_params.thr_type = ODP_THREAD_WORKER;
	thr_params.instance = global->instance;
	thr_params.start    = run_test;
	thr_params.arg      = global;

	ret = odp_cpumask_default_worker(&cpumask, num_cpu);

	if (num_cpu && ret != num_cpu) {
		printf("Error: Too many workers. Max supported %i\n.", ret);
		return -1;
	}

	/* Zero: all available workers */
	if (num_cpu == 0) {
		num_cpu = ret;
		test_options->num_cpu = num_cpu;
	}

	printf("  num workers          %u\n\n", num_cpu);

	odp_barrier_init(&global->barrier, num_cpu);

	if (odph_odpthreads_create(global->thread_tbl, &cpumask, &thr_params)
	    != num_cpu)
		return -1;

	return 0;
}

static void print_stat(test_global_t *global)
{
	int i, num;
	double rounds_ave, events_ave, nsec_ave, cycles_ave, retry_ave;
	test_options_t *test_options = &global->options;
	int num_cpu = test_options->num_cpu;
	uint64_t rounds_sum = 0;
	uint64_t events_sum = 0;
	uint64_t nsec_sum = 0;
	uint64_t cycles_sum = 0;
	uint64_t retry_sum = 0;

	/* Averages */
	for (i = 0; i < ODP_THREAD_COUNT_MAX; i++) {
		rounds_sum   += global->stat[i].rounds;
		events_sum   += global->stat[i].events;
		nsec_sum     += global->stat[i].nsec;
		cycles_sum   += global->stat[i].cycles;
		retry_sum    += global->stat[i].deq_retry;
	}

	if (rounds_sum == 0) {
		printf("No results.\n");
		return;
	}

	rounds_ave   = rounds_sum / num_cpu;
	events_ave   = events_sum / num_cpu;
	nsec_ave     = nsec_sum / num_cpu;
	cycles_ave   = cycles_sum / num_cpu;
	retry_ave    = retry_sum / num_cpu;
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

	printf("RESULTS - per thread average (%i threads):\n", num_cpu);
	printf("------------------------------------------\n");
	printf("  duration:                 %.3f msec\n", nsec_ave / 1000000);
	printf("  num cycles:               %.3f M\n", cycles_ave / 1000000);
	printf("  evenst per dequeue:       %.3f\n",
	       events_ave / rounds_ave);
	printf("  cycles per event:         %.3f\n",
	       cycles_ave / events_ave);
	printf("  deq retries per sec:      %.3f k\n",
	       (1000000.0 * retry_ave) / nsec_ave);
	printf("  events per sec:           %.3f M\n\n",
	       (1000.0 * events_ave) / nsec_ave);

	printf("TOTAL events per sec:       %.3f M\n\n",
	       (1000.0 * events_sum) / nsec_ave);
}

int main(int argc, char **argv)
{
	odp_instance_t instance;
	odp_init_t init;
	test_global_t *global;

	/* List features not to be used */
	odp_init_param_init(&init);
	init.not_used.feat.cls      = 1;
	init.not_used.feat.crypto   = 1;
	init.not_used.feat.ipsec    = 1;
	init.not_used.feat.schedule = 1;
	init.not_used.feat.timer    = 1;
	init.not_used.feat.tm       = 1;

	/* Init ODP before calling anything else */
	if (odp_init_global(&instance, &init, NULL)) {
		printf("Error: Global init failed.\n");
		return -1;
	}

	/* Init this thread */
	if (odp_init_local(instance, ODP_THREAD_WORKER)) {
		printf("Error: Local init failed.\n");
		return -1;
	}

	global = &test_global;
	memset(global, 0, sizeof(test_global_t));

	if (parse_options(argc, argv, &global->options))
		return -1;

	global->instance = instance;

	if (create_queues(global)) {
		printf("Error: Create queues failed.\n");
		goto destroy;
	}

	if (start_workers(global)) {
		printf("Error: Test start failed.\n");
		return -1;
	}

	/* Wait workers to exit */
	odph_odpthreads_join(global->thread_tbl);

	print_stat(global);

destroy:
	if (destroy_queues(global)) {
		printf("Error: Destroy queues failed.\n");
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
