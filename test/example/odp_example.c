/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP example application
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* ODP main header */
#include <odp.h>

/* ODP helper for Linux apps */
#include <helper/odp_linux.h>

/* Linux headers*/
#include <time.h>

/* GNU lib C */
#include <getopt.h>


#define MAX_WORKERS           32
#define MSG_POOL_SIZE         (1024*1024)
#define MAX_ALLOCS            35
#define QUEUES_PER_PRIO       32
#define QUEUE_ROUNDS          (1024*1024)
#define COUNTER_MAX           16


typedef struct {
	int msg_id;
	int seq;
} test_message_t;

#define MSG_HELLO 1
#define MSG_ACK   2


typedef struct {
	odp_spinlock_t lock;
	int counter;
	int foo;
	int bar;
} test_shared_data_t;


typedef struct {
	int core_count;
} test_args_t;


static __thread test_shared_data_t *test_shared_data;

static odp_barrier_t test_barrier;


static void test_shared(int thr)
{
	struct timespec delay;
	delay.tv_sec = 0;
	delay.tv_nsec = 1000;

	while (1) {
		nanosleep(&delay, NULL);

		odp_spinlock_lock(&test_shared_data->lock);

		if (test_shared_data->counter >= COUNTER_MAX) {
			odp_spinlock_unlock(&test_shared_data->lock);
			break;
		}

		test_shared_data->counter++;
		printf("  [%i] shared counter %i\n", thr,
		       test_shared_data->counter);

		if (test_shared_data->counter == COUNTER_MAX)
			printf("\n");

		odp_spinlock_unlock(&test_shared_data->lock);
	}
}


/*
 * Poll queue test
 *
 * Enqueue to and dequeue to/from a single shared queue.
 */
static int test_poll_queue(int thr, odp_buffer_pool_t msg_pool)
{
	odp_buffer_t buf;
	test_message_t *t_msg;
	odp_queue_t queue;
	uint64_t t1, t2, cycles, ns;
	int i;

	/* Alloc test message */
	buf = odp_buffer_alloc(msg_pool);

	if (!odp_buffer_is_valid(buf)) {
		printf("  [%i] msg_pool alloc failed\n", thr);
		return -1;
	}

	/* odp_buffer_print(buf); */

	t_msg = odp_buffer_addr(buf);
	t_msg->msg_id = MSG_HELLO;
	t_msg->seq    = 0;

	queue = odp_queue_lookup("poll_queue");

	if (queue == ODP_QUEUE_INVALID) {
		printf("  [%i] Queue lookup failed.\n", thr);
		return -1;
	}

	t1 = odp_time_get_cycles();

	for (i = 0; i < QUEUE_ROUNDS; i++) {
		if (odp_queue_enq(queue, buf)) {
			printf("  [%i] Queue enqueue failed.\n", thr);
			return -1;
		}

		buf = odp_queue_deq(queue);

		if (!odp_buffer_is_valid(buf)) {
			printf("  [%i] Queue empty.\n", thr);
			return -1;
		}
	}

	t2     = odp_time_get_cycles();
	cycles = odp_time_diff_cycles(t1, t2);
	ns     = odp_time_cycles_to_ns(cycles);

	printf("  [%i] poll_queue enq+deq %"PRIu64" cycles, %"PRIu64" ns\n",
	       thr, cycles/QUEUE_ROUNDS, ns/QUEUE_ROUNDS);

	odp_buffer_free(buf);
	return 0;
}


/*
 * Schedule single queue test
 *
 * A shared queues per priority.
 * Enqueue a buffer to a shared queue, schedule until
 * a buffer is returned. Repeat over all queues (priorities).
 */
static int test_sched_single_queue(int thr, odp_buffer_pool_t msg_pool)
{
	odp_buffer_t buf;
	odp_queue_t queue;
	uint64_t t1, t2, cycles, ns;
	int i;
	int prios;

	buf = odp_buffer_alloc(msg_pool);

	if (!odp_buffer_is_valid(buf)) {
		printf("  [%i] msg_pool alloc failed\n", thr);
		return -1;
	}

	prios = odp_schedule_num_prio();

	t1 = odp_time_get_cycles();

	for (i = 0; i < prios; i++) {
		char name[] = "sched_XX_00";
		int j;

		name[6] = '0' + i/10;
		name[7] = '0' + i - 10*(i/10);

		queue = odp_queue_lookup(name);

		if (queue == ODP_QUEUE_INVALID) {
			printf("  [%i] Queue %s lookup failed.\n", thr, name);
			return -1;
		}

		/* printf("  [%i] prio %i queue %s\n", thr, i, name); */

		for (j = 0; j < QUEUE_ROUNDS; j++) {
			if (odp_queue_enq(queue, buf)) {
				printf("  [%i] Queue enqueue failed.\n", thr);
				return -1;
			}

			buf = odp_schedule_poll(NULL);

			if (!odp_buffer_is_valid(buf)) {
				printf("  [%i] Sched queue empty.\n", thr);
				return -1;
			}
		}
	}

	t2     = odp_time_get_cycles();
	cycles = odp_time_diff_cycles(t1, t2);
	ns     = odp_time_cycles_to_ns(cycles);

	printf("  [%i] sched_single enq+deq %"PRIu64" cycles, %"PRIu64" ns\n",
	       thr, cycles/(prios*QUEUE_ROUNDS), ns/(prios*QUEUE_ROUNDS));

	odp_buffer_free(buf);
	return 0;
}


/*
 * Schedule multiple queue test
 *
 * Multiple shared queues per priority.
 * Enqueue a buffer per queue, schedule until
 * a buffer is returned. Repeat over all priorities.
 */
static int test_sched_multi_queue(int thr, odp_buffer_pool_t msg_pool)
{
	odp_buffer_t buf;
	odp_queue_t queue;
	uint64_t t1 = 0;
	uint64_t t2 = 0;
	uint64_t cycles, ns;
	int i, j;
	int prios;

	prios = odp_schedule_num_prio();

	for (i = 0; i < prios; i++) {
		char name[] = "sched_XX_YY";

		name[6] = '0' + i/10;
		name[7] = '0' + i - 10*(i/10);

		/* Alloc and enqueue a buffer per queue */
		for (j = 0; j < QUEUES_PER_PRIO; j++) {
			name[9]  = '0' + j/10;
			name[10] = '0' + j - 10*(j/10);

			queue = odp_queue_lookup(name);

			if (queue == ODP_QUEUE_INVALID) {
				printf("  [%i] Queue %s lookup failed.\n",
				       thr, name);
				return -1;
			}

			buf = odp_buffer_alloc(msg_pool);

			if (!odp_buffer_is_valid(buf)) {
				printf("  [%i] msg_pool alloc failed\n", thr);
				return -1;
			}

			if (odp_queue_enq(queue, buf)) {
				printf("  [%i] Queue enqueue failed.\n", thr);
				return -1;
			}
		}

		/* Start sched-enq loop */
		if (t1 == 0)
			t1 = odp_time_get_cycles();

		for (j = 0; j < QUEUE_ROUNDS; j++) {
			buf = odp_schedule_poll(&queue);

			if (!odp_buffer_is_valid(buf)) {
				printf("  [%i] Sched queue empty.\n", thr);
				return -1;
			}

			if (odp_queue_enq(queue, buf)) {
				printf("  [%i] Queue enqueue failed.\n", thr);
				return -1;
			}
		}

		t2 = odp_time_get_cycles();


		/* Empty queues of this priority. Free buffers */
		for (j = 0; j < QUEUES_PER_PRIO; j++) {
			buf = odp_schedule_poll(&queue);

			if (!odp_buffer_is_valid(buf)) {
				printf("  [%i] Sched queue empty.\n", thr);
				return -1;
			}

			odp_buffer_free(buf);
		}
	}

	cycles = odp_time_diff_cycles(t1, t2);
	ns     = odp_time_cycles_to_ns(cycles);

	printf("  [%i] sched_multi enq+deq %"PRIu64" cycles, %"PRIu64" ns\n",
	       thr, cycles/(prios*QUEUE_ROUNDS), ns/(prios*QUEUE_ROUNDS));

	return 0;
}




static void *run_thread(void *arg)
{
	int thr;
	odp_buffer_pool_t msg_pool;
	odp_buffer_t temp_buf[MAX_ALLOCS];
	int i;


	thr = odp_thread_id();

	printf("Thread %i starts on core %i\n", thr, odp_thread_core());

	/*
	 * Shared mem test
	 */

	test_shared_data = odp_shm_lookup("shared_data");
	printf("  [%i] shared data at %p\n",
	       thr, test_shared_data);

	test_shared(thr);

	/*
	 * Buffer pool test
	 */

	msg_pool = odp_buffer_pool_lookup("msg_pool");

	if (msg_pool == ODP_BUFFER_POOL_INVALID) {
		printf("  [%i] msg_pool not found\n", thr);
		return NULL;
	}

	for (i = 0; i < MAX_ALLOCS; i++) {
		temp_buf[i] = odp_buffer_alloc(msg_pool);

		if (!odp_buffer_is_valid(temp_buf[i]))
			break;
	}

	for (i = i; i > 0; i--)
		odp_buffer_free(temp_buf[i-1]);


	odp_barrier_sync(&test_barrier);

	if (test_poll_queue(thr, msg_pool))
		return NULL;

	odp_barrier_sync(&test_barrier);

	if (test_sched_single_queue(thr, msg_pool))
		return NULL;

	odp_barrier_sync(&test_barrier);

	if (test_sched_multi_queue(thr, msg_pool))
		return NULL;

	printf("Thread %i exits\n", thr);
	fflush(stdout);
	return arg;
}


static void print_usage(void)
{
	printf("\n\nUsage: ./odp_example [options]\n");
	printf("Options:\n");
	printf("  -c, --count <number>    core count, core IDs start from 1\n");
	printf("  -h, --help              this help\n");
	printf("\n\n");
}


static void parse_args(int argc, char *argv[], test_args_t *args)
{
	int opt;
	int long_index;

	static struct option longopts[] = {
		{"count", required_argument, NULL, 'c'},
		{"help", no_argument, NULL, 'h'},
		{NULL, 0, NULL, 0}
	};

	while (1) {
		opt = getopt_long(argc, argv, "+c:h", longopts, &long_index);

		if (opt == -1)
			break;	/* No more options */

		switch (opt) {
		case 'c':
			args->core_count = atoi(optarg);
			break;

		case 'h':
			print_usage();
			exit(EXIT_SUCCESS);
			break;

		default:
			break;
		}
	}
}


int main(int argc, char *argv[])
{
	odp_linux_pthread_t thread_tbl[MAX_WORKERS];
	test_args_t args;
	int thr_id;
	int num_workers;
	odp_buffer_pool_t pool;
	void *pool_base;
	odp_queue_t queue;
	int i, j;
	int prios;

	printf("\nODP example starts\n");

	memset(&args, 0, sizeof(args));
	parse_args(argc, argv, &args);

	memset(thread_tbl, 0, sizeof(thread_tbl));

	if (odp_init_global()) {
		printf("ODP global init failed.\n");
		return -1;
	}

	printf("\n");
	printf("ODP system info\n");
	printf("---------------\n");
	printf("ODP API version: %s\n",        odp_version_api_str());
	printf("CPU model:       %s\n",        odp_sys_cpu_model_str());
	printf("CPU freq (hz):   %"PRIu64"\n", odp_sys_cpu_hz());
	printf("Cache line size: %i\n",        odp_sys_cache_line_size());
	printf("Max core count:  %i\n",        odp_sys_core_count());

	printf("\n");

	/* A worker thread per core */
	num_workers = odp_sys_core_count();

	if (args.core_count)
		num_workers = args.core_count;

	/* force to max core count */
	if (num_workers > MAX_WORKERS)
		num_workers = MAX_WORKERS;

	printf("num worker threads: %i\n", num_workers);


	/*
	 * Init this thread. It makes also ODP calls when
	 * setting up resources for worker threads.
	 */
	thr_id = odp_thread_create(0);
	odp_init_local(thr_id);

	/*
	 * Create shared data
	 */
	test_shared_data = odp_shm_reserve("shared_data",
					  sizeof(test_shared_data_t),
					  ODP_CACHE_LINE_SIZE);

	memset(test_shared_data, 0, sizeof(test_shared_data_t));
	odp_spinlock_init(&test_shared_data->lock);

	printf("test shared data at %p\n\n", test_shared_data);

	/*
	 * Create message pool
	 */
	pool_base = odp_shm_reserve("msg_pool",
				    MSG_POOL_SIZE, ODP_CACHE_LINE_SIZE);

	pool = odp_buffer_pool_create("msg_pool", pool_base, MSG_POOL_SIZE,
				      sizeof(test_message_t),
				      ODP_CACHE_LINE_SIZE, ODP_BUFFER_TYPE_RAW);

	if (pool == ODP_BUFFER_POOL_INVALID) {
		printf("Pool create failed.\n");
		return -1;
	}

	/* odp_buffer_pool_print(pool); */

	/*
	 * Create a queue for direct poll test
	 */
	queue = odp_queue_create("poll_queue", ODP_QUEUE_TYPE_POLL, NULL);

	if (queue == ODP_QUEUE_INVALID) {
		printf("Poll queue create failed.\n");
		return -1;
	}


	/*
	 * Create queues for schedule test. QUEUES_PER_PRIO per priority.
	 */
	prios = odp_schedule_num_prio();

	for (i = 0; i < prios; i++) {
		odp_queue_param_t param;
		char name[] = "sched_XX_YY";

		name[6] = '0' + i/10;
		name[7] = '0' + i - 10*(i/10);

		param.sched.prio  = i;
		param.sched.sync  = ODP_SCHED_SYNC_NONE;
		param.sched.group = ODP_SCHED_GROUP_DEFAULT;

		for (j = 0; j < QUEUES_PER_PRIO; j++) {
			name[9]  = '0' + j/10;
			name[10] = '0' + j - 10*(j/10);

			queue = odp_queue_create(name, ODP_QUEUE_TYPE_SCHED,
						 &param);

			if (queue == ODP_QUEUE_INVALID) {
				printf("Schedule queue create failed.\n");
				return -1;
			}
		}
	}

	odp_shm_print_all();

	/* Barrier to sync test case execution */
	odp_barrier_init_count(&test_barrier, num_workers);

	/* Create and launch worker threads */
	odp_linux_pthread_create(thread_tbl, num_workers, 1, run_thread, NULL);

	/* Wait for worker threads to exit */
	odp_linux_pthread_join(thread_tbl, num_workers);

	printf("ODP example complete\n\n");

	return 0;
}

