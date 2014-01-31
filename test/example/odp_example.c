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
#define QUEUES_PER_PRIO       64
#define QUEUE_ROUNDS          (1024*1024)
#define ALLOC_ROUNDS          (1024*1024)
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

/*
 * Test shared data
 */
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
 * Test single buffer alloc and free
 */
static int test_alloc_single(int thr, odp_buffer_pool_t pool)
{
	int i;
	odp_buffer_t temp_buf;
	uint64_t t1, t2, cycles, ns;

	t1 = odp_time_get_cycles();

	for (i = 0; i < ALLOC_ROUNDS; i++) {
		temp_buf = odp_buffer_alloc(pool);

		if (!odp_buffer_is_valid(temp_buf)) {
			ODP_ERR("  [%i] alloc_single failed\n", thr);
			return -1;
		}

		odp_buffer_free(temp_buf);
	}

	t2     = odp_time_get_cycles();
	cycles = odp_time_diff_cycles(t1, t2);
	ns     = odp_time_cycles_to_ns(cycles);

	printf("  [%i] alloc_sng alloc+free %"PRIu64" cycles, %"PRIu64" ns\n",
	       thr, cycles/ALLOC_ROUNDS, ns/ALLOC_ROUNDS);

	return 0;
}

/*
 * Test multiple buffers alloc and free
 */
static int test_alloc_multi(int thr, odp_buffer_pool_t pool)
{
	int i, j;
	odp_buffer_t temp_buf[MAX_ALLOCS];
	uint64_t t1, t2, cycles, ns;

	t1 = odp_time_get_cycles();

	for (i = 0; i < ALLOC_ROUNDS; i++) {
		for (j = 0; j < MAX_ALLOCS; j++) {
			temp_buf[j] = odp_buffer_alloc(pool);

			if (!odp_buffer_is_valid(temp_buf[j])) {
				ODP_ERR("  [%i] alloc_multi failed\n", thr);
				return -1;
			}
		}

		for (; j > 0; j--)
			odp_buffer_free(temp_buf[j-1]);
	}

	t2     = odp_time_get_cycles();
	cycles = odp_time_diff_cycles(t1, t2);
	ns     = odp_time_cycles_to_ns(cycles);

	printf("  [%i] alloc_multi alloc+free %"PRIu64" cycles, %"PRIu64" ns\n",
	       thr, cycles/(ALLOC_ROUNDS*MAX_ALLOCS),
	       ns/(ALLOC_ROUNDS*MAX_ALLOCS));

	return 0;
}

/*
 * Test queue polling
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
		ODP_ERR("  [%i] msg_pool alloc failed\n", thr);
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
			ODP_ERR("  [%i] Queue enqueue failed.\n", thr);
			return -1;
		}

		buf = odp_queue_deq(queue);

		if (!odp_buffer_is_valid(buf)) {
			ODP_ERR("  [%i] Queue empty.\n", thr);
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
 * Test scheduling of a single queue
 *
 * Enqueue a buffer to the shared queue. Schedule and enqueue the received
 * buffer back into the queue.
 */
static int test_sched_single_queue(int thr, odp_buffer_pool_t msg_pool,
				   int prio)
{
	odp_buffer_t buf;
	odp_queue_t queue;
	uint64_t t1, t2, cycles, ns;
	char name[] = "sched_XX_00";
	int i;

	buf = odp_buffer_alloc(msg_pool);

	if (!odp_buffer_is_valid(buf)) {
		ODP_ERR("  [%i] msg_pool alloc failed\n", thr);
		return -1;
	}

	name[6] = '0' + prio/10;
	name[7] = '0' + prio - 10*(prio/10);

	queue = odp_queue_lookup(name);

	if (queue == ODP_QUEUE_INVALID) {
		ODP_ERR("  [%i] Queue %s lookup failed.\n", thr, name);
		return -1;
	}

	/* printf("  [%i] prio %i queue %s\n", thr, prio, name); */

	t1 = odp_time_get_cycles();

	for (i = 0; i < QUEUE_ROUNDS; i++) {
		if (odp_queue_enq(queue, buf)) {
			ODP_ERR("  [%i] Queue enqueue failed.\n", thr);
			return -1;
		}

		buf = odp_schedule_poll(NULL);

		if (!odp_buffer_is_valid(buf)) {
			ODP_ERR("  [%i] Sched queue empty.\n", thr);
			return -1;
		}
	}

	t2     = odp_time_get_cycles();
	cycles = odp_time_diff_cycles(t1, t2);
	ns     = odp_time_cycles_to_ns(cycles);

	printf("  [%i] sched_single enq+deq %"PRIu64" cycles, %"PRIu64" ns\n",
	       thr, cycles/QUEUE_ROUNDS, ns/QUEUE_ROUNDS);

	odp_buffer_free(buf);
	return 0;
}

/*
 * Test scheduling of multiple queues
 *
 * Enqueue a buffer to each queue. Schedule and enqueue the received
 * buffer back into the queue it came from.
 */
static int test_sched_multi_queue(int thr, odp_buffer_pool_t msg_pool, int prio)
{
	odp_buffer_t buf;
	odp_queue_t queue;
	uint64_t t1 = 0;
	uint64_t t2 = 0;
	uint64_t cycles, ns;
	int i;
	char name[] = "sched_XX_YY";

	name[6] = '0' + prio/10;
	name[7] = '0' + prio - 10*(prio/10);

	/* Alloc and enqueue a buffer per queue */
	for (i = 0; i < QUEUES_PER_PRIO; i++) {
		name[9]  = '0' + i/10;
		name[10] = '0' + i - 10*(i/10);

		queue = odp_queue_lookup(name);

		if (queue == ODP_QUEUE_INVALID) {
			ODP_ERR("  [%i] Queue %s lookup failed.\n", thr, name);
			return -1;
		}

		buf = odp_buffer_alloc(msg_pool);

		if (!odp_buffer_is_valid(buf)) {
			ODP_ERR("  [%i] msg_pool alloc failed\n", thr);
			return -1;
		}

		if (odp_queue_enq(queue, buf)) {
			ODP_ERR("  [%i] Queue enqueue failed.\n", thr);
			return -1;
		}
	}

	/* Start sched-enq loop */
	t1 = odp_time_get_cycles();

	for (i = 0; i < QUEUE_ROUNDS; i++) {
		buf = odp_schedule_poll(&queue);

		if (!odp_buffer_is_valid(buf)) {
			ODP_ERR("  [%i] Sched queue empty.\n", thr);
			return -1;
		}

		if (odp_queue_enq(queue, buf)) {
			ODP_ERR("  [%i] Queue enqueue failed.\n", thr);
			return -1;
		}
	}

	t2     = odp_time_get_cycles();
	cycles = odp_time_diff_cycles(t1, t2);
	ns     = odp_time_cycles_to_ns(cycles);

	/* Empty queues of this priority. Free buffers */
	for (i = 0; i < QUEUES_PER_PRIO; i++) {
		buf = odp_schedule_poll(&queue);

		if (!odp_buffer_is_valid(buf)) {
			ODP_ERR("  [%i] Sched queue empty.\n", thr);
			return -1;
		}

		odp_buffer_free(buf);
	}

	printf("  [%i] sched_multi enq+deq %"PRIu64" cycles, %"PRIu64" ns\n",
	       thr, cycles/QUEUE_ROUNDS, ns/QUEUE_ROUNDS);

	return 0;
}

static void *run_thread(void *arg)
{
	int thr;
	odp_buffer_pool_t msg_pool;

	thr = odp_thread_id();

	printf("Thread %i starts on core %i\n", thr, odp_thread_core());

	/*
	 * Test barriers back-to-back
	 */
	odp_barrier_sync(&test_barrier);
	odp_barrier_sync(&test_barrier);
	odp_barrier_sync(&test_barrier);
	odp_barrier_sync(&test_barrier);

	/*
	 * Shared mem test
	 */
	test_shared_data = odp_shm_lookup("shared_data");
	printf("  [%i] shared data at %p\n",
	       thr, test_shared_data);

	test_shared(thr);

	/*
	 * Find the buffer pool
	 */
	msg_pool = odp_buffer_pool_lookup("msg_pool");

	if (msg_pool == ODP_BUFFER_POOL_INVALID) {
		ODP_ERR("  [%i] msg_pool not found\n", thr);
		return NULL;
	}

	odp_barrier_sync(&test_barrier);

	if (test_alloc_single(thr, msg_pool))
		return NULL;

	odp_barrier_sync(&test_barrier);

	if (test_alloc_multi(thr, msg_pool))
		return NULL;

	odp_barrier_sync(&test_barrier);

	if (test_poll_queue(thr, msg_pool))
		return NULL;

	odp_barrier_sync(&test_barrier);

	if (test_sched_single_queue(thr, msg_pool, 0))
		return NULL;

	odp_barrier_sync(&test_barrier);

	if (test_sched_multi_queue(thr, msg_pool, 0))
		return NULL;

	printf("Thread %i exits\n", thr);
	fflush(NULL);
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
		ODP_ERR("Pool create failed.\n");
		return -1;
	}

	/* odp_buffer_pool_print(pool); */

	/*
	 * Create a queue for direct poll test
	 */
	queue = odp_queue_create("poll_queue", ODP_QUEUE_TYPE_POLL, NULL);

	if (queue == ODP_QUEUE_INVALID) {
		ODP_ERR("Poll queue create failed.\n");
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
				ODP_ERR("Schedule queue create failed.\n");
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
