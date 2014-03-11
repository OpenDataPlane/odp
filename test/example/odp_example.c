/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * @example  odp_example.c ODP example application
 */

#include <string.h>
#include <stdlib.h>

/* ODP main header */
#include <odp.h>

/* ODP helper for Linux apps */
#include <helper/odp_linux.h>

/* Needs librt*/
#include <time.h>

/* GNU lib C */
#include <getopt.h>


#define MAX_WORKERS           32
#define MSG_POOL_SIZE         (4*1024*1024)
#define MAX_ALLOCS            35
#define QUEUES_PER_PRIO       64
#define QUEUE_ROUNDS          (512*1024)
#define ALLOC_ROUNDS          (1024*1024)
#define MULTI_BUFS_MAX        4
#define SCHED_RETRY           100
#define TEST_SEC              2


typedef struct {
	int msg_id;
	int seq;
} test_message_t;

#define MSG_HELLO 1
#define MSG_ACK   2


typedef struct {
	int core_count;
} test_args_t;


static odp_barrier_t test_barrier;

/* #define TEST_TIMEOUTS */
#ifdef TEST_TIMEOUTS
static odp_timer_t test_timer;
#endif

/*
 * Clear all scheduled queues. Retry to be sure that all
 * buffers have been scheduled.
 */
static void clear_sched_queues(void)
{
	odp_buffer_t buf;

	while (1) {
		buf = odp_schedule_n(NULL, SCHED_RETRY);

		if (buf == ODP_BUFFER_INVALID)
			break;

		odp_buffer_free(buf);
	}
}

#ifdef TEST_TIMEOUTS
static void test_timeouts(int thr)
{
	uint64_t tick;
	odp_queue_t queue;
	odp_buffer_t buf;
	int num = 10;

	ODP_DBG("  [%i] test_timeouts\n", thr);

	queue = odp_queue_lookup("timer_queue");

	tick = odp_timer_current_tick(test_timer);

	ODP_DBG("  [%i] current tick %"PRIu64"\n", thr, tick);

	tick += 100;

	odp_timer_absolute_tmo(test_timer, tick,
			       queue, ODP_BUFFER_INVALID);


	while (1) {
		while ((buf = odp_queue_deq(queue) == ODP_BUFFER_INVALID))
			;

		/* ODP_DBG("  [%i] timeout\n", thr); */

		odp_buffer_free(buf);

		num--;

		if (num == 0)
			break;

		tick = odp_timer_current_tick(test_timer) + 100;

		odp_timer_absolute_tmo(test_timer, tick,
				       queue, ODP_BUFFER_INVALID);
	}
}
#endif

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
static int test_sched_single_queue(const char *str, int thr,
				   odp_buffer_pool_t msg_pool, int prio)
{
	odp_buffer_t buf;
	odp_queue_t queue;
	uint64_t t1, t2, cycles, ns;
	uint32_t i;
	uint32_t tot = 0;
	char name[] = "sched_XX_00";

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

	if (odp_queue_enq(queue, buf)) {
		ODP_ERR("  [%i] Queue enqueue failed.\n", thr);
		return -1;
	}

	t1 = odp_time_get_cycles();

	for (i = 0; i < QUEUE_ROUNDS; i++) {
		buf = odp_schedule_n(NULL, SCHED_RETRY);

		if (buf == ODP_BUFFER_INVALID)
			break;

		if (odp_queue_enq(queue, buf)) {
			ODP_ERR("  [%i] Queue enqueue failed.\n", thr);
			return -1;
		}
	}

	t2     = odp_time_get_cycles();
	cycles = odp_time_diff_cycles(t1, t2);
	ns     = odp_time_cycles_to_ns(cycles);
	tot    = i;

	odp_barrier_sync(&test_barrier);
	clear_sched_queues();

	if (tot) {
		cycles = cycles/tot;
		ns     = ns/tot;
	} else {
		cycles = 0;
		ns     = 0;
	}

	printf("  [%i] %s enq+deq %"PRIu64" cycles, %"PRIu64" ns\n",
	       thr, str, cycles, ns);

	return 0;
}

/*
 * Test scheduling of multiple queues
 *
 * Enqueue a buffer to each queue. Schedule and enqueue the received
 * buffer back into the queue it came from.
 */
static int test_sched_multi_queue(const char *str, int thr,
				  odp_buffer_pool_t msg_pool, int prio)
{
	odp_buffer_t buf;
	odp_queue_t queue;
	uint64_t t1 = 0;
	uint64_t t2 = 0;
	uint64_t cycles, ns;
	uint32_t i;
	uint32_t tot = 0;
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
		buf = odp_schedule_n(&queue, SCHED_RETRY);

		if (buf == ODP_BUFFER_INVALID)
			break;

		if (odp_queue_enq(queue, buf)) {
			ODP_ERR("  [%i] Queue enqueue failed.\n", thr);
			return -1;
		}
	}

	t2     = odp_time_get_cycles();
	cycles = odp_time_diff_cycles(t1, t2);
	ns     = odp_time_cycles_to_ns(cycles);
	tot    = i;

	odp_barrier_sync(&test_barrier);
	clear_sched_queues();

	if (tot) {
		cycles = cycles/tot;
		ns     = ns/tot;
	} else {
		cycles = 0;
		ns     = 0;
	}

	printf("  [%i] %s enq+deq %"PRIu64" cycles, %"PRIu64" ns\n",
	       thr, str, cycles, ns);

	return 0;
}


static int test_sched_multi_queue_m(const char *str, int thr,
				    odp_buffer_pool_t msg_pool, int prio)
{
	odp_buffer_t buf[MULTI_BUFS_MAX];
	odp_queue_t queue;
	uint64_t t1 = 0;
	uint64_t t2 = 0;
	uint64_t cycles, ns;
	int i, j;
	uint32_t tot = 0;
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

		for (j = 0; j < MULTI_BUFS_MAX; j++) {
			buf[j] = odp_buffer_alloc(msg_pool);

			if (!odp_buffer_is_valid(buf[j])) {
				ODP_ERR("  [%i] msg_pool alloc failed\n", thr);
				return -1;
			}
		}

		if (odp_queue_enq_multi(queue, buf, MULTI_BUFS_MAX)) {
			ODP_ERR("  [%i] Queue enqueue failed.\n", thr);
			return -1;
		}
	}

	/* Start sched-enq loop */
	t1 = odp_time_get_cycles();

	for (i = 0; i < QUEUE_ROUNDS; i++) {
		int num;

		num = odp_schedule_multi_n(&queue, buf,
					   MULTI_BUFS_MAX, SCHED_RETRY);

		if (num == 0)
			break;

		tot += num;

		if (odp_queue_enq_multi(queue, buf, num)) {
			ODP_ERR("  [%i] Queue enqueue failed.\n", thr);
			return -1;
		}
	}

	t2     = odp_time_get_cycles();
	cycles = odp_time_diff_cycles(t1, t2);
	ns     = odp_time_cycles_to_ns(cycles);

	odp_barrier_sync(&test_barrier);
	clear_sched_queues();

	if (tot) {
		cycles = cycles/tot;
		ns     = ns/tot;
	} else {
		cycles = 0;
		ns     = 0;
	}

	printf("  [%i] %s enq+deq %"PRIu64" cycles, %"PRIu64" ns\n",
	       thr, str, cycles, ns);

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

	if (test_sched_single_queue("sched_single_hi", thr, msg_pool,
				    ODP_SCHED_PRIO_HIGHEST))
		return NULL;

	odp_barrier_sync(&test_barrier);

	if (test_sched_single_queue("sched_single_lo", thr, msg_pool,
				    ODP_SCHED_PRIO_LOWEST))
		return NULL;

	odp_barrier_sync(&test_barrier);

	if (test_sched_multi_queue("sched_multi_hi", thr, msg_pool,
				   ODP_SCHED_PRIO_HIGHEST))
		return NULL;

	odp_barrier_sync(&test_barrier);

	if (test_sched_multi_queue("sched_multi_lo", thr, msg_pool,
				   ODP_SCHED_PRIO_LOWEST))
		return NULL;

	odp_barrier_sync(&test_barrier);

	if (test_sched_multi_queue_m("sched_multi_hi_m", thr, msg_pool,
				     ODP_SCHED_PRIO_HIGHEST))
		return NULL;

	odp_barrier_sync(&test_barrier);

	if (test_sched_multi_queue_m("sched_multi_lo_m", thr, msg_pool,
				     ODP_SCHED_PRIO_LOWEST))
		return NULL;

#ifdef TEST_TIMEOUTS
	odp_barrier_sync(&test_barrier);

	test_timeouts(thr);
#endif

	printf("Thread %i exits\n", thr);
	fflush(NULL);
	return arg;
}


static void test_time(void)
{
	struct timespec tp1, tp2;
	uint64_t t1, t2;
	uint64_t ns1, ns2, cycles;
	double err;

	if (clock_gettime(CLOCK_MONOTONIC, &tp2)) {
		ODP_ERR("clock_gettime failed.\n");
		return;
	}

	printf("\nTime accuracy test (%i sec)\n", TEST_SEC);

	do {
		if (clock_gettime(CLOCK_MONOTONIC, &tp1)) {
			ODP_ERR("clock_gettime failed.\n");
			return;
		}

	} while (tp1.tv_sec == tp2.tv_sec);

	t1 = odp_time_get_cycles();

	do {
		if (clock_gettime(CLOCK_MONOTONIC, &tp2)) {
			ODP_ERR("clock_gettime failed.\n");
			return;
		}

	} while ((tp2.tv_sec - tp1.tv_sec) < TEST_SEC);

	t2 = odp_time_get_cycles();

	ns1 = (tp2.tv_sec - tp1.tv_sec)*1000000000;

	if (tp2.tv_nsec > tp1.tv_nsec)
		ns1 += tp2.tv_nsec - tp1.tv_nsec;
	else
		ns1 -= tp1.tv_nsec - tp2.tv_nsec;

	cycles = odp_time_diff_cycles(t1, t2);
	ns2    = odp_time_cycles_to_ns(cycles);

	err = ((double)(ns2) - (double)ns1) / (double)ns1;

	printf("clock_gettime         %"PRIu64" ns\n",    ns1);
	printf("odp_time_get_cycles   %"PRIu64" cycles\n", cycles);
	printf("odp_time_cycles_to_ns %"PRIu64" ns\n",    ns2);
	printf("odp get cycle error   %f%%\n", err*100.0);

	printf("\n");
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
	int first_core;

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
	 * By default core #0 runs Linux kernel background tasks.
	 * Start mapping thread from core #1
	 */
	first_core = 1;

	if (odp_sys_core_count() == 1)
		first_core = 0;

	printf("first core:         %i\n", first_core);

	/*
	 * Init this thread. It makes also ODP calls when
	 * setting up resources for worker threads.
	 */
	thr_id = odp_thread_create(0);
	odp_init_local(thr_id);

	/* Test cycle count accuracy */
	test_time();

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


#ifdef TEST_TIMEOUTS
	/*
	 * Create a queue for timer test
	 */
	queue = odp_queue_create("timer_queue", ODP_QUEUE_TYPE_SCHED, NULL);

	if (queue == ODP_QUEUE_INVALID) {
		ODP_ERR("Timer queue create failed.\n");
		return -1;
	}

	test_timer = odp_timer_create("test_timer", pool,
				      1000000, 1000000, 1000000000000);
#endif

	/*
	 * Create queues for schedule test. QUEUES_PER_PRIO per priority.
	 */
	prios = odp_schedule_num_prio();

	for (i = 0; i < prios; i++) {
		if (i != ODP_SCHED_PRIO_HIGHEST &&
		    i != ODP_SCHED_PRIO_LOWEST)
			continue;

		odp_queue_param_t param;
		char name[] = "sched_XX_YY";

		name[6] = '0' + i/10;
		name[7] = '0' + i - 10*(i/10);

		param.sched.prio  = i;
		param.sched.sync  = ODP_SCHED_SYNC_ATOMIC;
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
	odp_linux_pthread_create(thread_tbl, num_workers, first_core,
				 run_thread, NULL);

	/* Wait for worker threads to exit */
	odp_linux_pthread_join(thread_tbl, num_workers);

	printf("ODP example complete\n\n");

	return 0;
}
