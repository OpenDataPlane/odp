/* Copyright (c) 2013-2018, Linaro Limited
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
#include <inttypes.h>

/* ODP main header */
#include <odp_api.h>

/* ODP helper for Linux apps */
#include <odp/helper/odph_api.h>

/* Needs librt*/
#include <time.h>

/* GNU lib C */
#include <getopt.h>

#define MAX_BUF              (512 * 1024)   /**< Maximum pool size */
#define MAX_ALLOCS            32            /**< Alloc burst size */
#define QUEUES_PER_PRIO       64            /**< Queue per priority */
#define NUM_PRIOS             2             /**< Number of tested priorities */
#define QUEUE_ROUNDS          (512 * 1024)    /**< Queue test rounds */
#define ALLOC_ROUNDS          (1024 * 1024)   /**< Alloc test rounds */
#define MULTI_BUFS_MAX        4             /**< Buffer burst size */
#define TEST_SEC              2             /**< Time test duration in sec */
#define STATS_PER_LINE        8             /**< Stats per printed line */

/** Dummy message */
typedef struct {
	int msg_id; /**< Message ID */
	int seq;    /**< Sequence number */
} test_message_t;

#define MSG_HELLO 1  /**< Hello */
#define MSG_ACK   2  /**< Ack */

/** Test arguments */
typedef struct {
	unsigned int cpu_count;  /**< CPU count */
	int fairness;   /**< Check fairness */
} test_args_t;

typedef struct ODP_ALIGNED_CACHE {
	uint64_t num_ev;

	/* Round up the struct size to cache line size */
	uint8_t pad[ODP_CACHE_LINE_SIZE - sizeof(uint64_t)];
} queue_context_t;

/** Test global variables */
typedef struct {
	odp_barrier_t    barrier;
	odp_spinlock_t   lock;
	odp_pool_t       pool;
	int              first_thr;
	int              queues_per_prio;
	test_args_t      args;
	odp_queue_t      queue[NUM_PRIOS][QUEUES_PER_PRIO];
	queue_context_t  queue_ctx[NUM_PRIOS][QUEUES_PER_PRIO];
} test_globals_t;

/* Prints and initializes queue statistics */
static void print_stats(int prio, test_globals_t *globals)
{
	int i, j, k;

	if (prio == ODP_SCHED_PRIO_HIGHEST)
		i = 0;
	else
		i = 1;

	printf("\nQueue fairness\n-----+--------\n");

	for (j = 0; j < globals->queues_per_prio;) {
		printf("  %2i | ", j);

		for (k = 0; k < STATS_PER_LINE - 1; k++) {
			printf(" %8" PRIu64,
			       globals->queue_ctx[i][j].num_ev);
			globals->queue_ctx[i][j++].num_ev = 0;
		}

		printf(" %8" PRIu64 "\n", globals->queue_ctx[i][j].num_ev);
		globals->queue_ctx[i][j++].num_ev = 0;
	}

	printf("\n");
}

/**
 * @internal Clear all scheduled queues. Retry to be sure that all
 * buffers have been scheduled.
 */
static void clear_sched_queues(void)
{
	odp_event_t ev;

	while (1) {
		ev = odp_schedule(NULL, ODP_SCHED_NO_WAIT);

		if (ev == ODP_EVENT_INVALID)
			break;

		odp_event_free(ev);
	}
}

/**
 * @internal Enqueue events into queues
 *
 * @param thr        Thread
 * @param prio       Queue priority
 * @param num_queues Number of queues
 * @param num_events Number of events
 * @param globals    Test shared data
 *
 * @return 0 if successful
 */
static int enqueue_events(int thr, int prio, int num_queues, int num_events,
			  test_globals_t *globals)
{
	odp_buffer_t buf[num_events];
	odp_event_t ev[num_events];
	odp_queue_t queue;
	int i, j, k, ret;

	if (prio == ODP_SCHED_PRIO_HIGHEST)
		i = 0;
	else
		i = 1;

	/* Alloc and enqueue a buffer per queue */
	for (j = 0; j < num_queues; j++) {
		queue = globals->queue[i][j];

		ret = odp_buffer_alloc_multi(globals->pool, buf, num_events);
		if (ret != num_events) {
			ODPH_ERR("  [%i] buffer alloc failed\n", thr);
			ret = ret < 0 ? 0 : ret;
			odp_buffer_free_multi(buf, ret);
			return -1;
		}
		for (k = 0; k < num_events; k++) {
			if (!odp_buffer_is_valid(buf[k])) {
				ODPH_ERR("  [%i] buffer alloc failed\n", thr);
				odp_buffer_free_multi(buf, num_events);
				return -1;
			}
			ev[k] = odp_buffer_to_event(buf[k]);
		}

		ret = odp_queue_enq_multi(queue, ev, num_events);
		if (ret != num_events) {
			ODPH_ERR("  [%i] Queue enqueue failed.\n", thr);
			ret = ret < 0 ? 0 : ret;
			odp_buffer_free_multi(&buf[ret], num_events - ret);
			return -1;
		}
	}

	return 0;
}

/**
 * @internal Test single buffer alloc and free
 *
 * @param thr     Thread
 * @param globals Test shared data
 *
 * @return 0 if successful
 */
static int test_alloc_single(int thr, test_globals_t *globals)
{
	int i;
	odp_buffer_t temp_buf;
	uint64_t c1, c2, cycles;

	c1 = odp_cpu_cycles();

	for (i = 0; i < ALLOC_ROUNDS; i++) {
		temp_buf = odp_buffer_alloc(globals->pool);

		if (!odp_buffer_is_valid(temp_buf)) {
			ODPH_ERR("  [%i] alloc_single failed\n", thr);
			return -1;
		}

		odp_buffer_free(temp_buf);
	}

	c2     = odp_cpu_cycles();
	cycles = odp_cpu_cycles_diff(c2, c1);
	cycles = cycles / ALLOC_ROUNDS;

	printf("  [%i] alloc_sng alloc+free   %6" PRIu64 " CPU cycles\n",
	       thr, cycles);

	return 0;
}

/**
 * @internal Test multiple buffers alloc and free
 *
 * @param thr     Thread
 * @param globals Test shared data
 *
 * @return 0 if successful
 */
static int test_alloc_multi(int thr, test_globals_t *globals)
{
	int i, j, ret;
	odp_buffer_t temp_buf[MAX_ALLOCS];
	uint64_t c1, c2, cycles;

	c1 = odp_cpu_cycles();

	for (i = 0; i < ALLOC_ROUNDS; i++) {
		ret = odp_buffer_alloc_multi(globals->pool, temp_buf,
					     MAX_ALLOCS);
		if (ret != MAX_ALLOCS) {
			ODPH_ERR("  [%i] buffer alloc failed\n", thr);
			ret = ret < 0 ? 0 : ret;
			odp_buffer_free_multi(temp_buf, ret);
			return -1;
		}

		for (j = 0; j < MAX_ALLOCS; j++) {
			if (!odp_buffer_is_valid(temp_buf[j])) {
				ODPH_ERR("  [%i] alloc_multi failed\n", thr);
				odp_buffer_free_multi(temp_buf, MAX_ALLOCS);
				return -1;
			}
		}
		odp_buffer_free_multi(temp_buf, MAX_ALLOCS);
	}

	c2     = odp_cpu_cycles();
	cycles = odp_cpu_cycles_diff(c2, c1);
	cycles = cycles / (ALLOC_ROUNDS * MAX_ALLOCS);

	printf("  [%i] alloc_multi alloc+free %6" PRIu64 " CPU cycles\n",
	       thr, cycles);

	return 0;
}

/**
 * @internal Test plain queues
 *
 * Enqueue to and dequeue to/from a single shared queue.
 *
 * @param thr      Thread
 * @param globals Test shared data
 *
 * @return 0 if successful
 */
static int test_plain_queue(int thr, test_globals_t *globals)
{
	odp_event_t ev;
	odp_buffer_t buf;
	test_message_t *t_msg;
	odp_queue_t queue;
	uint64_t c1, c2, cycles;
	int i, j;

	/* Alloc test message */
	buf = odp_buffer_alloc(globals->pool);

	if (!odp_buffer_is_valid(buf)) {
		ODPH_ERR("  [%i] buffer alloc failed\n", thr);
		return -1;
	}

	/* odp_buffer_print(buf); */

	t_msg = odp_buffer_addr(buf);
	t_msg->msg_id = MSG_HELLO;
	t_msg->seq    = 0;

	queue = odp_queue_lookup("plain_queue");

	if (queue == ODP_QUEUE_INVALID) {
		printf("  [%i] Queue lookup failed.\n", thr);
		return -1;
	}

	c1 = odp_cpu_cycles();

	for (i = 0; i < QUEUE_ROUNDS; i++) {
		ev = odp_buffer_to_event(buf);

		if (odp_queue_enq(queue, ev)) {
			ODPH_ERR("  [%i] Queue enqueue failed.\n", thr);
			odp_buffer_free(buf);
			return -1;
		}

		/* When enqueue and dequeue are decoupled (e.g. not using a
		 * common lock), an enqueued event may not be immediately
		 * visible to dequeue. So we just try again for a while. */
		for (j = 0; j < 100; j++) {
			ev = odp_queue_deq(queue);
			if (ev != ODP_EVENT_INVALID)
				break;
			odp_cpu_pause();
		}

		buf = odp_buffer_from_event(ev);

		if (!odp_buffer_is_valid(buf)) {
			ODPH_ERR("  [%i] Queue empty.\n", thr);
			return -1;
		}
	}

	c2     = odp_cpu_cycles();
	cycles = odp_cpu_cycles_diff(c2, c1);
	cycles = cycles / QUEUE_ROUNDS;

	printf("  [%i] plain_queue enq+deq    %6" PRIu64 " CPU cycles\n",
	       thr, cycles);

	odp_buffer_free(buf);
	return 0;
}

/**
 * @internal Test scheduling of a single queue - with odp_schedule()
 *
 * Enqueue a buffer to the shared queue. Schedule and enqueue the received
 * buffer back into the queue.
 *
 * @param str      Test case name string
 * @param thr      Thread
 * @param prio     Priority
 * @param globals  Test shared data
 *
 * @return 0 if successful
 */
static int test_schedule_single(const char *str, int thr,
				int prio, test_globals_t *globals)
{
	odp_event_t ev;
	odp_queue_t queue;
	uint64_t c1, c2, cycles;
	uint32_t i;
	uint32_t tot;

	if (enqueue_events(thr, prio, 1, 1, globals))
		return -1;

	c1 = odp_cpu_cycles();

	for (i = 0; i < QUEUE_ROUNDS; i++) {
		ev = odp_schedule(&queue, ODP_SCHED_WAIT);

		if (odp_queue_enq(queue, ev)) {
			ODPH_ERR("  [%i] Queue enqueue failed.\n", thr);
			odp_event_free(ev);
			return -1;
		}
	}

	/* Clear possible locally stored buffers */
	odp_schedule_pause();

	tot = i;

	while (1) {
		ev = odp_schedule(&queue, ODP_SCHED_NO_WAIT);

		if (ev == ODP_EVENT_INVALID)
			break;

		tot++;

		if (odp_queue_enq(queue, ev)) {
			ODPH_ERR("  [%i] Queue enqueue failed.\n", thr);
			odp_event_free(ev);
			return -1;
		}
	}

	c2     = odp_cpu_cycles();
	cycles = odp_cpu_cycles_diff(c2, c1);

	odp_barrier_wait(&globals->barrier);

	odp_schedule_resume();

	clear_sched_queues();

	cycles = cycles / tot;

	printf("  [%i] %s enq+deq %6" PRIu64 " CPU cycles\n", thr, str, cycles);

	return 0;
}

/**
 * @internal Test scheduling of multiple queues - with odp_schedule()
 *
 * Enqueue a buffer to each queue. Schedule and enqueue the received
 * buffer back into the queue it came from.
 *
 * @param str      Test case name string
 * @param thr      Thread
 * @param prio     Priority
 * @param globals  Test shared data
 *
 * @return 0 if successful
 */
static int test_schedule_many(const char *str, int thr,
			      int prio, test_globals_t *globals)
{
	odp_event_t ev;
	odp_queue_t queue;
	uint64_t c1, c2, cycles;
	uint32_t i;
	uint32_t tot;

	if (enqueue_events(thr, prio, globals->queues_per_prio, 1, globals))
		return -1;

	/* Start sched-enq loop */
	c1 = odp_cpu_cycles();

	for (i = 0; i < QUEUE_ROUNDS; i++) {
		ev = odp_schedule(&queue, ODP_SCHED_WAIT);

		if (odp_queue_enq(queue, ev)) {
			ODPH_ERR("  [%i] Queue enqueue failed.\n", thr);
			odp_event_free(ev);
			return -1;
		}
	}

	/* Clear possible locally stored buffers */
	odp_schedule_pause();

	tot = i;

	while (1) {
		ev = odp_schedule(&queue, ODP_SCHED_NO_WAIT);

		if (ev == ODP_EVENT_INVALID)
			break;

		tot++;

		if (odp_queue_enq(queue, ev)) {
			ODPH_ERR("  [%i] Queue enqueue failed.\n", thr);
			odp_event_free(ev);
			return -1;
		}
	}

	c2     = odp_cpu_cycles();
	cycles = odp_cpu_cycles_diff(c2, c1);

	odp_barrier_wait(&globals->barrier);

	odp_schedule_resume();

	clear_sched_queues();

	cycles = cycles / tot;

	printf("  [%i] %s enq+deq %6" PRIu64 " CPU cycles\n", thr, str, cycles);

	return 0;
}

/**
 * @internal Test scheduling of multiple queues with multi_sched and multi_enq
 *
 * @param str      Test case name string
 * @param thr      Thread
 * @param prio     Priority
 * @param globals  Test shared data
 *
 * @return 0 if successful
 */
static int test_schedule_multi(const char *str, int thr,
			       int prio, test_globals_t *globals)
{
	odp_event_t ev[MULTI_BUFS_MAX];
	odp_queue_t queue;
	uint64_t c1, c2, cycles;
	int i;
	int num;
	uint32_t tot = 0;

	if (enqueue_events(thr, prio, globals->queues_per_prio, MULTI_BUFS_MAX,
			   globals))
		return -1;

	/* Start sched-enq loop */
	c1 = odp_cpu_cycles();

	for (i = 0; i < QUEUE_ROUNDS; i++) {
		num = odp_schedule_multi(&queue, ODP_SCHED_WAIT, ev,
					 MULTI_BUFS_MAX);

		tot += num;

		if (globals->args.fairness) {
			queue_context_t *queue_ctx;

			queue_ctx = odp_queue_context(queue);
			queue_ctx->num_ev += num;
		}

		/* Assume we can enqueue all events */
		if (odp_queue_enq_multi(queue, ev, num) != num) {
			ODPH_ERR("  [%i] Queue enqueue failed.\n", thr);
			return -1;
		}
	}

	/* Clear possible locally stored events */
	odp_schedule_pause();

	while (1) {
		num = odp_schedule_multi(&queue, ODP_SCHED_NO_WAIT, ev,
					 MULTI_BUFS_MAX);

		if (num == 0)
			break;

		tot += num;

		if (globals->args.fairness) {
			queue_context_t *queue_ctx;

			queue_ctx = odp_queue_context(queue);
			queue_ctx->num_ev += num;
		}

		/* Assume we can enqueue all events */
		if (odp_queue_enq_multi(queue, ev, num) != num) {
			ODPH_ERR("  [%i] Queue enqueue failed.\n", thr);
			return -1;
		}
	}

	c2     = odp_cpu_cycles();
	cycles = odp_cpu_cycles_diff(c2, c1);

	odp_barrier_wait(&globals->barrier);

	odp_schedule_resume();

	clear_sched_queues();

	if (tot)
		cycles = cycles / tot;
	else
		cycles = 0;

	printf("  [%i] %s enq+deq %6" PRIu64 " CPU cycles\n", thr, str, cycles);

	odp_barrier_wait(&globals->barrier);

	if (globals->args.fairness && globals->first_thr == thr)
		print_stats(prio, globals);

	return 0;
}

/**
 * @internal Worker thread
 *
 * @param arg  Arguments
 *
 * @return non zero on failure
 */
static int run_thread(void *arg ODP_UNUSED)
{
	int thr;
	odp_shm_t shm;
	test_globals_t *globals;
	odp_barrier_t *barrier;

	thr = odp_thread_id();

	printf("Thread %i starts on CPU %i\n", thr, odp_cpu_id());

	shm     = odp_shm_lookup("test_globals");
	globals = odp_shm_addr(shm);

	if (globals == NULL) {
		ODPH_ERR("Shared mem lookup failed\n");
		return -1;
	}

	barrier = &globals->barrier;

	/*
	 * Test barriers back-to-back
	 */
	odp_barrier_wait(barrier);
	odp_barrier_wait(barrier);
	odp_barrier_wait(barrier);
	odp_barrier_wait(barrier);
	odp_barrier_wait(barrier);

	/* Select which thread is the first_thr */
	while (globals->first_thr < 0) {
		if (odp_spinlock_trylock(&globals->lock)) {
			globals->first_thr = thr;
			odp_spinlock_unlock(&globals->lock);
		}
	}

	odp_barrier_wait(barrier);

	if (test_alloc_single(thr, globals))
		return -1;

	odp_barrier_wait(barrier);

	if (test_alloc_multi(thr, globals))
		return -1;

	odp_barrier_wait(barrier);

	if (test_plain_queue(thr, globals))
		return -1;

	/* Low prio */

	odp_barrier_wait(barrier);

	if (test_schedule_single("sched_____s_lo", thr,
				 ODP_SCHED_PRIO_LOWEST, globals))
		return -1;

	odp_barrier_wait(barrier);

	if (test_schedule_many("sched_____m_lo", thr,
			       ODP_SCHED_PRIO_LOWEST, globals))
		return -1;

	odp_barrier_wait(barrier);

	if (test_schedule_multi("sched_multi_lo", thr,
				ODP_SCHED_PRIO_LOWEST, globals))
		return -1;

	/* High prio */

	odp_barrier_wait(barrier);

	if (test_schedule_single("sched_____s_hi", thr,
				 ODP_SCHED_PRIO_HIGHEST, globals))
		return -1;

	odp_barrier_wait(barrier);

	if (test_schedule_many("sched_____m_hi", thr,
			       ODP_SCHED_PRIO_HIGHEST, globals))
		return -1;

	odp_barrier_wait(barrier);

	if (test_schedule_multi("sched_multi_hi", thr,
				ODP_SCHED_PRIO_HIGHEST, globals))
		return -1;

	printf("Thread %i exits\n", thr);
	fflush(NULL);
	return 0;
}

/**
 * @internal Test cycle counter frequency
 */
static void test_cpu_freq(void)
{
	odp_time_t cur_time, test_time, start_time, end_time;
	uint64_t c1, c2, cycles;
	uint64_t nsec;
	double diff_max_hz, max_cycles;

	printf("\nCPU cycle count frequency test (runs about %i sec)\n",
	       TEST_SEC);

	test_time = odp_time_local_from_ns(TEST_SEC * ODP_TIME_SEC_IN_NS);
	start_time = odp_time_local();
	end_time = odp_time_sum(start_time, test_time);

	/* Start the measurement */
	c1 = odp_cpu_cycles();

	do {
		cur_time = odp_time_local();
	} while (odp_time_cmp(end_time, cur_time) > 0);

	c2 = odp_cpu_cycles();

	test_time = odp_time_diff(cur_time, start_time);
	nsec = odp_time_to_ns(test_time);

	cycles     = odp_cpu_cycles_diff(c2, c1);
	max_cycles = (nsec * odp_cpu_hz_max()) / 1000000000.0;

	/* Compare measured CPU cycles to maximum theoretical CPU cycle count */
	diff_max_hz = ((double)(cycles) - max_cycles) / max_cycles;

	printf("odp_time               %" PRIu64 " ns\n", nsec);
	printf("odp_cpu_cycles         %" PRIu64 " CPU cycles\n", cycles);
	printf("odp_sys_cpu_hz         %" PRIu64 " hz\n", odp_cpu_hz_max());
	printf("Diff from max CPU freq %f%%\n", diff_max_hz * 100.0);

	printf("\n");
}

/**
 * @internal Print help
 */
static void print_usage(void)
{
	printf("\n\nUsage: ./odp_example [options]\n");
	printf("Options:\n");
	printf("  -c, --count <number>    CPU count, 0=all available, default=1\n");
	printf("  -h, --help              this help\n");
	printf("  -f, --fair              collect fairness statistics\n");
	printf("\n\n");
}

/**
 * @internal Parse arguments
 *
 * @param argc  Argument count
 * @param argv  Argument vector
 * @param args  Test arguments
 */
static void parse_args(int argc, char *argv[], test_args_t *args)
{
	int opt;
	int long_index;

	static const struct option longopts[] = {
		{"count", required_argument, NULL, 'c'},
		{"fair", no_argument, NULL, 'f'},
		{"help", no_argument, NULL, 'h'},
		{NULL, 0, NULL, 0}
	};

	static const char *shortopts = "+c:fh";

	args->cpu_count = 1; /* use one worker by default */

	while (1) {
		opt = getopt_long(argc, argv, shortopts, longopts, &long_index);

		if (opt == -1)
			break;	/* No more options */

		switch (opt) {
		case 'f':
			args->fairness = 1;
			break;

		case 'c':
			args->cpu_count = atoi(optarg);
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

/**
 * Test main function
 */
int main(int argc, char *argv[])
{
	odph_helper_options_t helper_options;
	odph_thread_t *thread_tbl;
	test_args_t args;
	int num_workers;
	odp_cpumask_t cpumask;
	odp_pool_t pool;
	odp_queue_t plain_queue;
	int i, j;
	odp_shm_t shm;
	test_globals_t *globals;
	char cpumaskstr[ODP_CPUMASK_STR_SIZE];
	odp_pool_param_t params;
	int ret = 0;
	odp_instance_t instance;
	odp_init_t init_param;
	odph_thread_common_param_t thr_common;
	odph_thread_param_t thr_param;
	odp_queue_capability_t capa;
	odp_pool_capability_t pool_capa;
	odp_schedule_config_t schedule_config;
	uint32_t num_queues, num_buf;

	printf("\nODP example starts\n\n");

	/* Let helper collect its own arguments (e.g. --odph_proc) */
	argc = odph_parse_options(argc, argv);
	if (odph_options(&helper_options)) {
		ODPH_ERR("Error: reading ODP helper options failed.\n");
		exit(EXIT_FAILURE);
	}

	odp_init_param_init(&init_param);
	init_param.mem_model = helper_options.mem_model;

	memset(&args, 0, sizeof(args));
	parse_args(argc, argv, &args);

	/* ODP global init */
	if (odp_init_global(&instance, &init_param, NULL)) {
		ODPH_ERR("ODP global init failed.\n");
		return -1;
	}

	/*
	 * Init this thread. It makes also ODP calls when
	 * setting up resources for worker threads.
	 */
	if (odp_init_local(instance, ODP_THREAD_CONTROL)) {
		ODPH_ERR("ODP global init failed.\n");
		return -1;
	}

	printf("\n");
	odp_sys_info_print();

	/* Get default worker cpumask */
	num_workers = odp_cpumask_default_worker(&cpumask, args.cpu_count);
	(void)odp_cpumask_to_str(&cpumask, cpumaskstr, sizeof(cpumaskstr));

	printf("num worker threads: %i\n", num_workers);
	printf("first CPU:          %i\n", odp_cpumask_first(&cpumask));
	printf("cpu mask:           %s\n", cpumaskstr);

	thread_tbl = calloc(sizeof(odph_thread_t), num_workers);
	if (!thread_tbl) {
		ODPH_ERR("no memory for thread_tbl\n");
		return -1;
	}

	/* Test cycle count frequency */
	test_cpu_freq();

	shm = odp_shm_reserve("test_globals",
			      sizeof(test_globals_t), ODP_CACHE_LINE_SIZE, 0);
	if (shm == ODP_SHM_INVALID) {
		ODPH_ERR("Shared memory reserve failed.\n");
		return -1;
	}

	globals = odp_shm_addr(shm);
	memset(globals, 0, sizeof(test_globals_t));
	memcpy(&globals->args, &args, sizeof(test_args_t));

	/*
	 * Create message pool
	 */
	if (odp_pool_capability(&pool_capa)) {
		ODPH_ERR("Pool capabilities failed.\n");
		return -1;
	}

	num_buf = MAX_BUF;
	if (pool_capa.buf.max_num && pool_capa.buf.max_num < MAX_BUF)
		num_buf = pool_capa.buf.max_num;

	odp_pool_param_init(&params);
	params.buf.size  = sizeof(test_message_t);
	params.buf.align = 0;
	params.buf.num   = num_buf;
	params.type      = ODP_POOL_BUFFER;

	pool = odp_pool_create("msg_pool", &params);

	if (pool == ODP_POOL_INVALID) {
		ODPH_ERR("Pool create failed.\n");
		return -1;
	}

	globals->pool = pool;

	if (odp_queue_capability(&capa)) {
		ODPH_ERR("Fetching queue capabilities failed.\n");
		return -1;
	}

	odp_schedule_config_init(&schedule_config);
	odp_schedule_config(&schedule_config);

	globals->queues_per_prio = QUEUES_PER_PRIO;
	num_queues = globals->queues_per_prio * NUM_PRIOS;
	if (schedule_config.num_queues &&
	    num_queues > schedule_config.num_queues)
		globals->queues_per_prio = schedule_config.num_queues /
			NUM_PRIOS;

	/* One plain queue is also used */
	num_queues = (globals->queues_per_prio *  NUM_PRIOS) + 1;
	if (num_queues > capa.max_queues)
		globals->queues_per_prio--;

	if (globals->queues_per_prio <= 0) {
		ODPH_ERR("Not enough queues. At least 1 plain and %d scheduled "
			 "queues required.\n", NUM_PRIOS);
		return -1;
	}

	/*
	 * Create a queue for plain queue test
	 */
	plain_queue = odp_queue_create("plain_queue", NULL);

	if (plain_queue == ODP_QUEUE_INVALID) {
		ODPH_ERR("Plain queue create failed.\n");
		return -1;
	}

	/*
	 * Create queues for schedule test.
	 */
	for (i = 0; i < NUM_PRIOS; i++) {
		char name[] = "sched_XX_YY";
		odp_queue_t queue;
		odp_queue_param_t param;
		int prio;

		if (i == 0)
			prio = ODP_SCHED_PRIO_HIGHEST;
		else
			prio = ODP_SCHED_PRIO_LOWEST;

		name[6] = '0' + (prio / 10);
		name[7] = '0' + prio - (10 * (prio / 10));

		odp_queue_param_init(&param);
		param.type        = ODP_QUEUE_TYPE_SCHED;
		param.sched.prio  = prio;
		param.sched.sync  = ODP_SCHED_SYNC_ATOMIC;
		param.sched.group = ODP_SCHED_GROUP_ALL;

		for (j = 0; j < globals->queues_per_prio; j++) {
			name[9]  = '0' + j / 10;
			name[10] = '0' + j - 10 * (j / 10);

			queue = odp_queue_create(name, &param);

			if (queue == ODP_QUEUE_INVALID) {
				ODPH_ERR("Schedule queue create failed.\n");
				return -1;
			}

			globals->queue[i][j] = queue;

			if (odp_queue_context_set(queue,
						  &globals->queue_ctx[i][j],
						  sizeof(queue_context_t))
						  < 0) {
				ODPH_ERR("Queue context set failed.\n");
				return -1;
			}
		}
	}

	odp_shm_print_all();

	odp_pool_print(pool);

	/* Barrier to sync test case execution */
	odp_barrier_init(&globals->barrier, num_workers);

	odp_spinlock_init(&globals->lock);
	globals->first_thr = -1;

	/* Create and launch worker threads */
	memset(&thr_common, 0, sizeof(thr_common));
	memset(&thr_param, 0, sizeof(thr_param));

	thr_param.thr_type = ODP_THREAD_WORKER;
	thr_param.start    = run_thread;
	thr_param.arg      = NULL;

	thr_common.instance = instance;
	thr_common.cpumask  = &cpumask;
	thr_common.share_param = 1;

	odph_thread_create(thread_tbl, &thr_common, &thr_param, num_workers);

	/* Wait for worker threads to terminate */
	odph_thread_join(thread_tbl, num_workers);
	free(thread_tbl);

	printf("ODP example complete\n\n");

	for (i = 0; i < NUM_PRIOS; i++) {
		odp_queue_t queue;

		for (j = 0; j < globals->queues_per_prio; j++) {
			queue = globals->queue[i][j];
			ret += odp_queue_destroy(queue);
		}
	}

	ret += odp_shm_free(shm);
	ret += odp_queue_destroy(plain_queue);
	ret += odp_pool_destroy(pool);
	ret += odp_term_local();
	ret += odp_term_global(instance);

	return ret;
}
