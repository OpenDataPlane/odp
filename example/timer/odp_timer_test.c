/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * @example  odp_timer_test.c ODP timer example application
 */

#include <string.h>
#include <stdlib.h>

/* ODP main header */
#include <odp.h>

/* ODP helper for Linux apps */
#include <odph_linux.h>

/* GNU lib C */
#include <getopt.h>


#define MAX_WORKERS           32            /**< Max worker threads */
#define MSG_POOL_SIZE         (4*1024*1024) /**< Message pool size */


/** Test arguments */
typedef struct {
	int core_count;    /**< Core count*/
	int resolution_us; /**< Timeout resolution in usec*/
	int min_us;        /**< Minimum timeout in usec*/
	int max_us;        /**< Maximum timeout in usec*/
	int period_us;     /**< Timeout period in usec*/
	int tmo_count;     /**< Timeout count*/
} test_args_t;


/** @private Barrier for test synchronisation */
static odp_barrier_t test_barrier;

/** @private Timer handle*/
static odp_timer_t test_timer;


/** @private test timeout */
static void test_abs_timeouts(int thr, test_args_t *args)
{
	uint64_t tick;
	uint64_t period;
	uint64_t period_ns;
	odp_queue_t queue;
	odp_buffer_t buf;
	int num;

	ODP_DBG("  [%i] test_timeouts\n", thr);

	queue = odp_queue_lookup("timer_queue");

	period_ns = args->period_us*ODP_TIME_USEC;
	period    = odp_timer_ns_to_tick(test_timer, period_ns);

	ODP_DBG("  [%i] period %"PRIu64" ticks,  %"PRIu64" ns\n", thr,
		period, period_ns);

	tick = odp_timer_current_tick(test_timer);

	ODP_DBG("  [%i] current tick %"PRIu64"\n", thr, tick);

	tick += period;

	if (odp_timer_absolute_tmo(test_timer, tick, queue, ODP_BUFFER_INVALID)
	    == ODP_TIMER_TMO_INVALID){
		ODP_DBG("Timeout request failed\n");
		return;
	}

	num = args->tmo_count;

	while (1) {
		odp_timeout_t tmo;

		buf = odp_schedule_one(&queue, ODP_SCHED_WAIT);

		tmo  = odp_timeout_from_buffer(buf);
		tick = odp_timeout_tick(tmo);

		ODP_DBG("  [%i] timeout, tick %"PRIu64"\n", thr, tick);

		odp_buffer_free(buf);

		num--;

		if (num == 0)
			break;

		tick += period;

		odp_timer_absolute_tmo(test_timer, tick,
				       queue, ODP_BUFFER_INVALID);
	}

	if (odp_queue_sched_type(queue) == ODP_SCHED_SYNC_ATOMIC)
		odp_schedule_release_atomic();
}


/**
 * @internal Worker thread
 *
 * @param ptr  Pointer to test arguments
 *
 * @return Pointer to exit status
 */
static void *run_thread(void *ptr)
{
	int thr;
	odp_buffer_pool_t msg_pool;
	test_args_t *args;

	args = ptr;
	thr  = odp_thread_id();

	printf("Thread %i starts on core %i\n", thr, odp_thread_core());

	/*
	 * Find the buffer pool
	 */
	msg_pool = odp_buffer_pool_lookup("msg_pool");

	if (msg_pool == ODP_BUFFER_POOL_INVALID) {
		ODP_ERR("  [%i] msg_pool not found\n", thr);
		return NULL;
	}

	odp_barrier_sync(&test_barrier);

	test_abs_timeouts(thr, args);


	printf("Thread %i exits\n", thr);
	fflush(NULL);
	return NULL;
}


/**
 * @internal Print help
 */
static void print_usage(void)
{
	printf("\n\nUsage: ./odp_example [options]\n");
	printf("Options:\n");
	printf("  -c, --count <number>    core count, core IDs start from 1\n");
	printf("  -r, --resolution <us>   timeout resolution in usec\n");
	printf("  -m, --min <us>          minimum timeout in usec\n");
	printf("  -x, --max <us>          maximum timeout in usec\n");
	printf("  -p, --period <us>       timeout period in usec\n");
	printf("  -t, --timeouts <count>  timeout repeat count\n");
	printf("  -h, --help              this help\n");
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

	static struct option longopts[] = {
		{"count",      required_argument, NULL, 'c'},
		{"resolution", required_argument, NULL, 'r'},
		{"min",        required_argument, NULL, 'm'},
		{"max",        required_argument, NULL, 'x'},
		{"period",     required_argument, NULL, 'p'},
		{"timeouts",   required_argument, NULL, 't'},
		{"help",       no_argument,       NULL, 'h'},
		{NULL, 0, NULL, 0}
	};

	/* defaults */
	args->core_count    = 0; /* all cores */
	args->resolution_us = 10000;
	args->min_us        = args->resolution_us;
	args->max_us        = 10000000;
	args->period_us     = 1000000;
	args->tmo_count     = 30;

	while (1) {
		opt = getopt_long(argc, argv, "+c:r:m:x:p:t:h",
				 longopts, &long_index);

		if (opt == -1)
			break;	/* No more options */

		switch (opt) {
		case 'c':
			args->core_count = atoi(optarg);
			break;
		case 'r':
			args->resolution_us = atoi(optarg);
			break;
		case 'm':
			args->min_us = atoi(optarg);
			break;
		case 'x':
			args->max_us = atoi(optarg);
			break;
		case 'p':
			args->period_us = atoi(optarg);
			break;
		case 't':
			args->tmo_count = atoi(optarg);
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
	odph_linux_pthread_t thread_tbl[MAX_WORKERS];
	test_args_t args;
	int thr_id;
	int num_workers;
	odp_buffer_pool_t pool;
	void *pool_base;
	odp_queue_t queue;
	int first_core;
	uint64_t cycles, ns;
	odp_queue_param_t param;

	printf("\nODP timer example starts\n");

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
	printf("resolution:         %i usec\n", args.resolution_us);
	printf("min timeout:        %i usec\n", args.min_us);
	printf("max timeout:        %i usec\n", args.max_us);
	printf("period:             %i usec\n", args.period_us);
	printf("timeouts:           %i\n", args.tmo_count);

	/*
	 * Init this thread. It makes also ODP calls when
	 * setting up resources for worker threads.
	 */
	thr_id = odp_thread_create(0);
	odp_init_local(thr_id);

	/*
	 * Create message pool
	 */
	pool_base = odp_shm_reserve("msg_pool",
				    MSG_POOL_SIZE, ODP_CACHE_LINE_SIZE, 0);

	pool = odp_buffer_pool_create("msg_pool", pool_base, MSG_POOL_SIZE,
				      0,
				      ODP_CACHE_LINE_SIZE,
				      ODP_BUFFER_TYPE_TIMEOUT);

	if (pool == ODP_BUFFER_POOL_INVALID) {
		ODP_ERR("Pool create failed.\n");
		return -1;
	}

	/*
	 * Create a queue for timer test
	 */
	memset(&param, 0, sizeof(param));
	param.sched.prio  = ODP_SCHED_PRIO_DEFAULT;
	param.sched.sync  = ODP_SCHED_SYNC_NONE;
	param.sched.group = ODP_SCHED_GROUP_DEFAULT;

	queue = odp_queue_create("timer_queue", ODP_QUEUE_TYPE_SCHED, &param);

	if (queue == ODP_QUEUE_INVALID) {
		ODP_ERR("Timer queue create failed.\n");
		return -1;
	}

	test_timer = odp_timer_create("test_timer", pool,
				      args.resolution_us*ODP_TIME_USEC,
				      args.min_us*ODP_TIME_USEC,
				      args.max_us*ODP_TIME_USEC);

	if (test_timer == ODP_TIMER_INVALID) {
		ODP_ERR("Timer create failed.\n");
		return -1;
	}


	odp_shm_print_all();

	printf("CPU freq %"PRIu64" hz\n", odp_sys_cpu_hz());
	printf("Cycles vs nanoseconds:\n");
	ns = 0;
	cycles = odp_time_ns_to_cycles(ns);

	printf("  %12"PRIu64" ns      ->  %12"PRIu64" cycles\n", ns, cycles);
	printf("  %12"PRIu64" cycles  ->  %12"PRIu64" ns\n", cycles,
	       odp_time_cycles_to_ns(cycles));

	for (ns = 1; ns <= 100*ODP_TIME_SEC; ns *= 10) {
		cycles = odp_time_ns_to_cycles(ns);

		printf("  %12"PRIu64" ns      ->  %12"PRIu64" cycles\n", ns,
		       cycles);
		printf("  %12"PRIu64" cycles  ->  %12"PRIu64" ns\n", cycles,
		       odp_time_cycles_to_ns(cycles));
	}

	printf("\n");

	/* Barrier to sync test case execution */
	odp_barrier_init_count(&test_barrier, num_workers);

	/* Create and launch worker threads */
	odph_linux_pthread_create(thread_tbl, num_workers, first_core,
				  run_thread, &args);

	/* Wait for worker threads to exit */
	odph_linux_pthread_join(thread_tbl, num_workers);

	printf("ODP timer test complete\n\n");

	return 0;
}
