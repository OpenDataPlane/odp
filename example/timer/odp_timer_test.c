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

#include <example_debug.h>

/* ODP main header */
#include <odp.h>

/* ODP helper for Linux apps */
#include <odp/helper/linux.h>

/* GNU lib C */
#include <getopt.h>


#define MAX_WORKERS           32            /**< Max worker threads */
#define NUM_TMOS              10000         /**< Number of timers */


/** Test arguments */
typedef struct {
	int cpu_count;     /**< CPU count*/
	int resolution_us; /**< Timeout resolution in usec*/
	int min_us;        /**< Minimum timeout in usec*/
	int max_us;        /**< Maximum timeout in usec*/
	int period_us;     /**< Timeout period in usec*/
	int tmo_count;     /**< Timeout count*/
} test_args_t;


/** @private Barrier for test synchronisation */
static odp_barrier_t test_barrier;

/** @private Pool handle */
static odp_pool_t pool;

/** @private Timer pool handle */
static odp_timer_pool_t tp;

/** @private Number of timeouts to receive */
static odp_atomic_u32_t remain;

/** @private Timer set status ASCII strings */
static const char *timerset2str(odp_timer_set_t val)
{
	switch (val) {
	case ODP_TIMER_SUCCESS:
		return "success";
	case ODP_TIMER_TOOEARLY:
		return "too early";
	case ODP_TIMER_TOOLATE:
		return "too late";
	case ODP_TIMER_NOEVENT:
		return "no event";
	default:
		return "?";
	}
};

/** @private Helper struct for timers */
struct test_timer {
	odp_timer_t tim;
	odp_event_t ev;
};

/** @private Array of all timer helper structs */
static struct test_timer tt[256];

/** @private test timeout */
static void test_abs_timeouts(int thr, test_args_t *args)
{
	uint64_t period;
	uint64_t period_ns;
	odp_queue_t queue;
	uint64_t tick;
	struct test_timer *ttp;
	odp_timeout_t tmo;

	EXAMPLE_DBG("  [%i] test_timeouts\n", thr);

	queue = odp_queue_lookup("timer_queue");

	period_ns = args->period_us*ODP_TIME_USEC;
	period    = odp_timer_ns_to_tick(tp, period_ns);

	EXAMPLE_DBG("  [%i] period %"PRIu64" ticks,  %"PRIu64" ns\n", thr,
		    period, period_ns);

	EXAMPLE_DBG("  [%i] current tick %"PRIu64"\n", thr,
		    odp_timer_current_tick(tp));

	ttp = &tt[thr - 1]; /* Thread starts at 1 */
	ttp->tim = odp_timer_alloc(tp, queue, ttp);
	if (ttp->tim == ODP_TIMER_INVALID) {
		EXAMPLE_ERR("Failed to allocate timer\n");
		return;
	}
	tmo = odp_timeout_alloc(pool);
	if (tmo == ODP_TIMEOUT_INVALID) {
		EXAMPLE_ERR("Failed to allocate timeout\n");
		return;
	}
	ttp->ev = odp_timeout_to_event(tmo);
	tick = odp_timer_current_tick(tp);

	while ((int)odp_atomic_load_u32(&remain) > 0) {
		odp_event_t ev;
		odp_timer_set_t rc;

		tick += period;
		rc = odp_timer_set_abs(ttp->tim, tick, &ttp->ev);
		if (odp_unlikely(rc != ODP_TIMER_SUCCESS)) {
			/* Too early or too late timeout requested */
			EXAMPLE_ABORT("odp_timer_set_abs() failed: %s\n",
				      timerset2str(rc));
		}

		/* Get the next expired timeout.
		 * We invoke the scheduler in a loop with a timeout because
		 * we are not guaranteed to receive any more timeouts. The
		 * scheduler isn't guaranteeing fairness when scheduling
		 * buffers to threads.
		 * Use 1.5 second timeout for scheduler */
		uint64_t sched_tmo =
			odp_schedule_wait_time(1500000000ULL);
		do {
			ev = odp_schedule(&queue, sched_tmo);
			/* Check if odp_schedule() timed out, possibly there
			 * are no remaining timeouts to receive */
		} while (ev == ODP_EVENT_INVALID &&
			 (int)odp_atomic_load_u32(&remain) > 0);

		if (ev == ODP_EVENT_INVALID)
			break; /* No more timeouts */
		if (odp_event_type(ev) != ODP_EVENT_TIMEOUT) {
			/* Not a default timeout event */
			EXAMPLE_ABORT("Unexpected event type (%u) received\n",
				      odp_event_type(ev));
		}
		odp_timeout_t tmo = odp_timeout_from_event(ev);
		tick = odp_timeout_tick(tmo);
		ttp = odp_timeout_user_ptr(tmo);
		ttp->ev = ev;
		if (!odp_timeout_fresh(tmo)) {
			/* Not the expected expiration tick, timer has
			 * been reset or cancelled or freed */
			EXAMPLE_ABORT("Unexpected timeout received (timer %x, tick %"PRIu64")\n",
				      ttp->tim, tick);
		}
		EXAMPLE_DBG("  [%i] timeout, tick %"PRIu64"\n", thr, tick);

		odp_atomic_dec_u32(&remain);
	}

	/* Cancel and free last timer used */
	(void)odp_timer_cancel(ttp->tim, &ttp->ev);
	if (ttp->ev != ODP_EVENT_INVALID)
		odp_timeout_free(odp_timeout_from_event(ttp->ev));
	else
		EXAMPLE_ERR("Lost timeout event at timer cancel\n");
	/* Since we have cancelled the timer, there is no timeout event to
	 * return from odp_timer_free() */
	(void)odp_timer_free(ttp->tim);
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
	odp_pool_t msg_pool;
	test_args_t *args;

	args = ptr;
	thr  = odp_thread_id();

	printf("Thread %i starts on cpu %i\n", thr, odp_thread_cpu());

	/*
	 * Find the pool
	 */
	msg_pool = odp_pool_lookup("msg_pool");

	if (msg_pool == ODP_POOL_INVALID) {
		EXAMPLE_ERR("  [%i] msg_pool not found\n", thr);
		return NULL;
	}

	odp_barrier_wait(&test_barrier);

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
	printf("  -c, --count <number>    CPU count\n");
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
	args->cpu_count     = 0; /* all CPU's */
	args->resolution_us = 10000;
	args->min_us        = 0;
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
			args->cpu_count = atoi(optarg);
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
	int num_workers;
	odp_queue_t queue;
	uint64_t cycles, ns;
	odp_queue_param_t param;
	odp_pool_param_t params;
	odp_timer_pool_param_t tparams;
	odp_timer_pool_info_t tpinfo;
	odp_cpumask_t cpumask;
	char cpumaskstr[64];

	printf("\nODP timer example starts\n");

	memset(&args, 0, sizeof(args));
	parse_args(argc, argv, &args);

	memset(thread_tbl, 0, sizeof(thread_tbl));

	if (odp_init_global(NULL, NULL)) {
		printf("ODP global init failed.\n");
		return -1;
	}

	/* Init this thread. */
	if (odp_init_local()) {
		printf("ODP local init failed.\n");
		return -1;
	}

	printf("\n");
	printf("ODP system info\n");
	printf("---------------\n");
	printf("ODP API version: %s\n",        odp_version_api_str());
	printf("CPU model:       %s\n",        odp_sys_cpu_model_str());
	printf("CPU freq (hz):   %"PRIu64"\n", odp_sys_cpu_hz());
	printf("Cache line size: %i\n",        odp_sys_cache_line_size());
	printf("Max CPU count:   %i\n",        odp_sys_cpu_count());

	printf("\n");

	/* Default to system CPU count unless user specified */
	num_workers = MAX_WORKERS;
	if (args.cpu_count)
		num_workers = args.cpu_count;

	/*
	 * By default CPU #0 runs Linux kernel background tasks.
	 * Start mapping thread from CPU #1
	 */
	num_workers = odph_linux_cpumask_default(&cpumask, num_workers);
	odp_cpumask_to_str(&cpumask, cpumaskstr, sizeof(cpumaskstr));

	printf("num worker threads: %i\n", num_workers);
	printf("first CPU:          %i\n", odp_cpumask_first(&cpumask));
	printf("cpu mask:           %s\n", cpumaskstr);

	printf("resolution:         %i usec\n", args.resolution_us);
	printf("min timeout:        %i usec\n", args.min_us);
	printf("max timeout:        %i usec\n", args.max_us);
	printf("period:             %i usec\n", args.period_us);
	printf("timeouts:           %i\n", args.tmo_count);

	/*
	 * Create pool for timeouts
	 */
	params.tmo.num   = NUM_TMOS;
	params.type      = ODP_POOL_TIMEOUT;

	pool = odp_pool_create("msg_pool", ODP_SHM_NULL, &params);

	if (pool == ODP_POOL_INVALID) {
		EXAMPLE_ERR("Pool create failed.\n");
		return -1;
	}

	tparams.res_ns = args.resolution_us*ODP_TIME_USEC;
	tparams.min_tmo = args.min_us*ODP_TIME_USEC;
	tparams.max_tmo = args.max_us*ODP_TIME_USEC;
	tparams.num_timers = num_workers; /* One timer per worker */
	tparams.private = 0; /* Shared */
	tparams.clk_src = ODP_CLOCK_CPU;
	tp = odp_timer_pool_create("timer_pool", &tparams);
	if (tp == ODP_TIMER_POOL_INVALID) {
		EXAMPLE_ERR("Timer pool create failed.\n");
		return -1;
	}
	odp_timer_pool_start();

	odp_shm_print_all();
	(void)odp_timer_pool_info(tp, &tpinfo);
	printf("Timer pool\n");
	printf("----------\n");
	printf("  name: %s\n", tpinfo.name);
	printf("  resolution: %"PRIu64" ns\n", tpinfo.param.res_ns);
	printf("  min tmo: %"PRIu64" ticks\n", tpinfo.param.min_tmo);
	printf("  max tmo: %"PRIu64" ticks\n", tpinfo.param.max_tmo);
	printf("\n");

	/*
	 * Create a queue for timer test
	 */
	memset(&param, 0, sizeof(param));
	param.sched.prio  = ODP_SCHED_PRIO_DEFAULT;
	param.sched.sync  = ODP_SCHED_SYNC_NONE;
	param.sched.group = ODP_SCHED_GROUP_DEFAULT;

	queue = odp_queue_create("timer_queue", ODP_QUEUE_TYPE_SCHED, &param);

	if (queue == ODP_QUEUE_INVALID) {
		EXAMPLE_ERR("Timer queue create failed.\n");
		return -1;
	}

	printf("CPU freq %"PRIu64" Hz\n", odp_sys_cpu_hz());
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

	/* Initialize number of timeouts to receive */
	odp_atomic_init_u32(&remain, args.tmo_count * num_workers);

	/* Barrier to sync test case execution */
	odp_barrier_init(&test_barrier, num_workers);

	/* Create and launch worker threads */
	odph_linux_pthread_create(thread_tbl, &cpumask,
				  run_thread, &args);

	/* Wait for worker threads to exit */
	odph_linux_pthread_join(thread_tbl, num_workers);

	printf("ODP timer test complete\n\n");

	return 0;
}
