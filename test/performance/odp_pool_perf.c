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

typedef struct test_options_t {
	uint32_t num_cpu;
	uint32_t num_event;
	uint32_t num_round;
	uint32_t max_burst;

} test_options_t;

typedef struct test_stat_t {
	uint64_t rounds;
	uint64_t frees;
	uint64_t events;
	uint64_t nsec;
	uint64_t cycles;

} test_stat_t;

typedef struct test_global_t {
	test_options_t test_options;

	odp_barrier_t barrier;
	odp_pool_t pool;
	odp_cpumask_t cpumask;
	odph_odpthread_t thread_tbl[ODP_THREAD_COUNT_MAX];
	test_stat_t stat[ODP_THREAD_COUNT_MAX];

} test_global_t;

test_global_t test_global;

static void print_usage(void)
{
	printf("\n"
	       "Pool performance test\n"
	       "\n"
	       "Usage: odp_pool_perf [options]\n"
	       "\n"
	       "  -c, --num_cpu          Number of CPUs (worker threads). 0: all available CPUs. Default 1.\n"
	       "  -e, --num_event        Number of events\n"
	       "  -r, --num_round        Number of rounds\n"
	       "  -b, --burst            Maximum number of events per operation\n"
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
		{"num_event", required_argument, NULL, 'e'},
		{"num_round", required_argument, NULL, 'r'},
		{"burst",     required_argument, NULL, 'b'},
		{"help",      no_argument,       NULL, 'h'},
		{NULL, 0, NULL, 0}
	};

	static const char *shortopts = "+c:e:r:b:h";

	test_options->num_cpu   = 1;
	test_options->num_event = 1000;
	test_options->num_round = 100000;
	test_options->max_burst = 100;

	while (1) {
		opt = getopt_long(argc, argv, shortopts, longopts, &long_index);

		if (opt == -1)
			break;

		switch (opt) {
		case 'c':
			test_options->num_cpu = atoi(optarg);
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
		case 'h':
			/* fall through */
		default:
			print_usage();
			ret = -1;
			break;
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
	uint32_t num_event = test_options->num_event;
	uint32_t num_round = test_options->num_round;
	uint32_t max_burst = test_options->max_burst;
	uint32_t num_cpu   = test_options->num_cpu;

	printf("\nPool performance test\n");
	printf("  num cpu    %u\n", num_cpu);
	printf("  num rounds %u\n", num_round);
	printf("  num events %u\n", num_event);
	printf("  max burst  %u\n\n", max_burst);

	if (odp_pool_capability(&pool_capa)) {
		printf("Error: Pool capa failed.\n");
		return -1;
	}

	if (num_event > pool_capa.buf.max_num) {
		printf("Max events supported %u\n", pool_capa.buf.max_num);
		return -1;
	}

	odp_pool_param_init(&pool_param);
	pool_param.type = ODP_POOL_BUFFER;
	pool_param.buf.num = num_event;

	pool = odp_pool_create("pool perf", &pool_param);

	if (pool == ODP_POOL_INVALID) {
		printf("Error: Pool create failed.\n");
		return -1;
	}

	global->pool = pool;

	return 0;
}

static int test_pool(void *arg)
{
	int num, ret, thr;
	uint32_t i, rounds;
	uint64_t c1, c2, cycles, nsec;
	uint64_t events, frees;
	odp_time_t t1, t2;
	test_global_t *global = arg;
	test_options_t *test_options = &global->test_options;
	uint32_t num_round = test_options->num_round;
	uint32_t max_burst = test_options->max_burst;
	odp_pool_t pool = global->pool;
	odp_buffer_t buf[max_burst];

	thr = odp_thread_id();

	for (i = 0; i < max_burst; i++)
		buf[i] = ODP_BUFFER_INVALID;

	events = 0;
	frees = 0;
	ret = 0;

	/* Start all workers at the same time */
	odp_barrier_wait(&global->barrier);

	t1 = odp_time_local();
	c1 = odp_cpu_cycles();

	for (rounds = 0; rounds < num_round; rounds++) {
		num = odp_buffer_alloc_multi(pool, buf, max_burst);

		if (odp_likely(num > 0)) {
			events += num;
			odp_buffer_free_multi(buf, num);
			frees++;
			continue;
		}

		if (num < 0) {
			printf("Error: Alloc failed. Round %u\n", rounds);
			ret = -1;
			break;
		}
	}

	c2 = odp_cpu_cycles();
	t2 = odp_time_local();

	nsec   = odp_time_diff_ns(t2, t1);
	cycles = odp_cpu_cycles_diff(c2, c1);

	/* Update stats*/
	global->stat[thr].rounds = rounds;
	global->stat[thr].frees  = frees;
	global->stat[thr].events = events;
	global->stat[thr].nsec   = nsec;
	global->stat[thr].cycles = cycles;

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
	thr_params.start    = test_pool;
	thr_params.arg      = global;

	if (odph_odpthreads_create(global->thread_tbl, &global->cpumask,
				   &thr_params) != num_cpu)
		return -1;

	return 0;
}

static void print_stat(test_global_t *global)
{
	int i, num;
	double rounds_ave, frees_ave, events_ave, nsec_ave, cycles_ave;
	test_options_t *test_options = &global->test_options;
	int num_cpu = test_options->num_cpu;
	uint64_t rounds_sum = 0;
	uint64_t frees_sum = 0;
	uint64_t events_sum = 0;
	uint64_t nsec_sum = 0;
	uint64_t cycles_sum = 0;

	/* Averages */
	for (i = 0; i < ODP_THREAD_COUNT_MAX; i++) {
		rounds_sum += global->stat[i].rounds;
		frees_sum  += global->stat[i].frees;
		events_sum += global->stat[i].events;
		nsec_sum   += global->stat[i].nsec;
		cycles_sum += global->stat[i].cycles;
	}

	if (rounds_sum == 0) {
		printf("No results.\n");
		return;
	}

	rounds_ave = rounds_sum / num_cpu;
	frees_ave  = frees_sum / num_cpu;
	events_ave = events_sum / num_cpu;
	nsec_ave   = nsec_sum / num_cpu;
	cycles_ave = cycles_sum / num_cpu;
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
	printf("  alloc calls:          %.3f\n", rounds_ave);
	printf("  free calls:           %.3f\n", frees_ave);
	printf("  duration:             %.3f msec\n", nsec_ave / 1000000);
	printf("  num cycles:           %.3f M\n", cycles_ave / 1000000);
	printf("  cycles per round:     %.3f\n",
	       cycles_ave / rounds_ave);
	printf("  cycles per event:     %.3f\n",
	       cycles_ave / events_ave);
	printf("  ave events allocated: %.3f\n",
	       events_ave / rounds_ave);
	printf("  operations per sec:   %.3f M\n",
	       (1000.0 * rounds_ave) / nsec_ave);
	printf("  events per sec:       %.3f M\n\n",
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
	init.not_used.feat.schedule = 1;
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

	/* Start workers */
	start_workers(global, instance);

	/* Wait workers to exit */
	odph_odpthreads_join(global->thread_tbl);

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
