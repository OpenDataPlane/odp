/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2024 Nokia
 */

/**
 * @example odp_random.c
 *
 * Performance test application for random data APIs
 *
 * @cond _ODP_HIDE_FROM_DOXYGEN_
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <getopt.h>

#include <odp_api.h>
#include <odp/helper/odph_api.h>

#define PSEUDO_RANDOM (-1)

#define MB (1024ull * 1024ull)

typedef struct test_global_t test_global_t;

typedef struct thread_arg_t {
	test_global_t *global;
	int thread_idx;
	uint8_t *data;

} thread_arg_t;

struct test_global_t {
	odp_barrier_t barrier;
	odp_random_kind_t type;
	uint8_t *data;
	uint32_t rounds;

	thread_arg_t thread_arg[ODP_THREAD_COUNT_MAX];

	struct {
		uint64_t nsec[ODP_THREAD_COUNT_MAX];
		uint64_t sum[ODP_THREAD_COUNT_MAX];
		uint64_t min[ODP_THREAD_COUNT_MAX];
		uint64_t max[ODP_THREAD_COUNT_MAX];
	} stat;
};

/* Command line options */
typedef struct {
	int mode;
	int num_threads;
	uint32_t size;
	uint32_t rounds;
	uint64_t delay;

} options_t;

static options_t options;
static const options_t options_def = {
	.mode = 0,
	.num_threads = 1,
	.size = 256,
	.rounds = 100000,
	.delay = 0,
};

static void print_usage(void)
{
	printf("\n"
	       "random data performance test\n"
	       "\n"
	       "Usage: odp_random [options]\n"
	       "\n"
	       "  -m, --mode    Test mode select (default: 0):\n"
	       "                  0: Data throughput\n"
	       "                  1: Data generation latency (size: 8B by default)\n"
	       "  -c, --num_cpu Number of CPUs (worker threads). 0: all available CPUs. Default 1.\n"
	       "  -s, --size    Size of buffer in bytes. Default %u.\n"
	       "  -r, --rounds  Number of test rounds. Default %u.\n"
	       "                Divided by 100 for ODP_RANDOM_TRUE.\n"
	       "  -d, --delay   Delay (nsec) between buffer fills. Default %" PRIu64 ".\n"
	       "                Affects only latency mode.\n"
	       "  -h, --help    This help.\n"
	       "\n",
	       options_def.size, options_def.rounds, options_def.delay);
}

static int parse_options(int argc, char *argv[])
{
	int opt;
	int long_index;
	int ret = 0;

	static const struct option longopts[] = {
		{ "mode", required_argument, NULL, 'm' },
		{ "num_cpu", required_argument, NULL, 'c' },
		{ "size", required_argument, NULL, 's' },
		{ "rounds", required_argument, NULL, 'r' },
		{ "delay", required_argument, NULL, 'd' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 }
	};

	static const char *shortopts = "+m:c:s:r:d:h";

	options = options_def;
	options.size = 0;

	while (1) {
		opt = getopt_long(argc, argv, shortopts, longopts, &long_index);

		if (opt == -1)
			break;

		switch (opt) {
		case 'm':
			options.mode = atoi(optarg);
			break;
		case 'c':
			options.num_threads = atol(optarg);
			break;
		case 's':
			options.size = atol(optarg);
			break;
		case 'r':
			options.rounds = atol(optarg);
			break;
		case 'd':
			options.delay = atol(optarg);
			break;
		case 'h':
			/* fall through */
		default:
			print_usage();
			ret = -1;
			break;
		}
	}

	if (options.num_threads < 1 || options.num_threads > ODP_THREAD_COUNT_MAX) {
		ODPH_ERR("Bad number of threads: %i\n", options.num_threads);
		return -1;
	}

	if (options.size == 0) {
		options.size = options_def.size;

		if (options.mode)
			options.size = 8;
	}

	printf("\nOptions:\n");
	printf("------------------------\n");
	printf("  mode:      %i\n", options.mode);
	printf("  num_cpu:   %i\n", options.num_threads);
	printf("  size:      %u\n", options.size);
	printf("  rounds:    %u\n", options.rounds);
	printf("  delay:     %" PRIu64 "\n", options.delay);
	printf("\n");

	return ret;
}

static inline void random_data_loop(odp_random_kind_t type, uint32_t rounds,
				    uint8_t *data, uint32_t size)
{
	uint32_t i;
	int32_t ret;

	if ((int)type == PSEUDO_RANDOM) {
		uint64_t seed = 0;

		for (i = 0; i < rounds; i++) {
			uint32_t pos = 0;

			while (pos < size) {
				ret = odp_random_test_data(data + pos, size - pos, &seed);

				if (ret < 0) {
					ODPH_ERR("odp_random_test_data() failed\n");
					exit(EXIT_FAILURE);
				}

				pos += ret;
			}
		}
	} else {
		for (i = 0; i < rounds; i++) {
			uint32_t pos = 0;

			while (pos < size) {
				ret = odp_random_data(data + pos, size - pos, type);

				if (ret < 0) {
					ODPH_ERR("odp_random_data() failed\n");
					exit(EXIT_FAILURE);
				}

				pos += ret;
			}
		}
	}
}

static int test_random_perf(void *ptr)
{
	odp_time_t start;
	uint64_t nsec;
	thread_arg_t *thread_arg = ptr;
	test_global_t *global = thread_arg->global;
	odp_random_kind_t type = global->type;
	int thread_idx = thread_arg->thread_idx;
	uint8_t *data = thread_arg->data;
	uint32_t size = options.size;
	uint32_t rounds = global->rounds;

	/* One warm up round */
	random_data_loop(type, 1, data, size);

	odp_barrier_wait(&global->barrier);

	/* Test run */
	start = odp_time_local();

	random_data_loop(type, rounds, data, size);

	nsec = odp_time_diff_ns(odp_time_local(), start);

	global->stat.nsec[thread_idx] = nsec;

	return 0;
}

static inline void random_data_latency(test_global_t *global, int thread_idx,
				       uint32_t rounds, uint8_t *data, uint32_t size)
{
	uint32_t i;
	int32_t ret;
	odp_time_t t1, t2, start;
	uint64_t nsec;
	odp_random_kind_t type = global->type;
	uint64_t delay = options.delay;
	uint64_t min = UINT64_MAX;
	uint64_t max = 0;
	uint64_t sum = 0;
	uint64_t seed = 0;

	start = odp_time_local();

	for (i = 0; i < rounds; i++) {
		uint32_t pos = 0;

		if (delay)
			odp_time_wait_ns(delay);

		if ((int)type == PSEUDO_RANDOM) {
			t1 = odp_time_local_strict();
			while (pos < size) {
				ret = odp_random_test_data(data + pos, size - pos, &seed);

				if (ret < 0) {
					ODPH_ERR("odp_random_test_data() failed\n");
					exit(EXIT_FAILURE);
				}

				pos += ret;
			}
			t2 = odp_time_local_strict();
		} else {
			t1 = odp_time_local_strict();
			while (pos < size) {
				ret = odp_random_data(data + pos, size - pos, type);

				if (ret < 0) {
					ODPH_ERR("odp_random_data() failed\n");
					exit(EXIT_FAILURE);
				}

				pos += ret;
			}
			t2 = odp_time_local_strict();
		}

		nsec = odp_time_diff_ns(t2, t1);
		sum += nsec;

		if (nsec > max)
			max = nsec;
		if (nsec < min)
			min = nsec;
	}

	nsec = odp_time_diff_ns(odp_time_local(), start);

	global->stat.nsec[thread_idx] = nsec;
	global->stat.sum[thread_idx] = sum;
	global->stat.min[thread_idx] = min;
	global->stat.max[thread_idx] = max;
}

static int test_random_latency(void *ptr)
{
	thread_arg_t *thread_arg = ptr;
	test_global_t *global = thread_arg->global;
	odp_random_kind_t type = global->type;
	int thread_idx = thread_arg->thread_idx;
	uint8_t *data = thread_arg->data;
	uint32_t size = options.size;
	uint32_t rounds = global->rounds;

	/* One warm up round */
	random_data_loop(type, 1, data, size);

	odp_barrier_wait(&global->barrier);

	/* Test run */
	random_data_latency(global, thread_idx, rounds, data, size);

	return 0;
}

static uint32_t type_rounds(odp_random_kind_t type)
{
	switch (type) {
	case ODP_RANDOM_TRUE:
		return options.rounds / 100;
	default:
		return options.rounds;
	}
}

static void test_type(odp_instance_t instance, test_global_t *global, odp_random_kind_t type)
{
	int i;
	int num_threads = options.num_threads;
	uint32_t rounds = type_rounds(type);
	uint32_t size = options.size;

	memset(&global->stat, 0, sizeof(global->stat));
	global->type = type;
	global->rounds = rounds;
	odp_barrier_init(&global->barrier, num_threads);

	odp_cpumask_t cpumask;
	odph_thread_common_param_t thr_common;
	odph_thread_param_t thr_param[num_threads];
	odph_thread_t thr_worker[num_threads];

	if (odp_cpumask_default_worker(&cpumask, num_threads) != num_threads) {
		ODPH_ERR("Failed to get default CPU mask.\n");
		exit(EXIT_FAILURE);
	}

	odph_thread_common_param_init(&thr_common);
	thr_common.instance = instance;
	thr_common.cpumask = &cpumask;

	for (i = 0; i < num_threads; i++) {
		odph_thread_param_init(&thr_param[i]);
		thr_param[i].thr_type = ODP_THREAD_WORKER;
		thr_param[i].arg      = &global->thread_arg[i];

		if (options.mode == 0)
			thr_param[i].start = test_random_perf;
		else
			thr_param[i].start = test_random_latency;
	}

	memset(&thr_worker, 0, sizeof(thr_worker));

	if (odph_thread_create(thr_worker, &thr_common, thr_param, num_threads) != num_threads) {
		ODPH_ERR("Failed to create worker threads.\n");
		exit(EXIT_FAILURE);
	}

	odph_thread_join_result_t res[num_threads];

	if (odph_thread_join_result(thr_worker, res, num_threads) != num_threads) {
		ODPH_ERR("Failed to join worker threads.\n");
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < num_threads; i++) {
		if (res[i].is_sig || res[i].ret != 0) {
			ODPH_ERR("Worker thread failure%s: %d\n", res[i].is_sig ?
					" (signaled)" : "", res[i].ret);
			exit(EXIT_FAILURE);
		}
	}

	double mb, seconds, nsec = 0;

	for (i = 0; i < num_threads; i++)
		nsec += global->stat.nsec[i];

	nsec /= num_threads;

	switch (type) {
	case ODP_RANDOM_BASIC:
		printf("ODP_RANDOM_BASIC\n");
		break;
	case ODP_RANDOM_CRYPTO:
		printf("ODP_RANDOM_CRYPTO\n");
		break;
	case ODP_RANDOM_TRUE:
		printf("ODP_RANDOM_TRUE\n");
		break;
	default:
		printf("odp_random_test_data\n");
	}

	printf("--------------------\n");
	printf("threads: %d  size: %u B  rounds: %u  ", num_threads, size, rounds);
	mb = (uint64_t)num_threads * (uint64_t)size * (uint64_t)rounds;
	mb /= MB;
	seconds = (double)nsec / (double)ODP_TIME_SEC_IN_NS;
	printf("MB: %.3f  seconds: %.3f  ", mb, seconds);
	printf("MB/s: %.3f  ", mb / seconds);
	printf("MB/s/thread: %.3f\n", mb / seconds / (double)num_threads);

	if (options.mode) {
		double ave;
		uint64_t min = UINT64_MAX;
		uint64_t max = 0;
		uint64_t sum = 0;

		printf("  latency (nsec)\n");
		printf("  thread      min      max        ave\n");
		for (i = 0; i < num_threads; i++) {
			ave  = (double)global->stat.sum[i] / rounds;
			sum += global->stat.sum[i];

			if (global->stat.min[i] < min)
				min = global->stat.min[i];

			if (global->stat.max[i] > max)
				max = global->stat.max[i];

			printf("%8i %8" PRIu64 " %8" PRIu64 " %10.1f\n", i, global->stat.min[i],
			       global->stat.max[i], ave);
		}

		printf("     all %8" PRIu64 " %8" PRIu64 " %10.1f\n",
		       min, max, ((double)sum / rounds) / num_threads);
	}

	printf("\n");
}

int main(int argc, char **argv)
{
	odph_helper_options_t helper_options;
	odp_instance_t instance;
	odp_init_t init;
	odp_shm_t shm_glb, shm_data;
	test_global_t *global;
	int num_threads, i;
	uint64_t tot_size, size;
	uint8_t *addr;

	/* Let helper collect its own arguments (e.g. --odph_proc) */
	argc = odph_parse_options(argc, argv);

	if (odph_options(&helper_options)) {
		ODPH_ERR("Failed to read ODP helper options.\n");
		exit(EXIT_FAILURE);
	}

	if (parse_options(argc, argv))
		exit(EXIT_FAILURE);

	/* List features not to be used */
	odp_init_param_init(&init);
	init.not_used.feat.cls = 1;
	init.not_used.feat.compress = 1;
	init.not_used.feat.crypto = 1;
	init.not_used.feat.ipsec = 1;
	init.not_used.feat.schedule = 1;
	init.not_used.feat.stash = 1;
	init.not_used.feat.timer = 1;
	init.not_used.feat.tm = 1;
	init.mem_model = helper_options.mem_model;

	/* Init ODP before calling anything else */
	if (odp_init_global(&instance, &init, NULL)) {
		ODPH_ERR("Global init failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Init this thread */
	if (odp_init_local(instance, ODP_THREAD_CONTROL)) {
		ODPH_ERR("Local init failed.\n");
		exit(EXIT_FAILURE);
	}

	odp_sys_info_print();

	global = NULL;
	shm_glb = odp_shm_reserve("test_globals", sizeof(test_global_t), ODP_CACHE_LINE_SIZE, 0);

	if (shm_glb != ODP_SHM_INVALID)
		global = (test_global_t *)odp_shm_addr(shm_glb);

	if (!global) {
		ODPH_ERR("Failed to reserve shm\n");
		exit(EXIT_FAILURE);
	}

	memset(global, 0, sizeof(test_global_t));

	num_threads = options.num_threads;
	addr = NULL;
	size = ODP_CACHE_LINE_SIZE + ODP_CACHE_LINE_ROUNDUP(options.size);
	tot_size = num_threads * size;
	shm_data = odp_shm_reserve("test_data", tot_size, ODP_CACHE_LINE_SIZE, 0);

	if (shm_data != ODP_SHM_INVALID)
		addr = odp_shm_addr(shm_data);

	if (!addr) {
		ODPH_ERR("Failed to reserve shm: size %" PRIu64 " bytes\n", tot_size);
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < num_threads; i++) {
		global->thread_arg[i].global = global;
		global->thread_arg[i].thread_idx = i;
		global->thread_arg[i].data = addr + i * size;
	}

	odp_shm_print_all();

	switch (odp_random_max_kind()) {
	case ODP_RANDOM_TRUE:
		test_type(instance, global, ODP_RANDOM_TRUE);
		/* fall through */
	case ODP_RANDOM_CRYPTO:
		test_type(instance, global, ODP_RANDOM_CRYPTO);
		/* fall through */
	default:
		test_type(instance, global, ODP_RANDOM_BASIC);
		test_type(instance, global, PSEUDO_RANDOM);
	}

	if (odp_shm_free(shm_data)) {
		ODPH_ERR("odp_shm_free() failed\n");
		exit(EXIT_FAILURE);
	}

	if (odp_shm_free(shm_glb)) {
		ODPH_ERR("odp_shm_free() failed\n");
		exit(EXIT_FAILURE);
	}

	if (odp_term_local()) {
		ODPH_ERR("Local terminate failed.\n");
		exit(EXIT_FAILURE);
	}

	if (odp_term_global(instance)) {
		ODPH_ERR("Global terminate failed.\n");
		exit(EXIT_FAILURE);
	}

	return 0;
}
