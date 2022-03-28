/* Copyright (c) 2021-2022, Nokia
 *
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
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
	} stat;
};

/* Command line options */
typedef struct {
	int num_threads;
	uint32_t size;
	uint32_t rounds;
} options_t;

static options_t options;
static const options_t options_def = {
	.num_threads = 1,
	.size = 256,
	.rounds = 100000,
};

static void print_usage(void)
{
	printf("\n"
	       "random data performance test\n"
	       "\n"
	       "Usage: odp_random [options]\n"
	       "\n"
	       "  -t, --threads Number of worker threads (default %u)\n"
	       "  -s, --size    Size of buffer in bytes (default %u)\n"
	       "  -r, --rounds  Number of test rounds (default %u)\n"
	       "                Divided by 100 for ODP_RANDOM_TRUE\n"
	       "  -h, --help    This help\n"
	       "\n",
	       options_def.num_threads, options_def.size, options_def.rounds);
}

static int parse_options(int argc, char *argv[])
{
	int opt;
	int long_index;
	int ret = 0;

	static const struct option longopts[] = {
		{ "threads", required_argument, NULL, 't' },
		{ "size", required_argument, NULL, 's' },
		{ "rounds", required_argument, NULL, 'r' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 }
	};

	static const char *shortopts = "+t:s:r:h";

	options = options_def;

	while (1) {
		opt = getopt_long(argc, argv, shortopts, longopts, &long_index);

		if (opt == -1)
			break;

		switch (opt) {
		case 't':
			options.num_threads = atol(optarg);
			break;
		case 's':
			options.size = atol(optarg);
			break;
		case 'r':
			options.rounds = atol(optarg);
			break;
		case 'h':
			/* fall through */
		default:
			print_usage();
			ret = -1;
			break;
		}
	}

	if (options.size < 1) {
		ODPH_ERR("Invalid size: %" PRIu32 "\n", options.size);
		return -1;
	}

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
		thr_param[i].start    = test_random_perf;
		thr_param[i].arg      = &global->thread_arg[i];
	}

	memset(&thr_worker, 0, sizeof(thr_worker));

	if (odph_thread_create(thr_worker, &thr_common, thr_param, num_threads) != num_threads) {
		ODPH_ERR("Failed to create worker threads.\n");
		exit(EXIT_FAILURE);
	}

	if (odph_thread_join(thr_worker, num_threads) != num_threads) {
		ODPH_ERR("Failed to join worker threads.\n");
		exit(EXIT_FAILURE);
	}

	double mb, seconds, nsec = 0;

	for (i = 0; i < ODP_THREAD_COUNT_MAX; i++)
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
	printf("threads: %d  size: %u B  rounds: %u  ", num_threads,
	       options.size, rounds);
	mb = (uint64_t)num_threads * (uint64_t)options.size *
	     (uint64_t)rounds;
	mb /= MB;
	seconds = (double)nsec / (double)ODP_TIME_SEC_IN_NS;
	printf("MB: %.3f  seconds: %.3f  ", mb, seconds);
	printf("MB/s: %.3f  ", mb / seconds);
	printf("MB/s/thread: %.3f", mb / seconds / (double)num_threads);
	printf("\n\n");
}

int main(int argc, char **argv)
{
	odp_instance_t instance;
	odp_init_t init;
	odp_shm_t shm_glb, shm_data;
	test_global_t *global;
	int num_threads, i;
	uint64_t tot_size, size;
	uint8_t *addr;

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
