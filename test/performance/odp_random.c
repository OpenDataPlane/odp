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

#define MB (1024ull * 1024ull)

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

const char *shm_name = "odp_random_test";

typedef struct test_shm_t {
	odp_barrier_t barrier;
	odp_random_kind_t type;
	uint64_t nsec[ODP_THREAD_COUNT_MAX];
} test_shm_t;

static test_shm_t *shm_lookup(void)
{
	test_shm_t *shm = NULL;
	odp_shm_t shm_hdl = odp_shm_lookup(shm_name);

	if (shm_hdl != ODP_SHM_INVALID)
		shm = (test_shm_t *)odp_shm_addr(shm_hdl);

	return shm;
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

static int test_random(void *p)
{
	(void)p;

	uint8_t *buf, *data;
	const unsigned long page = ODP_PAGE_SIZE;
	odp_time_t start;
	uint64_t nsec;
	uint32_t rounds;
	test_shm_t *shm = shm_lookup();

	if (!shm) {
		ODPH_ERR("Failed to look up shm %s\n", shm_name);
		exit(EXIT_FAILURE);
	}

	rounds = type_rounds(shm->type);

	/* One extra page for alignment. */
	buf = (uint8_t *)malloc(options.size + page);

	if (!buf) {
		ODPH_ERR("Memory allocation failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Align to start of page. */
	data = (uint8_t *)(((uintptr_t)buf + (page - 1)) & ~(page - 1));

	odp_barrier_wait(&shm->barrier);
	start = odp_time_local();

	for (uint32_t i = 0; i < rounds; i++) {
		uint32_t pos = 0;

		while (pos < options.size) {
			int32_t n = odp_random_data(data + pos,
						    options.size - pos,
						    shm->type);

			if (n < 0) {
				ODPH_ERR("odp_random_data() failed\n");
				exit(EXIT_FAILURE);
			}

			pos += n;
		}
	}

	nsec = odp_time_diff_ns(odp_time_local(), start);
	shm->nsec[odp_thread_id()] = nsec;
	free(buf);

	return 0;
}

static int test_random_test(void *p)
{
	(void)p;

	uint8_t *buf, *data;
	const unsigned long page = ODP_PAGE_SIZE;
	odp_time_t start;
	uint64_t nsec;
	uint64_t seed = 0;
	uint32_t rounds;
	test_shm_t *shm = shm_lookup();

	if (!shm) {
		ODPH_ERR("Failed to look up shm %s\n", shm_name);
		exit(EXIT_FAILURE);
	}

	rounds = type_rounds(shm->type);

	/* One extra page for alignment. */
	buf = (uint8_t *)malloc(options.size + page);

	if (!buf) {
		ODPH_ERR("Memory allocation failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Align to start of page. */
	data = (uint8_t *)(((uintptr_t)buf + (page - 1)) & ~(page - 1));

	odp_barrier_wait(&shm->barrier);
	start = odp_time_local();

	for (uint32_t i = 0; i < rounds; i++) {
		uint32_t pos = 0;

		while (pos < options.size) {
			int32_t n = odp_random_test_data(data + pos,
							 options.size - pos,
							 &seed);

			if (n < 0) {
				ODPH_ERR("odp_random_data() failed\n");
				exit(EXIT_FAILURE);
			}

			pos += n;
		}
	}

	nsec = odp_time_diff_ns(odp_time_local(), start);
	shm->nsec[odp_thread_id()] = nsec;
	free(buf);

	return 0;
}

static void test_type(odp_instance_t instance, test_shm_t *shm,
		      odp_random_kind_t type)
{
	memset(shm, 0, sizeof(test_shm_t));
	shm->type = type;
	odp_barrier_init(&shm->barrier, options.num_threads);

	odp_cpumask_t cpumask;
	odph_thread_common_param_t thr_common;
	odph_thread_param_t thr_param;
	odph_thread_t thr_worker[options.num_threads];

	if (odp_cpumask_default_worker(&cpumask, options.num_threads) !=
	    options.num_threads) {
		ODPH_ERR("Failed to get default CPU mask.\n");
		exit(EXIT_FAILURE);
	}

	odph_thread_common_param_init(&thr_common);
	thr_common.instance = instance;
	thr_common.cpumask = &cpumask;
	thr_common.share_param = 1;

	odph_thread_param_init(&thr_param);
	thr_param.thr_type = ODP_THREAD_WORKER;
	thr_param.start = test_random;

	if (type == (odp_random_kind_t)-1)
		thr_param.start = test_random_test;

	memset(&thr_worker, 0, sizeof(thr_worker));

	if (odph_thread_create(thr_worker, &thr_common, &thr_param,
			       options.num_threads) != options.num_threads) {
		ODPH_ERR("Failed to create worker threads.\n");
		exit(EXIT_FAILURE);
	}

	if (odph_thread_join(thr_worker, options.num_threads) !=
	    options.num_threads) {
		ODPH_ERR("Failed to join worker threads.\n");
		exit(EXIT_FAILURE);
	}

	double mb, seconds, nsec = 0;

	for (int i = 0; i < ODP_THREAD_COUNT_MAX; i++)
		nsec += shm->nsec[i];

	nsec /= options.num_threads;

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

	uint32_t rounds = type_rounds(type);

	printf("--------------------\n");
	printf("threads: %d  size: %u B  rounds: %u  ", options.num_threads,
	       options.size, rounds);
	mb = (uint64_t)options.num_threads * (uint64_t)options.size *
	     (uint64_t)rounds;
	mb /= MB;
	seconds = (double)nsec / (double)ODP_TIME_SEC_IN_NS;
	printf("MB: %.3f  seconds: %.3f  ", mb, seconds);
	printf("MB/s: %.3f  ", mb / seconds);
	printf("MB/s/thread: %.3f", mb / seconds / (double)options.num_threads);
	printf("\n\n");
}

int main(int argc, char **argv)
{
	odp_instance_t instance;
	odp_init_t init;

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

	test_shm_t *shm = NULL;
	odp_shm_t shm_hdl = odp_shm_reserve(shm_name, sizeof(test_shm_t), 64,
					    0);

	if (shm_hdl != ODP_SHM_INVALID)
		shm = (test_shm_t *)odp_shm_addr(shm_hdl);

	if (!shm) {
		ODPH_ERR("Failed to reserve shm %s\n", shm_name);
		exit(EXIT_FAILURE);
	}

	switch (odp_random_max_kind()) {
	case ODP_RANDOM_TRUE:
		test_type(instance, shm, ODP_RANDOM_TRUE);
		/* fall through */
	case ODP_RANDOM_CRYPTO:
		test_type(instance, shm, ODP_RANDOM_CRYPTO);
		/* fall through */
	default:
		test_type(instance, shm, ODP_RANDOM_BASIC);
		test_type(instance, shm, -1);
	}

	if (odp_shm_free(shm_hdl)) {
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
