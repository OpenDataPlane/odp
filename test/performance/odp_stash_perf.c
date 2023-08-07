/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2018 Linaro Limited
 * Copyright (c) 2021 Nokia
 * Copyright (c) 2023 Arm
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>
#include <getopt.h>

#include <odp_api.h>
#include <odp/helper/odph_api.h>

#define MAX_STASHES (32)

typedef struct test_options_t {
	uint32_t num_stash;
	uint32_t num_round;
	uint32_t max_burst;
	uint32_t stash_size;
	int strict;
	int num_cpu;

} test_options_t;

typedef struct test_stat_t {
	uint64_t rounds;
	uint64_t ops;
	uint64_t nsec;
	uint64_t cycles;
	uint64_t num_retry;

} test_stat_t;

typedef struct test_global_t {
	odp_barrier_t barrier;
	test_options_t options;
	odp_instance_t instance;
	odp_shm_t shm;
	odp_pool_t pool;
	odp_stash_t stash[MAX_STASHES];
	odph_thread_t thread_tbl[ODP_THREAD_COUNT_MAX];
	test_stat_t stat[ODP_THREAD_COUNT_MAX];

} test_global_t;

static void print_usage(void)
{
	printf("\n"
	       "Stash performance test\n"
	       "\n"
	       "Usage: odp_stash_perf [options]\n"
	       "\n"
	       "  -c, --num_cpu <num>    Number of worker threads. Default: 1\n"
	       "  -n, --num_stash <num>  Number of stashes. Default: 1\n"
	       "  -b, --burst_size <num> Max number of objects per stash call. Default: 1\n"
	       "  -s, --stash_size <num> Stash size. Default: 1000\n"
	       "  -r, --num_round <num>  Number of rounds. Default: 1000\n"
	       "  -m, --strict           Strict size stash\n"
	       "  -h, --help             This help\n"
	       "\n");
}

static int parse_options(int argc, char *argv[], test_options_t *test_options)
{
	int opt;
	int long_index;
	int ret = 0;

	static const struct option longopts[] = {
		{ "num_cpu", required_argument, NULL, 'c' },
		{ "num_stash", required_argument, NULL, 'n' },
		{ "burst_size", required_argument, NULL, 'b' },
		{ "stash_size", required_argument, NULL, 's' },
		{ "num_round", required_argument, NULL, 'r' },
		{ "strict", no_argument, NULL, 'm' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 }
	};

	static const char *shortopts = "+c:n:b:s:r:mh";

	test_options->num_cpu = 1;
	test_options->num_stash = 1;
	test_options->max_burst = 1;
	test_options->stash_size = 1000;
	test_options->num_round = 1000;
	test_options->strict = 0;

	while (1) {
		opt = getopt_long(argc, argv, shortopts, longopts, &long_index);

		if (opt == -1)
			break;

		switch (opt) {
		case 'c':
			test_options->num_cpu = atoi(optarg);
			break;
		case 'n':
			test_options->num_stash = atoi(optarg);
			break;
		case 'b':
			test_options->max_burst = atoi(optarg);
			break;
		case 's':
			test_options->stash_size = atoi(optarg);
			break;
		case 'r':
			test_options->num_round = atoi(optarg);
			break;
		case 'm':
			test_options->strict = 1;
			break;
		case 'h':
			/* fall through */
		default:
			print_usage();
			ret = -1;
			break;
		}
	}

	if (test_options->num_stash > MAX_STASHES) {
		ODPH_ERR("Too many stashes %u. Test maximum %u.\n",
			 test_options->num_stash, MAX_STASHES);
		return -1;
	}

	return ret;
}

static int create_stashes(test_global_t *global)
{
	uint32_t i;
	uint32_t tmp = 0;
	test_options_t *test_options = &global->options;

	uint32_t num_stash = test_options->num_stash;
	uint32_t num_round = test_options->num_round;
	int num_stored;
	uint32_t num_remain;
	odp_stash_t *stash = global->stash;
	odp_stash_capability_t stash_capa;

	printf("\nTesting %s stashes\n",
	       test_options->strict == 0 ? "NORMAL" : "STRICT_SIZE");
	printf("  num rounds           %u\n", num_round);
	printf("  num stashes          %u\n", num_stash);
	printf("  stash size           %u\n", test_options->stash_size);
	printf("  max burst size       %u\n", test_options->max_burst);

	if (odp_stash_capability(&stash_capa, ODP_STASH_TYPE_DEFAULT)) {
		ODPH_ERR("Get stash capability failed\n");
		return -1;
	}

	if (test_options->stash_size > stash_capa.max_num_obj) {
		ODPH_ERR("Max stash size supported %" PRIu64 "\n",
			 stash_capa.max_num_obj);
		return -1;
	}

	if (test_options->num_stash > stash_capa.max_stashes) {
		ODPH_ERR("Max stash supported %u\n", stash_capa.max_stashes);
		return -1;
	}

	for (i = 0; i < num_stash; i++) {
		odp_stash_param_t stash_param;

		odp_stash_param_init(&stash_param);
		stash_param.num_obj = test_options->stash_size;
		stash_param.obj_size = sizeof(uint32_t);
		stash_param.strict_size = test_options->strict;

		stash[i] = odp_stash_create("test_stash_u32", &stash_param);
		if (stash[i] == ODP_STASH_INVALID) {
			ODPH_ERR("Stash create failed\n");
			return -1;
		}

		num_remain = test_options->stash_size;
		do {
			num_stored = odp_stash_put_u32(stash[i], &tmp, 1);
			if (num_stored < 0) {
				ODPH_ERR("Error: Stash put failed\n");
				return -1;
			}
			num_remain -= num_stored;
		} while (num_remain);
	}

	return 0;
}

static int destroy_stashes(test_global_t *global)
{
	odp_stash_t *stash = global->stash;
	test_options_t *test_options = &global->options;
	uint32_t num_stash = test_options->num_stash;
	uint32_t tmp;
	int num;

	for (uint32_t i = 0; i < num_stash; i++) {
		do {
			num = odp_stash_get_u32(stash[i], &tmp, 1);
			if (num < 0) {
				ODPH_ERR("Error: Stash get failed %u\n", i);
				return -1;
			}
		} while (num);

		if (odp_stash_destroy(stash[i])) {
			ODPH_ERR("Stash destroy failed\n");
			return -1;
		}
	}

	return 0;
}

static int run_test(void *arg)
{
	uint64_t c1, c2, cycles, nsec;
	odp_time_t t1, t2;
	uint32_t rounds;
	int num_stored;
	int num_remain;
	int num_obj;
	test_stat_t *stat;
	test_global_t *global = arg;
	test_options_t *test_options = &global->options;
	odp_stash_t stash;
	uint64_t num_retry = 0;
	uint64_t ops = 0;
	uint32_t num_stash = test_options->num_stash;
	uint32_t num_round = test_options->num_round;
	int thr = odp_thread_id();
	int ret = 0;
	uint32_t i = 0;
	uint32_t max_burst = test_options->max_burst;
	uint32_t *tmp = malloc(sizeof(uint32_t) * max_burst);

	if (tmp == NULL) {
		ODPH_ERR("Error: malloc failed\n");
		ret = -1;
		goto error;
	}

	stat = &global->stat[thr];

	/* Start all workers at the same time */
	odp_barrier_wait(&global->barrier);

	t1 = odp_time_local();
	c1 = odp_cpu_cycles();

	for (rounds = 0; rounds < num_round; rounds++) {
		stash = global->stash[i++];

		if (i == num_stash)
			i = 0;

		num_obj = odp_stash_get_u32(stash, tmp, max_burst);
		if (num_obj == 0)
			continue;

		if (num_obj < 0) {
			ODPH_ERR("Error: Stash get failed\n");
			ret = -1;
			goto error;
		}
		num_remain = num_obj;
		do {
			num_stored = odp_stash_put_u32(stash, tmp, num_remain);
			if (num_stored < 0) {
				ODPH_ERR("Error: Stash put failed\n");
				ret = -1;
				goto error;
			}

			if (num_stored != num_remain)
				num_retry++;

			num_remain -= num_stored;
		} while (num_remain);
		ops += num_obj;
	}

	c2 = odp_cpu_cycles();
	t2 = odp_time_local();

	nsec = odp_time_diff_ns(t2, t1);
	cycles = odp_cpu_cycles_diff(c2, c1);

	stat->rounds = rounds;
	stat->ops = ops;
	stat->nsec = nsec;
	stat->cycles = cycles;
	stat->num_retry = num_retry;
error:
	free(tmp);
	return ret;
}

static int start_workers(test_global_t *global)
{
	odph_thread_common_param_t thr_common;
	odph_thread_param_t thr_param;
	odp_cpumask_t cpumask;
	int ret;
	test_options_t *test_options = &global->options;
	int num_cpu = test_options->num_cpu;

	ret = odp_cpumask_default_worker(&cpumask, num_cpu);

	if (num_cpu && ret != num_cpu) {
		ODPH_ERR("Error: Too many workers. Max supported %i\n.", ret);
		return -1;
	}

	/* Zero: all available workers */
	if (num_cpu == 0) {
		num_cpu = ret;
		test_options->num_cpu = num_cpu;
	}

	printf("  num workers          %u\n\n", num_cpu);

	odp_barrier_init(&global->barrier, num_cpu);

	odph_thread_common_param_init(&thr_common);
	thr_common.instance = global->instance;
	thr_common.cpumask = &cpumask;
	thr_common.share_param = 1;

	odph_thread_param_init(&thr_param);
	thr_param.start = run_test;
	thr_param.arg = global;
	thr_param.thr_type = ODP_THREAD_WORKER;

	if (odph_thread_create(global->thread_tbl, &thr_common, &thr_param,
			       num_cpu) != num_cpu)
		return -1;

	return 0;
}

static void print_stat(test_global_t *global)
{
	int i, num;
	double rounds_ave, ops_ave, nsec_ave, cycles_ave, retry_ave;
	test_options_t *test_options = &global->options;
	int num_cpu = test_options->num_cpu;
	uint64_t rounds_sum = 0;
	uint64_t ops_sum = 0;
	uint64_t nsec_sum = 0;
	uint64_t cycles_sum = 0;
	uint64_t retry_sum = 0;

	/* Averages */
	for (i = 0; i < ODP_THREAD_COUNT_MAX; i++) {
		rounds_sum += global->stat[i].rounds;
		ops_sum += global->stat[i].ops;
		nsec_sum += global->stat[i].nsec;
		cycles_sum += global->stat[i].cycles;
		retry_sum += global->stat[i].num_retry;
	}

	if (rounds_sum == 0) {
		printf("No results.\n");
		return;
	}

	rounds_ave = rounds_sum / num_cpu;
	ops_ave = ops_sum / num_cpu;
	nsec_ave = nsec_sum / num_cpu;
	cycles_ave = cycles_sum / num_cpu;
	retry_ave = retry_sum / num_cpu;
	num = 0;

	printf("RESULTS - per thread (Million ops per sec):\n");
	printf("----------------------------------------------\n");
	printf("        1      2      3      4      5      6      7      8      9     10");

	for (i = 0; i < ODP_THREAD_COUNT_MAX; i++) {
		if (global->stat[i].rounds) {
			if ((num % 10) == 0)
				printf("\n   ");

			printf("%6.1f ", (1000.0 * global->stat[i].ops) /
						 global->stat[i].nsec);
			num++;
		}
	}
	printf("\n\n");

	printf("RESULTS - per thread average (%i threads):\n", num_cpu);
	printf("------------------------------------------\n");
	printf("  duration:                 %.3f msec\n", nsec_ave / 1000000);
	printf("  num cycles:               %.3f M\n", cycles_ave / 1000000);
	printf("  ops per get:              %.3f\n", ops_ave / rounds_ave);
	printf("  cycles per ops:           %.3f\n", cycles_ave / ops_ave);
	printf("  retries per sec:          %.3f k\n",
	       (1000000.0 * retry_ave) / nsec_ave);
	printf("  ops per sec:              %.3f M\n\n",
	       (1000.0 * ops_ave) / nsec_ave);

	printf("TOTAL ops per sec:          %.3f M\n\n",
	       (1000.0 * ops_sum) / nsec_ave);
}

int main(int argc, char **argv)
{
	odph_helper_options_t helper_options;
	odp_instance_t instance;
	odp_init_t init;
	odp_shm_t shm;
	test_global_t *global;

	/* Let helper collect its own arguments (e.g. --odph_proc) */
	argc = odph_parse_options(argc, argv);
	if (odph_options(&helper_options)) {
		ODPH_ERR("Error: Reading ODP helper options failed.\n");
		exit(EXIT_FAILURE);
	}

	/* List features not to be used */
	odp_init_param_init(&init);
	init.not_used.feat.cls = 1;
	init.not_used.feat.compress = 1;
	init.not_used.feat.crypto = 1;
	init.not_used.feat.ipsec = 1;
	init.not_used.feat.schedule = 1;
	init.not_used.feat.timer = 1;
	init.not_used.feat.tm = 1;

	init.mem_model = helper_options.mem_model;

	/* Init ODP before calling anything else */
	if (odp_init_global(&instance, &init, NULL)) {
		ODPH_ERR("Error: Global init failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Init this thread */
	if (odp_init_local(instance, ODP_THREAD_WORKER)) {
		ODPH_ERR("Error: Local init failed.\n");
		exit(EXIT_FAILURE);
	}

	shm = odp_shm_reserve("stash_perf_global", sizeof(test_global_t),
			      ODP_CACHE_LINE_SIZE, 0);
	if (shm == ODP_SHM_INVALID) {
		ODPH_ERR("Error: Shared mem reserve failed.\n");
		exit(EXIT_FAILURE);
	}

	global = odp_shm_addr(shm);
	if (global == NULL) {
		ODPH_ERR("Error: Shared mem alloc failed\n");
		exit(EXIT_FAILURE);
	}

	memset(global, 0, sizeof(test_global_t));

	if (parse_options(argc, argv, &global->options))
		exit(EXIT_FAILURE);

	odp_sys_info_print();

	global->instance = instance;

	if (create_stashes(global)) {
		ODPH_ERR("Error: Create stashes failed.\n");
		goto destroy;
	}

	if (start_workers(global)) {
		ODPH_ERR("Error: Test start failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Wait workers to exit */
	odph_thread_join(global->thread_tbl, global->options.num_cpu);

	print_stat(global);

destroy:
	if (destroy_stashes(global)) {
		ODPH_ERR("Error: Destroy stashes failed.\n");
		exit(EXIT_FAILURE);
	}

	if (odp_shm_free(shm)) {
		ODPH_ERR("Error: Shared mem free failed.\n");
		exit(EXIT_FAILURE);
	}

	if (odp_term_local()) {
		ODPH_ERR("Error: term local failed.\n");
		exit(EXIT_FAILURE);
	}

	if (odp_term_global(instance)) {
		ODPH_ERR("Error: term global failed.\n");
		exit(EXIT_FAILURE);
	}

	return 0;
}
