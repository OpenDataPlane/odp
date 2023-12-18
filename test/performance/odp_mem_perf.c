/* Copyright (c) 2021, Nokia
 *
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @example odp_mem_perf.c
 *
 * Test application for measuring memory system bandwidth
 *
 * @cond _ODP_HIDE_FROM_DOXYGEN_
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
	uint32_t num_round;
	uint64_t data_len;
	uint32_t shm_flags;
	int private;
	int mode;

} test_options_t;

typedef struct test_global_t test_global_t;

typedef struct test_thread_ctx_t {
	test_global_t *global;
	void *shm_addr;
	uint64_t nsec;

} test_thread_ctx_t;

struct test_global_t {
	test_options_t test_options;

	odp_barrier_t barrier;
	uint32_t num_shm;
	odp_shm_t shm[ODP_THREAD_COUNT_MAX];
	void *shm_addr[ODP_THREAD_COUNT_MAX];
	odp_cpumask_t cpumask;
	odph_thread_t thread_tbl[ODP_THREAD_COUNT_MAX];
	test_thread_ctx_t thread_ctx[ODP_THREAD_COUNT_MAX];

};

static void print_usage(void)
{
	printf("\n"
	       "Memory performance test\n"
	       "\n"
	       "Usage: odp_mem_perf [options]\n"
	       "\n"
	       "  -c, --num_cpu          Number of CPUs (worker threads). 0: all available CPUs. Default 1.\n"
	       "  -r, --num_round        Number of rounds\n"
	       "  -l, --data_len         Data length in bytes\n"
	       "  -f, --flags            SHM flags parameter. Default 0.\n"
	       "  -p, --private          0: The same memory area is shared between threads (default)\n"
	       "                         1: Memory areas are private to each thread. This increases\n"
	       "                            memory consumption to num_cpu * data_len.\n"
	       "  -m, --mode             0: Memset data (default)\n"
	       "                         1: Memcpy data. On each round, reads data from one half of the memory area\n"
	       "                            and writes it to the other half.\n"
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
		{"num_round", required_argument, NULL, 'r'},
		{"data_len",  required_argument, NULL, 'l'},
		{"flags",     required_argument, NULL, 'f'},
		{"private",   required_argument, NULL, 'p'},
		{"mode",      required_argument, NULL, 'm'},
		{"help",      no_argument,       NULL, 'h'},
		{NULL, 0, NULL, 0}
	};

	static const char *shortopts = "+c:r:l:f:p:m:h";

	test_options->num_cpu   = 1;
	test_options->num_round = 1000;
	test_options->data_len  = 10 * 1024 * 1024;
	test_options->shm_flags = 0;
	test_options->private   = 0;
	test_options->mode      = 0;

	while (1) {
		opt = getopt_long(argc, argv, shortopts, longopts, &long_index);

		if (opt == -1)
			break;

		switch (opt) {
		case 'c':
			test_options->num_cpu = atoi(optarg);
			break;
		case 'r':
			test_options->num_round = atoi(optarg);
			break;
		case 'l':
			test_options->data_len = strtoull(optarg, NULL, 0);
			break;
		case 'f':
			test_options->shm_flags = strtoul(optarg, NULL, 0);
			break;
		case 'p':
			test_options->private = atoi(optarg);
			break;
		case 'm':
			test_options->mode = atoi(optarg);
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
	int ret, max_num;
	test_options_t *test_options = &global->test_options;
	int num_cpu = test_options->num_cpu;

	/* One thread used for the main thread */
	if (num_cpu > ODP_THREAD_COUNT_MAX - 1) {
		ODPH_ERR("Too many workers. Maximum is %i.\n", ODP_THREAD_COUNT_MAX - 1);
		return -1;
	}

	max_num = num_cpu;
	if (num_cpu == 0)
		max_num = ODP_THREAD_COUNT_MAX - 1;

	ret = odp_cpumask_default_worker(&global->cpumask, max_num);

	if (num_cpu && ret != num_cpu) {
		ODPH_ERR("Too many workers. Max supported %i.\n", ret);
		return -1;
	}

	/* Zero: all available workers */
	if (num_cpu == 0) {
		if (ret > max_num) {
			ODPH_ERR("Too many cpus from odp_cpumask_default_worker(): %i\n", ret);
			return -1;
		}

		num_cpu = ret;
		test_options->num_cpu = num_cpu;
	}

	odp_barrier_init(&global->barrier, num_cpu);

	return 0;
}

static int create_shm(test_global_t *global)
{
	odp_shm_capability_t shm_capa;
	odp_shm_t shm;
	void *addr;
	uint32_t i, num_shm;
	test_options_t *test_options = &global->test_options;
	uint32_t num_round = test_options->num_round;
	uint32_t num_cpu   = test_options->num_cpu;
	uint64_t data_len  = test_options->data_len;
	uint32_t shm_flags = test_options->shm_flags;
	int private        = test_options->private;
	char name[] = "mem_perf_00";

	num_shm = 1;
	if (private)
		num_shm = num_cpu;

	printf("\nMemory performance test\n");
	printf("  num cpu          %u\n", num_cpu);
	printf("  num rounds       %u\n", num_round);
	printf("  data len         %" PRIu64 "\n", data_len);
	printf("  memory footprint %" PRIu64 "\n", num_shm * data_len);
	printf("  shm flags        0x%x\n", shm_flags);
	printf("  num shm          %u\n", num_shm);
	printf("  private          %i\n", private);
	printf("  mode             %i\n", test_options->mode);

	if (odp_shm_capability(&shm_capa)) {
		ODPH_ERR("SHM capa failed.\n");
		return -1;
	}

	if (shm_capa.max_size && data_len > shm_capa.max_size) {
		ODPH_ERR("Data len too large. Maximum len is %" PRIu64 "\n", shm_capa.max_size);
		return -1;
	}

	if (num_shm > shm_capa.max_blocks) {
		ODPH_ERR("Too many SHM blocks. Maximum is %u\n", shm_capa.max_blocks);
		return -1;
	}

	for (i = 0; i < num_shm; i++) {
		name[9]  = '0' + i / 10;
		name[10] = '0' + i % 10;

		shm = odp_shm_reserve(name, data_len, ODP_CACHE_LINE_SIZE, shm_flags);

		if (shm == ODP_SHM_INVALID) {
			ODPH_ERR("SHM[%u] reserve failed.\n", i);
			return -1;
		}

		global->shm[i] = shm;

		addr = odp_shm_addr(shm);
		if (addr == NULL) {
			ODPH_ERR("SHM[%u] addr failed.\n", i);
			return -1;
		}

		global->shm_addr[i] = addr;

		printf("  shm addr[%u]      %p\n", i, addr);
	}

	printf("\n");
	global->num_shm = num_shm;

	odp_shm_print_all();

	return 0;
}

static int free_shm(test_global_t *global)
{
	uint32_t i;

	for (i = 0; i < global->num_shm; i++) {
		if (odp_shm_free(global->shm[i])) {
			ODPH_ERR("SHM[%u] free failed.\n", i);
			return -1;
		}
	}

	return 0;
}

static int run_test(void *arg)
{
	int thr;
	uint32_t i;
	uint64_t nsec;
	odp_time_t t1, t2;
	test_thread_ctx_t *thread_ctx = arg;
	test_global_t *global = thread_ctx->global;
	test_options_t *test_options = &global->test_options;
	uint32_t num_round = test_options->num_round;
	uint64_t data_len = test_options->data_len;
	uint64_t half_len = data_len / 2;
	int mode = test_options->mode;
	uint8_t *addr = thread_ctx->shm_addr;

	thr = odp_thread_id();

	/* Start all workers at the same time */
	odp_barrier_wait(&global->barrier);

	t1 = odp_time_local();

	if (mode == 0) {
		for (i = 0; i < num_round; i++)
			memset(addr, thr + i, data_len);
	} else {
		for (i = 0; i < num_round; i++) {
			if ((i & 0x1) == 0)
				memcpy(&addr[half_len], addr, half_len);
			else
				memcpy(addr, &addr[half_len], half_len);
		}
	}

	t2 = odp_time_local();

	nsec   = odp_time_diff_ns(t2, t1);

	/* Update stats */
	thread_ctx->nsec   = nsec;

	return 0;
}

static int start_workers(test_global_t *global, odp_instance_t instance)
{
	odph_thread_common_param_t param;
	int i, ret;
	test_options_t *test_options = &global->test_options;
	int num_cpu = test_options->num_cpu;
	odph_thread_param_t thr_param[num_cpu];

	odph_thread_common_param_init(&param);
	param.instance = instance;
	param.cpumask  = &global->cpumask;

	for (i = 0; i < num_cpu; i++) {
		test_thread_ctx_t *thread_ctx = &global->thread_ctx[i];

		thread_ctx->global = global;
		thread_ctx->shm_addr = global->shm_addr[0];
		if (global->test_options.private)
			thread_ctx->shm_addr = global->shm_addr[i];

		odph_thread_param_init(&thr_param[i]);
		thr_param[i].thr_type = ODP_THREAD_WORKER;
		thr_param[i].start    = run_test;
		thr_param[i].arg      = thread_ctx;
	}

	ret = odph_thread_create(global->thread_tbl, &param, thr_param, num_cpu);
	if (ret != num_cpu) {
		ODPH_ERR("Failed to create all threads %i\n", ret);
		return -1;
	}

	return 0;
}

static void print_stat(test_global_t *global)
{
	int i, num;
	double nsec_ave;
	uint64_t data_touch;
	test_options_t *test_options = &global->test_options;
	int num_cpu = test_options->num_cpu;
	uint32_t num_round = test_options->num_round;
	uint64_t data_len = test_options->data_len;
	uint64_t nsec_sum = 0;

	for (i = 0; i < ODP_THREAD_COUNT_MAX; i++)
		nsec_sum += global->thread_ctx[i].nsec;

	if (nsec_sum == 0) {
		printf("No results.\n");
		return;
	}

	data_touch = num_round * data_len;
	nsec_ave = nsec_sum / num_cpu;
	num = 0;

	printf("RESULTS - per thread (MB per sec):\n");
	printf("----------------------------------\n");
	printf("          1        2        3        4        5        6        7        8        9       10");

	for (i = 0; i < ODP_THREAD_COUNT_MAX; i++) {
		if (global->thread_ctx[i].nsec) {
			if ((num % 10) == 0)
				printf("\n   ");

			printf("%8.1f ", data_touch / (global->thread_ctx[i].nsec / 1000.0));
			num++;
		}
	}
	printf("\n\n");

	printf("RESULTS - average over %i threads:\n", num_cpu);
	printf("----------------------------------\n");
	printf("  duration:          %.6f sec\n",  nsec_ave / 1000000000);
	printf("  bandwidth per cpu: %.3f MB/s\n", data_touch / (nsec_ave / 1000.0));
	printf("  total bandwidth:   %.3f MB/s\n", (num_cpu * data_touch) / (nsec_ave / 1000.0));
	printf("\n");
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
		ODPH_ERR("Reading ODP helper options failed.\n");
		exit(EXIT_FAILURE);
	}

	/* List features not to be used */
	odp_init_param_init(&init);
	init.not_used.feat.cls      = 1;
	init.not_used.feat.compress = 1;
	init.not_used.feat.crypto   = 1;
	init.not_used.feat.ipsec    = 1;
	init.not_used.feat.schedule = 1;
	init.not_used.feat.timer    = 1;
	init.not_used.feat.tm       = 1;

	init.mem_model = helper_options.mem_model;

	/* Init ODP before calling anything else */
	if (odp_init_global(&instance, &init, NULL)) {
		ODPH_ERR("Global init failed.\n");
		return -1;
	}

	/* Init this thread */
	if (odp_init_local(instance, ODP_THREAD_CONTROL)) {
		ODPH_ERR("Local init failed.\n");
		return -1;
	}

	shm = odp_shm_reserve("mem_perf_global", sizeof(test_global_t), ODP_CACHE_LINE_SIZE, 0);
	if (shm == ODP_SHM_INVALID) {
		ODPH_ERR("Shared mem reserve failed.\n");
		exit(EXIT_FAILURE);
	}

	global = odp_shm_addr(shm);
	if (global == NULL) {
		ODPH_ERR("Shared mem alloc failed\n");
		exit(EXIT_FAILURE);
	}

	memset(global, 0, sizeof(test_global_t));

	if (parse_options(argc, argv, &global->test_options))
		return -1;

	odp_sys_info_print();

	if (set_num_cpu(global))
		return -1;

	if (create_shm(global))
		return -1;

	/* Start workers */
	if (start_workers(global, instance))
		return -1;

	/* Wait workers to exit */
	odph_thread_join(global->thread_tbl, global->test_options.num_cpu);

	print_stat(global);

	if (free_shm(global))
		return -1;

	if (odp_shm_free(shm)) {
		ODPH_ERR("Shared mem free failed.\n");
		exit(EXIT_FAILURE);
	}

	if (odp_term_local()) {
		ODPH_ERR("term local failed.\n");
		return -1;
	}

	if (odp_term_global(instance)) {
		ODPH_ERR("term global failed.\n");
		return -1;
	}

	return 0;
}
