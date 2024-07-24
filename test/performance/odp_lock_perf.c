/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2024 Nokia
 */

/**
 * @example odp_lock_perf.c
 *
 * Performance test application for lock APIs
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

#include <export_results.h>

/* Max number of workers if num_cpu=0 */
#define DEFAULT_MAX_WORKERS 10

/* Max number of counters */
#define MAX_COUNTERS 8

#define TEST_INFO(name, test, validate) { name, test, validate }

/* Maximum number of results to be held */
#define TEST_MAX_BENCH 50

typedef enum repeat_t {
	REPEAT_NO,
	REPEAT_UNTIL_FAIL,
	REPEAT_FOREVER,
} repeat_t;

typedef enum place_t {
	PLACE_PACK,
	PLACE_SEPARATE,
	PLACE_ALL_SEPARATE,
} place_t;

/* Command line options */
typedef struct test_options_t {
	uint32_t num_cpu;
	uint32_t type;
	uint64_t num_round;
	repeat_t repeat;
	uint32_t num_counter;
	place_t place;
} test_options_t;

/* command line options default values */
static test_options_t test_options_def = {
	.num_cpu = 0,
	.type = 0,
	.num_round = 100000,
	.repeat = REPEAT_NO,
	.num_counter = 2,
	.place = 2,
};

typedef struct test_global_t test_global_t;

/* Test function template */
typedef void (*test_fn_t)(test_global_t *g, uint64_t **counter,
			  uint32_t num_counter);
/* Test result validation function template */
typedef int (*validate_fn_t)(test_global_t *g, uint64_t **counter,
			     uint32_t num_counter);

/* Worker thread context */
typedef struct test_thread_ctx_t {
	test_global_t *global;
	test_fn_t func;
	uint64_t nsec;
	uint64_t cycles;
	uint32_t idx;
} test_thread_ctx_t;

typedef struct results_t {
	const char *test_name;
	double cycles_per_round;
	double nsec_per_op;
	double rounds_per_cpu;
	double total_rounds;
} results_t;

/* Global data */
struct test_global_t {
	test_options_t test_options;
	uint32_t cur_type;
	odp_barrier_t barrier;
	odp_cpumask_t cpumask;
	odph_thread_t thread_tbl[ODP_THREAD_COUNT_MAX];
	test_thread_ctx_t thread_ctx[ODP_THREAD_COUNT_MAX];
	test_common_options_t common_options;
	results_t results[TEST_MAX_BENCH];
	struct {
		struct ODP_ALIGNED_CACHE {
			odp_spinlock_t lock;
			uint64_t counter[MAX_COUNTERS];
		} spinlock;
		struct ODP_ALIGNED_CACHE {
			odp_spinlock_recursive_t lock;
			uint64_t counter[MAX_COUNTERS];
		} spinlock_recursive;
		struct ODP_ALIGNED_CACHE {
			odp_rwlock_t lock;
			uint64_t counter[MAX_COUNTERS];
		} rwlock;
		struct ODP_ALIGNED_CACHE {
			odp_rwlock_recursive_t lock;
			uint64_t counter[MAX_COUNTERS];
		} rwlock_recursive;
		struct ODP_ALIGNED_CACHE {
			odp_ticketlock_t lock;
			uint64_t counter[MAX_COUNTERS];
		} ticketlock;
		struct ODP_ALIGNED_CACHE {
			uint64_t counter[MAX_COUNTERS];
		} separate;
		struct {
			uint64_t ODP_ALIGNED_CACHE counter;
		} all_separate[MAX_COUNTERS];
	} item;
};

typedef struct {
	const char *name;
	test_fn_t test_fn;
	validate_fn_t validate_fn;
} test_case_t;

static test_global_t *test_global;

static inline void test_spinlock(test_global_t *g, uint64_t **counter,
				 uint32_t num_counter)
{
	odp_spinlock_t *lock = &g->item.spinlock.lock;

	for (uint64_t i = 0; i < g->test_options.num_round; i++) {
		odp_spinlock_lock(lock);
		for (uint32_t j = 0; j < num_counter; j++)
			(*counter[j])++;
		odp_spinlock_unlock(lock);
	}
}

static inline void test_spinlock_recursive(test_global_t *g, uint64_t **counter,
					   uint32_t num_counter)
{
	odp_spinlock_recursive_t *lock = &g->item.spinlock_recursive.lock;

	for (uint64_t i = 0; i < g->test_options.num_round; i++) {
		odp_spinlock_recursive_lock(lock);
		odp_spinlock_recursive_lock(lock);
		for (uint32_t j = 0; j < num_counter; j++)
			(*counter[j])++;
		odp_spinlock_recursive_unlock(lock);
		odp_spinlock_recursive_unlock(lock);
	}
}

static inline void test_rwlock(test_global_t *g, uint64_t **counter,
			       uint32_t num_counter)
{
	odp_rwlock_t *lock = &g->item.rwlock.lock;

	for (uint64_t i = 0; i < g->test_options.num_round; i++) {
		odp_rwlock_write_lock(lock);
		for (uint32_t j = 0; j < num_counter; j++)
			(*counter[j])++;
		odp_rwlock_write_unlock(lock);
		odp_rwlock_read_lock(lock);
		for (uint32_t j = 1; j < num_counter; j++)
			if (*counter[0] != *counter[j]) {
				odp_rwlock_read_unlock(lock);
				ODPH_ERR("Error: Counter mismatch\n");
				return;
			}
		odp_rwlock_read_unlock(lock);
	}
}

static inline void test_rwlock_recursive(test_global_t *g, uint64_t **counter,
					 uint32_t num_counter)
{
	odp_rwlock_recursive_t *lock = &g->item.rwlock_recursive.lock;

	for (uint64_t i = 0; i < g->test_options.num_round; i++) {
		odp_rwlock_recursive_write_lock(lock);
		odp_rwlock_recursive_write_lock(lock);
		for (uint32_t j = 0; j < num_counter; j++)
			(*counter[j])++;
		odp_rwlock_recursive_write_unlock(lock);
		odp_rwlock_recursive_write_unlock(lock);
		odp_rwlock_recursive_read_lock(lock);
		odp_rwlock_recursive_read_lock(lock);
		for (uint32_t j = 1; j < num_counter; j++)
			if (*counter[0] != *counter[j]) {
				odp_rwlock_recursive_read_unlock(lock);
				odp_rwlock_recursive_read_unlock(lock);
				ODPH_ERR("Error: Counter mismatch\n");
				return;
			}
		odp_rwlock_recursive_read_unlock(lock);
		odp_rwlock_recursive_read_unlock(lock);
	}
}

static inline void test_ticketlock(test_global_t *g, uint64_t **counter,
				   uint32_t num_counter)
{
	odp_ticketlock_t *lock = &g->item.ticketlock.lock;

	for (uint64_t i = 0; i < g->test_options.num_round; i++) {
		odp_ticketlock_lock(lock);
		for (uint32_t j = 0; j < num_counter; j++)
			(*counter[j])++;
		odp_ticketlock_unlock(lock);
	}
}

static inline int validate_generic(test_global_t *g, uint64_t **counter,
				   uint32_t num_counter)
{
	int status = 0;
	uint64_t total = (uint64_t)g->test_options.num_cpu * g->test_options.num_round;

	for (uint32_t i = 0; i < num_counter; i++) {
		if (*counter[i] != total) {
			status = 1;
			ODPH_ERR("Error: Counter %d value %" PRIu64 " expected %" PRIu64 "\n",
				 i, *counter[i], total);
		}
	}

	return status;
}

static void print_usage(void)
{
	printf("\n"
	       "Lock performance test\n"
	       "\n"
	       "Usage: odp_lock_perf [options]\n"
	       "\n"
	       "  -c, --num_cpu          Number of CPUs (worker threads). 0: all available CPUs (or max %d) (default)\n"
	       "  -t, --type             Lock type to test. 0: all (default %u)\n"
	       "                             1: odp_spinlock_t\n"
	       "                             2: odp_spinlock_recursive_t\n"
	       "                             3: odp_rwlock_t\n"
	       "                             4: odp_rwlock_recursive_t\n"
	       "                             5: odp_ticketlock_t\n"
	       "  -r, --num_round        Number of rounds (default %" PRIu64 ")\n"
	       "  -e, --repeat           Repeat the tests (default %u)\n"
	       "                             0: no repeat, run the tests once\n"
	       "                             1: repeat until failure\n"
	       "                             2: repeat forever\n"
	       "  -o, --num_counter      Number of counters (default %u)\n"
	       "  -p, --place            Counter placement (default %d)\n"
	       "                             0: pack to same cache line with lock\n"
	       "                             1: pack to separate cache line\n"
	       "                             2: place each counter to separate cache line\n"
	       "  -h, --help             This help\n"
	       "\n",
	       DEFAULT_MAX_WORKERS, test_options_def.type,
	       test_options_def.num_round, test_options_def.repeat,
	       test_options_def.num_counter, test_options_def.place);
}

static void print_info(test_options_t *test_options)
{
	printf("\nLock performance test configuration:\n");
	printf("  num cpu          %u\n", test_options->num_cpu);
	printf("  type             %u\n", test_options->type);
	printf("  num rounds       %" PRIu64 "\n", test_options->num_round);
	printf("  repeat           %u\n", test_options->repeat);
	printf("  num counters     %u\n", test_options->num_counter);
	printf("  place            %u\n", test_options->place);
	printf("\n\n");
}

static int output_summary(test_global_t *global)
{
	int results_size = ODPH_ARRAY_SIZE(global->results);
	results_t res;

	if (global->common_options.is_export) {
		if (test_common_write("function name,rounds/cpu (M/s),"
			"total rounds (M/s),cycles/op,nsec/op\n")) {
			test_common_write_term();
			return -1;
		}
	}

	printf("Average results over %i threads:\n", global->test_options.num_cpu);
	printf("%-33s %-18s %-20s %-14s %-12s\n", "function name", "rounds/cpu (M/s)",
	       "total rounds (M/s)", "cycles/round", "nsec/round");
	printf("----------------------------------------------------------------------------"
		"---------------------\n");
	for (int i = 0; i < results_size && global->results[i].test_name; i++) {
		res = global->results[i];
		printf("[%02d] %-28s %-18.2f %-20.2f %-14.2f %-12.2f\n", i + 1,
		       res.test_name, res.rounds_per_cpu, res.total_rounds,
		       res.cycles_per_round, res.nsec_per_op);
		if (global->common_options.is_export) {
			if (test_common_write("%s,%f,%f,%f,%f\n", res.test_name, res.rounds_per_cpu,
					      res.total_rounds, res.cycles_per_round,
					      res.nsec_per_op)){
				test_common_write_term();
				return -1;
			}
		}
	}
	return 0;
}

static int parse_options(int argc, char *argv[], test_options_t *test_options)
{
	int opt;
	int long_index;
	int ret = 0;

	static const struct option longopts[] = {
		{ "num_cpu", required_argument, NULL, 'c' },
		{ "type", required_argument, NULL, 't' },
		{ "num_round", required_argument, NULL, 'r' },
		{ "repeat", required_argument, NULL, 'e' },
		{ "num_counter", required_argument, NULL, 'o' },
		{ "place", required_argument, NULL, 'p' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 }
	};

	static const char *shortopts = "+c:t:r:e:o:p:h";

	*test_options = test_options_def;

	while (1) {
		opt = getopt_long(argc, argv, shortopts, longopts, &long_index);

		if (opt == -1)
			break;

		switch (opt) {
		case 'c':
			test_options->num_cpu = atoi(optarg);
			break;
		case 't':
			test_options->type = atoi(optarg);
			break;
		case 'r':
			test_options->num_round = atoll(optarg);
			break;
		case 'e':
			test_options->repeat = atoi(optarg);
			break;
		case 'o':
			test_options->num_counter = atoi(optarg);
			break;
		case 'p':
			test_options->place = atoi(optarg);
			break;
		case 'h':
			/* fall through */
		default:
			print_usage();
			ret = -1;
			break;
		}
	}

	if (test_options->num_round < 1) {
		ODPH_ERR("Invalid number of test rounds: %" PRIu64 "\n",
			 test_options->num_round);
		return -1;
	}

	if (test_options->num_counter < 1 ||
	    test_options->num_counter > MAX_COUNTERS) {
		ODPH_ERR("Invalid number of counters: %" PRIu32 "\n",
			 test_options->num_counter);
		return -1;
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
	if (num_cpu == 0) {
		max_num = ODP_THREAD_COUNT_MAX - 1;
		if (max_num > DEFAULT_MAX_WORKERS)
			max_num = DEFAULT_MAX_WORKERS;
	}

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

static int init_test(test_global_t *g, const char *name)
{
	printf("TEST: %s\n", name);

	memset(&g->item, 0, sizeof(g->item));
	odp_spinlock_init(&g->item.spinlock.lock);
	odp_spinlock_recursive_init(&g->item.spinlock_recursive.lock);
	odp_rwlock_init(&g->item.rwlock.lock);
	odp_rwlock_recursive_init(&g->item.rwlock_recursive.lock);
	odp_ticketlock_init(&g->item.ticketlock.lock);

	return 0;
}

static void fill_counter_ptrs(test_global_t *g, uint64_t **counter_out)
{
	test_options_t *test_options = &g->test_options;

	memset(counter_out, 0, sizeof(uint64_t *) * MAX_COUNTERS);

	switch (test_options->place) {
	case PLACE_PACK:
		for (uint32_t i = 0; i < test_options->num_counter; i++) {
			switch (g->cur_type) {
			case 0:
				counter_out[i] = &g->item.spinlock.counter[i];
				break;
			case 1:
				counter_out[i] = &g->item.spinlock_recursive.counter[i];
				break;
			case 2:
				counter_out[i] = &g->item.rwlock.counter[i];
				break;
			case 3:
				counter_out[i] = &g->item.rwlock_recursive.counter[i];
				break;
			case 4:
				counter_out[i] = &g->item.ticketlock.counter[i];
				break;
			}
		}
		break;
	case PLACE_SEPARATE:
		for (uint32_t i = 0; i < test_options->num_counter; i++)
			counter_out[i] = &g->item.separate.counter[i];
		break;
	case PLACE_ALL_SEPARATE:
		for (uint32_t i = 0; i < test_options->num_counter; i++)
			counter_out[i] = &g->item.all_separate[i].counter;
		break;
	}
}

static int run_test(void *arg)
{
	uint64_t nsec;
	odp_time_t t1, t2;
	uint64_t cycles;
	uint64_t c1, c2;
	test_thread_ctx_t *thread_ctx = arg;
	test_global_t *global = thread_ctx->global;
	test_options_t *test_options = &global->test_options;
	test_fn_t test_func = thread_ctx->func;
	uint64_t *counter[MAX_COUNTERS];

	fill_counter_ptrs(global, counter);

	/* Start all workers at the same time */
	odp_barrier_wait(&global->barrier);

	t1 = odp_time_local_strict();
	c1 = odp_cpu_cycles();

	test_func(global, counter, test_options->num_counter);

	c2 = odp_cpu_cycles();
	t2 = odp_time_local_strict();

	nsec = odp_time_diff_ns(t2, t1);
	cycles = odp_cpu_cycles_diff(c2, c1);

	/* Update stats */
	thread_ctx->nsec = nsec;
	thread_ctx->cycles = cycles;

	return 0;
}

static int start_workers(test_global_t *global, odp_instance_t instance,
			 test_fn_t func)
{
	odph_thread_common_param_t param;
	int i, ret;
	test_options_t *test_options = &global->test_options;
	int num_cpu = test_options->num_cpu;
	odph_thread_param_t thr_param[num_cpu];

	odph_thread_common_param_init(&param);
	param.instance = instance;
	param.cpumask = &global->cpumask;

	for (i = 0; i < num_cpu; i++) {
		test_thread_ctx_t *thread_ctx = &global->thread_ctx[i];

		thread_ctx->global = global;
		thread_ctx->idx = i;
		thread_ctx->func = func;

		odph_thread_param_init(&thr_param[i]);
		thr_param[i].thr_type = ODP_THREAD_WORKER;
		thr_param[i].start = run_test;
		thr_param[i].arg = thread_ctx;
	}

	ret = odph_thread_create(global->thread_tbl, &param, thr_param,
				 num_cpu);
	if (ret != num_cpu) {
		ODPH_ERR("Failed to create all threads %i\n", ret);
		return -1;
	}

	return 0;
}

static int validate_results(test_global_t *global, validate_fn_t validate)
{
	test_options_t *test_options = &global->test_options;
	uint64_t *counter[MAX_COUNTERS];

	fill_counter_ptrs(global, counter);

	if (validate(global, counter, test_options->num_counter))
		return -1;

	return 0;
}

/**
 * Test functions
 */
static test_case_t test_suite[] = {
	TEST_INFO("odp_spinlock", test_spinlock, validate_generic),
	TEST_INFO("odp_spinlock_recursive", test_spinlock_recursive, validate_generic),
	TEST_INFO("odp_rwlock", test_rwlock, validate_generic),
	TEST_INFO("odp_rwlock_recursive", test_rwlock_recursive, validate_generic),
	TEST_INFO("odp_ticketlock", test_ticketlock, validate_generic),
};

ODP_STATIC_ASSERT(ODPH_ARRAY_SIZE(test_suite) < TEST_MAX_BENCH,
		  "Result array is too small to hold all the results");

static void output_results(test_global_t *global, int idx)
{
	int i, num;
	double cycles_per_round, nsec_ave, nsec_per_round, rounds_per_cpu, total_rounds;
	test_options_t *test_options = &global->test_options;
	int num_cpu = test_options->num_cpu;
	uint64_t num_round = test_options->num_round;
	uint64_t nsec_sum = 0;
	uint64_t cycles_sum = 0;

	global->results[idx].test_name = test_suite[idx].name;

	for (i = 0; i < ODP_THREAD_COUNT_MAX; i++) {
		nsec_sum += global->thread_ctx[i].nsec;
		cycles_sum += global->thread_ctx[i].cycles;
	}

	if (nsec_sum == 0) {
		printf("No results.\n");
		return;
	}

	nsec_ave = (double)nsec_sum / num_cpu;
	nsec_per_round = (double)nsec_sum / (num_cpu * num_round);
	cycles_per_round = (double)cycles_sum / (num_cpu * num_round);
	num = 0;

	rounds_per_cpu = num_round / (nsec_ave / 1000.0);
	total_rounds = ((uint64_t)num_cpu * num_round) / (nsec_ave / 1000.0);

	global->results[idx].cycles_per_round = cycles_per_round;
	global->results[idx].rounds_per_cpu = rounds_per_cpu;
	global->results[idx].nsec_per_op = nsec_per_round;
	global->results[idx].total_rounds = total_rounds;

	printf("------------------------------------------------\n");
	printf("Per thread results (Millions of rounds per sec):\n");
	printf("------------------------------------------------\n");
	printf("          1        2        3        4        5        6        7        8        9       10");

	for (i = 0; i < ODP_THREAD_COUNT_MAX; i++) {
		if (global->thread_ctx[i].nsec) {
			if ((num % 10) == 0)
				printf("\n   ");

			printf("%8.3f ", num_round / (global->thread_ctx[i].nsec / 1000.0));
			num++;
		}
	}
	printf("\n\n");

	printf("Average results over %i threads:\n", num_cpu);
	printf("------------------------------------------\n");
	printf("  duration:	      %8.4f  sec\n", nsec_ave / ODP_TIME_SEC_IN_NS);
	printf("  cycles per round    %8.2f\n", cycles_per_round);
	printf("  nsec per round:     %8.2f\n", nsec_per_round);
	printf("  rounds per cpu:     %8.3fM rounds/sec\n", rounds_per_cpu);
	printf("  total rounds:       %8.3fM rounds/sec\n", total_rounds);
	printf("\n\n");
}

int main(int argc, char **argv)
{
	odph_helper_options_t helper_options;
	odp_instance_t instance;
	odp_init_t init;
	odp_shm_t shm;
	test_options_t test_options;
	int num_tests, i;
	test_common_options_t common_options;

	/* Let helper collect its own arguments (e.g. --odph_proc) */
	argc = odph_parse_options(argc, argv);
	if (odph_options(&helper_options)) {
		ODPH_ERR("Error: reading ODP helper options failed.\n");
		exit(EXIT_FAILURE);
	}

	argc = test_common_parse_options(argc, argv);
	if (test_common_options(&common_options)) {
		ODPH_ERR("Error: reading test common options failed\n");
		exit(EXIT_FAILURE);
	}

	if (parse_options(argc, argv, &test_options))
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

	/* Reserve memory for global data from shared mem */
	shm = odp_shm_reserve("test_global", sizeof(test_global_t),
			      ODP_CACHE_LINE_SIZE, 0);

	if (shm == ODP_SHM_INVALID) {
		ODPH_ERR("Shared memory reserve failed.\n");
		exit(EXIT_FAILURE);
	}

	test_global = odp_shm_addr(shm);
	if (test_global == NULL) {
		ODPH_ERR("Shared memory alloc failed.\n");
		exit(EXIT_FAILURE);
	}
	memset(test_global, 0, sizeof(test_global_t));
	test_global->test_options = test_options;
	test_global->common_options = common_options;

	odp_sys_info_print();

	if (set_num_cpu(test_global))
		exit(EXIT_FAILURE);

	print_info(&test_global->test_options);

	/* Loop all test cases */
	num_tests = ODPH_ARRAY_SIZE(test_suite);

	while (1) {
		for (i = 0; i < num_tests; i++) {
			if (test_options.type && test_options.type != (uint32_t)i + 1)
				continue;

			test_global->cur_type = i;

			/* Initialize test variables */
			if (init_test(test_global, test_suite[i].name)) {
				ODPH_ERR("Failed to initialize test.\n");
				exit(EXIT_FAILURE);
			}

			/* Start workers */
			if (start_workers(test_global, instance, test_suite[i].test_fn))
				exit(EXIT_FAILURE);

			/* Wait workers to exit */
			odph_thread_join(test_global->thread_tbl,
					 test_global->test_options.num_cpu);

			output_results(test_global, i);

			/* Validate test results */
			if (validate_results(test_global, test_suite[i].validate_fn)) {
				ODPH_ERR("Test %s result validation failed.\n",
					 test_suite[i].name);
				if (test_options.repeat != REPEAT_FOREVER)
					exit(EXIT_FAILURE);
			}
		}

		if (test_options.repeat == REPEAT_NO)
			break;
	}

	if (output_summary(test_global)) {
		ODPH_ERR("Outputting summary failed.\n");
		exit(EXIT_FAILURE);
	}

	if (odp_shm_free(shm)) {
		ODPH_ERR("Shm free failed.\n");
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
