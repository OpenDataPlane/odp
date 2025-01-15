/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2017-2018 Linaro Limited
 * Copyright (c) 2022-2024 Nokia
 */

/**
 * @example odp_bench_buffer.c
 *
 * Microbenchmark application for buffer API functions
 *
 * @cond _ODP_HIDE_FROM_DOXYGEN_
 */

#include <odp_api.h>
#include <odp/helper/odph_api.h>

#include <bench_common.h>
#include <export_results.h>

#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

/** Default buffer size */
#define TEST_BUF_SIZE 1024

/** Default pool user area size in bytes */
#define TEST_UAREA_SIZE 8

/** Number of API function calls per test case */
#define TEST_REPEAT_COUNT 1000

/** Default number of rounds per test case */
#define TEST_ROUNDS 100u

/** Maximum burst size for *_multi operations */
#define TEST_MAX_BURST 64

/** Default burst size for *_multi operations */
#define TEST_DEF_BURST 8

/** Maximum number of results to be held */
#define TEST_MAX_BENCH 40

/** Get rid of path in filename - only for unix-type paths using '/' */
#define NO_PATH(file_name) (strrchr((file_name), '/') ? \
			    strrchr((file_name), '/') + 1 : (file_name))

#define BENCH_INFO(run_fn, init_fn, term_fn, alt_name) \
	{.name = #run_fn, .run = run_fn, .init = init_fn, .term = term_fn, .desc = alt_name}

#define BENCH_INFO_COND(run_fn, init_fn, term_fn, alt_name, cond_fn) \
	{.name = #run_fn, .run = run_fn, .init = init_fn, .term = term_fn, .desc = alt_name, \
	 .cond = cond_fn}

/**
 * Parsed command line arguments
 */
typedef struct {
	int bench_idx;   /** Benchmark index to run indefinitely */
	int burst_size;  /** Burst size for *_multi operations */
	int cache_size;  /** Pool cache size */
	int time;        /** Measure time vs. CPU cycles */
	uint32_t rounds; /** Rounds per test case */
} appl_args_t;

/**
 * Grouping of all global data
 */
typedef struct {
	/** Application (parsed) arguments */
	appl_args_t appl;
	/** Common benchmark suite data */
	bench_suite_t suite;
	/** Buffer pool */
	odp_pool_t pool;
	/** Buffer size */
	uint32_t buf_size;
	/** Buffer user area size */
	uint32_t uarea_size;
	/** Max flow id */
	uint32_t max_flow_id;
	/** Array for storing test buffers */
	odp_buffer_t buf_tbl[TEST_REPEAT_COUNT * TEST_MAX_BURST];
	/** Array for storing test event */
	odp_event_t event_tbl[TEST_REPEAT_COUNT * TEST_MAX_BURST];
	/** Array for storing test pointers */
	void *ptr_tbl[TEST_REPEAT_COUNT];
	/** Array for storing test pool handles */
	odp_pool_t pool_tbl[TEST_REPEAT_COUNT];
	/** Array for storing test event types */
	odp_event_type_t event_type_tbl[TEST_REPEAT_COUNT * TEST_MAX_BURST];
	/** Array for storing test event subtypes */
	odp_event_subtype_t event_subtype_tbl[TEST_REPEAT_COUNT * TEST_MAX_BURST];
	/** CPU mask as string */
	char cpumask_str[ODP_CPUMASK_STR_SIZE];
	/** Array for storing results */
	double result[TEST_MAX_BENCH];
} args_t;

/** Global pointer to args */
static args_t *gbl_args;

static void sig_handler(int signo ODP_UNUSED)
{
	if (gbl_args == NULL)
		return;
	odp_atomic_store_u32(&gbl_args->suite.exit_worker, 1);
}

static void allocate_test_buffers(odp_buffer_t buf[], int num)
{
	int num_buf = 0;

	while (num_buf < num) {
		int ret;

		ret = odp_buffer_alloc_multi(gbl_args->pool, &buf[num_buf], num - num_buf);
		if (ret < 0)
			ODPH_ABORT("Allocating test buffers failed\n");

		num_buf += ret;
	}
}

static void create_buffers(void)
{
	allocate_test_buffers(gbl_args->buf_tbl, TEST_REPEAT_COUNT);
}

static void create_buffers_multi(void)
{
	allocate_test_buffers(gbl_args->buf_tbl, TEST_REPEAT_COUNT * gbl_args->appl.burst_size);
}

static void create_events(void)
{
	odp_buffer_t *buf_tbl = gbl_args->buf_tbl;

	allocate_test_buffers(gbl_args->buf_tbl, TEST_REPEAT_COUNT);

	for (int i = 0; i < TEST_REPEAT_COUNT; i++)
		gbl_args->event_tbl[i] = odp_buffer_to_event(buf_tbl[i]);
}

static void create_events_multi(void)
{
	odp_buffer_t *buf_tbl = gbl_args->buf_tbl;

	allocate_test_buffers(gbl_args->buf_tbl,
			      TEST_REPEAT_COUNT * gbl_args->appl.burst_size);

	for (int i = 0; i < TEST_REPEAT_COUNT * gbl_args->appl.burst_size; i++)
		gbl_args->event_tbl[i] = odp_buffer_to_event(buf_tbl[i]);
}

static void free_buffers(void)
{
	odp_buffer_free_multi(gbl_args->buf_tbl, TEST_REPEAT_COUNT);
}

static void free_buffers_multi(void)
{
	odp_buffer_free_multi(gbl_args->buf_tbl, TEST_REPEAT_COUNT * gbl_args->appl.burst_size);
}

static int check_uarea(void)
{
	return !!gbl_args->uarea_size;
}

static int check_flow_aware(void)
{
	return !!gbl_args->max_flow_id;
}

static int buffer_from_event(void)
{
	odp_buffer_t *buf_tbl = gbl_args->buf_tbl;
	odp_event_t *event_tbl = gbl_args->event_tbl;
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		buf_tbl[i] = odp_buffer_from_event(event_tbl[i]);

	return i;
}

static int buffer_from_event_multi(void)
{
	odp_buffer_t *buf_tbl = gbl_args->buf_tbl;
	odp_event_t *event_tbl = gbl_args->event_tbl;
	int burst_size = gbl_args->appl.burst_size;
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		odp_buffer_from_event_multi(&buf_tbl[i * burst_size],
					    &event_tbl[i * burst_size], burst_size);

	return i;
}

static int buffer_to_event(void)
{
	odp_buffer_t *buf_tbl = gbl_args->buf_tbl;
	odp_event_t *event_tbl = gbl_args->event_tbl;
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		event_tbl[i] = odp_buffer_to_event(buf_tbl[i]);

	return i;
}

static int buffer_to_event_multi(void)
{
	odp_buffer_t *buf_tbl = gbl_args->buf_tbl;
	odp_event_t *event_tbl = gbl_args->event_tbl;
	int burst_size = gbl_args->appl.burst_size;
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		odp_buffer_to_event_multi(&buf_tbl[i * burst_size],
					  &event_tbl[i * burst_size], burst_size);

	return i;
}

static int buffer_addr(void)
{
	odp_buffer_t *buf_tbl = gbl_args->buf_tbl;
	void **ptr_tbl = gbl_args->ptr_tbl;
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ptr_tbl[i] = odp_buffer_addr(buf_tbl[i]);

	return i;
}

static int buffer_size(void)
{
	odp_buffer_t *buf_tbl = gbl_args->buf_tbl;
	uint32_t ret = 0;

	for (int i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_buffer_size(buf_tbl[i]);

	return ret;
}

static int buffer_user_area(void)
{
	odp_buffer_t *buf_tbl = gbl_args->buf_tbl;
	void **ptr_tbl = gbl_args->ptr_tbl;
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ptr_tbl[i] = odp_buffer_user_area(buf_tbl[i]);

	return i;
}

static int buffer_pool(void)
{
	odp_buffer_t *buf_tbl = gbl_args->buf_tbl;
	odp_pool_t *pool_tbl = gbl_args->pool_tbl;
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		pool_tbl[i] = odp_buffer_pool(buf_tbl[i]);

	return i;
}

static int buffer_alloc(void)
{
	odp_buffer_t *buf_tbl = gbl_args->buf_tbl;
	odp_pool_t pool = gbl_args->pool;
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		buf_tbl[i] = odp_buffer_alloc(pool);

	return i;
}

static int buffer_alloc_multi(void)
{
	odp_buffer_t *buf_tbl = gbl_args->buf_tbl;
	odp_pool_t pool = gbl_args->pool;
	int burst_size = gbl_args->appl.burst_size;
	int num = 0;

	for (int i = 0; i < TEST_REPEAT_COUNT; i++)
		num += odp_buffer_alloc_multi(pool, &buf_tbl[num], burst_size);

	return num;
}

static int buffer_free(void)
{
	odp_buffer_t *buf_tbl = gbl_args->buf_tbl;
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		odp_buffer_free(buf_tbl[i]);

	return i;
}

static int buffer_free_multi(void)
{
	odp_buffer_t *buf_tbl = gbl_args->buf_tbl;
	int burst_size = gbl_args->appl.burst_size;
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		odp_buffer_free_multi(&buf_tbl[i * burst_size], burst_size);

	return i;
}

static int buffer_alloc_free(void)
{
	odp_pool_t pool = gbl_args->pool;
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++) {
		odp_buffer_t buf = odp_buffer_alloc(pool);

		if (odp_unlikely(buf == ODP_BUFFER_INVALID))
			return 0;

		odp_buffer_free(buf);
	}
	return i;
}

static int buffer_alloc_free_multi(void)
{
	odp_buffer_t *buf_tbl = gbl_args->buf_tbl;
	odp_pool_t pool = gbl_args->pool;
	int burst_size = gbl_args->appl.burst_size;
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++) {
		int num = odp_buffer_alloc_multi(pool, buf_tbl, burst_size);

		if (odp_unlikely(num < 1))
			return 0;

		odp_buffer_free_multi(buf_tbl, num);
	}
	return i;
}

static int buffer_is_valid(void)
{
	odp_buffer_t *buf_tbl = gbl_args->buf_tbl;
	uint32_t ret = 0;

	for (int i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_buffer_is_valid(buf_tbl[i]);

	return ret;
}

static int event_type(void)
{
	odp_event_t *event_tbl = gbl_args->event_tbl;
	odp_event_type_t *event_type_tbl = gbl_args->event_type_tbl;
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		event_type_tbl[i] = odp_event_type(event_tbl[i]);

	return i;
}

static int event_subtype(void)
{
	odp_event_t *event_tbl = gbl_args->event_tbl;
	odp_event_subtype_t *event_subtype_tbl = gbl_args->event_subtype_tbl;
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		event_subtype_tbl[i] = odp_event_subtype(event_tbl[i]);

	return i;
}

static int event_types(void)
{
	odp_event_t *event_tbl = gbl_args->event_tbl;
	odp_event_type_t *event_type_tbl = gbl_args->event_type_tbl;
	odp_event_subtype_t *event_subtype_tbl = gbl_args->event_subtype_tbl;
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		event_type_tbl[i] = odp_event_types(event_tbl[i], &event_subtype_tbl[i]);

	return i;
}

static int event_types_multi(void)
{
	odp_event_t *event_tbl = gbl_args->event_tbl;
	odp_event_type_t *event_type_tbl = gbl_args->event_type_tbl;
	odp_event_subtype_t *event_subtype_tbl = gbl_args->event_subtype_tbl;
	int burst_size = gbl_args->appl.burst_size;
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		odp_event_types_multi(&event_tbl[i * burst_size],
				      &event_type_tbl[i * burst_size],
				      &event_subtype_tbl[i * burst_size], burst_size);

	return i;
}

static int event_types_multi_no_sub(void)
{
	odp_event_t *event_tbl = gbl_args->event_tbl;
	odp_event_type_t *event_type_tbl = gbl_args->event_type_tbl;
	int burst_size = gbl_args->appl.burst_size;
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		odp_event_types_multi(&event_tbl[i * burst_size],
				      &event_type_tbl[i * burst_size], NULL, burst_size);

	return i;
}

static int event_type_multi(void)
{
	odp_event_t *event_tbl = gbl_args->event_tbl;
	odp_event_type_t *event_type_tbl = gbl_args->event_type_tbl;
	int burst_size = gbl_args->appl.burst_size;
	uint32_t ret = 0;

	for (int i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_event_type_multi(&event_tbl[i * burst_size], burst_size,
					    &event_type_tbl[i]);

	return ret;
}

static int event_pool(void)
{
	odp_event_t *event_tbl = gbl_args->event_tbl;
	odp_pool_t *pool_tbl = gbl_args->pool_tbl;
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		pool_tbl[i] = odp_event_pool(event_tbl[i]);

	return i;
}

static int event_user_area(void)
{
	odp_event_t *event_tbl = gbl_args->event_tbl;
	void **ptr_tbl = gbl_args->ptr_tbl;
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ptr_tbl[i] = odp_event_user_area(event_tbl[i]);

	return i;
}

static int event_user_area_and_flag(void)
{
	odp_event_t *event_tbl = gbl_args->event_tbl;
	void **ptr_tbl = gbl_args->ptr_tbl;
	int ret = 0;
	int flag;

	for (int i = 0; i < TEST_REPEAT_COUNT; i++) {
		ptr_tbl[i] = odp_event_user_area_and_flag(event_tbl[i], &flag);
		ret += flag;
	}

	return ret;
}

static int event_is_valid(void)
{
	odp_event_t *event_tbl = gbl_args->event_tbl;

	uint32_t ret = 0;

	for (int i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_event_is_valid(event_tbl[i]);

	return ret;
}

static int event_free(void)
{
	odp_event_t *event_tbl = gbl_args->event_tbl;

	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		odp_event_free(event_tbl[i]);

	return i;
}

static int event_free_multi(void)
{
	odp_event_t *event_tbl = gbl_args->event_tbl;
	int burst_size = gbl_args->appl.burst_size;
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		odp_event_free_multi(&event_tbl[i * burst_size], burst_size);

	return i;
}

static int event_free_sp(void)
{
	odp_event_t *event_tbl = gbl_args->event_tbl;
	int burst_size = gbl_args->appl.burst_size;
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		odp_event_free_sp(&event_tbl[i * burst_size], burst_size);

	return i;
}

static int event_flow_id(void)
{
	odp_event_t *event_tbl = gbl_args->event_tbl;
	uint32_t ret = 0;

	for (int i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_event_flow_id(event_tbl[i]);

	return !ret;
}

static int event_flow_id_set(void)
{
	odp_event_t *event_tbl = gbl_args->event_tbl;
	int i = 0;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		odp_event_flow_id_set(event_tbl[i], 0);

	return i;
}

/**
 * Print usage information
 */
static void usage(char *progname)
{
	printf("\n"
	       "OpenDataPlane Buffer/Event API microbenchmarks.\n"
	       "\n"
	       "Usage: %s OPTIONS\n"
	       "  E.g. %s\n"
	       "\n"
	       "Optional OPTIONS:\n"
	       "  -b, --burst <num>       Test burst size.\n"
	       "  -c, --cache_size <num>  Pool cache size.\n"
	       "  -i, --index <idx>       Benchmark index to run indefinitely.\n"
	       "  -r, --rounds <num>      Run each test case 'num' times (default %u).\n"
	       "  -t, --time <opt>        Time measurement. 0: measure CPU cycles (default), 1: measure time\n"
	       "  -h, --help              Display help and exit.\n\n"
	       "\n", NO_PATH(progname), NO_PATH(progname), TEST_ROUNDS);
}

/**
 * Parse and store the command line arguments
 *
 * @param argc       argument count
 * @param argv[]     argument vector
 * @param appl_args  Store application arguments here
 */
static void parse_args(int argc, char *argv[], appl_args_t *appl_args)
{
	int opt;
	static const struct option longopts[] = {
		{"burst", required_argument, NULL, 'b'},
		{"cache_size", required_argument, NULL, 'c'},
		{"index", required_argument, NULL, 'i'},
		{"rounds", required_argument, NULL, 'r'},
		{"time", required_argument, NULL, 't'},
		{"help", no_argument, NULL, 'h'},
		{NULL, 0, NULL, 0}
	};

	static const char *shortopts =  "c:b:i:r:t:h";

	appl_args->bench_idx = 0; /* Run all benchmarks */
	appl_args->burst_size = TEST_DEF_BURST;
	appl_args->cache_size = -1;
	appl_args->rounds = TEST_ROUNDS;
	appl_args->time = 0;

	while (1) {
		opt = getopt_long(argc, argv, shortopts, longopts, NULL);

		if (opt == -1)
			break;	/* No more options */

		switch (opt) {
		case 'c':
			appl_args->cache_size = atoi(optarg);
			break;
		case 'b':
			appl_args->burst_size = atoi(optarg);
			break;
		case 'h':
			usage(argv[0]);
			exit(EXIT_SUCCESS);
			break;
		case 'i':
			appl_args->bench_idx = atoi(optarg);
			break;
		case 'r':
			appl_args->rounds = atoi(optarg);
			break;
		case 't':
			appl_args->time = atoi(optarg);
			break;
		default:
			break;
		}
	}

	if (appl_args->burst_size < 1 ||
	    appl_args->burst_size > TEST_MAX_BURST) {
		printf("Invalid burst size (max %d)\n", TEST_MAX_BURST);
		exit(EXIT_FAILURE);
	}

	if (appl_args->rounds < 1) {
		printf("Invalid number test rounds: %d\n", appl_args->rounds);
		exit(EXIT_FAILURE);
	}

	optind = 1; /* Reset 'extern optind' from the getopt lib */
}

/**
 * Print system and application info
 */
static void print_info(void)
{
	odp_sys_info_print();

	printf("\n"
	       "odp_bench_buffer options\n"
	       "------------------------\n");

	printf("Burst size:        %d\n", gbl_args->appl.burst_size);
	printf("Buffer size:       %d\n", gbl_args->buf_size);
	printf("CPU mask:          %s\n", gbl_args->cpumask_str);
	if (gbl_args->appl.cache_size < 0)
		printf("Pool cache size:   default\n");
	else
		printf("Pool cache size:   %d\n", gbl_args->appl.cache_size);
	printf("Measurement unit:  %s\n", gbl_args->appl.time ? "nsec" : "CPU cycles");
	printf("Test rounds:       %u\n", gbl_args->appl.rounds);
	printf("\n");
}

static int bench_buffer_export(void *data)
{
	args_t *gbl_args = data;
	int ret = 0;

	if (test_common_write("%s", gbl_args->appl.time ?
			      "Function name,Average nsec per function call\n" :
			      "Function name,Average CPU cycles per function call\n")) {
		ret = -1;
		goto exit;
	}

	for (int i = 0; i < gbl_args->suite.num_bench; i++) {
		if (test_common_write("odp_%s,%f\n",
				      gbl_args->suite.bench[i].name,
				      gbl_args->suite.result[i])) {
			ret = -1;
			goto exit;
		}
	}

exit:
	test_common_write_term();

	return ret;
}

/**
 * Test functions
 */
bench_info_t test_suite[] = {
	BENCH_INFO(buffer_from_event, create_events, free_buffers, NULL),
	BENCH_INFO(buffer_from_event_multi, create_events_multi, free_buffers_multi, NULL),
	BENCH_INFO(buffer_to_event, create_buffers, free_buffers, NULL),
	BENCH_INFO(buffer_to_event_multi, create_buffers_multi, free_buffers_multi, NULL),
	BENCH_INFO(buffer_addr, create_buffers, free_buffers, NULL),
	BENCH_INFO(buffer_size, create_buffers, free_buffers, NULL),
	BENCH_INFO_COND(buffer_user_area, create_buffers, free_buffers, NULL, check_uarea),
	BENCH_INFO(buffer_pool, create_buffers, free_buffers, NULL),
	BENCH_INFO(buffer_alloc, NULL, free_buffers, NULL),
	BENCH_INFO(buffer_alloc_multi, NULL, free_buffers_multi, NULL),
	BENCH_INFO(buffer_free, create_buffers, NULL, NULL),
	BENCH_INFO(buffer_free_multi, create_buffers_multi, NULL, NULL),
	BENCH_INFO(buffer_alloc_free, NULL, NULL, NULL),
	BENCH_INFO(buffer_alloc_free_multi, NULL, NULL, NULL),
	BENCH_INFO(buffer_is_valid, create_buffers, free_buffers, NULL),
	BENCH_INFO(event_type, create_events, free_buffers, NULL),
	BENCH_INFO(event_subtype, create_events, free_buffers, NULL),
	BENCH_INFO(event_types, create_events, free_buffers, NULL),
	BENCH_INFO(event_types_multi, create_events_multi, free_buffers_multi, NULL),
	BENCH_INFO(event_types_multi_no_sub, create_events_multi, free_buffers_multi,
		   "event_types_multi (no sub)"),
	BENCH_INFO(event_type_multi, create_events_multi, free_buffers_multi, NULL),
	BENCH_INFO(event_pool, create_events, free_buffers, NULL),
	BENCH_INFO_COND(event_user_area, create_events, free_buffers, NULL, check_uarea),
	BENCH_INFO_COND(event_user_area_and_flag, create_events, free_buffers, NULL, check_uarea),
	BENCH_INFO(event_is_valid, create_events, free_buffers, NULL),
	BENCH_INFO(event_free, create_events, NULL, NULL),
	BENCH_INFO(event_free_multi, create_events_multi, NULL, NULL),
	BENCH_INFO(event_free_sp, create_events_multi, NULL, NULL),
	BENCH_INFO_COND(event_flow_id, create_events, free_buffers, NULL, check_flow_aware),
	BENCH_INFO_COND(event_flow_id_set, create_events, free_buffers, NULL, check_flow_aware),
};

ODP_STATIC_ASSERT(ODPH_ARRAY_SIZE(test_suite) < TEST_MAX_BENCH,
		  "Result array is too small to hold all the results");

/**
 * ODP buffer microbenchmark application
 */
int main(int argc, char *argv[])
{
	odph_helper_options_t helper_options;
	test_common_options_t common_options;
	odph_thread_t worker_thread;
	odph_thread_common_param_t thr_common;
	odph_thread_param_t thr_param;
	int cpu;
	odp_shm_t shm;
	odp_cpumask_t cpumask, default_mask;
	odp_schedule_capability_t sched_capa;
	odp_pool_capability_t capa;
	odp_pool_param_t params;
	odp_instance_t instance;
	odp_init_t init_param;
	uint32_t buf_num;
	uint8_t ret;

	/* Let helper collect its own arguments (e.g. --odph_proc) */
	argc = odph_parse_options(argc, argv);
	if (odph_options(&helper_options)) {
		ODPH_ERR("Error: reading ODP helper options failed\n");
		exit(EXIT_FAILURE);
	}

	argc = test_common_parse_options(argc, argv);
	if (test_common_options(&common_options)) {
		ODPH_ERR("Error: reading test options failed\n");
		exit(EXIT_FAILURE);
	}

	odp_init_param_init(&init_param);
	init_param.mem_model = helper_options.mem_model;

	/* Init ODP before calling anything else */
	if (odp_init_global(&instance, &init_param, NULL)) {
		ODPH_ERR("Error: ODP global init failed\n");
		exit(EXIT_FAILURE);
	}

	/* Init this thread */
	if (odp_init_local(instance, ODP_THREAD_CONTROL)) {
		ODPH_ERR("Error: ODP local init failed\n");
		exit(EXIT_FAILURE);
	}

	/* Reserve memory for args from shared mem */
	shm = odp_shm_reserve("shm_args", sizeof(args_t), ODP_CACHE_LINE_SIZE, 0);
	if (shm == ODP_SHM_INVALID) {
		ODPH_ERR("Error: shared mem reserve failed\n");
		exit(EXIT_FAILURE);
	}

	gbl_args = odp_shm_addr(shm);
	if (gbl_args == NULL) {
		ODPH_ERR("Error: shared mem alloc failed\n");
		exit(EXIT_FAILURE);
	}

	memset(gbl_args, 0, sizeof(args_t));

	/* Parse and store the application arguments */
	parse_args(argc, argv, &gbl_args->appl);

	bench_suite_init(&gbl_args->suite);
	gbl_args->suite.bench = test_suite;
	gbl_args->suite.num_bench = ODPH_ARRAY_SIZE(test_suite);
	gbl_args->suite.indef_idx = gbl_args->appl.bench_idx;
	gbl_args->suite.rounds = gbl_args->appl.rounds;
	gbl_args->suite.repeat_count = TEST_REPEAT_COUNT;
	gbl_args->suite.measure_time = !!gbl_args->appl.time;
	if (common_options.is_export)
		gbl_args->suite.result = gbl_args->result;

	/* Get default worker cpumask */
	if (odp_cpumask_default_worker(&default_mask, 1) != 1) {
		ODPH_ERR("Error: unable to allocate worker thread\n");
		exit(EXIT_FAILURE);
	}
	(void)odp_cpumask_to_str(&default_mask, gbl_args->cpumask_str,
				 sizeof(gbl_args->cpumask_str));

	if (odp_schedule_capability(&sched_capa)) {
		ODPH_ERR("Error: schedule capability failed\n");
		exit(EXIT_FAILURE);
	}

	gbl_args->max_flow_id = 0;
	if (sched_capa.max_flow_id) {
		odp_schedule_config_t sched_config;

		odp_schedule_config_init(&sched_config);
		sched_config.max_flow_id = 1;

		if (odp_schedule_config(&sched_config)) {
			ODPH_ERR("Error: schedule config failed\n");
			exit(EXIT_FAILURE);
		}
		gbl_args->max_flow_id = 1;
	}

	if (odp_pool_capability(&capa)) {
		ODPH_ERR("Error: unable to query pool capability\n");
		exit(EXIT_FAILURE);
	}

	buf_num = gbl_args->appl.burst_size * TEST_REPEAT_COUNT;

	if (capa.buf.max_num && capa.buf.max_num < buf_num) {
		ODPH_ERR("Error: pool size not supported (max %" PRIu32 ")\n", capa.buf.max_num);
		exit(EXIT_FAILURE);
	} else if (gbl_args->appl.cache_size > (int)capa.buf.max_cache_size) {
		ODPH_ERR("Error: cache size not supported (max %" PRIu32 ")\n",
			 capa.buf.max_cache_size);
		exit(EXIT_FAILURE);
	}

	gbl_args->buf_size = TEST_BUF_SIZE;
	if (capa.buf.max_size && capa.buf.max_size < TEST_BUF_SIZE)
		gbl_args->buf_size = capa.buf.max_size;

	gbl_args->uarea_size = TEST_UAREA_SIZE < capa.buf.max_uarea_size ?
				TEST_UAREA_SIZE : capa.buf.max_uarea_size;

	print_info();

	/* Create buffer pool */
	odp_pool_param_init(&params);
	params.buf.size = gbl_args->buf_size;
	params.buf.num = buf_num;
	params.buf.uarea_size = gbl_args->uarea_size;
	if (gbl_args->appl.cache_size >= 0)
		params.buf.cache_size = gbl_args->appl.cache_size;
	params.type = ODP_POOL_BUFFER;

	gbl_args->pool = odp_pool_create("microbench", &params);
	if (gbl_args->pool == ODP_POOL_INVALID) {
		ODPH_ERR("Error: pool create failed\n");
		exit(EXIT_FAILURE);
	}

	odp_pool_print(gbl_args->pool);

	memset(&worker_thread, 0, sizeof(odph_thread_t));

	signal(SIGINT, sig_handler);

	/* Create worker thread */
	cpu = odp_cpumask_first(&default_mask);

	odp_cpumask_zero(&cpumask);
	odp_cpumask_set(&cpumask, cpu);

	odph_thread_common_param_init(&thr_common);
	thr_common.instance = instance;
	thr_common.cpumask = &cpumask;
	thr_common.share_param = 1;

	odph_thread_param_init(&thr_param);
	thr_param.start = bench_run;
	thr_param.arg = &gbl_args->suite;
	thr_param.thr_type = ODP_THREAD_WORKER;

	odph_thread_create(&worker_thread, &thr_common, &thr_param, 1);

	odph_thread_join(&worker_thread, 1);

	ret = gbl_args->suite.retval;

	if (ret == 0 && common_options.is_export) {
		if (bench_buffer_export(gbl_args)) {
			ODPH_ERR("Error: Export failed\n");
			ret = -1;
		}
	}

	if (odp_pool_destroy(gbl_args->pool)) {
		ODPH_ERR("Error: pool destroy\n");
		exit(EXIT_FAILURE);
	}

	if (odp_shm_free(shm)) {
		ODPH_ERR("Error: shm free\n");
		exit(EXIT_FAILURE);
	}

	if (odp_term_local()) {
		ODPH_ERR("Error: term local\n");
		exit(EXIT_FAILURE);
	}

	if (odp_term_global(instance)) {
		ODPH_ERR("Error: term global\n");
		exit(EXIT_FAILURE);
	}

	return ret;
}
