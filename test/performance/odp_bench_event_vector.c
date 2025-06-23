/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2025 Nokia
 */

/**
 * @example odp_bench_event_vector.c
 *
 * Microbenchmark application for event vector API functions
 *
 * @cond _ODP_HIDE_FROM_DOXYGEN_
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* Needed for sigaction */
#endif

#include <odp_api.h>
#include <odp/helper/odph_api.h>

#include <bench_common.h>
#include <export_results.h>

#include <getopt.h>
#include <inttypes.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

/** Max event vector size */
#define TEST_MAX_EVV_SIZE 128u

/** Default event vector size */
#define TEST_EVV_SIZE 8

/** Default buffer size */
#define TEST_BUF_SIZE 32

/** Default pool user area size in bytes */
#define TEST_UAREA_SIZE 8u

/** Number of API function calls per test case */
#define TEST_REPEAT_COUNT 1000

/** Default number of rounds per test case */
#define TEST_ROUNDS 100u

/** Maximum number of results to be held */
#define TEST_MAX_BENCH 20

#define BENCH_INFO(run_fn, init_fn, term_fn, alt_name) \
	{.name = #run_fn, .run = run_fn, .init = init_fn, .term = term_fn, .desc = alt_name}

/**
 * Parsed command line arguments
 */
typedef struct {
	int bench_idx;           /** Benchmark index to run indefinitely */
	int cache_size;          /** Pool cache size */
	int time;                /** Measure time vs. CPU cycles */
	uint32_t rounds;         /** Rounds per test case */
	uint32_t max_evv_size;   /** Maximum number of events in each event vector */
	uint32_t num_events;     /** Number of events in each event vector */
} appl_args_t;

/**
 * Grouping of all global data
 */
typedef struct {
	/** Application (parsed) arguments */
	appl_args_t appl;
	/** Common benchmark suite data */
	bench_suite_t suite;
	/** Event vector pool */
	odp_pool_t evv_pool;
	/** Buffer pool */
	odp_pool_t buf_pool;
	/** Event vector user area size */
	uint32_t evv_uarea_size;
	/** Array for storing test event vectors */
	odp_event_vector_t evv_arr[TEST_REPEAT_COUNT];
	/** Array for storing test events */
	odp_event_t event_arr[TEST_REPEAT_COUNT];
	/** Table for buffer events in event vectors */
	odp_event_t buf_event_tbl[TEST_REPEAT_COUNT][TEST_MAX_EVV_SIZE];
	/** Array for storing test pointers */
	void *ptr_tbl[TEST_REPEAT_COUNT];
	/** Array for storing test pool handles */
	odp_pool_t pool_tbl[TEST_REPEAT_COUNT];
	/** Array for storing test event types */
	odp_event_type_t event_type_arr[TEST_REPEAT_COUNT];
	/** CPU mask as string */
	char cpumask_str[ODP_CPUMASK_STR_SIZE];
	/** Array for storing results */
	double result[TEST_MAX_BENCH];
} args_t;

/* Global pointer to args */
static args_t *gbl_args;

static void sig_handler(int signo ODP_UNUSED)
{
	if (gbl_args == NULL)
		return;
	odp_atomic_store_u32(&gbl_args->suite.exit_worker, 1);
}

static int setup_sig_handler(void)
{
	struct sigaction action = { .sa_handler = sig_handler };

	if (sigemptyset(&action.sa_mask) || sigaction(SIGINT, &action, NULL))
		return -1;

	return 0;
}

static void allocate_test_evv_and_contents(odp_event_vector_t evv[], uint32_t num)
{
	odp_pool_t evv_pool = gbl_args->evv_pool;
	odp_pool_t buf_pool = gbl_args->buf_pool;
	uint32_t max_evv_size = gbl_args->appl.max_evv_size;
	uint32_t num_events = gbl_args->appl.num_events;
	odp_event_t (*buf_event_tbl)[TEST_MAX_EVV_SIZE] = gbl_args->buf_event_tbl;
	odp_buffer_t buf[max_evv_size];
	odp_event_t *evv_tbl;
	uint32_t num_buf, i, j;
	int alloc_ret;

	for (i = 0; i < num; i++) {
		evv[i] = odp_event_vector_alloc(evv_pool);
		if (evv[i] == ODP_EVENT_VECTOR_INVALID)
			ODPH_ABORT("Allocating test event vector failed\n");

		odp_event_vector_tbl(evv[i], &evv_tbl);

		num_buf = 0;
		while (num_buf < num_events) {
			alloc_ret = odp_buffer_alloc_multi(buf_pool,
							   &buf[num_buf], num_events - num_buf);
			if (alloc_ret < 0)
				ODPH_ABORT("Allocating test buffer(s) failed\n");
			num_buf += alloc_ret;
		}

		for (j = 0; j < num_events; j++) {
			buf_event_tbl[i][j] = odp_buffer_to_event(buf[j]);
			evv_tbl[j] = buf_event_tbl[i][j];
		}

		odp_event_vector_size_set(evv[i], num_events);
	}
}

static void create_event_vectors(void)
{
	odp_event_vector_t *evv = gbl_args->evv_arr;

	allocate_test_evv_and_contents(evv, TEST_REPEAT_COUNT);
}

static void create_events(void)
{
	odp_event_vector_t *evv = gbl_args->evv_arr;
	odp_event_t *tbl = gbl_args->event_arr;

	allocate_test_evv_and_contents(evv, TEST_REPEAT_COUNT);
	for (int i = 0; i < TEST_REPEAT_COUNT; i++)
		tbl[i] = odp_event_vector_to_event(evv[i]);
}

/**
 * Set the correct size and free the event vectors
 * Call as clean-up for event_vector_size_set()
 */
static void free_event_vector_size_set(void)
{
	odp_event_vector_t *evv_arr = gbl_args->evv_arr;
	uint32_t num_events = gbl_args->appl.num_events;

	for (int i = 0; i < TEST_REPEAT_COUNT; i++) {
		if (evv_arr[i] == ODP_EVENT_VECTOR_INVALID)
			ODPH_ABORT("Freeing event vector failed\n");
		odp_event_vector_size_set(evv_arr[i], num_events);
		odp_event_free(odp_event_vector_to_event(evv_arr[i]));
	}
}

static void free_event_vectors(void)
{
	odp_event_vector_t *evv_arr = gbl_args->evv_arr;

	for (int i = 0; i < TEST_REPEAT_COUNT; i++) {
		if (evv_arr[i] == ODP_EVENT_VECTOR_INVALID)
			ODPH_ABORT("Freeing event vector failed\n");
		odp_event_free(odp_event_vector_to_event(evv_arr[i]));
	}
}

static void free_buf_events(void)
{
	uint32_t num_events = gbl_args->appl.num_events;
	odp_event_t (*buf_event_tbl)[TEST_MAX_EVV_SIZE] = gbl_args->buf_event_tbl;

	for (int i = 0; i < TEST_REPEAT_COUNT; i++)
		odp_event_free_multi(buf_event_tbl[i], num_events);
}

static int event_vector_from_event(void)
{
	odp_event_vector_t *evv_arr = gbl_args->evv_arr;
	odp_event_t *event_arr = gbl_args->event_arr;
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		evv_arr[i] = odp_event_vector_from_event(event_arr[i]);

	return i;
}

static int event_vector_to_event(void)
{
	odp_event_vector_t *evv_arr = gbl_args->evv_arr;
	odp_event_t *event_arr = gbl_args->event_arr;
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		event_arr[i] = odp_event_vector_to_event(evv_arr[i]);

	return i;
}

static int event_vector_alloc(void)
{
	odp_event_vector_t *evv_arr = gbl_args->evv_arr;
	odp_pool_t evv_pool = gbl_args->evv_pool;
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		evv_arr[i] = odp_event_vector_alloc(evv_pool);

	return i;
}

static int event_vector_free(void)
{
	odp_event_vector_t *evv_arr = gbl_args->evv_arr;
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		odp_event_vector_free(evv_arr[i]);

	return i;
}

static int event_free(void)
{
	odp_event_t *event_arr = gbl_args->event_arr;
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		odp_event_free(event_arr[i]);

	return i;
}

static int event_vector_alloc_free(void)
{
	odp_pool_t evv_pool = gbl_args->evv_pool;
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++) {
		odp_event_vector_t evv = odp_event_vector_alloc(evv_pool);

		if (odp_unlikely(evv == ODP_EVENT_VECTOR_INVALID))
			return 0;

		odp_event_vector_free(evv);
	}
	return i;
}

static int event_vector_tbl(void)
{
	odp_event_vector_t *evv_arr = gbl_args->evv_arr;
	uint32_t num_events = gbl_args->appl.num_events;
	uint32_t ret = 0;
	odp_event_t *ptr;

	for (int i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_event_vector_tbl(evv_arr[i], &ptr);

	return ret == num_events * TEST_REPEAT_COUNT;
}

static int event_vector_size(void)
{
	odp_event_vector_t *evv_arr = gbl_args->evv_arr;
	uint32_t num_events = gbl_args->appl.num_events;
	uint32_t ret = 0;

	for (int i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_event_vector_size(evv_arr[i]);

	return ret == num_events * TEST_REPEAT_COUNT;
}

static int event_vector_type(void)
{
	odp_event_vector_t *evv_arr = gbl_args->evv_arr;
	odp_event_type_t *event_type = gbl_args->event_type_arr;
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		event_type[i] = odp_event_vector_type(evv_arr[i]);

	return i;
}

static int event_vector_size_set(void)
{
	const uint32_t size = gbl_args->appl.num_events ? gbl_args->appl.num_events - 1 : 0;
	odp_event_vector_t *evv_arr = gbl_args->evv_arr;
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		odp_event_vector_size_set(evv_arr[i], size);

	return i;
}

static int event_vector_user_area(void)
{
	odp_event_vector_t *evv_arr = gbl_args->evv_arr;
	void **ptr_tbl = gbl_args->ptr_tbl;
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ptr_tbl[i] = odp_event_vector_user_area(evv_arr[i]);

	return i;
}

static int event_vector_user_flag(void)
{
	odp_event_vector_t *evv_arr = gbl_args->evv_arr;
	int ret = 0;

	for (int i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += !odp_event_vector_user_flag(evv_arr[i]);

	return ret;
}

static int event_vector_user_flag_set(void)
{
	odp_event_vector_t *evv_arr = gbl_args->evv_arr;
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		odp_event_vector_user_flag_set(evv_arr[i], 1);

	return i;
}

static int event_vector_pool(void)
{
	odp_event_vector_t *evv_arr = gbl_args->evv_arr;
	odp_pool_t *pool_tbl = gbl_args->pool_tbl;
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		pool_tbl[i] = odp_event_vector_pool(evv_arr[i]);

	return i;
}

/**
 * Print usage information
 */
static void usage(void)
{
	printf("\n"
	       "OpenDataPlane Event vector API microbenchmarks.\n"
	       "\n"
	       "Optional OPTIONS:\n"
	       "  -c, --cache_size <num>  Pool cache size.\n"
	       "  -i, --index <idx>       Benchmark index to run indefinitely.\n"
	       "  -r, --rounds <num>      Run each test case 'num' times (default %u).\n"
	       "  -m,  -max_events <num>  Maximum number of events in each event vector (default %u).\n"
	       "  -n, --num_events <num>  Number of events in each event vector (default %u).\n"
	       "  -t, --time <opt>        Time measurement. 0: measure CPU cycles (default), 1: measure time\n"
	       "  -h, --help              Display help and exit.\n\n"
	       "\n", TEST_ROUNDS, TEST_EVV_SIZE, TEST_EVV_SIZE);
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
		{"cache_size", required_argument, NULL, 'c'},
		{"index", required_argument, NULL, 'i'},
		{"rounds", required_argument, NULL, 'r'},
		{"max_events", required_argument, NULL, 'm'},
		{"num_events", required_argument, NULL, 'n'},
		{"time", required_argument, NULL, 't'},
		{"help", no_argument, NULL, 'h'},
		{NULL, 0, NULL, 0}
	};

	static const char *shortopts =  "c:i:r:m:n:t:h";

	appl_args->bench_idx = 0; /* Run all benchmarks */
	appl_args->cache_size = -1;
	appl_args->rounds = TEST_ROUNDS;
	appl_args->max_evv_size = TEST_EVV_SIZE;
	appl_args->num_events = TEST_EVV_SIZE;
	appl_args->time = 0;

	while (1) {
		opt = getopt_long(argc, argv, shortopts, longopts, NULL);

		if (opt == -1)
			break;	/* No more options */

		switch (opt) {
		case 'c':
			appl_args->cache_size = atoi(optarg);
			break;
		case 'h':
			usage();
			exit(EXIT_SUCCESS);
			break;
		case 'i':
			appl_args->bench_idx = atoi(optarg);
			break;
		case 'r':
			appl_args->rounds = atoi(optarg);
			break;
		case 'm':
			appl_args->max_evv_size = atoi(optarg);
			break;
		case 'n':
			appl_args->num_events = atoi(optarg);
			break;
		case 't':
			appl_args->time = atoi(optarg);
			break;
		default:
			break;
		}
	}

	if (appl_args->rounds < 1) {
		printf("Invalid number test rounds: %d\n", appl_args->rounds);
		exit(EXIT_FAILURE);
	}

	if (appl_args->max_evv_size == 0) {
		printf("Invalid event vector maximum size: %d\n", appl_args->max_evv_size);
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
	       "odp_bench_event_vector options\n"
	       "------------------------\n");

	printf("Maximum number of events in each event vector:       %d\n",
	       gbl_args->appl.max_evv_size);
	printf("Number of events in each event vector:               %d\n",
	       gbl_args->appl.num_events);
	printf("CPU mask:                                            %s\n",
	       gbl_args->cpumask_str);
	if (gbl_args->appl.cache_size < 0)
		printf("Pool cache size:                                     default\n");
	else
		printf("Pool cache size:                                     %d\n",
		       gbl_args->appl.cache_size);
	printf("Measurement unit:                                    %s\n",
	       gbl_args->appl.time ? "nsec" : "CPU cycles");
	printf("Test rounds:                                         %u\n",
	       gbl_args->appl.rounds);
	printf("\n");
}

static int bench_event_vector_export(void *data)
{
	args_t *gbl_args = data;
	int ret = 0;

	if (test_common_write("%s", gbl_args->appl.time ?
			      "function name,average nsec per function call\n" :
			      "function name,average cpu cycles per function call\n")) {
		ret = -1;
		goto exit;
	}

	for (int i = 0; i < gbl_args->suite.num_bench; i++) {
		if (test_common_write("odp_%s,%f\n", gbl_args->suite.bench[i].desc != NULL ?
				      gbl_args->suite.bench[i].desc : gbl_args->suite.bench[i].name,
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
	BENCH_INFO(event_vector_from_event, create_events, free_event_vectors, NULL),
	BENCH_INFO(event_vector_to_event, create_event_vectors, free_event_vectors, NULL),
	BENCH_INFO(event_vector_alloc, NULL, free_event_vectors, NULL),
	BENCH_INFO(event_vector_free, create_event_vectors, free_buf_events, NULL),
	BENCH_INFO(event_free, create_events, NULL, NULL),
	BENCH_INFO(event_vector_alloc_free, NULL, NULL, NULL),
	BENCH_INFO(event_vector_tbl, create_event_vectors, free_event_vectors, NULL),
	BENCH_INFO(event_vector_size, create_event_vectors, free_event_vectors, NULL),
	BENCH_INFO(event_vector_type, create_event_vectors, free_event_vectors, NULL),
	BENCH_INFO(event_vector_size_set, create_event_vectors, free_event_vector_size_set, NULL),
	BENCH_INFO(event_vector_user_area, create_event_vectors, free_event_vectors, NULL),
	BENCH_INFO(event_vector_user_flag, create_event_vectors, free_event_vectors, NULL),
	BENCH_INFO(event_vector_user_flag_set, create_event_vectors, free_event_vectors, NULL),
	BENCH_INFO(event_vector_pool, create_event_vectors, free_event_vectors, NULL),
};

ODP_STATIC_ASSERT(ODPH_ARRAY_SIZE(test_suite) < TEST_MAX_BENCH,
		  "Result array is too small to hold all the results");

static int create_pools(void)
{
	odp_pool_capability_t capa;
	odp_pool_param_t evv_pool_params;
	odp_pool_param_t buf_pool_params;
	uint32_t buf_num = TEST_REPEAT_COUNT * gbl_args->appl.num_events;

	if (odp_pool_capability(&capa)) {
		ODPH_ERR("Error: unable to query pool capability\n");
		return -1;
	}

	if (capa.event_vector.max_pools == 0) {
		ODPH_ERR("Error: event vector pools not supported\n");
		return -1;
	}

	if (capa.event_vector.max_num && capa.event_vector.max_num < TEST_REPEAT_COUNT) {
		ODPH_ERR("Error: event vector pool size not supported (max %" PRIu32 ")\n",
			 capa.event_vector.max_num);
		return -1;
	}

	if (gbl_args->appl.cache_size > (int)capa.event_vector.max_cache_size) {
		ODPH_ERR("Error: cache size not supported (max %" PRIu32 ")\n",
			 capa.event_vector.max_cache_size);
		return -1;
	}

	if (gbl_args->appl.cache_size != -1 &&
	    gbl_args->appl.cache_size < (int)capa.buf.min_cache_size) {
		ODPH_ERR("Error: event vector pool cache size not supported (min %" PRIu32 ")\n",
			 capa.event_vector.min_cache_size);
		return -1;
	}

	if (gbl_args->appl.max_evv_size > ODPH_MIN(TEST_MAX_EVV_SIZE, capa.event_vector.max_size)) {
		ODPH_ERR("Error: event vector size not supported (max %" PRIu32 ")\n",
			 ODPH_MIN(capa.event_vector.max_size, TEST_MAX_EVV_SIZE));
		return -1;
	}

	if (gbl_args->appl.num_events > gbl_args->appl.max_evv_size) {
		ODPH_ERR("Error: number of event vector elements is larger than max (%u/%u)\n",
			 gbl_args->appl.num_events, gbl_args->appl.max_evv_size);
		return -1;
	}

	gbl_args->evv_uarea_size = ODPH_MIN(TEST_UAREA_SIZE, capa.event_vector.max_uarea_size);

	if (buf_num > capa.buf.max_num) {
		ODPH_ERR("Error: buffer pool size not supported (max %" PRIu32 ")\n",
			 capa.buf.max_num);
		return -1;
	}

	print_info();

	/* Create event vector pool */
	odp_pool_param_init(&evv_pool_params);
	evv_pool_params.event_vector.max_size = gbl_args->appl.max_evv_size;
	evv_pool_params.event_vector.num = TEST_REPEAT_COUNT;
	evv_pool_params.event_vector.uarea_size = gbl_args->evv_uarea_size;

	if (gbl_args->appl.cache_size >= 0)
		evv_pool_params.event_vector.cache_size = gbl_args->appl.cache_size;

	evv_pool_params.type = ODP_POOL_EVENT_VECTOR;
	gbl_args->evv_pool = odp_pool_create("microbench event vector", &evv_pool_params);

	if (gbl_args->evv_pool == ODP_POOL_INVALID) {
		ODPH_ERR("Error: pool create failed\n");
		return -1;
	}

	odp_pool_print(gbl_args->evv_pool);

	/* Create buffer pool */
	if (gbl_args->appl.num_events) {
		odp_pool_param_init(&buf_pool_params);
		buf_pool_params.buf.size = TEST_BUF_SIZE;
		buf_pool_params.buf.num = buf_num;
		buf_pool_params.type = ODP_POOL_BUFFER;

		gbl_args->buf_pool = odp_pool_create("microbench buffer", &buf_pool_params);
		if (gbl_args->buf_pool == ODP_POOL_INVALID) {
			ODPH_ERR("Error: pool create failed\n");
			return -1;
		}

		odp_pool_print(gbl_args->buf_pool);
	}

	return 0;
}

/**
 * ODP event vector microbenchmark application
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
	odp_instance_t instance;
	odp_init_t init_param;
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

	if (setup_sig_handler()) {
		ODPH_ERR("Signal handler setup failed\n");
		exit(EXIT_FAILURE);
	}

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
		ret = -1;
		goto exit;
	}
	(void)odp_cpumask_to_str(&default_mask, gbl_args->cpumask_str,
				 sizeof(gbl_args->cpumask_str));

	if (create_pools()) {
		ret = -1;
		goto exit;
	}

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

	if (odph_thread_create(&worker_thread, &thr_common, &thr_param, 1) != 1) {
		ODPH_ERR("Error: unable to create worker thread\n");
		ret = -1;
		goto exit;
	}

	if (odph_thread_join(&worker_thread, 1) != 1) {
		ODPH_ERR("Error: unable to join worker thread\n");
		ret = -1;
		goto exit;
	}

	ret = gbl_args->suite.retval;

	if (ret == 0 && common_options.is_export) {
		if (bench_event_vector_export(gbl_args)) {
			ODPH_ERR("Error: Export failed\n");
			ret = -1;
		}
	}

exit:
	if ((gbl_args->evv_pool && odp_pool_destroy(gbl_args->evv_pool)) ||
	    (gbl_args->buf_pool && odp_pool_destroy(gbl_args->buf_pool))) {
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
