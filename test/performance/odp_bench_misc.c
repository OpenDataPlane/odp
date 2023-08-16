/* Copyright (c) 2022-2023, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* Needed for sigaction */
#endif

#include <odp_api.h>
#include <odp/helper/odph_api.h>

#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

/* Number of API function calls per test case */
#define REPEAT_COUNT 1000

/* Default number of rounds per test case */
#define ROUNDS 1000u

#define BENCH_INFO(run, init, max, name) \
	{#run, run, init, max, name}

typedef struct {
	/* Measure time vs CPU cycles */
	int time;

	/* Benchmark index to run indefinitely */
	int bench_idx;

	/* Rounds per test case */
	uint32_t rounds;

} appl_args_t;

/* Initialize benchmark resources */
typedef void (*bench_init_fn_t)(void);

/* Run benchmark, returns >0 on success */
typedef int (*bench_run_fn_t)(void);

/* Benchmark data */
typedef struct {
	/* Default test name */
	const char *name;

	/* Test function to run */
	bench_run_fn_t run;

	/* Test init function */
	bench_init_fn_t init;

	/* Test specific limit for rounds (tuning for slow implementation) */
	uint32_t max_rounds;

	/* Override default test name */
	const char *desc;

} bench_info_t;

/* Global data */
typedef struct {
	appl_args_t appl;

	/* Benchmark functions */
	bench_info_t *bench;

	/* Number of benchmark functions */
	int num_bench;

	/* Break worker loop if set to 1 */
	odp_atomic_u32_t exit_thread;

	/* Test case input / output data */
	odp_time_t t1[REPEAT_COUNT];
	odp_time_t t2[REPEAT_COUNT];
	odp_time_t t3[REPEAT_COUNT];
	uint64_t   a1[REPEAT_COUNT];
	uint64_t   a2[REPEAT_COUNT];
	uint32_t   b1[REPEAT_COUNT];
	uint32_t   b2[REPEAT_COUNT];
	uint16_t   c1[REPEAT_COUNT];
	uint16_t   c2[REPEAT_COUNT];

	/* Dummy result */
	uint64_t dummy;

	/* Benchmark run failed */
	int bench_failed;

	/* CPU mask as string */
	char cpumask_str[ODP_CPUMASK_STR_SIZE];

} gbl_args_t;

static gbl_args_t *gbl_args;

static void sig_handler(int signo ODP_UNUSED)
{
	if (gbl_args == NULL)
		return;
	odp_atomic_store_u32(&gbl_args->exit_thread, 1);
}

static int setup_sig_handler(void)
{
	struct sigaction action;

	memset(&action, 0, sizeof(action));
	action.sa_handler = sig_handler;

	/* No additional signals blocked. By default, the signal which triggered
	 * the handler is blocked. */
	if (sigemptyset(&action.sa_mask))
		return -1;

	if (sigaction(SIGINT, &action, NULL))
		return -1;

	return 0;
}

/* Run given benchmark indefinitely */
static void run_indef(gbl_args_t *args, int idx)
{
	const char *desc;
	const bench_info_t *bench = &args->bench[idx];

	desc = bench->desc != NULL ? bench->desc : bench->name;

	printf("Running odp_%s test indefinitely\n", desc);

	while (!odp_atomic_load_u32(&gbl_args->exit_thread)) {
		int ret;

		if (bench->init != NULL)
			bench->init();

		ret = bench->run();

		if (!ret)
			ODPH_ABORT("Benchmark %s failed\n", desc);
	}
}

static int run_benchmarks(void *arg)
{
	int i, j;
	uint64_t c1, c2;
	odp_time_t t1, t2;
	gbl_args_t *args = arg;
	const int meas_time = args->appl.time;

	printf("\nAverage %s per function call\n", meas_time ? "time (nsec)" : "CPU cycles");
	printf("-------------------------------------------------\n");

	/* Run each test twice. Results from the first warm-up round are ignored. */
	for (i = 0; i < 2; i++) {
		uint64_t total = 0;
		uint32_t round = 1;

		for (j = 0; j < gbl_args->num_bench; round++) {
			int ret;
			const char *desc;
			const bench_info_t *bench = &args->bench[j];
			uint32_t max_rounds = args->appl.rounds;

			if (bench->max_rounds && max_rounds > bench->max_rounds)
				max_rounds = bench->max_rounds;

			/* Run selected test indefinitely */
			if (args->appl.bench_idx) {
				if ((j + 1) != args->appl.bench_idx) {
					j++;
					continue;
				}

				run_indef(args, j);
				return 0;
			}

			desc = bench->desc != NULL ? bench->desc : bench->name;

			if (bench->init != NULL)
				bench->init();

			if (meas_time)
				t1 = odp_time_local();
			else
				c1 = odp_cpu_cycles();

			ret = bench->run();

			if (meas_time)
				t2 = odp_time_local();
			else
				c2 = odp_cpu_cycles();

			if (!ret) {
				ODPH_ERR("Benchmark odp_%s failed\n", desc);
				args->bench_failed = -1;
				return -1;
			}

			if (meas_time)
				total += odp_time_diff_ns(t2, t1);
			else
				total += odp_cpu_cycles_diff(c2, c1);

			if (round >= max_rounds) {
				double result;

				/* Each benchmark runs internally REPEAT_COUNT times. */
				result = ((double)total) / (max_rounds * REPEAT_COUNT);

				/* No print from warm-up round */
				if (i > 0)
					printf("[%02d] odp_%-26s: %12.2f\n", j + 1, desc, result);

				j++;
				total = 0;
				round = 1;
			}
		}
	}

	/* Print dummy result to prevent compiler to optimize it away*/
	printf("\n(dummy result: 0x%" PRIx64 ")\n", args->dummy);

	printf("\n");

	return 0;
}

static void init_time_global(void)
{
	int i;
	odp_time_t *t1 = gbl_args->t1;
	odp_time_t *t2 = gbl_args->t2;
	uint64_t *a1 = gbl_args->a1;

	for (i = 0; i < REPEAT_COUNT; i++)
		t1[i] = odp_time_global();

	for (i = 0; i < REPEAT_COUNT; i++)
		t2[i] = odp_time_global();

	for (i = 0; i < REPEAT_COUNT; i++)
		a1[i] = odp_time_global_ns();
}

static void init_time_local(void)
{
	int i;
	odp_time_t *t1 = gbl_args->t1;
	odp_time_t *t2 = gbl_args->t2;
	uint64_t *a1 = gbl_args->a1;

	for (i = 0; i < REPEAT_COUNT; i++)
		t1[i] = odp_time_local();

	for (i = 0; i < REPEAT_COUNT; i++)
		t2[i] = odp_time_local();

	for (i = 0; i < REPEAT_COUNT; i++)
		a1[i] = odp_time_local_ns();
}

static void init_cpu_cycles(void)
{
	int i;
	uint64_t *a1 = gbl_args->a1;
	uint64_t *a2 = gbl_args->a2;

	for (i = 0; i < REPEAT_COUNT; i++)
		a1[i] = odp_cpu_cycles();

	for (i = 0; i < REPEAT_COUNT; i++)
		a2[i] = odp_cpu_cycles();
}

static int time_local(void)
{
	int i;
	odp_time_t *t1 = gbl_args->t1;

	for (i = 0; i < REPEAT_COUNT; i++)
		t1[i] = odp_time_local();

	return i;
}

static int time_local_strict(void)
{
	int i;
	odp_time_t *t1 = gbl_args->t1;

	for (i = 0; i < REPEAT_COUNT; i++)
		t1[i] = odp_time_local_strict();

	return i;
}

static int time_local_ns(void)
{
	int i;
	uint64_t *a1 = gbl_args->a1;

	for (i = 0; i < REPEAT_COUNT; i++)
		a1[i] = odp_time_local_ns();

	return i;
}

static int time_local_strict_ns(void)
{
	int i;
	uint64_t *a1 = gbl_args->a1;

	for (i = 0; i < REPEAT_COUNT; i++)
		a1[i] = odp_time_local_strict_ns();

	return i;
}

static int time_global(void)
{
	int i;
	odp_time_t *t1 = gbl_args->t1;

	for (i = 0; i < REPEAT_COUNT; i++)
		t1[i] = odp_time_global();

	return i;
}

static int time_global_strict(void)
{
	int i;
	odp_time_t *t1 = gbl_args->t1;

	for (i = 0; i < REPEAT_COUNT; i++)
		t1[i] = odp_time_global_strict();

	return i;
}

static int time_global_ns(void)
{
	int i;
	uint64_t *a1 = gbl_args->a1;

	for (i = 0; i < REPEAT_COUNT; i++)
		a1[i] = odp_time_global_ns();

	return i;
}

static int time_global_strict_ns(void)
{
	int i;
	uint64_t *a1 = gbl_args->a1;

	for (i = 0; i < REPEAT_COUNT; i++)
		a1[i] = odp_time_global_strict_ns();

	return i;
}

static int time_diff(void)
{
	int i;
	odp_time_t *t1 = gbl_args->t1;
	odp_time_t *t2 = gbl_args->t2;
	odp_time_t *t3 = gbl_args->t3;

	for (i = 0; i < REPEAT_COUNT; i++)
		t3[i] = odp_time_diff(t2[i], t1[i]);

	return i;
}

static int time_diff_ns(void)
{
	int i;
	odp_time_t *t1 = gbl_args->t1;
	odp_time_t *t2 = gbl_args->t2;
	uint64_t res = 0;

	for (i = 0; i < REPEAT_COUNT; i++)
		res += odp_time_diff_ns(t2[i], t1[i]);

	gbl_args->dummy += res;

	return i;
}

static int time_sum(void)
{
	int i;
	odp_time_t *t1 = gbl_args->t1;
	odp_time_t *t2 = gbl_args->t2;
	odp_time_t *t3 = gbl_args->t3;

	for (i = 0; i < REPEAT_COUNT; i++)
		t3[i] = odp_time_sum(t1[i], t2[i]);

	return i;
}

static int time_to_ns(void)
{
	int i;
	odp_time_t *t1 = gbl_args->t1;
	uint64_t res = 0;

	for (i = 0; i < REPEAT_COUNT; i++)
		res += odp_time_to_ns(t1[i]);

	gbl_args->dummy += res;

	return i;
}

static int time_local_from_ns(void)
{
	int i;
	odp_time_t *t1 = gbl_args->t1;
	uint64_t *a1 = gbl_args->a1;

	for (i = 0; i < REPEAT_COUNT; i++)
		t1[i] = odp_time_local_from_ns(a1[i]);

	return i;
}

static int time_global_from_ns(void)
{
	int i;
	odp_time_t *t1 = gbl_args->t1;
	uint64_t *a1 = gbl_args->a1;

	for (i = 0; i < REPEAT_COUNT; i++)
		t1[i] = odp_time_global_from_ns(a1[i]);

	return i;
}

static int time_cmp(void)
{
	int i;
	odp_time_t *t1 = gbl_args->t1;
	odp_time_t *t2 = gbl_args->t2;
	int res = 0;

	for (i = 0; i < REPEAT_COUNT; i++)
		res += odp_time_cmp(t1[i], t2[i]);

	gbl_args->dummy += res;

	return i;
}

static int time_local_res(void)
{
	int i;
	uint64_t *a1 = gbl_args->a1;

	for (i = 0; i < REPEAT_COUNT; i++)
		a1[i] = odp_time_local_res();

	return i;
}

static int time_global_res(void)
{
	int i;
	uint64_t *a1 = gbl_args->a1;

	for (i = 0; i < REPEAT_COUNT; i++)
		a1[i] = odp_time_global_res();

	return i;
}

static int cpu_id(void)
{
	int i;
	uint64_t *a1 = gbl_args->a1;

	for (i = 0; i < REPEAT_COUNT; i++)
		a1[i] = odp_cpu_id();

	return i;
}

static int cpu_count(void)
{
	int i;
	uint64_t *a1 = gbl_args->a1;

	for (i = 0; i < REPEAT_COUNT; i++)
		a1[i] = odp_cpu_count();

	return i;
}

static int cpu_hz(void)
{
	int i;
	uint64_t *a1 = gbl_args->a1;

	for (i = 0; i < REPEAT_COUNT; i++)
		a1[i] = odp_cpu_hz();

	return i;
}

static int cpu_hz_id(void)
{
	int i;
	const int id = odp_cpu_id();
	uint64_t *a1 = gbl_args->a1;

	for (i = 0; i < REPEAT_COUNT; i++)
		a1[i] = odp_cpu_hz_id(id);

	return i;
}

static int cpu_hz_max(void)
{
	int i;
	uint64_t *a1 = gbl_args->a1;

	for (i = 0; i < REPEAT_COUNT; i++)
		a1[i] = odp_cpu_hz_max();

	return i;
}

static int cpu_hz_max_id(void)
{
	int i;
	const int id = odp_cpu_id();
	uint64_t *a1 = gbl_args->a1;

	for (i = 0; i < REPEAT_COUNT; i++)
		a1[i] = odp_cpu_hz_max_id(id);

	return i;
}

static int cpu_cycles(void)
{
	int i;
	uint64_t *a1 = gbl_args->a1;

	for (i = 0; i < REPEAT_COUNT; i++)
		a1[i] = odp_cpu_cycles();

	return i;
}

static int cpu_cycles_diff(void)
{
	int i;
	uint64_t *a1 = gbl_args->a1;
	uint64_t *a2 = gbl_args->a2;
	uint64_t res = 0;

	for (i = 0; i < REPEAT_COUNT; i++)
		res += odp_cpu_cycles_diff(a2[i], a1[i]);

	gbl_args->dummy += res;

	return i;
}

static int cpu_cycles_max(void)
{
	int i;
	uint64_t *a1 = gbl_args->a1;

	for (i = 0; i < REPEAT_COUNT; i++)
		a1[i] = odp_cpu_cycles_max();

	return i;
}

static int cpu_cycles_resolution(void)
{
	int i;
	uint64_t *a1 = gbl_args->a1;

	for (i = 0; i < REPEAT_COUNT; i++)
		a1[i] = odp_cpu_cycles_resolution();

	return i;
}

static int cpu_pause(void)
{
	int i;

	for (i = 0; i < REPEAT_COUNT; i++)
		odp_cpu_pause();

	return i;
}

static int thread_id(void)
{
	int i;
	uint64_t *a1 = gbl_args->a1;

	for (i = 0; i < REPEAT_COUNT; i++)
		a1[i] = odp_thread_id();

	return i;
}

static int thread_count(void)
{
	int i;
	uint64_t *a1 = gbl_args->a1;

	for (i = 0; i < REPEAT_COUNT; i++)
		a1[i] = odp_thread_count();

	return i;
}

static int thread_count_max(void)
{
	int i;
	uint64_t *a1 = gbl_args->a1;

	for (i = 0; i < REPEAT_COUNT; i++)
		a1[i] = odp_thread_count_max();

	return i;
}

static int thread_type(void)
{
	int i;
	uint64_t *a1 = gbl_args->a1;

	for (i = 0; i < REPEAT_COUNT; i++)
		a1[i] = (int)odp_thread_type();

	return i;
}

static int be_to_cpu_64(void)
{
	int i;
	uint64_t *a1 = gbl_args->a1;
	uint64_t *a2 = gbl_args->a2;

	for (i = 0; i < REPEAT_COUNT; i++)
		a2[i] = odp_be_to_cpu_64(a1[i]);

	return i;
}

static int be_to_cpu_32(void)
{
	int i;
	uint32_t *b1 = gbl_args->b1;
	uint32_t *b2 = gbl_args->b2;

	for (i = 0; i < REPEAT_COUNT; i++)
		b2[i] = odp_be_to_cpu_32(b1[i]);

	return i;
}

static int be_to_cpu_16(void)
{
	int i;
	uint16_t *c1 = gbl_args->c1;
	uint16_t *c2 = gbl_args->c2;

	for (i = 0; i < REPEAT_COUNT; i++)
		c2[i] = odp_be_to_cpu_16(c1[i]);

	return i;
}

static int cpu_to_be_64(void)
{
	int i;
	uint64_t *a1 = gbl_args->a1;
	uint64_t *a2 = gbl_args->a2;

	for (i = 0; i < REPEAT_COUNT; i++)
		a2[i] = odp_cpu_to_be_64(a1[i]);

	return i;
}

static int cpu_to_be_32(void)
{
	int i;
	uint32_t *b1 = gbl_args->b1;
	uint32_t *b2 = gbl_args->b2;

	for (i = 0; i < REPEAT_COUNT; i++)
		b2[i] = odp_cpu_to_be_32(b1[i]);

	return i;
}

static int cpu_to_be_16(void)
{
	int i;
	uint16_t *c1 = gbl_args->c1;
	uint16_t *c2 = gbl_args->c2;

	for (i = 0; i < REPEAT_COUNT; i++)
		c2[i] = odp_cpu_to_be_16(c1[i]);

	return i;
}

static int le_to_cpu_64(void)
{
	int i;
	uint64_t *a1 = gbl_args->a1;
	uint64_t *a2 = gbl_args->a2;

	for (i = 0; i < REPEAT_COUNT; i++)
		a2[i] = odp_le_to_cpu_64(a1[i]);

	return i;
}

static int le_to_cpu_32(void)
{
	int i;
	uint32_t *b1 = gbl_args->b1;
	uint32_t *b2 = gbl_args->b2;

	for (i = 0; i < REPEAT_COUNT; i++)
		b2[i] = odp_le_to_cpu_32(b1[i]);

	return i;
}

static int le_to_cpu_16(void)
{
	int i;
	uint16_t *c1 = gbl_args->c1;
	uint16_t *c2 = gbl_args->c2;

	for (i = 0; i < REPEAT_COUNT; i++)
		c2[i] = odp_le_to_cpu_16(c1[i]);

	return i;
}

static int cpu_to_le_64(void)
{
	int i;
	uint64_t *a1 = gbl_args->a1;
	uint64_t *a2 = gbl_args->a2;

	for (i = 0; i < REPEAT_COUNT; i++)
		a2[i] = odp_cpu_to_le_64(a1[i]);

	return i;
}

static int cpu_to_le_32(void)
{
	int i;
	uint32_t *b1 = gbl_args->b1;
	uint32_t *b2 = gbl_args->b2;

	for (i = 0; i < REPEAT_COUNT; i++)
		b2[i] = odp_cpu_to_le_32(b1[i]);

	return i;
}

static int cpu_to_le_16(void)
{
	int i;
	uint16_t *c1 = gbl_args->c1;
	uint16_t *c2 = gbl_args->c2;

	for (i = 0; i < REPEAT_COUNT; i++)
		c2[i] = odp_cpu_to_le_16(c1[i]);

	return i;
}

static int mb_release(void)
{
	int i;

	for (i = 0; i < REPEAT_COUNT; i++)
		odp_mb_release();

	return i;
}

static int mb_acquire(void)
{
	int i;

	for (i = 0; i < REPEAT_COUNT; i++)
		odp_mb_acquire();

	return i;
}

static int mb_full(void)
{
	int i;

	for (i = 0; i < REPEAT_COUNT; i++)
		odp_mb_full();

	return i;
}

bench_info_t test_suite[] = {
	BENCH_INFO(time_local, NULL, 0, NULL),
	BENCH_INFO(time_local_strict, NULL, 0, NULL),
	BENCH_INFO(time_local_ns, NULL, 0, NULL),
	BENCH_INFO(time_local_strict_ns, NULL, 0, NULL),
	BENCH_INFO(time_global, NULL, 0, NULL),
	BENCH_INFO(time_global_strict, NULL, 0, NULL),
	BENCH_INFO(time_global_ns, NULL, 0, NULL),
	BENCH_INFO(time_global_strict_ns, NULL, 0, NULL),
	BENCH_INFO(time_diff, init_time_global, 0, "time_diff (global)"),
	BENCH_INFO(time_diff, init_time_local, 0, "time_diff (local)"),
	BENCH_INFO(time_diff_ns, init_time_global, 0, NULL),
	BENCH_INFO(time_sum, init_time_global, 0, NULL),
	BENCH_INFO(time_to_ns, init_time_global, 0, NULL),
	BENCH_INFO(time_local_from_ns, init_time_global, 0, NULL),
	BENCH_INFO(time_global_from_ns, init_time_global, 0, NULL),
	BENCH_INFO(time_cmp, init_time_global, 0, NULL),
	BENCH_INFO(time_local_res, NULL, 0, NULL),
	BENCH_INFO(time_global_res, NULL, 0, NULL),
	BENCH_INFO(cpu_id, NULL, 0, NULL),
	BENCH_INFO(cpu_count, NULL, 0, NULL),
	BENCH_INFO(cpu_hz, NULL, 1, NULL),
	BENCH_INFO(cpu_hz_id, NULL, 1, NULL),
	BENCH_INFO(cpu_hz_max, NULL, 0, NULL),
	BENCH_INFO(cpu_hz_max_id, NULL, 0, NULL),
	BENCH_INFO(cpu_cycles, NULL, 0, NULL),
	BENCH_INFO(cpu_cycles_diff, init_cpu_cycles, 0, NULL),
	BENCH_INFO(cpu_cycles_max, NULL, 0, NULL),
	BENCH_INFO(cpu_cycles_resolution, NULL, 0, NULL),
	BENCH_INFO(cpu_pause, NULL, 0, NULL),
	BENCH_INFO(thread_id, NULL, 0, NULL),
	BENCH_INFO(thread_count, NULL, 0, NULL),
	BENCH_INFO(thread_count_max, NULL, 0, NULL),
	BENCH_INFO(thread_type, NULL, 0, NULL),
	BENCH_INFO(be_to_cpu_64, NULL, 0, NULL),
	BENCH_INFO(be_to_cpu_32, NULL, 0, NULL),
	BENCH_INFO(be_to_cpu_16, NULL, 0, NULL),
	BENCH_INFO(cpu_to_be_64, NULL, 0, NULL),
	BENCH_INFO(cpu_to_be_32, NULL, 0, NULL),
	BENCH_INFO(cpu_to_be_16, NULL, 0, NULL),
	BENCH_INFO(le_to_cpu_64, NULL, 0, NULL),
	BENCH_INFO(le_to_cpu_32, NULL, 0, NULL),
	BENCH_INFO(le_to_cpu_16, NULL, 0, NULL),
	BENCH_INFO(cpu_to_le_64, NULL, 0, NULL),
	BENCH_INFO(cpu_to_le_32, NULL, 0, NULL),
	BENCH_INFO(cpu_to_le_16, NULL, 0, NULL),
	BENCH_INFO(mb_release, NULL, 0, NULL),
	BENCH_INFO(mb_acquire, NULL, 0, NULL),
	BENCH_INFO(mb_full, NULL, 0, NULL),
};

/* Print usage information */
static void usage(void)
{
	printf("\n"
	       "ODP miscellaneous API micro benchmarks\n"
	       "\n"
	       "Options:\n"
	       "  -t, --time <opt>        Time measurement. 0: measure CPU cycles (default), 1: measure time\n"
	       "  -i, --index <idx>       Benchmark index to run indefinitely.\n"
	       "  -r, --rounds <num>      Run each test case 'num' times (default %u).\n"
	       "  -h, --help              Display help and exit.\n\n"
	       "\n", ROUNDS);
}

/* Parse command line arguments */
static int parse_args(int argc, char *argv[])
{
	int opt;
	int long_index;
	appl_args_t *appl_args = &gbl_args->appl;
	static const struct option longopts[] = {
		{"time", required_argument, NULL, 't'},
		{"index", required_argument, NULL, 'i'},
		{"rounds", required_argument, NULL, 'r'},
		{"help", no_argument, NULL, 'h'},
		{NULL, 0, NULL, 0}
	};

	static const char *shortopts =  "t:i:r:h";

	appl_args->time = 0;        /* Measure CPU cycles */
	appl_args->bench_idx = 0;   /* Run all benchmarks */
	appl_args->rounds = ROUNDS;

	while (1) {
		opt = getopt_long(argc, argv, shortopts, longopts, &long_index);

		if (opt == -1)
			break;	/* No more options */

		switch (opt) {
		case 't':
			appl_args->time = atoi(optarg);
			break;
		case 'i':
			appl_args->bench_idx = atoi(optarg);
			break;
		case 'r':
			appl_args->rounds = atoi(optarg);
			break;
		case 'h':
			usage();
			return 1;
		default:
			ODPH_ERR("Bad option. Use -h for help.\n");
			return -1;
		}
	}

	if (appl_args->rounds < 1) {
		ODPH_ERR("Invalid test cycle repeat count: %u\n", appl_args->rounds);
		return -1;
	}

	if (appl_args->bench_idx < 0 || appl_args->bench_idx > gbl_args->num_bench) {
		ODPH_ERR("Bad bench index %i\n", appl_args->bench_idx);
		return -1;
	}

	optind = 1; /* Reset 'extern optind' from the getopt lib */

	return 0;
}

/* Print system and application info */
static void print_info(void)
{
	odp_sys_info_print();

	printf("\n"
	       "odp_bench_misc options\n"
	       "----------------------\n");

	printf("CPU mask:          %s\n", gbl_args->cpumask_str);
	printf("Measurement unit:  %s\n", gbl_args->appl.time ? "nsec" : "CPU cycles");
	printf("Test rounds:       %u\n", gbl_args->appl.rounds);
	printf("\n");
}

int main(int argc, char *argv[])
{
	odph_helper_options_t helper_options;
	odph_thread_t worker_thread;
	odph_thread_common_param_t thr_common;
	odph_thread_param_t thr_param;
	int cpu, i;
	odp_shm_t shm;
	odp_cpumask_t cpumask, default_mask;
	odp_instance_t instance;
	odp_init_t init_param;
	int ret = 0;

	/* Let helper collect its own arguments (e.g. --odph_proc) */
	argc = odph_parse_options(argc, argv);
	if (odph_options(&helper_options)) {
		ODPH_ERR("Reading ODP helper options failed\n");
		exit(EXIT_FAILURE);
	}

	odp_init_param_init(&init_param);
	init_param.mem_model = helper_options.mem_model;

	/* Init ODP before calling anything else */
	if (odp_init_global(&instance, &init_param, NULL)) {
		ODPH_ERR("Global init failed\n");
		exit(EXIT_FAILURE);
	}

	/* Init this thread */
	if (odp_init_local(instance, ODP_THREAD_CONTROL)) {
		ODPH_ERR("Local init failed\n");
		exit(EXIT_FAILURE);
	}

	if (setup_sig_handler()) {
		ODPH_ERR("Signal handler setup failed\n");
		exit(EXIT_FAILURE);
	}

	/* Reserve memory for args from shared mem */
	shm = odp_shm_reserve("shm_args", sizeof(gbl_args_t), ODP_CACHE_LINE_SIZE, 0);
	if (shm == ODP_SHM_INVALID) {
		ODPH_ERR("Shared mem reserve failed\n");
		exit(EXIT_FAILURE);
	}

	gbl_args = odp_shm_addr(shm);
	if (gbl_args == NULL) {
		ODPH_ERR("Shared mem alloc failed\n");
		exit(EXIT_FAILURE);
	}

	memset(gbl_args, 0, sizeof(gbl_args_t));
	odp_atomic_init_u32(&gbl_args->exit_thread, 0);

	gbl_args->bench = test_suite;
	gbl_args->num_bench = sizeof(test_suite) / sizeof(test_suite[0]);

	for (i = 0; i < REPEAT_COUNT; i++) {
		gbl_args->t1[i] = ODP_TIME_NULL;
		gbl_args->t2[i] = ODP_TIME_NULL;
		gbl_args->t3[i] = ODP_TIME_NULL;
		gbl_args->a1[i] = i;
		gbl_args->a2[i] = i;
		gbl_args->b1[i] = i;
		gbl_args->b2[i] = i;
		gbl_args->c1[i] = i;
		gbl_args->c2[i] = i;
	}

	/* Parse and store the application arguments */
	ret = parse_args(argc, argv);
	if (ret)
		goto exit;

	/* Get default worker cpumask */
	if (odp_cpumask_default_worker(&default_mask, 1) != 1) {
		ODPH_ERR("Unable to allocate worker thread\n");
		ret = -1;
		goto exit;
	}

	(void)odp_cpumask_to_str(&default_mask, gbl_args->cpumask_str,
				 sizeof(gbl_args->cpumask_str));

	print_info();

	memset(&worker_thread, 0, sizeof(odph_thread_t));

	/* Create worker thread */
	cpu = odp_cpumask_first(&default_mask);

	odp_cpumask_zero(&cpumask);
	odp_cpumask_set(&cpumask, cpu);

	odph_thread_common_param_init(&thr_common);
	thr_common.instance = instance;
	thr_common.cpumask = &cpumask;
	thr_common.share_param = 1;

	odph_thread_param_init(&thr_param);
	thr_param.start = run_benchmarks;
	thr_param.arg = gbl_args;
	thr_param.thr_type = ODP_THREAD_WORKER;

	odph_thread_create(&worker_thread, &thr_common, &thr_param, 1);

	odph_thread_join(&worker_thread, 1);

	ret = gbl_args->bench_failed;

exit:
	if (odp_shm_free(shm)) {
		ODPH_ERR("Shared mem free failed\n");
		exit(EXIT_FAILURE);
	}

	if (odp_term_local()) {
		ODPH_ERR("Local term failed\n");
		exit(EXIT_FAILURE);
	}

	if (odp_term_global(instance)) {
		ODPH_ERR("Global term failed\n");
		exit(EXIT_FAILURE);
	}

	if (ret < 0)
		return EXIT_FAILURE;

	return EXIT_SUCCESS;
}
