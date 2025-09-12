/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023-2025 Nokia
 */

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

#ifndef BENCH_COMMON_H
#define BENCH_COMMON_H

#ifdef __cplusplus
extern "C" {
#endif

#include <odp_api.h>
#include <odp/helper/odph_api.h>

#include <stdint.h>

/**
 * Check benchmark preconditions
 *
 * Returns !0 if benchmark precondition is met.
 */
typedef int (*bench_cond_fn_t)(void);

/**
 * Initialize benchmark resources
 */
typedef void (*bench_init_fn_t)(void);

/**
 * Run benchmark
 *
 * Returns >0 on success and 0 on failure.
 */
typedef int (*bench_run_fn_t)(void);

/**
 * Release benchmark resources
 */
typedef void (*bench_term_fn_t)(void);

/* Benchmark test data */
typedef struct {
	/* Default test name */
	const char *name;

	/* Optional alternate test description */
	const char *desc;

	/* Optional precondition to run test */
	bench_cond_fn_t cond;

	/* Optional test initializer function */
	bench_init_fn_t init;

	/* Test function to run */
	bench_run_fn_t run;

	/* Optional test terminate function */
	bench_term_fn_t term;

	/* Optional test specific limit for rounds (tuning for slow implementations) */
	uint32_t max_rounds;

} bench_info_t;

/* Benchmark suite data */
typedef struct {
	/* Array of benchmark functions */
	bench_info_t *bench;

	/* Number of benchmark functions */
	int num_bench;

	/* Optional benchmark index to run indefinitely (1...num_bench) */
	int indef_idx;

	/* Suite exit value output */
	int retval;

	/* Measure time vs. CPU cycles */
	odp_bool_t measure_time;

	/* Break worker loop if set to 1 */
	odp_atomic_u32_t exit_worker;

	/* Number of API function calls per test case */
	uint64_t repeat_count;

	/* Number of rounds per test case */
	uint64_t rounds;

	/* Dummy test result output */
	uint64_t dummy;

	/* Optional test result output array */
	double *result;

} bench_suite_t;

/**
 * Initialize benchmark suite parameters
 */
void bench_suite_init(bench_suite_t *suite);

/**
 * Run test suite and print results
 *
 * The argument is of type 'bench_suite_t *'. Returns 0 on success and <0 on failure.
 */
int bench_run(void *arg);

/*
 * Timed benchmark framework
 *
 * The main difference compared to the standard benchmark suite is that all
 * latency measurements are performed inside the test cases.
 */

/* Maximum number of benchmarked functions per test case */
#define BENCH_TM_MAX_FUNC 8

/* Stamp type for recording current instant in ODP time or cycles based on suite configuration */
typedef union {
	odp_time_t time;
	uint64_t cycles;

} bench_tm_stamp_t;

/* Function specific statistics */
typedef struct {
	/* Name of function */
	const char *name;

	/* Total duration of all function calls */
	bench_tm_stamp_t tot;

	/* Minimum duration */
	bench_tm_stamp_t min;

	/* Maximum duration */
	bench_tm_stamp_t max;

	/* Number of measurements */
	uint64_t num;

} bench_tm_func_res_t;

/* Get current instant */
typedef void (*bench_tm_now_fn_t)(bench_tm_stamp_t *stamp);

/* Record results of two stamps */
typedef void (*bench_tm_record_fn_t)(const bench_tm_stamp_t *s2, const bench_tm_stamp_t *s1,
				     bench_tm_func_res_t *res);

/* Get uint64_t representation of stamp */
typedef uint64_t (*bench_tm_to_u64_fn_t)(const bench_tm_stamp_t *stamp);

/* Timed benchmark results */
typedef struct bench_tm_results_s {
	/* Configured measurement operations */
	struct {
		bench_tm_now_fn_t now_fn;
		bench_tm_record_fn_t record_fn;
		bench_tm_to_u64_fn_t to_u64_fn;

	} op;

	/* Results per function */
	bench_tm_func_res_t func[BENCH_TM_MAX_FUNC];

	/* Number of registered test functions */
	uint8_t num;

} bench_tm_result_t;

/**
 * Timed benchmark test case
 *
 * Returns >0 on success and 0 on failure.
 */
typedef int (*bench_tm_run_fn_t)(bench_tm_result_t *res, int repeat_count);

/* Timed benchmark test case */
typedef struct {
	/* Test case name */
	const char *name;

	/* Optional precondition to run test */
	bench_cond_fn_t cond;

	/* Optional test initializer function */
	bench_init_fn_t init;

	/* Test function to run */
	bench_tm_run_fn_t run;

	/* Optional test termination function */
	bench_term_fn_t term;

	/* Optional test specific limit for rounds (tuning for slow implementations) */
	uint32_t max_rounds;

} bench_tm_info_t;

/* Timed benchmark suite data */
typedef struct {
	/* Array of benchmark test cases */
	bench_tm_info_t *bench;

	/* Number of benchmark test cases */
	uint32_t num_bench;

	/* Optional benchmark index to run (1...num_bench) */
	uint32_t bench_idx;

	/* Suite exit value output */
	int retval;

	/* Number of rounds per test case */
	uint64_t rounds;

	/* Measure time vs. CPU cycles */
	odp_bool_t measure_time;

	/* Break worker loop if set to 1 */
	odp_atomic_u32_t exit_worker;

	/* Optional test result output array */
	bench_tm_result_t *result;

} bench_tm_suite_t;

/**
 * Initialize benchmark suite data
 */
void bench_tm_suite_init(bench_tm_suite_t *suite);

/**
 * Register function for benchmarking
 *
 * Called by each test case to register benchmarked functions. Returns function
 * ID for recording benchmark results. At most BENCH_TM_MAX_FUNC functions can
 * be registered per test case.
 */
uint8_t bench_tm_func_register(bench_tm_result_t *res, const char *func_name);

/**
 * Record current instant
 */
void bench_tm_now(bench_tm_result_t *res, bench_tm_stamp_t *stamp);

/**
 * Get stamp as uint64_t
 */
uint64_t bench_tm_to_u64(bench_tm_result_t *res, const bench_tm_stamp_t *stamp);

/**
 * Record results for previously registered function
 *
 * Test case must call this function every test round for each registered
 * function.
 */
void bench_tm_func_record(bench_tm_stamp_t *s2, bench_tm_stamp_t *s1, bench_tm_result_t *res,
			  uint8_t id);

/**
 * Run timed test suite and print results
 *
 * The argument is of type 'bench_tm_suite_t *'. Returns 0 on success and <0 on failure.
 */
int bench_tm_run(void *arg);

#ifdef __cplusplus
}
#endif

#endif
