/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Nokia
 */

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
 * @retval !0 test enabled
 */
typedef int (*bench_cond_fn_t)(void);

/**
 * Initialize benchmark resources
 */
typedef void (*bench_init_fn_t)(void);

/**
 * Run benchmark
 *
 * @retval >0 on success
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

/**
 * Run selected test indefinitely
 */
void bench_run_indef(bench_info_t *info, odp_atomic_u32_t *exit_thread);

#ifdef __cplusplus
}
#endif

#endif
