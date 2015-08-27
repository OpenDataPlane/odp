/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP test application common headers
 */

#ifndef ODP_CUNICT_COMMON_H
#define ODP_CUNICT_COMMON_H

#include <stdint.h>
#include "CUnit/Basic.h"

#define MAX_WORKERS 32 /**< Maximum number of work threads */

/* the function, called by module main(), to run the testsuites: */
int odp_cunit_run(CU_SuiteInfo testsuites[]);

/* the macro used to have test names (strings) matching function symbols */
#define _CU_TEST_INFO(test_func) {#test_func, test_func}

typedef struct {
	uint32_t foo;
	uint32_t bar;
} test_shared_data_t;

/**
 * Thread argument
 */
typedef struct {
	int testcase; /**< specifies which set of API's to exercise */
	int numthrds; /**< no of pthreads to create */
} pthrd_arg;

/** create thread fro start_routine function */
extern int odp_cunit_thread_create(void *func_ptr(void *), pthrd_arg *arg);
extern int odp_cunit_thread_exit(pthrd_arg *);

/**
 * Global tests initialization/termination.
 *
 * Initialize global resources needed by the test executable. Default
 * definition does ODP init / term (both global and local).
 * Test executables can override it by calling one of the register function
 * below.
 * The functions are called at the very beginning and very end of the test
 * execution. Passing NULL to odp_cunit_register_global_init() and/or
 * odp_cunit_register_global_term() is legal and will simply prevent the
 * default (ODP init/term) to be done.
 */
void odp_cunit_register_global_init(int (*func_init_ptr)(void));

void odp_cunit_register_global_term(int (*func_term_ptr)(void));

#endif /* ODP_CUNICT_COMMON_H */
