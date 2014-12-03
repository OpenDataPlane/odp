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

#include "CUnit/Basic.h"

#define MAX_WORKERS 32 /**< Maximum number of work threads */

/**
 * Array of testsuites provided by a test application. Array must be terminated
 * by CU_SUITE_INFO_NULL and must be suitable to be used by
 * CU_register_suites().
 */
extern CU_SuiteInfo odp_testsuites[];

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

#endif /* ODP_CUNICT_COMMON_H */
