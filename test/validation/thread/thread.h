/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef _ODP_TEST_THREAD_H_
#define _ODP_TEST_THREAD_H_

#include <odp.h>
#include <CUnit/Basic.h>

/* test functions: */
#ifndef TEST_THRMASK
#define TEST_THRMASK
#endif
#include "mask_common.h"
void thread_test_odp_cpu_id(void);
void thread_test_odp_thread_id(void);
void thread_test_odp_thread_count(void);
void thread_test_odp_thrmask_control(void);
void thread_test_odp_thrmask_worker(void);

/* test arrays: */
extern CU_TestInfo thread_suite[];

/* test registry: */
extern CU_SuiteInfo thread_suites[];

/* main test program: */
int thread_main(void);

#endif
