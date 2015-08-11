/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef _ODP_TEST_TIMER_H_
#define _ODP_TEST_TIMER_H_

#include <CUnit/Basic.h>

/* test functions: */
void timer_test_timeout_pool_alloc(void);
void timer_test_timeout_pool_free(void);
void timer_test_odp_timer_cancel(void);
void timer_test_odp_timer_all(void);

/* test arrays: */
extern CU_TestInfo timer_suite[];

/* test registry: */
extern CU_SuiteInfo timer_suites[];

/* main test program: */
int timer_main(void);

#endif
