/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef _ODP_TEST_ERRNO_H_
#define _ODP_TEST_ERRNO_H_

#include <CUnit/Basic.h>

/* test functions: */
void errno_test_odp_errno_sunny_day(void);

/* test arrays: */
extern CU_TestInfo errno_suite[];

/* test registry: */
extern CU_SuiteInfo errno_suites[];

/* main test program: */
int errno_main(void);

#endif
