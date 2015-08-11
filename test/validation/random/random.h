/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef _ODP_TEST_RANDOM_H_
#define _ODP_TEST_RANDOM_H_

#include <CUnit/Basic.h>

/* test functions: */
void random_test_get_size(void);

/* test arrays: */
extern CU_TestInfo random_suite[];

/* test registry: */
extern CU_SuiteInfo random_suites[];

/* main test program: */
int random_main(void);

#endif
