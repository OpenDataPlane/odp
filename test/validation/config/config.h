/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#ifndef _ODP_TEST_CONFIG_H_
#define _ODP_TEST_CONFIG_H_

#include <CUnit/Basic.h>

/* test functions: */
void config_test(void);

/* test arrays: */
extern CU_TestInfo config_suite[];

/* test array init/term functions: */
int config_suite_init(void);
int config_suite_term(void);

/* test registry: */
extern CU_SuiteInfo config_suites[];

/* main test program: */
int config_main(void);

#endif
