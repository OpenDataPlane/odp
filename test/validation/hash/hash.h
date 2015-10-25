/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef _ODP_TEST_HASH_H_
#define _ODP_TEST_HASH_H_

#include <CUnit/Basic.h>

/* test functions: */
void hash_test_crc32c(void);

/* test arrays: */
extern CU_TestInfo hash_suite[];

/* test registry: */
extern CU_SuiteInfo hash_suites[];

/* main test program: */
int hash_main(void);

#endif
