/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp.h>
#include <odp_cunit_common.h>

/* Helper macro for CU_TestInfo initialization */
#define _CU_TEST_INFO(test_func) {#test_func, test_func}

static void test_odp_cpu_id(void)
{
	(void) odp_cpu_id();
	CU_PASS();
}

static void test_odp_thread_id(void)
{
	(void) odp_thread_id();
	CU_PASS();
}

static void test_odp_thread_count(void)
{
	(void) odp_thread_count();
	CU_PASS();
}

CU_TestInfo test_odp_thread[] = {
	_CU_TEST_INFO(test_odp_cpu_id),
	_CU_TEST_INFO(test_odp_thread_id),
	_CU_TEST_INFO(test_odp_thread_count),
	CU_TEST_INFO_NULL,
};

CU_SuiteInfo odp_testsuites[] = {
	{"thread", NULL, NULL, NULL, NULL, test_odp_thread},
	CU_SUITE_INFO_NULL,
};
