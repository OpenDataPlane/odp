/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp.h>
#include <odp_cunit_common.h>

/* Helper macro for CU_TestInfo initialization */
#define _CU_TEST_INFO(test_func) {#test_func, test_func}

static void thread_test_odp_cpu_id(void)
{
	(void)odp_cpu_id();
	CU_PASS();
}

static void thread_test_odp_thread_id(void)
{
	(void)odp_thread_id();
	CU_PASS();
}

static void thread_test_odp_thread_count(void)
{
	(void)odp_thread_count();
	CU_PASS();
}

static CU_TestInfo thread_suite[] = {
	_CU_TEST_INFO(thread_test_odp_cpu_id),
	_CU_TEST_INFO(thread_test_odp_thread_id),
	_CU_TEST_INFO(thread_test_odp_thread_count),
	CU_TEST_INFO_NULL,
};

static CU_SuiteInfo thread_suites[] = {
	{"thread", NULL, NULL, NULL, NULL, thread_suite},
	CU_SUITE_INFO_NULL,
};

static int thread_main(void)
{
	return odp_cunit_run(thread_suites);
}

/* the following main function will be separated when lib is created */
int main(void)
{
	return thread_main();
}
