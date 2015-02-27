/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp.h>
#include <CUnit/Basic.h>

#define DEFAULT_MSG_POOL_SIZE	(4*1024*1024)
#define DEFAULT_MSG_SIZE	(8)

static void test_odp_init_global(void)
{
	int status;
	status = odp_init_global(NULL, NULL);
	CU_ASSERT(status == 0);

	status = odp_term_global();
	CU_ASSERT(status == 0);
}

CU_TestInfo test_odp_init[] = {
	{"test_odp_init_global",  test_odp_init_global},
	CU_TEST_INFO_NULL,
};

CU_SuiteInfo odp_testsuites[] = {
	{"Init", NULL, NULL, NULL, NULL, test_odp_init},
	CU_SUITE_INFO_NULL,
};

int main(void)
{
	int ret;

	printf("\tODP API version: %s\n", odp_version_api_str());
	printf("\tODP implementation version: %s\n", odp_version_impl_str());

	CU_set_error_action(CUEA_ABORT);

	CU_initialize_registry();
	CU_register_suites(odp_testsuites);
	CU_basic_set_mode(CU_BRM_VERBOSE);
	CU_basic_run_tests();

	ret = CU_get_number_of_failure_records();

	CU_cleanup_registry();

	return ret;
}
