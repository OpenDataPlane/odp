/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdarg.h>
#include <odp.h>
#include <CUnit/Basic.h>

static void odp_init_abort(void) ODP_NORETURN;

static void test_odp_init_global_replace_abort(void)
{
	int status;
	struct odp_init_t init_data;

	memset(&init_data, 0, sizeof(init_data));
	init_data.abort_fn = &odp_init_abort;

	status = odp_init_global(&init_data, NULL);
	CU_ASSERT_FATAL(status == 0);

	status = odp_term_global();
	CU_ASSERT(status == 0);
}

CU_TestInfo test_odp_init[] = {
	{"replace abort",  test_odp_init_global_replace_abort},
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

void odp_init_abort(void)
{
	abort();
}
