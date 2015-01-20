/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdarg.h>
#include <odp.h>
#include <CUnit/Basic.h>

#define DEFAULT_MSG_POOL_SIZE	(4*1024*1024)
#define DEFAULT_MSG_SIZE	(8)

int replacement_logging_used;

static int odp_init_log(odp_log_level_e level , const char *fmt, ...);

static void test_odp_init_global(void)
{
	int status;
	status = odp_init_global(NULL, NULL);
	CU_ASSERT_FATAL(status == 0);

	status = odp_term_global();
	CU_ASSERT(status == 0);
}

static void test_odp_init_global_replace_log(void)
{
	int status;
	struct odp_init_t init_data;

	init_data.log_fn = &odp_init_log;

	replacement_logging_used = 0;

	status = odp_init_global(&init_data, NULL);
	CU_ASSERT_FATAL(status == 0);

	CU_ASSERT_TRUE(replacement_logging_used);

	status = odp_term_global();
	CU_ASSERT(status == 0);
}

CU_TestInfo test_odp_init[] = {
	{"test_odp_init_global",  test_odp_init_global},
	{"replace log",  test_odp_init_global_replace_log},
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

int odp_init_log(odp_log_level_e level __attribute__((unused)),
		 const char *fmt, ...)
{
	va_list args;
	int r;

	/* just set a flag to be sure the replacement fn was used */
	replacement_logging_used = 1;

	va_start(args, fmt);
	r = vfprintf(stderr, fmt, args);
	va_end(args);

	return r;
}
