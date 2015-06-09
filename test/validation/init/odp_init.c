/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdarg.h>
#include <odp.h>
#include <CUnit/Basic.h>
#include "odp_cunit_common.h"

#define DEFAULT_MSG_POOL_SIZE	(4 * 1024 * 1024)
#define DEFAULT_MSG_SIZE	(8)

/* overwrite common default so as not to perform odp init in main */
int tests_global_init(void)
{
	return 0;
}

/* overwrite common default so as not to perform odp term in main */
int tests_global_term(void)
{
	return 0;
}

static void test_odp_init_global(void)
{
	int status;

	status = odp_init_global(NULL, NULL);
	CU_ASSERT_FATAL(status == 0);

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
