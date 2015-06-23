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

static void init_test_odp_init_global(void)
{
	int status;

	status = odp_init_global(NULL, NULL);
	CU_ASSERT_FATAL(status == 0);

	status = odp_term_global();
	CU_ASSERT(status == 0);
}

static CU_TestInfo init_suite_ok[] = {
	{"test_odp_init_global",  init_test_odp_init_global},
	CU_TEST_INFO_NULL,
};

static CU_SuiteInfo init_suites_ok[] = {
	{"Init", NULL, NULL, NULL, NULL, init_suite_ok},
	CU_SUITE_INFO_NULL,
};

static int init_main_ok(void)
{
	return odp_cunit_run(init_suites_ok);
}

/* the following main function will be separated when lib is created */
int main(void)
{
	return init_main_ok();
}
