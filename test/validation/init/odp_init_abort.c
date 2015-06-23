/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdarg.h>
#include <stdlib.h>
#include <odp.h>
#include <CUnit/Basic.h>
#include "odp_cunit_common.h"

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

static CU_TestInfo test_odp_init[] = {
	{"replace abort",  test_odp_init_global_replace_abort},
	CU_TEST_INFO_NULL,
};

static CU_SuiteInfo init_suites_abort[] = {
	{"Init", NULL, NULL, NULL, NULL, test_odp_init},
	CU_SUITE_INFO_NULL,
};

void odp_init_abort(void)
{
	abort();
}

static int init_main_abort(void)
{
	return odp_cunit_run(init_suites_abort);
}

/* the following main function will be separated when lib is created */
int main(void)
{
	return init_main_abort();
}
