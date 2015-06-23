/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdarg.h>
#include <odp.h>
#include <CUnit/Basic.h>
#include "odp_cunit_common.h"

int replacement_logging_used;

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

ODP_PRINTF_FORMAT(2, 3)
static int odp_init_log(odp_log_level_e level, const char *fmt, ...);

static void init_test_odp_init_global_replace_log(void)
{
	int status;
	struct odp_init_t init_data;

	memset(&init_data, 0, sizeof(init_data));
	init_data.log_fn = &odp_init_log;

	replacement_logging_used = 0;

	status = odp_init_global(&init_data, NULL);
	CU_ASSERT_FATAL(status == 0);

	CU_ASSERT_TRUE(replacement_logging_used);

	status = odp_term_global();
	CU_ASSERT(status == 0);
}

static CU_TestInfo init_suite_log[] = {
	{"replace log",  init_test_odp_init_global_replace_log},
	CU_TEST_INFO_NULL,
};

static CU_SuiteInfo init_suites_log[] = {
	{"Init", NULL, NULL, NULL, NULL, init_suite_log},
	CU_SUITE_INFO_NULL,
};

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

static int init_main_log(void)
{
	return odp_cunit_run(init_suites_log);
}

/* the following main function will be separated when lib is created */
int main(void)
{
	return init_main_log();
}
