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
#include "init.h"

/* flag set when the replacement logging function is used */
int replacement_logging_used;

/* replacement abort function: */
static void odp_init_abort(void) ODP_NORETURN;

/* replacement log function: */
ODP_PRINTF_FORMAT(2, 3)
static int odp_init_log(odp_log_level_e level, const char *fmt, ...);

/* test ODP global init, with alternate abort function */
void init_test_odp_init_global_replace_abort(void)
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

CU_TestInfo init_suite_abort[] = {
	_CU_TEST_INFO(init_test_odp_init_global_replace_abort),
	CU_TEST_INFO_NULL,
};

CU_SuiteInfo init_suites_abort[] = {
	{"Init", NULL, NULL, NULL, NULL, init_suite_abort},
	CU_SUITE_INFO_NULL,
};

static void odp_init_abort(void)
{
	abort();
}

int init_main_abort(void)
{
	/* prevent default ODP init: */
	odp_cunit_register_global_init(NULL);
	odp_cunit_register_global_term(NULL);

	/* run the tests: */
	return odp_cunit_run(init_suites_abort);
}

/* test ODP global init, with alternate log function */
void init_test_odp_init_global_replace_log(void)
{
	int status;
	struct odp_init_t init_data;

	memset(&init_data, 0, sizeof(init_data));
	init_data.log_fn = &odp_init_log;

	replacement_logging_used = 0;

	status = odp_init_global(&init_data, NULL);
	CU_ASSERT_FATAL(status == 0);

	CU_ASSERT_TRUE(replacement_logging_used || ODP_DEBUG_PRINT == 0);

	status = odp_term_global();
	CU_ASSERT(status == 0);
}

CU_TestInfo init_suite_log[] = {
	_CU_TEST_INFO(init_test_odp_init_global_replace_log),
	CU_TEST_INFO_NULL,
};

CU_SuiteInfo init_suites_log[] = {
	{"Init", NULL, NULL, NULL, NULL, init_suite_log},
	CU_SUITE_INFO_NULL,
};

static int odp_init_log(odp_log_level_e level __attribute__((unused)),
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

int init_main_log(void)
{
	/* prevent default ODP init: */
	odp_cunit_register_global_init(NULL);
	odp_cunit_register_global_term(NULL);

	/* run the tests: */
	return odp_cunit_run(init_suites_log);
}

/* test normal ODP global init */
void init_test_odp_init_global(void)
{
	int status;

	status = odp_init_global(NULL, NULL);
	CU_ASSERT_FATAL(status == 0);

	status = odp_term_global();
	CU_ASSERT(status == 0);
}

CU_TestInfo init_suite_ok[] = {
	_CU_TEST_INFO(init_test_odp_init_global),
	CU_TEST_INFO_NULL,
};

CU_SuiteInfo init_suites_ok[] = {
	{"Init", NULL, NULL, NULL, NULL, init_suite_ok},
	CU_SUITE_INFO_NULL,
};

int init_main_ok(void)
{
	/* prevent default ODP init: */
	odp_cunit_register_global_init(NULL);
	odp_cunit_register_global_term(NULL);

	/* run the tests: */
	return odp_cunit_run(init_suites_ok);
}
