/* Copyright (c) 2015-2018, Linaro Limited
 * Copyright (c) 2019, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_api.h>
#include <odp_cunit_common.h>

#include <stdarg.h>
#include <stdlib.h>

/* Replacement abort function */
static void ODP_NORETURN my_abort_func(void)
{
	abort();
}

/* Replacement log function */
ODP_PRINTF_FORMAT(2, 3)
static int my_log_func(odp_log_level_t level __attribute__((unused)),
		       const char *fmt, ...)
{
	va_list args;
	int r;

	va_start(args, fmt);
	r = vfprintf(stderr, fmt, args);
	va_end(args);

	return r;
}

static void init_test_defaults(void)
{
	int ret;
	odp_instance_t instance;
	odp_init_t param;

	odp_init_param_init(&param);

	ret = odp_init_global(&instance, &param, NULL);
	CU_ASSERT_FATAL(ret == 0);

	ret = odp_init_local(instance, ODP_THREAD_WORKER);
	CU_ASSERT_FATAL(ret == 0);

	ret = odp_term_local();
	CU_ASSERT_FATAL(ret == 0);

	ret = odp_term_global(instance);
	CU_ASSERT(ret == 0);
}

static void init_test_abort(void)
{
	int ret;
	odp_instance_t instance;
	odp_init_t param;

	odp_init_param_init(&param);
	param.abort_fn = &my_abort_func;

	ret = odp_init_global(&instance, &param, NULL);
	CU_ASSERT_FATAL(ret == 0);

	ret = odp_init_local(instance, ODP_THREAD_WORKER);
	CU_ASSERT_FATAL(ret == 0);

	ret = odp_term_local();
	CU_ASSERT_FATAL(ret == 0);

	ret = odp_term_global(instance);
	CU_ASSERT(ret == 0);
}

static void init_test_log(void)
{
	int ret;
	odp_instance_t instance;
	odp_init_t param;

	odp_init_param_init(&param);
	param.log_fn = &my_log_func;

	ret = odp_init_global(&instance, &param, NULL);
	CU_ASSERT_FATAL(ret == 0);

	ret = odp_init_local(instance, ODP_THREAD_WORKER);
	CU_ASSERT_FATAL(ret == 0);

	ret = odp_term_local();
	CU_ASSERT_FATAL(ret == 0);

	ret = odp_term_global(instance);
	CU_ASSERT(ret == 0);
}

static void init_test_num_thr(void)
{
	int ret;
	odp_instance_t instance;
	odp_init_t param;

	odp_init_param_init(&param);
	param.mem_model    = ODP_MEM_MODEL_THREAD;
	param.num_worker   = 1;
	param.num_control  = 1;
	param.worker_cpus  = NULL;
	param.control_cpus = NULL;

	ret = odp_init_global(&instance, &param, NULL);
	CU_ASSERT_FATAL(ret == 0);

	ret = odp_init_local(instance, ODP_THREAD_WORKER);
	CU_ASSERT_FATAL(ret == 0);

	ret = odp_term_local();
	CU_ASSERT_FATAL(ret == 0);

	ret = odp_term_global(instance);
	CU_ASSERT(ret == 0);
}

static void init_test_feature(void)
{
	int ret;
	odp_instance_t instance;
	odp_init_t param;

	odp_init_param_init(&param);
	param.not_used.all_feat      = 0;
	param.not_used.feat.cls      = 1;
	param.not_used.feat.crypto   = 1;
	param.not_used.feat.ipsec    = 1;
	param.not_used.feat.schedule = 1;
	param.not_used.feat.time     = 1;
	param.not_used.feat.timer    = 1;
	param.not_used.feat.tm       = 1;

	ret = odp_init_global(&instance, &param, NULL);
	CU_ASSERT_FATAL(ret == 0);

	ret = odp_init_local(instance, ODP_THREAD_CONTROL);
	CU_ASSERT_FATAL(ret == 0);

	ret = odp_term_local();
	CU_ASSERT_FATAL(ret == 0);

	ret = odp_term_global(instance);
	CU_ASSERT(ret == 0);
}

odp_testinfo_t testinfo[] = {
	ODP_TEST_INFO(init_test_defaults),
	ODP_TEST_INFO(init_test_abort),
	ODP_TEST_INFO(init_test_log),
	ODP_TEST_INFO(init_test_num_thr),
	ODP_TEST_INFO(init_test_feature)
};

odp_testinfo_t init_suite[] = {
	ODP_TEST_INFO_NULL,
	ODP_TEST_INFO_NULL
};

odp_suiteinfo_t init_suites[] = {
	{"Init", NULL, NULL, init_suite},
	ODP_SUITE_INFO_NULL,
};

static int fill_testinfo(odp_testinfo_t *info, unsigned int test_case)
{
	if (test_case >= (sizeof(testinfo) / sizeof(odp_testinfo_t))) {
		printf("Bad test case number %u\n", test_case);
		return -1;
	}

	*info = testinfo[test_case];

	return 0;
}

int main(int argc, char *argv[])
{
	int ret;

	if (fill_testinfo(&init_suite[0], INIT_TEST))
		return -1;

	/* Parse common options */
	if (odp_cunit_parse_options(argc, argv))
		return -1;

	/* Prevent default ODP init */
	odp_cunit_register_global_init(NULL);
	odp_cunit_register_global_term(NULL);

	/* Register the tests */
	ret = odp_cunit_register(init_suites);

	/* Run the tests */
	if (ret == 0)
		ret = odp_cunit_run();

	return ret;
}
