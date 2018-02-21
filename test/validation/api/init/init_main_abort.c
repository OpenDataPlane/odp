/* Copyright (c) 2015-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "config.h"

#include <stdlib.h>
#include <odp_api.h>
#include <odp_cunit_common.h>

/* replacement abort function: */
static void ODP_NORETURN odp_init_abort(void)
{
	abort();
}

/* test ODP global init, with alternate abort function */
static void init_test_odp_init_global_replace_abort(void)
{
	int status;
	odp_init_t init_data;
	odp_instance_t instance;

	odp_init_param_init(&init_data);
	init_data.abort_fn = &odp_init_abort;

	status = odp_init_global(&instance, &init_data, NULL);
	CU_ASSERT_FATAL(status == 0);

	status = odp_term_global(instance);
	CU_ASSERT(status == 0);
}

odp_testinfo_t init_suite_abort[] = {
	ODP_TEST_INFO(init_test_odp_init_global_replace_abort),
	ODP_TEST_INFO_NULL,
};

odp_suiteinfo_t init_suites_abort[] = {
	{"Init", NULL, NULL, init_suite_abort},
	ODP_SUITE_INFO_NULL,
};

int main(int argc, char *argv[])
{
	int ret;

	/* parse common options: */
	if (odp_cunit_parse_options(argc, argv))
		return -1;

	/* prevent default ODP init: */
	odp_cunit_register_global_init(NULL);
	odp_cunit_register_global_term(NULL);

	/* run the tests: */
	ret = odp_cunit_register(init_suites_abort);

	if (ret == 0)
		ret = odp_cunit_run();

	return ret;
}
