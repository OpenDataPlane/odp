/* Copyright (c) 2015-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "config.h"

#include <odp_api.h>
#include <odp_cunit_common.h>

/* test normal ODP global init */
static void init_test_odp_init_global(void)
{
	int status;
	odp_instance_t instance;

	status = odp_init_global(&instance, NULL, NULL);
	CU_ASSERT_FATAL(status == 0);

	status = odp_term_global(instance);
	CU_ASSERT(status == 0);
}

odp_testinfo_t init_suite_ok[] = {
	ODP_TEST_INFO(init_test_odp_init_global),
	ODP_TEST_INFO_NULL,
};

odp_suiteinfo_t init_suites_ok[] = {
	{"Init", NULL, NULL, init_suite_ok},
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

	/* register the tests: */
	ret = odp_cunit_register(init_suites_ok);

	/* run the tests: */
	if (ret == 0)
		ret = odp_cunit_run();

	return ret;
}
