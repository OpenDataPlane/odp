/* Copyright (c) 2015-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_api.h>
#include "odp_cunit_common.h"

static void errno_test_odp_errno_sunny_day(void)
{
	int my_errno;

	odp_errno_zero();
	my_errno = odp_errno();
	CU_ASSERT_TRUE(my_errno == 0);
	odp_errno_print("odp_errno");
	CU_ASSERT_PTR_NOT_NULL(odp_errno_str(my_errno));
}

odp_testinfo_t errno_suite[] = {
	ODP_TEST_INFO(errno_test_odp_errno_sunny_day),
	ODP_TEST_INFO_NULL,
};

odp_suiteinfo_t errno_suites[] = {
	{"Errno", NULL, NULL, errno_suite},
	ODP_SUITE_INFO_NULL,
};

int main(int argc, char *argv[])
{
	int ret;

	/* parse common options: */
	if (odp_cunit_parse_options(argc, argv))
		return -1;

	ret = odp_cunit_register(errno_suites);

	if (ret == 0)
		ret = odp_cunit_run();

	return ret;
}
