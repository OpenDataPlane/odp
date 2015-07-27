/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp.h>
#include "odp_cunit_common.h"
#include "errno.h"

static void errno_test_odp_errno_sunny_day(void)
{
	int my_errno;

	odp_errno_zero();
	my_errno = odp_errno();
	CU_ASSERT_TRUE(my_errno == 0);
	odp_errno_print("odp_errno");
	CU_ASSERT_PTR_NOT_NULL(odp_errno_str(my_errno));
}

CU_TestInfo errno_suite[] = {
	{"sunny day", errno_test_odp_errno_sunny_day},
	CU_TEST_INFO_NULL,
};

CU_SuiteInfo errno_suites[] = {
	{"Errno",	NULL, NULL, NULL, NULL, errno_suite},
	CU_SUITE_INFO_NULL,
};

int errno_main(void)
{
	return odp_cunit_run(errno_suites);
}
