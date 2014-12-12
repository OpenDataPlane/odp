/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include "odp_buffer_tests.h"

CU_SuiteInfo odp_testsuites[] = {
	{ .pName = "buffer Pool tests",
			.pTests = buffer_pool_tests,
	},
	CU_SUITE_INFO_NULL,
};
