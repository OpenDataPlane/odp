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
	{ .pName = "buffer tests",
			.pTests = buffer_tests,
			.pInitFunc = buffer_testsuite_init,
			.pCleanupFunc = buffer_testsuite_finalize,
	},
	{ .pName = "packet tests",
			.pTests = packet_tests,
			.pInitFunc = packet_testsuite_init,
			.pCleanupFunc = packet_testsuite_finalize,
	},
	CU_SUITE_INFO_NULL,
};
