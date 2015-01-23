/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include "odp_classification_testsuites.h"

CU_SuiteInfo odp_testsuites[] = {
	{ .pName = "classification basic",
			.pTests = classification_basic,
	},
	{ .pName = "classification tests",
			.pTests = classification_tests,
			.pInitFunc = classification_tests_init,
			.pCleanupFunc = classification_tests_finalize,
	},
	CU_SUITE_INFO_NULL,
};
