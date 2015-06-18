/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include <odp.h>
#include <odp_cunit_common.h>
#include "odp_classification_testsuites.h"

static CU_SuiteInfo classification_suites[] = {
	{ .pName = "classification basic",
			.pTests = classification_suite_basic,
	},
	{ .pName = "classification tests",
			.pTests = classification_suite,
			.pInitFunc = classification_suite_init,
			.pCleanupFunc = classification_suite_term,
	},
	CU_SUITE_INFO_NULL,
};

static int classification_main(void)
{
	return odp_cunit_run(classification_suites);
}

/* the following main function will be separated when lib is created */
int main(void)
{
	return classification_main();
}
