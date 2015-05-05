/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include <odp.h>
#include "odp_cunit_common.h"
#include "odp_errno.h"
#include "odp_system.h"

CU_SuiteInfo odp_testsuites[] = {
	{"Errno",	NULL, NULL, NULL, NULL, test_odp_errno},
	{"System Info", NULL, NULL, NULL, NULL, test_odp_system},
	CU_SUITE_INFO_NULL,
};
