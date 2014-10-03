/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "odp.h"
#include "CUnit/Basic.h"

#define DEFAULT_MSG_POOL_SIZE	(4*1024*1024)
#define DEFAULT_MSG_SIZE	(8)

static void test_odp_init_global(void)
{
	int status;
	status = odp_init_global();
	CU_ASSERT(status == 0);
}

static int init(void)
{
	printf("\tODP version: %s\n", odp_version_api_str());
	return 0;
}

static int finalise(void)
{
	return 0;
}

int main(void)
{
	CU_pSuite ptr_suite = NULL;
	/* initialize the CUnit test registry */
	if (CUE_SUCCESS != CU_initialize_registry())
		return CU_get_error();
	/* add a suite to the registry */
	ptr_suite = CU_add_suite("odp intalization", init, finalise);
	if (NULL == ptr_suite) {
		CU_cleanup_registry();
		return CU_get_error();
	}
	/* add the tests to the suite */
	if (NULL == CU_ADD_TEST(ptr_suite, test_odp_init_global)) {
		CU_cleanup_registry();
		return CU_get_error();
	}
	/* Run all tests using the CUnit Basic interface */
	CU_basic_set_mode(CU_BRM_VERBOSE);
	CU_basic_run_tests();
	CU_cleanup_registry();
	return CU_get_error();
}
