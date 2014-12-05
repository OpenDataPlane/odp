/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP test application common
 */

#include <string.h>
#include <odp.h>
#include <odp_cunit_common.h>
#include <odph_linux.h>
/* Globals */
static odph_linux_pthread_t thread_tbl[MAX_WORKERS];

/** create test thread */
int odp_cunit_thread_create(void *func_ptr(void *), pthrd_arg *arg)
{
	/* Create and init additional threads */
	odph_linux_pthread_create(thread_tbl, arg->numthrds, 0, func_ptr,
				  (void *)arg);

	return 0;
}

/** exit from test thread */
int odp_cunit_thread_exit(pthrd_arg *arg)
{
	/* Wait for other threads to exit */
	odph_linux_pthread_join(thread_tbl, arg->numthrds);

	return 0;
}

__attribute__((__weak__)) int tests_global_init(void)
{
	return 0;
}

int main(void)
{
	int ret;

	printf("\tODP API version: %s\n", odp_version_api_str());
	printf("\tODP implementation version: %s\n", odp_version_impl_str());

	if (0 != odp_init_global(NULL, NULL)) {
		printf("odp_init_global fail.\n");
		return -1;
	}
	if (0 != odp_init_local()) {
		printf("odp_init_local fail.\n");
		return -1;
	}

	ret = tests_global_init();
	if (ret)
		return ret;

	CU_set_error_action(CUEA_ABORT);

	CU_initialize_registry();
	CU_register_suites(odp_testsuites);
	CU_basic_set_mode(CU_BRM_VERBOSE);
	CU_basic_run_tests();

	ret = CU_get_number_of_failure_records();

	CU_cleanup_registry();

	odp_term_local();
	odp_term_global();

	return ret;
}
