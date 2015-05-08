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
#include <odp/helper/linux.h>
/* Globals */
static odph_linux_pthread_t thread_tbl[MAX_WORKERS];

/** create test thread */
int odp_cunit_thread_create(void *func_ptr(void *), pthrd_arg *arg)
{
	odp_cpumask_t cpumask;

	/* Create and init additional threads */
	odp_cpumask_def_worker(&cpumask, arg->numthrds);
	odph_linux_pthread_create(thread_tbl, &cpumask, func_ptr,
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

ODP_WEAK_SYMBOL int tests_global_init(void)
{
	if (0 != odp_init_global(NULL, NULL)) {
		fprintf(stderr, "error: odp_init_global() failed.\n");
		return -1;
	}
	if (0 != odp_init_local(ODP_THREAD_CONTROL)) {
		fprintf(stderr, "error: odp_init_local() failed.\n");
		return -1;
	}

	return 0;
}

ODP_WEAK_SYMBOL int tests_global_term(void)
{
	if (0 != odp_term_local()) {
		fprintf(stderr, "error: odp_term_local() failed.\n");
		return -1;
	}

	if (0 != odp_term_global()) {
		fprintf(stderr, "error: odp_term_global() failed.\n");
		return -1;
	}

	return 0;
}

int main(void)
{
	int ret;

	printf("\tODP API version: %s\n", odp_version_api_str());
	printf("\tODP implementation version: %s\n", odp_version_impl_str());

	if (0 != tests_global_init())
		return -1;

	CU_set_error_action(CUEA_ABORT);

	CU_initialize_registry();
	CU_register_suites(odp_testsuites);
	CU_basic_set_mode(CU_BRM_VERBOSE);
	CU_basic_run_tests();

	ret = CU_get_number_of_failure_records();

	CU_cleanup_registry();

	if (0 != tests_global_term())
		return -1;

	return (ret) ? -1 : 0;
}
