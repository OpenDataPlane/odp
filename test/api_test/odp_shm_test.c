/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP test shared memory
 */

#include <string.h>
#include <odp.h>
#include "odp_common.h"
#include "odp_shm_test.h"

static void *run_thread(void *arg)
{
	pthrd_arg *parg = (pthrd_arg *)arg;
	int thr;

	thr = odp_thread_id();

	printf("Thread %i starts\n", thr);

	switch (parg->testcase) {
	case ODP_SHM_TEST:
		test_shared_data = odp_shm_lookup("test_shared_data");
		printf("  [%i] shared data at %p\n", thr, test_shared_data);
		break;
	default:
		ODP_ERR("Invalid test case [%d]\n", parg->testcase);
	}
	fflush(stdout);

	return parg;
}

int main(int argc ODP_UNUSED, char *argv[] ODP_UNUSED)
{
	pthrd_arg thrdarg;

	if (odp_test_global_init() != 0)
		return -1;

	odp_print_system_info();

	test_shared_data = odp_shm_reserve("test_shared_data",
					   sizeof(test_shared_data_t), 128);
	memset(test_shared_data, 0, sizeof(test_shared_data_t));
	printf("test shared data at %p\n\n", test_shared_data);

	thrdarg.testcase = ODP_SHM_TEST;
	odp_test_thread_create(run_thread, &thrdarg);

	odp_test_thread_exit();

	return 0;
}
