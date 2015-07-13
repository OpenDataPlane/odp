/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp.h>
#include <odp_cunit_common.h>
#include "shmem.h"

#define ALIGE_SIZE  (128)
#define TESTNAME "cunit_test_shared_data"
#define TEST_SHARE_FOO (0xf0f0f0f0)
#define TEST_SHARE_BAR (0xf0f0f0f)

static void *run_shm_thread(void *arg)
{
	odp_shm_info_t  info;
	odp_shm_t shm;
	test_shared_data_t *test_shared_data;
	int thr;

	thr = odp_thread_id();
	printf("Thread %i starts\n", thr);

	shm = odp_shm_lookup(TESTNAME);
	CU_ASSERT(ODP_SHM_INVALID != shm);
	test_shared_data = odp_shm_addr(shm);
	CU_ASSERT(TEST_SHARE_FOO == test_shared_data->foo);
	CU_ASSERT(TEST_SHARE_BAR == test_shared_data->bar);
	CU_ASSERT(0 == odp_shm_info(shm, &info));
	CU_ASSERT(0 == strcmp(TESTNAME, info.name));
	CU_ASSERT(0 == info.flags);
	CU_ASSERT(test_shared_data == info.addr);
	CU_ASSERT(sizeof(test_shared_data_t) <= info.size);
#ifdef MAP_HUGETLB
	CU_ASSERT(odp_sys_huge_page_size() == info.page_size);
#else
	CU_ASSERT(odp_sys_page_size() == info.page_size);
#endif
	odp_shm_print_all();

	fflush(stdout);
	return arg;
}

static void shmem_test_odp_shm_sunnyday(void)
{
	pthrd_arg thrdarg;
	odp_shm_t shm;
	test_shared_data_t *test_shared_data;

	shm = odp_shm_reserve(TESTNAME,
			      sizeof(test_shared_data_t), ALIGE_SIZE, 0);
	CU_ASSERT(ODP_SHM_INVALID != shm);
	CU_ASSERT(odp_shm_to_u64(shm) != odp_shm_to_u64(ODP_SHM_INVALID));

	CU_ASSERT(0 == odp_shm_free(shm));
	CU_ASSERT(ODP_SHM_INVALID == odp_shm_lookup(TESTNAME));

	shm = odp_shm_reserve(TESTNAME,
			      sizeof(test_shared_data_t), ALIGE_SIZE, 0);
	CU_ASSERT(ODP_SHM_INVALID != shm);

	test_shared_data = odp_shm_addr(shm);
	CU_ASSERT_FATAL(NULL != test_shared_data);
	test_shared_data->foo = TEST_SHARE_FOO;
	test_shared_data->bar = TEST_SHARE_BAR;

	thrdarg.numthrds = odp_cpu_count();

	if (thrdarg.numthrds > MAX_WORKERS)
		thrdarg.numthrds = MAX_WORKERS;

	odp_cunit_thread_create(run_shm_thread, &thrdarg);
	odp_cunit_thread_exit(&thrdarg);
}

static CU_TestInfo shmem_suite[] = {
	{"test_odp_shm_creat",  shmem_test_odp_shm_sunnyday},
	CU_TEST_INFO_NULL,
};

static CU_SuiteInfo shmem_suites[] = {
	{"Shared Memory", NULL, NULL, NULL, NULL, shmem_suite},
	CU_SUITE_INFO_NULL,
};

int shmem_main(void)
{
	return odp_cunit_run(shmem_suites);
}
