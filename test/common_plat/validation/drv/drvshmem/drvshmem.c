/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_drv.h>
#include <odp_api.h>
#include <odp_cunit_common.h>
#include "drvshmem.h"
#include <stdlib.h>

#define ALIGN_SIZE  (128)
#define MEM_NAME "test_shmem"
#define TEST_SHARE_FOO (0xf0f0f0f0)
#define TEST_SHARE_BAR (0xf0f0f0f)
#define SMALL_MEM 10
#define MEDIUM_MEM 4096
#define BIG_MEM 16777216

typedef struct {
	odpdrv_barrier_t test_barrier1;
	odpdrv_barrier_t test_barrier2;
	odpdrv_barrier_t test_barrier3;
	odpdrv_barrier_t test_barrier4;
	uint32_t foo;
	uint32_t bar;
	odpdrv_atomic_u32_t index;
	uint32_t nb_threads;
	odpdrv_shm_t shm[MAX_WORKERS];
	void *address[MAX_WORKERS];
} shared_test_data_t;

/* memory stuff expected to fit in a single page */
typedef struct {
	int data[SMALL_MEM];
} shared_test_data_small_t;

/* memory stuff expected to fit in a huge page */
typedef struct {
	int data[MEDIUM_MEM];
} shared_test_data_medium_t;

/* memory stuff expected to fit in many huge pages */
typedef struct {
	int data[BIG_MEM];
} shared_test_data_big_t;

/*
 * thread part for the drvshmem_test_basic test
 */
static int run_test_basic_thread(void *arg ODP_UNUSED)
{
	odpdrv_shm_info_t  info;
	odpdrv_shm_t shm;
	shared_test_data_t *shared_test_data;
	int thr;

	thr = odp_thread_id();
	printf("Thread %i starts\n", thr);

	shm = odpdrv_shm_lookup_by_name(MEM_NAME);
	CU_ASSERT(ODPDRV_SHM_INVALID != shm);
	shared_test_data = odpdrv_shm_addr(shm);
	CU_ASSERT(NULL != shared_test_data);

	odpdrv_barrier_wait(&shared_test_data->test_barrier1);
	odpdrv_shm_print_all("(from thread) After lookup for the global shmem");
	CU_ASSERT(TEST_SHARE_FOO == shared_test_data->foo);
	CU_ASSERT(TEST_SHARE_BAR == shared_test_data->bar);
	CU_ASSERT(0 == odpdrv_shm_info(shm, &info));
	CU_ASSERT(0 == strcmp(MEM_NAME, info.name));
	CU_ASSERT(0 == info.flags);
	CU_ASSERT(shared_test_data == info.addr);
	CU_ASSERT(sizeof(shared_test_data_t) <= info.size);
#ifdef MAP_HUGETLB
	CU_ASSERT(odp_sys_huge_page_size() == info.page_size);
#else
	CU_ASSERT(odp_sys_page_size() == info.page_size);
#endif
	odpdrv_shm_print_all("(from thread) About to end");

	fflush(stdout);
	return CU_get_number_of_failures();
}

/*
 * test basic things: shmem creation, info, share, and free
 */
void drvshmem_test_basic(void)
{
	int base;	/* memory usage when test starts */
	pthrd_arg thrdarg;
	odpdrv_shm_t shm;
	shared_test_data_t *shared_test_data;
	odp_cpumask_t unused;

	base = odpdrv_shm_print_all("Before drvshmem_test_basic");
	shm = odpdrv_shm_reserve(MEM_NAME,
				 sizeof(shared_test_data_t), ALIGN_SIZE, 0);
	CU_ASSERT(ODPDRV_SHM_INVALID != shm);
	CU_ASSERT(odpdrv_shm_to_u64(shm) !=
					odpdrv_shm_to_u64(ODPDRV_SHM_INVALID));

	CU_ASSERT(0 == odpdrv_shm_free_by_handle(shm));
	CU_ASSERT(ODPDRV_SHM_INVALID == odpdrv_shm_lookup_by_name(MEM_NAME));

	shm = odpdrv_shm_reserve(MEM_NAME,
				 sizeof(shared_test_data_t), ALIGN_SIZE, 0);
	CU_ASSERT(ODPDRV_SHM_INVALID != shm);

	shared_test_data = odpdrv_shm_addr(shm);
	CU_ASSERT_FATAL(NULL != shared_test_data);
	shared_test_data->foo = TEST_SHARE_FOO;
	shared_test_data->bar = TEST_SHARE_BAR;

	CU_ASSERT(odpdrv_shm_free_by_address((char *)shared_test_data - 1) < 0);

	thrdarg.numthrds = odp_cpumask_default_worker(&unused, 0);

	if (thrdarg.numthrds > MAX_WORKERS)
		thrdarg.numthrds = MAX_WORKERS;

	odpdrv_barrier_init(&shared_test_data->test_barrier1, thrdarg.numthrds);
	odp_cunit_thread_create(run_test_basic_thread, &thrdarg);
	CU_ASSERT(odp_cunit_thread_exit(&thrdarg) >= 0);

	CU_ASSERT(0 == odpdrv_shm_free_by_handle(shm));
	CU_ASSERT(odpdrv_shm_print_all("Test completion") == base);
}

/*
 * thread part for the drvshmem_test_reserve_after_fork
 */
static int run_test_reserve_after_fork(void *arg ODP_UNUSED)
{
	odpdrv_shm_t shm;
	shared_test_data_t *glob_data;
	int thr;
	int thr_index;
	char *name;
	int name_len;
	int size;
	shared_test_data_small_t  *pattern_small;
	shared_test_data_medium_t *pattern_medium;
	shared_test_data_big_t    *pattern_big;
	int i;

	thr = odp_thread_id();
	printf("Thread %i starts\n", thr);

	shm = odpdrv_shm_lookup_by_name(MEM_NAME);
	glob_data = odpdrv_shm_addr(shm);

	/*
	 * odp_thread_id are not guaranteed to be consecutive, so we create
	 * a consecutive ID
	 */
	thr_index = odpdrv_atomic_fetch_inc_u32(&glob_data->index);

	/* allocate some memory (of different sizes) and fill with pattern */
	name_len = strlen(MEM_NAME) + 20;
	name = malloc(name_len);
	snprintf(name, name_len, "%s-%09d", MEM_NAME, thr_index);
	switch (thr_index % 3) {
	case 0:
		size = sizeof(shared_test_data_small_t);
		shm = odpdrv_shm_reserve(name, size, 0, 0);
		CU_ASSERT(ODPDRV_SHM_INVALID != shm);
		glob_data->shm[thr_index] = shm;
		pattern_small = odpdrv_shm_addr(shm);
		CU_ASSERT_PTR_NOT_NULL(pattern_small);
		for (i = 0; i < SMALL_MEM; i++)
			pattern_small->data[i] = i;
		break;
	case 1:
		size = sizeof(shared_test_data_medium_t);
		shm = odpdrv_shm_reserve(name, size, 0, 0);
		CU_ASSERT(ODPDRV_SHM_INVALID != shm);
		glob_data->shm[thr_index] = shm;
		pattern_medium = odpdrv_shm_addr(shm);
		CU_ASSERT_PTR_NOT_NULL(pattern_medium);
		for (i = 0; i < MEDIUM_MEM; i++)
			pattern_medium->data[i] = (i << 2);
		break;
	case 2:
		size = sizeof(shared_test_data_big_t);
		shm = odpdrv_shm_reserve(name, size, 0, 0);
		CU_ASSERT(ODPDRV_SHM_INVALID != shm);
		glob_data->shm[thr_index] = shm;
		pattern_big = odpdrv_shm_addr(shm);
		CU_ASSERT_PTR_NOT_NULL(pattern_big);
		for (i = 0; i < BIG_MEM; i++)
			pattern_big->data[i] = (i >> 2);
		break;
	}
	free(name);

	/* print block address */
	printf("In thread: Block index: %d mapped at %lx\n",
	       thr_index, (long int)odpdrv_shm_addr(shm));

	odpdrv_barrier_wait(&glob_data->test_barrier1);
	odpdrv_barrier_wait(&glob_data->test_barrier2);

	fflush(stdout);
	return CU_get_number_of_failures();
}

/*
 * test sharing memory reserved after odp_thread creation (e.g. fork()):
 */
void drvshmem_test_reserve_after_fork(void)
{
	int base;	/* memory usage when test starts */
	pthrd_arg thrdarg;
	odpdrv_shm_t shm;
	odpdrv_shm_t thr_shm;
	shared_test_data_t *glob_data;
	odp_cpumask_t unused;
	char *name;
	int name_len;
	int thr_index;
	int i;
	void *address;
	shared_test_data_small_t  *pattern_small;
	shared_test_data_medium_t *pattern_medium;
	shared_test_data_big_t    *pattern_big;

	base = odpdrv_shm_print_all("Before drvshmem_test_reserve_after_fork");
	shm = odpdrv_shm_reserve(MEM_NAME, sizeof(shared_test_data_t), 0, 0);
	CU_ASSERT(ODPDRV_SHM_INVALID != shm);
	glob_data = odpdrv_shm_addr(shm);
	CU_ASSERT_PTR_NOT_NULL(glob_data);

	thrdarg.numthrds = odp_cpumask_default_worker(&unused, 0);
	if (thrdarg.numthrds > MAX_WORKERS)
		thrdarg.numthrds = MAX_WORKERS;

	odpdrv_barrier_init(&glob_data->test_barrier1, thrdarg.numthrds + 1);
	odpdrv_barrier_init(&glob_data->test_barrier2, thrdarg.numthrds + 1);
	odpdrv_atomic_store_u32(&glob_data->index, 0);

	odp_cunit_thread_create(run_test_reserve_after_fork, &thrdarg);

	/* wait until all threads have made their shm_reserve: */
	odpdrv_barrier_wait(&glob_data->test_barrier1);
	CU_ASSERT(odpdrv_shm_print_all("After all thread reserve")
		  == base + thrdarg.numthrds + 1);

	/* perform a lookup of all memories, by handle or name: */
	name_len = strlen(MEM_NAME) + 20;
	name = malloc(name_len);
	for (thr_index = 0; thr_index < thrdarg.numthrds; thr_index++) {
		if (thr_index % 2) {
			snprintf(name, name_len, "%s-%09d",
				 MEM_NAME, thr_index);
			thr_shm = odpdrv_shm_lookup_by_name(name);
			CU_ASSERT(thr_shm == glob_data->shm[thr_index]);
		} else {
			odpdrv_shm_lookup_by_handle(glob_data->shm[thr_index]);
		}
	}

	/* check that the patterns are correct: */
	for (thr_index = 0; thr_index < thrdarg.numthrds; thr_index++) {
		switch (thr_index % 3) {
		case 0:
			pattern_small =
				odpdrv_shm_addr(glob_data->shm[thr_index]);
			CU_ASSERT_PTR_NOT_NULL(pattern_small);
			for (i = 0; i < SMALL_MEM; i++)
				CU_ASSERT(pattern_small->data[i] == i);
			break;
		case 1:
			pattern_medium =
				odpdrv_shm_addr(glob_data->shm[thr_index]);
			CU_ASSERT_PTR_NOT_NULL(pattern_medium);
			for (i = 0; i < MEDIUM_MEM; i++)
				CU_ASSERT(pattern_medium->data[i] == (i << 2));
			break;
		case 2:
			pattern_big =
				odpdrv_shm_addr(glob_data->shm[thr_index]);
			CU_ASSERT_PTR_NOT_NULL(pattern_big);
			for (i = 0; i < BIG_MEM; i++)
				CU_ASSERT(pattern_big->data[i] == (i >> 2));
			break;
		}
	}

	/*
	 * print the mapping address of the blocks
	 */
	for (thr_index = 0; thr_index < thrdarg.numthrds; thr_index++) {
		address = odpdrv_shm_addr(glob_data->shm[thr_index]);
		printf("In main Block index: %d mapped at %lx\n",
		       thr_index, (long int)address);
	}

	CU_ASSERT(odpdrv_shm_print_all("After main lookup of thread shmem")
		  == base + thrdarg.numthrds + 1);

	/* unblock the threads and let them terminate (no free is done): */
	odpdrv_barrier_wait(&glob_data->test_barrier2);

	/* at the same time, (race),free of all memories, by handle or name: */
	for (thr_index = 0; thr_index < thrdarg.numthrds; thr_index++) {
		if (thr_index % 2) {
			thr_shm = glob_data->shm[thr_index];
			CU_ASSERT(odpdrv_shm_free_by_handle(thr_shm) == 0);
		} else {
			snprintf(name, name_len, "%s-%09d",
				 MEM_NAME, thr_index);
			CU_ASSERT(odpdrv_shm_free_by_name(name) == 0);
		}
	}
	free(name);

	/* wait for all thread endings: */
	CU_ASSERT(odp_cunit_thread_exit(&thrdarg) >= 0);

	/* just glob_data should remain: */
	CU_ASSERT(odpdrv_shm_print_all("After all threads end") == base + 1);

	CU_ASSERT(0 == odpdrv_shm_free_by_handle(shm));
	CU_ASSERT(odpdrv_shm_print_all("Test completion") == base);
}

/*
 * thread part for the drvshmem_test_singleva_after_fork
 */
static int run_test_singleva_after_fork(void *arg ODP_UNUSED)
{
	odpdrv_shm_t shm;
	shared_test_data_t *glob_data;
	int thr;
	int thr_index;
	char *name;
	int name_len;
	int size;
	shared_test_data_small_t  *pattern_small;
	shared_test_data_medium_t *pattern_medium;
	shared_test_data_big_t    *pattern_big;
	uint32_t i;
	int ret;

	thr = odp_thread_id();
	printf("Thread %i starts\n", thr);

	shm = odpdrv_shm_lookup_by_name(MEM_NAME);
	glob_data = odpdrv_shm_addr(shm);

	/*
	 * odp_thread_id are not guaranteed to be consecutive, so we create
	 * a consecutive ID
	 */
	thr_index = odpdrv_atomic_fetch_inc_u32(&glob_data->index);

	/* allocate some memory (of different sizes) and fill with pattern */
	name_len = strlen(MEM_NAME) + 20;
	name = malloc(name_len);
	snprintf(name, name_len, "%s-%09d", MEM_NAME, thr_index);
	switch (thr_index % 3) {
	case 0:
		size = sizeof(shared_test_data_small_t);
		shm = odpdrv_shm_reserve(name, size, 0, ODPDRV_SHM_SINGLE_VA);
		CU_ASSERT(ODPDRV_SHM_INVALID != shm);
		glob_data->shm[thr_index] = shm;
		pattern_small = odpdrv_shm_addr(shm);
		CU_ASSERT_PTR_NOT_NULL(pattern_small);
		glob_data->address[thr_index] = (void *)pattern_small;
		for (i = 0; i < SMALL_MEM; i++)
			pattern_small->data[i] = i;
		break;
	case 1:
		size = sizeof(shared_test_data_medium_t);
		shm = odpdrv_shm_reserve(name, size, 0, ODPDRV_SHM_SINGLE_VA);
		CU_ASSERT(ODPDRV_SHM_INVALID != shm);
		glob_data->shm[thr_index] = shm;
		pattern_medium = odpdrv_shm_addr(shm);
		CU_ASSERT_PTR_NOT_NULL(pattern_medium);
		glob_data->address[thr_index] = (void *)pattern_medium;
		for (i = 0; i < MEDIUM_MEM; i++)
			pattern_medium->data[i] = (i << 2);
		break;
	case 2:
		size = sizeof(shared_test_data_big_t);
		shm = odpdrv_shm_reserve(name, size, 0, ODPDRV_SHM_SINGLE_VA);
		CU_ASSERT(ODPDRV_SHM_INVALID != shm);
		glob_data->shm[thr_index] = shm;
		pattern_big = odpdrv_shm_addr(shm);
		CU_ASSERT_PTR_NOT_NULL(pattern_big);
		glob_data->address[thr_index] = (void *)pattern_big;
		for (i = 0; i < BIG_MEM; i++)
			pattern_big->data[i] = (i >> 2);
		break;
	}
	free(name);

	/* print block address */
	printf("In thread: Block index: %d mapped at %lx\n",
	       thr_index, (long int)odpdrv_shm_addr(shm));

	odpdrv_barrier_wait(&glob_data->test_barrier1);
	odpdrv_barrier_wait(&glob_data->test_barrier2);

	/* map each-other block, checking common address: */
	for (i = 0; i < glob_data->nb_threads; i++) {
		shm = odpdrv_shm_lookup_by_address(glob_data->address[i]);
		CU_ASSERT(shm == glob_data->shm[i]);
		CU_ASSERT(odpdrv_shm_addr(shm) == glob_data->address[i]);
	}

	/* wait for main control task and free the allocated block */
	odpdrv_barrier_wait(&glob_data->test_barrier3);
	odpdrv_barrier_wait(&glob_data->test_barrier4);
	ret = odpdrv_shm_free_by_address(glob_data->address[thr_index]);
	CU_ASSERT(ret == 0);

	fflush(stdout);
	return CU_get_number_of_failures();
}

/*
 * test sharing memory reserved after odp_thread creation (e.g. fork()):
 * with single VA flag.
 */
void drvshmem_test_singleva_after_fork(void)
{
	int base;	/* memory usage when test starts */
	pthrd_arg thrdarg;
	odpdrv_shm_t shm;
	odpdrv_shm_t thr_shm;
	shared_test_data_t *glob_data;
	odp_cpumask_t unused;
	char *name;
	int name_len;
	int thr_index;
	int i;
	void *address;
	shared_test_data_small_t  *pattern_small;
	shared_test_data_medium_t *pattern_medium;
	shared_test_data_big_t    *pattern_big;

	base = odpdrv_shm_print_all("Before drvshmem_test_singleva_after_fork");

	shm = odpdrv_shm_reserve(MEM_NAME, sizeof(shared_test_data_t),
				 0, ODPDRV_SHM_LOCK);
	CU_ASSERT(ODPDRV_SHM_INVALID != shm);
	glob_data = odpdrv_shm_addr(shm);
	CU_ASSERT_PTR_NOT_NULL(glob_data);

	thrdarg.numthrds = odp_cpumask_default_worker(&unused, 0);
	if (thrdarg.numthrds > MAX_WORKERS)
		thrdarg.numthrds = MAX_WORKERS;

	glob_data->nb_threads = thrdarg.numthrds;
	odpdrv_barrier_init(&glob_data->test_barrier1, thrdarg.numthrds + 1);
	odpdrv_barrier_init(&glob_data->test_barrier2, thrdarg.numthrds + 1);
	odpdrv_barrier_init(&glob_data->test_barrier3, thrdarg.numthrds + 1);
	odpdrv_barrier_init(&glob_data->test_barrier4, thrdarg.numthrds + 1);
	odpdrv_atomic_store_u32(&glob_data->index, 0);

	odp_cunit_thread_create(run_test_singleva_after_fork, &thrdarg);

	/* wait until all threads have made their shm_reserve: */
	odpdrv_barrier_wait(&glob_data->test_barrier1);
	CU_ASSERT(odpdrv_shm_print_all("After thread reserve")
		  == base + thrdarg.numthrds + 1);

	/* perform a lookup of all memories, by handle or name: */
	name_len = strlen(MEM_NAME) + 20;
	name = malloc(name_len);
	for (thr_index = 0; thr_index < thrdarg.numthrds; thr_index++) {
		if (thr_index % 2) {
			snprintf(name, name_len, "%s-%09d",
				 MEM_NAME, thr_index);
			thr_shm = odpdrv_shm_lookup_by_name(name);
			CU_ASSERT(thr_shm == glob_data->shm[thr_index]);
		} else {
			odpdrv_shm_lookup_by_handle(glob_data->shm[thr_index]);
		}
	}
	free(name);

	/* check that the patterns are correct: */
	for (thr_index = 0; thr_index < thrdarg.numthrds; thr_index++) {
		switch (thr_index % 3) {
		case 0:
			pattern_small =
				odpdrv_shm_addr(glob_data->shm[thr_index]);
			CU_ASSERT_PTR_NOT_NULL(pattern_small);
			for (i = 0; i < SMALL_MEM; i++)
				CU_ASSERT(pattern_small->data[i] == i);
			break;
		case 1:
			pattern_medium =
				odpdrv_shm_addr(glob_data->shm[thr_index]);
			CU_ASSERT_PTR_NOT_NULL(pattern_medium);
			for (i = 0; i < MEDIUM_MEM; i++)
				CU_ASSERT(pattern_medium->data[i] == (i << 2));
			break;
		case 2:
			pattern_big =
				odpdrv_shm_addr(glob_data->shm[thr_index]);
			CU_ASSERT_PTR_NOT_NULL(pattern_big);
			for (i = 0; i < BIG_MEM; i++)
				CU_ASSERT(pattern_big->data[i] == (i >> 2));
			break;
		}
	}

	/*
	 * check that the mapping address is common to all (SINGLE_VA):
	 */
	for (thr_index = 0; thr_index < thrdarg.numthrds; thr_index++) {
		address = odpdrv_shm_addr(glob_data->shm[thr_index]);
		CU_ASSERT(glob_data->address[thr_index] == address);
	}

	CU_ASSERT(odpdrv_shm_print_all("After local lookup")
		  == base + thrdarg.numthrds + 1);

	/* unblock the threads and let them map each-other blocks: */
	odpdrv_barrier_wait(&glob_data->test_barrier2);

	/* then check mem status */
	odpdrv_barrier_wait(&glob_data->test_barrier3);
	CU_ASSERT(odpdrv_shm_print_all("After mutual lookup")
		  == base + thrdarg.numthrds + 1);

	/* unblock the threads and let them free all thread blocks: */
	odpdrv_barrier_wait(&glob_data->test_barrier4);

	/* wait for all thread endings: */
	CU_ASSERT(odp_cunit_thread_exit(&thrdarg) >= 0);

	/* just glob_data should remain: */
	CU_ASSERT(odpdrv_shm_print_all("After threads free") == base + 1);

	CU_ASSERT(0 == odpdrv_shm_free_by_name(MEM_NAME));
	CU_ASSERT(odpdrv_shm_print_all("Test completion") == base);
}

odp_testinfo_t drvshmem_suite[] = {
	ODP_TEST_INFO(drvshmem_test_basic),
	ODP_TEST_INFO(drvshmem_test_reserve_after_fork),
	ODP_TEST_INFO(drvshmem_test_singleva_after_fork),
	ODP_TEST_INFO_NULL,
};

odp_suiteinfo_t drvshmem_suites[] = {
	{"Shared Memory", NULL, NULL, drvshmem_suite},
	ODP_SUITE_INFO_NULL,
};

int drvshmem_main(int argc, char *argv[])
{
	int ret;

	/* parse common options: */
	if (odp_cunit_parse_options(argc, argv))
		return -1;

	ret = odp_cunit_register(drvshmem_suites);

	if (ret == 0)
		ret = odp_cunit_run();

	return ret;
}
