/* Copyright (c) 2019, Nokia
 * Copyright (c) 2014-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_api.h>
#include <odp_cunit_common.h>
#include <stdlib.h>

#define ALIGN_SIZE  (128)
#define MEM_NAME "test_shmem"
#define NAME_LEN (sizeof(MEM_NAME) + 20)
#define TEST_SHARE_FOO (0xf0f0f0f0)
#define TEST_SHARE_BAR (0xf0f0f0f)
#define SMALL_MEM 10
#define MEDIUM_MEM 4096
#define BIG_MEM 65536
#define STRESS_SIZE 32		/* power of 2 and <=256 */
#define STRESS_RANDOM_SZ 5
#define STRESS_ITERATION 5000
#define MAX_SIZE_TESTED  (100 * 1000000UL)
#define MAX_ALIGN_TESTED (1024 * 1024)

typedef enum {
	STRESS_FREE, /* entry is free and can be allocated */
	STRESS_BUSY, /* entry is being processed: don't touch */
	STRESS_ALLOC /* entry is allocated  and can be freed */
} stress_state_t;

typedef struct {
	stress_state_t state;
	odp_shm_t shm;
	char name[NAME_LEN];
	void *address;
	uint32_t flags;
	uint32_t size;
	uint64_t align;
	uint8_t data_val;
} stress_data_t;

typedef struct {
	odp_barrier_t test_barrier1;
	odp_barrier_t test_barrier2;
	odp_barrier_t test_barrier3;
	odp_barrier_t test_barrier4;
	uint32_t foo;
	uint32_t bar;
	odp_atomic_u32_t index;
	uint32_t nb_threads;
	odp_shm_t shm[MAX_WORKERS];
	void *address[MAX_WORKERS];
	char name[MAX_WORKERS][NAME_LEN];
	odp_spinlock_t  stress_lock;
	stress_data_t stress[STRESS_SIZE];
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
 * thread part for the shmem_test_basic test
 */
static int run_test_basic_thread(void *arg ODP_UNUSED)
{
	odp_shm_info_t  info;
	odp_shm_t shm;
	shared_test_data_t *shared_test_data;
	int thr;
	int pagesz_match = 0;

	thr = odp_thread_id();
	printf("Thread %i starts\n", thr);

	shm = odp_shm_lookup(MEM_NAME);
	CU_ASSERT(ODP_SHM_INVALID != shm);
	shared_test_data = odp_shm_addr(shm);
	CU_ASSERT(NULL != shared_test_data);

	odp_barrier_wait(&shared_test_data->test_barrier1);
	odp_shm_print_all();
	CU_ASSERT(TEST_SHARE_FOO == shared_test_data->foo);
	CU_ASSERT(TEST_SHARE_BAR == shared_test_data->bar);
	CU_ASSERT(0 == odp_shm_info(shm, &info));
	CU_ASSERT(0 == strcmp(MEM_NAME, info.name));
	CU_ASSERT(0 == info.flags);
	CU_ASSERT(shared_test_data == info.addr);
	CU_ASSERT(sizeof(shared_test_data_t) <= info.size);

	if (info.page_size == odp_sys_page_size()) {
		pagesz_match = 1;
	} else {
		int num = odp_sys_huge_page_size_all(NULL, 0);

		if (num > 0) {
			uint64_t pagesz_tbs[num];
			int i;

			num = odp_sys_huge_page_size_all(pagesz_tbs, num);
			for (i = 0; i < num; i++) {
				if (info.page_size == pagesz_tbs[i]) {
					pagesz_match = 1;
					break;
				}
			}
		}
	}
	CU_ASSERT(pagesz_match == 1);

	odp_shm_print_all();

	fflush(stdout);
	return CU_get_number_of_failures();
}

/*
 * test basic things: shmem creation, info, share, and free
 */
static void shmem_test_basic(void)
{
	pthrd_arg thrdarg;
	odp_shm_t shm;
	odp_shm_t shm2;
	shared_test_data_t *shared_test_data;
	odp_cpumask_t unused;
	int i;
	char max_name[ODP_SHM_NAME_LEN];

	for (i = 0; i < ODP_SHM_NAME_LEN; i++)
		max_name[i] = 'A' + (i % 26);

	max_name[ODP_SHM_NAME_LEN - 1] = 0;

	/* NULL name */
	shm = odp_shm_reserve(NULL,
			      sizeof(shared_test_data_t), ALIGN_SIZE, 0);
	CU_ASSERT(ODP_SHM_INVALID != shm);
	shared_test_data = odp_shm_addr(shm);
	CU_ASSERT_FATAL(NULL != shared_test_data);
	shared_test_data->foo = 0;
	CU_ASSERT(0 == odp_shm_free(shm));

	/* Maximum length name */
	shm = odp_shm_reserve(max_name,
			      sizeof(shared_test_data_t), ALIGN_SIZE, 0);
	CU_ASSERT(ODP_SHM_INVALID != shm);
	shm2 = odp_shm_lookup(max_name);
	CU_ASSERT(ODP_SHM_INVALID != shm2);
	CU_ASSERT(odp_shm_addr(shm) == odp_shm_addr(shm2));
	shared_test_data = odp_shm_addr(shm);
	CU_ASSERT_FATAL(NULL != shared_test_data);
	shared_test_data->foo = 0;
	CU_ASSERT(0 == odp_shm_free(shm));

	/* Non-unique name */
	shm = odp_shm_reserve(MEM_NAME,
			      sizeof(shared_test_data_t), ALIGN_SIZE, 0);
	CU_ASSERT(ODP_SHM_INVALID != shm);
	CU_ASSERT(odp_shm_to_u64(shm) !=
					odp_shm_to_u64(ODP_SHM_INVALID));
	shm2 = odp_shm_reserve(MEM_NAME,
			       sizeof(shared_test_data_t), ALIGN_SIZE, 0);
	CU_ASSERT(ODP_SHM_INVALID != shm2);
	CU_ASSERT(odp_shm_to_u64(shm2) !=
					odp_shm_to_u64(ODP_SHM_INVALID));

	CU_ASSERT(odp_shm_addr(shm) != odp_shm_addr(shm2));
	shared_test_data = odp_shm_addr(shm);
	CU_ASSERT_FATAL(NULL != shared_test_data);
	shared_test_data->foo = 0;
	shared_test_data = odp_shm_addr(shm2);
	CU_ASSERT_FATAL(NULL != shared_test_data);
	shared_test_data->foo = 0;
	CU_ASSERT(0 == odp_shm_free(shm));
	CU_ASSERT(0 == odp_shm_free(shm2));
	CU_ASSERT(ODP_SHM_INVALID == odp_shm_lookup(MEM_NAME));

	/* Share with multiple threads */
	shm = odp_shm_reserve(MEM_NAME,
			      sizeof(shared_test_data_t), ALIGN_SIZE, 0);
	CU_ASSERT(ODP_SHM_INVALID != shm);

	shared_test_data = odp_shm_addr(shm);
	CU_ASSERT_FATAL(NULL != shared_test_data);
	shared_test_data->foo = TEST_SHARE_FOO;
	shared_test_data->bar = TEST_SHARE_BAR;

	thrdarg.numthrds = odp_cpumask_default_worker(&unused, 0);

	if (thrdarg.numthrds > MAX_WORKERS)
		thrdarg.numthrds = MAX_WORKERS;

	odp_barrier_init(&shared_test_data->test_barrier1, thrdarg.numthrds);
	odp_cunit_thread_create(run_test_basic_thread, &thrdarg);
	CU_ASSERT(odp_cunit_thread_exit(&thrdarg) >= 0);

	odp_shm_print(shm);

	CU_ASSERT(0 == odp_shm_free(shm));
}

/*
 * test reserving memory from huge pages
 */
static void shmem_test_hp(void)
{
	odp_shm_t shm;
	odp_shm_info_t info;
	int i;
	int num_sizes = odp_sys_huge_page_size_all(NULL, 0);

	CU_ASSERT_FATAL(num_sizes >= 0);

	shm = odp_shm_reserve(MEM_NAME, sizeof(shared_test_data_t),
			      ALIGN_SIZE, ODP_SHM_HP);
	if (shm == ODP_SHM_INVALID) {
		printf("    No huge pages available\n");
		return;
	}

	/* Make sure that the memory is reserved from huge pages */

	CU_ASSERT_FATAL(num_sizes > 0);
	CU_ASSERT_FATAL(odp_shm_info(shm, &info) == 0);

	uint64_t hp_sizes[num_sizes];

	CU_ASSERT_FATAL(odp_sys_huge_page_size_all(hp_sizes, num_sizes) ==
				num_sizes);

	for (i = 0; i < num_sizes; i++) {
		if (hp_sizes[i] == info.page_size)
			break;
	}

	CU_ASSERT(i < num_sizes);

	CU_ASSERT(odp_shm_free(shm) == 0);
}

/*
 * maximum size reservation
 */
static void shmem_test_max_reserve(void)
{
	odp_shm_capability_t capa;
	odp_shm_t shm;
	uint64_t size, align;
	uint8_t *data;
	uint64_t i;

	memset(&capa, 0, sizeof(odp_shm_capability_t));
	CU_ASSERT_FATAL(odp_shm_capability(&capa) == 0);

	CU_ASSERT(capa.max_blocks > 0);

	size  = capa.max_size;
	align = capa.max_align;

	/* Assuming that system has at least MAX_SIZE_TESTED bytes available */
	if (capa.max_size == 0 || capa.max_size > MAX_SIZE_TESTED)
		size = MAX_SIZE_TESTED;

	if (capa.max_align == 0 || capa.max_align > MAX_ALIGN_TESTED)
		align = MAX_ALIGN_TESTED;

	printf("\n    size:  %" PRIu64 "\n", size);
	printf("    align: %" PRIu64 "\n", align);

	shm = odp_shm_reserve("test_max_reserve", size, align, 0);
	CU_ASSERT(shm != ODP_SHM_INVALID);

	data = odp_shm_addr(shm);
	CU_ASSERT(data != NULL);

	if (data) {
		memset(data, 0xde, size);
		for (i = 0; i < size; i++) {
			if (data[i] != 0xde) {
				printf("    data error i:%" PRIu64 ", data %x"
				       "\n", i, data[i]);
				CU_FAIL("Data error");
				break;
			}
		}
	}

	if (shm != ODP_SHM_INVALID)
		CU_ASSERT(odp_shm_free(shm) == 0);
}

/*
 * thread part for the shmem_test_reserve_after_fork
 */
static int run_test_reserve_after_fork(void *arg ODP_UNUSED)
{
	odp_shm_t shm;
	shared_test_data_t *glob_data;
	int thr;
	int thr_index;
	int size;
	shared_test_data_small_t  *pattern_small;
	shared_test_data_medium_t *pattern_medium;
	shared_test_data_big_t    *pattern_big;
	int i;

	thr = odp_thread_id();
	printf("Thread %i starts\n", thr);

	shm = odp_shm_lookup(MEM_NAME);
	glob_data = odp_shm_addr(shm);

	/*
	 * odp_thread_id are not guaranteed to be consecutive, so we create
	 * a consecutive ID
	 */
	thr_index = odp_atomic_fetch_inc_u32(&glob_data->index);

	/* allocate some memory (of different sizes) and fill with pattern */
	snprintf(glob_data->name[thr_index], NAME_LEN, "%s-%09d",
		 MEM_NAME, thr_index);
	switch (thr_index % 3) {
	case 0:
		size = sizeof(shared_test_data_small_t);
		shm = odp_shm_reserve(glob_data->name[thr_index], size, 0, 0);
		CU_ASSERT(ODP_SHM_INVALID != shm);
		glob_data->shm[thr_index] = shm;
		pattern_small = odp_shm_addr(shm);
		CU_ASSERT_PTR_NOT_NULL(pattern_small);
		for (i = 0; i < SMALL_MEM; i++)
			pattern_small->data[i] = i;
		break;
	case 1:
		size = sizeof(shared_test_data_medium_t);
		shm = odp_shm_reserve(glob_data->name[thr_index], size, 0, 0);
		CU_ASSERT(ODP_SHM_INVALID != shm);
		glob_data->shm[thr_index] = shm;
		pattern_medium = odp_shm_addr(shm);
		CU_ASSERT_PTR_NOT_NULL(pattern_medium);
		for (i = 0; i < MEDIUM_MEM; i++)
			pattern_medium->data[i] = (i << 2);
		break;
	case 2:
		size = sizeof(shared_test_data_big_t);
		shm = odp_shm_reserve(glob_data->name[thr_index], size, 0, 0);
		CU_ASSERT(ODP_SHM_INVALID != shm);
		glob_data->shm[thr_index] = shm;
		pattern_big = odp_shm_addr(shm);
		CU_ASSERT_PTR_NOT_NULL(pattern_big);
		for (i = 0; i < BIG_MEM; i++)
			pattern_big->data[i] = (i >> 2);
		break;
	}

	/* print block address */
	printf("In thread: Block index: %d mapped at %lx\n",
	       thr_index, (long int)odp_shm_addr(shm));

	odp_barrier_wait(&glob_data->test_barrier1);
	odp_barrier_wait(&glob_data->test_barrier2);

	fflush(stdout);
	return CU_get_number_of_failures();
}

/*
 * test sharing memory reserved after odp_thread creation (e.g. fork()):
 */
static void shmem_test_reserve_after_fork(void)
{
	pthrd_arg thrdarg;
	odp_shm_t shm;
	odp_shm_t thr_shm;
	shared_test_data_t *glob_data;
	odp_cpumask_t unused;
	int thr_index;
	int i;
	void *address;
	shared_test_data_small_t  *pattern_small;
	shared_test_data_medium_t *pattern_medium;
	shared_test_data_big_t    *pattern_big;

	shm = odp_shm_reserve(MEM_NAME, sizeof(shared_test_data_t), 0, 0);
	CU_ASSERT(ODP_SHM_INVALID != shm);
	glob_data = odp_shm_addr(shm);
	CU_ASSERT_PTR_NOT_NULL(glob_data);

	thrdarg.numthrds = odp_cpumask_default_worker(&unused, 0);
	if (thrdarg.numthrds > MAX_WORKERS)
		thrdarg.numthrds = MAX_WORKERS;

	odp_barrier_init(&glob_data->test_barrier1, thrdarg.numthrds + 1);
	odp_barrier_init(&glob_data->test_barrier2, thrdarg.numthrds + 1);
	odp_atomic_store_u32(&glob_data->index, 0);

	odp_cunit_thread_create(run_test_reserve_after_fork, &thrdarg);

	/* wait until all threads have made their shm_reserve: */
	odp_barrier_wait(&glob_data->test_barrier1);

	/* perform a lookup of all memories: */
	for (thr_index = 0; thr_index < thrdarg.numthrds; thr_index++) {
		thr_shm = odp_shm_lookup(glob_data->name[thr_index]);
		CU_ASSERT(thr_shm == glob_data->shm[thr_index]);
	}

	/* check that the patterns are correct: */
	for (thr_index = 0; thr_index < thrdarg.numthrds; thr_index++) {
		switch (thr_index % 3) {
		case 0:
			pattern_small =
				odp_shm_addr(glob_data->shm[thr_index]);
			CU_ASSERT_PTR_NOT_NULL(pattern_small);
			for (i = 0; i < SMALL_MEM; i++)
				CU_ASSERT(pattern_small->data[i] == i);
			break;
		case 1:
			pattern_medium =
				odp_shm_addr(glob_data->shm[thr_index]);
			CU_ASSERT_PTR_NOT_NULL(pattern_medium);
			for (i = 0; i < MEDIUM_MEM; i++)
				CU_ASSERT(pattern_medium->data[i] == (i << 2));
			break;
		case 2:
			pattern_big =
				odp_shm_addr(glob_data->shm[thr_index]);
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
		address = odp_shm_addr(glob_data->shm[thr_index]);
		printf("In main Block index: %d mapped at %lx\n",
		       thr_index, (long int)address);
	}

	/* unblock the threads and let them terminate (no free is done): */
	odp_barrier_wait(&glob_data->test_barrier2);

	/* at the same time, (race),free of all memories: */
	for (thr_index = 0; thr_index < thrdarg.numthrds; thr_index++) {
		thr_shm = glob_data->shm[thr_index];
		CU_ASSERT(odp_shm_free(thr_shm) == 0);
	}

	/* wait for all thread endings: */
	CU_ASSERT(odp_cunit_thread_exit(&thrdarg) >= 0);

	/* just glob_data should remain: */

	CU_ASSERT(0 == odp_shm_free(shm));
}

/*
 * thread part for the shmem_test_singleva_after_fork
 */
static int run_test_singleva_after_fork(void *arg ODP_UNUSED)
{
	odp_shm_t shm;
	shared_test_data_t *glob_data;
	int thr;
	int thr_index;
	int size;
	shared_test_data_small_t  *pattern_small;
	shared_test_data_medium_t *pattern_medium;
	shared_test_data_big_t    *pattern_big;
	uint32_t i;
	int ret;

	thr = odp_thread_id();
	printf("Thread %i starts\n", thr);

	shm = odp_shm_lookup(MEM_NAME);
	glob_data = odp_shm_addr(shm);

	/*
	 * odp_thread_id are not guaranteed to be consecutive, so we create
	 * a consecutive ID
	 */
	thr_index = odp_atomic_fetch_inc_u32(&glob_data->index);

	/* allocate some memory (of different sizes) and fill with pattern */
	snprintf(glob_data->name[thr_index], NAME_LEN, "%s-%09d",
		 MEM_NAME, thr_index);
	switch (thr_index % 3) {
	case 0:
		size = sizeof(shared_test_data_small_t);
		shm = odp_shm_reserve(glob_data->name[thr_index], size,
				      0, ODP_SHM_SINGLE_VA);
		CU_ASSERT_FATAL(ODP_SHM_INVALID != shm);
		glob_data->shm[thr_index] = shm;
		pattern_small = odp_shm_addr(shm);
		CU_ASSERT_PTR_NOT_NULL(pattern_small);
		glob_data->address[thr_index] = (void *)pattern_small;
		for (i = 0; i < SMALL_MEM; i++)
			pattern_small->data[i] = i;
		break;
	case 1:
		size = sizeof(shared_test_data_medium_t);
		shm = odp_shm_reserve(glob_data->name[thr_index], size,
				      0, ODP_SHM_SINGLE_VA);
		CU_ASSERT_FATAL(ODP_SHM_INVALID != shm);
		glob_data->shm[thr_index] = shm;
		pattern_medium = odp_shm_addr(shm);
		CU_ASSERT_PTR_NOT_NULL(pattern_medium);
		glob_data->address[thr_index] = (void *)pattern_medium;
		for (i = 0; i < MEDIUM_MEM; i++)
			pattern_medium->data[i] = (i << 2);
		break;
	case 2:
		size = sizeof(shared_test_data_big_t);
		shm = odp_shm_reserve(glob_data->name[thr_index], size,
				      0, ODP_SHM_SINGLE_VA);
		CU_ASSERT_FATAL(ODP_SHM_INVALID != shm);
		glob_data->shm[thr_index] = shm;
		pattern_big = odp_shm_addr(shm);
		CU_ASSERT_PTR_NOT_NULL(pattern_big);
		glob_data->address[thr_index] = (void *)pattern_big;
		for (i = 0; i < BIG_MEM; i++)
			pattern_big->data[i] = (i >> 2);
		break;
	}

	/* print block address */
	printf("In thread: Block index: %d mapped at %lx\n",
	       thr_index, (long int)odp_shm_addr(shm));

	odp_barrier_wait(&glob_data->test_barrier1);
	odp_barrier_wait(&glob_data->test_barrier2);

	/* map each-other block, checking common address: */
	for (i = 0; i < glob_data->nb_threads; i++) {
		shm = odp_shm_lookup(glob_data->name[i]);
		CU_ASSERT(shm == glob_data->shm[i]);
		CU_ASSERT(odp_shm_addr(shm) == glob_data->address[i]);
	}

	/* wait for main control task and free the allocated block */
	odp_barrier_wait(&glob_data->test_barrier3);
	odp_barrier_wait(&glob_data->test_barrier4);
	ret = odp_shm_free(glob_data->shm[thr_index]);
	CU_ASSERT(ret == 0);

	fflush(stdout);
	return CU_get_number_of_failures();
}

/*
 * test sharing memory reserved after odp_thread creation (e.g. fork()):
 * with single VA flag.
 */
static void shmem_test_singleva_after_fork(void)
{
	pthrd_arg thrdarg;
	odp_shm_t shm;
	odp_shm_t thr_shm;
	shared_test_data_t *glob_data;
	odp_cpumask_t unused;
	int thr_index;
	int i;
	void *address;
	shared_test_data_small_t  *pattern_small;
	shared_test_data_medium_t *pattern_medium;
	shared_test_data_big_t    *pattern_big;

	shm = odp_shm_reserve(MEM_NAME, sizeof(shared_test_data_t),
			      0, 0);
	CU_ASSERT(ODP_SHM_INVALID != shm);
	glob_data = odp_shm_addr(shm);
	CU_ASSERT_PTR_NOT_NULL(glob_data);

	thrdarg.numthrds = odp_cpumask_default_worker(&unused, 3);
	if (thrdarg.numthrds > MAX_WORKERS)
		thrdarg.numthrds = MAX_WORKERS;

	glob_data->nb_threads = thrdarg.numthrds;
	odp_barrier_init(&glob_data->test_barrier1, thrdarg.numthrds + 1);
	odp_barrier_init(&glob_data->test_barrier2, thrdarg.numthrds + 1);
	odp_barrier_init(&glob_data->test_barrier3, thrdarg.numthrds + 1);
	odp_barrier_init(&glob_data->test_barrier4, thrdarg.numthrds + 1);
	odp_atomic_store_u32(&glob_data->index, 0);

	odp_cunit_thread_create(run_test_singleva_after_fork, &thrdarg);

	/* wait until all threads have made their shm_reserve: */
	odp_barrier_wait(&glob_data->test_barrier1);

	/* perform a lookup of all memories: */
	for (thr_index = 0; thr_index < thrdarg.numthrds; thr_index++) {
		thr_shm = odp_shm_lookup(glob_data->name[thr_index]);
		CU_ASSERT(thr_shm == glob_data->shm[thr_index]);
	}

	/* check that the patterns are correct: */
	for (thr_index = 0; thr_index < thrdarg.numthrds; thr_index++) {
		switch (thr_index % 3) {
		case 0:
			pattern_small =
				odp_shm_addr(glob_data->shm[thr_index]);
			CU_ASSERT_PTR_NOT_NULL_FATAL(pattern_small);
			for (i = 0; i < SMALL_MEM; i++)
				CU_ASSERT(pattern_small->data[i] == i);
			break;
		case 1:
			pattern_medium =
				odp_shm_addr(glob_data->shm[thr_index]);
			CU_ASSERT_PTR_NOT_NULL_FATAL(pattern_medium);
			for (i = 0; i < MEDIUM_MEM; i++)
				CU_ASSERT(pattern_medium->data[i] == (i << 2));
			break;
		case 2:
			pattern_big =
				odp_shm_addr(glob_data->shm[thr_index]);
			CU_ASSERT_PTR_NOT_NULL_FATAL(pattern_big);
			for (i = 0; i < BIG_MEM; i++)
				CU_ASSERT(pattern_big->data[i] == (i >> 2));
			break;
		}
	}

	/*
	 * check that the mapping address is common to all (SINGLE_VA):
	 */
	for (thr_index = 0; thr_index < thrdarg.numthrds; thr_index++) {
		address = odp_shm_addr(glob_data->shm[thr_index]);
		CU_ASSERT(glob_data->address[thr_index] == address);
	}

	/* unblock the threads and let them map each-other blocks: */
	odp_barrier_wait(&glob_data->test_barrier2);

	/* then check mem status */
	odp_barrier_wait(&glob_data->test_barrier3);

	/* unblock the threads and let them free all thread blocks: */
	odp_barrier_wait(&glob_data->test_barrier4);

	/* wait for all thread endings: */
	CU_ASSERT(odp_cunit_thread_exit(&thrdarg) >= 0);

	/* just glob_data should remain: */

	CU_ASSERT(0 == odp_shm_free(shm));
}

/*
 * thread part for the shmem_test_stress
 */
static int run_test_stress(void *arg ODP_UNUSED)
{
	odp_shm_t shm;
	uint8_t *address;
	shared_test_data_t *glob_data;
	uint8_t random_bytes[STRESS_RANDOM_SZ];
	uint32_t index;
	uint32_t size;
	uint64_t align;
	uint32_t flags;
	uint8_t data;
	uint32_t iter;
	uint32_t i;

	shm = odp_shm_lookup(MEM_NAME);
	glob_data = odp_shm_addr(shm);
	CU_ASSERT_PTR_NOT_NULL(glob_data);

	/* wait for general GO! */
	odp_barrier_wait(&glob_data->test_barrier1);

	/*
	 * at each iteration: pick up a random index for
	 * glob_data->stress[index]: If the entry is free, allocated mem
	 * randomly. If it is already allocated, make checks and free it:
	 * Note that different tread can allocate or free a given block
	 */
	for (iter = 0; iter < STRESS_ITERATION; iter++) {
		/* get 4 random bytes from which index, size ,align, flags
		 * and data will be derived:
		 */
		odp_random_data(random_bytes, STRESS_RANDOM_SZ, 0);
		index = random_bytes[0] & (STRESS_SIZE - 1);

		odp_spinlock_lock(&glob_data->stress_lock);

		switch (glob_data->stress[index].state) {
		case STRESS_FREE:
			/* allocated a new block for this entry */

			glob_data->stress[index].state = STRESS_BUSY;
			odp_spinlock_unlock(&glob_data->stress_lock);

			size  = (random_bytes[1] + 1) << 6; /* up to 16Kb */
			/* we just play with the VA flag. randomly setting
			 * the mlock flag may exceed user ulimit -l
			 */
			flags = random_bytes[2] & ODP_SHM_SINGLE_VA;
			align = (random_bytes[3] + 1) << 6;/* up to 16Kb */
			data  = random_bytes[4];

			snprintf(glob_data->stress[index].name, NAME_LEN,
				 "%s-%09d", MEM_NAME, index);
			shm = odp_shm_reserve(glob_data->stress[index].name,
					      size, align, flags);
			glob_data->stress[index].shm = shm;
			if (shm == ODP_SHM_INVALID) { /* out of mem ? */
				odp_spinlock_lock(&glob_data->stress_lock);
				glob_data->stress[index].state = STRESS_ALLOC;
				odp_spinlock_unlock(&glob_data->stress_lock);
				continue;
			}

			address = odp_shm_addr(shm);
			CU_ASSERT_PTR_NOT_NULL(address);
			glob_data->stress[index].address = address;
			glob_data->stress[index].flags = flags;
			glob_data->stress[index].size = size;
			glob_data->stress[index].align = align;
			glob_data->stress[index].data_val = data;

			/* write some data: writing each byte would be a
			 * waste of time: just make sure each page is reached */
			for (i = 0; i < size; i += 256)
				address[i] = (data++) & 0xFF;
			odp_spinlock_lock(&glob_data->stress_lock);
			glob_data->stress[index].state = STRESS_ALLOC;
			odp_spinlock_unlock(&glob_data->stress_lock);

			break;

		case STRESS_ALLOC:
			/* free the block for this entry */

			glob_data->stress[index].state = STRESS_BUSY;
			odp_spinlock_unlock(&glob_data->stress_lock);
			shm = glob_data->stress[index].shm;

			if (shm == ODP_SHM_INVALID) { /* out of mem ? */
				odp_spinlock_lock(&glob_data->stress_lock);
				glob_data->stress[index].state = STRESS_FREE;
				odp_spinlock_unlock(&glob_data->stress_lock);
				continue;
			}

			CU_ASSERT(odp_shm_lookup(glob_data->stress[index].name)
				  != 0);

			address = odp_shm_addr(shm);
			CU_ASSERT_PTR_NOT_NULL(address);

			align = glob_data->stress[index].align;
			if (align) {
				align = glob_data->stress[index].align;
				CU_ASSERT(((uintptr_t)address & (align - 1))
									== 0)
			}

			flags = glob_data->stress[index].flags;
			if (flags & ODP_SHM_SINGLE_VA)
				CU_ASSERT(glob_data->stress[index].address ==
							address)

			/* check that data is reachable and correct: */
			data = glob_data->stress[index].data_val;
			size = glob_data->stress[index].size;
			for (i = 0; i < size; i += 256) {
				CU_ASSERT(address[i] == (data & 0xFF));
				data++;
			}

			CU_ASSERT(!odp_shm_free(glob_data->stress[index].shm));

			odp_spinlock_lock(&glob_data->stress_lock);
			glob_data->stress[index].state = STRESS_FREE;
			odp_spinlock_unlock(&glob_data->stress_lock);

			break;

		case STRESS_BUSY:
		default:
			odp_spinlock_unlock(&glob_data->stress_lock);
			break;
		}
	}

	fflush(stdout);
	return CU_get_number_of_failures();
}

/*
 * stress tests
 */
static void shmem_test_stress(void)
{
	pthrd_arg thrdarg;
	odp_shm_t shm;
	odp_shm_t globshm;
	shared_test_data_t *glob_data;
	odp_cpumask_t unused;
	uint32_t i;

	globshm = odp_shm_reserve(MEM_NAME, sizeof(shared_test_data_t),
				  0, 0);
	CU_ASSERT(ODP_SHM_INVALID != globshm);
	glob_data = odp_shm_addr(globshm);
	CU_ASSERT_PTR_NOT_NULL(glob_data);

	thrdarg.numthrds = odp_cpumask_default_worker(&unused, 0);
	if (thrdarg.numthrds > MAX_WORKERS)
		thrdarg.numthrds = MAX_WORKERS;

	glob_data->nb_threads = thrdarg.numthrds;
	odp_barrier_init(&glob_data->test_barrier1, thrdarg.numthrds);
	odp_spinlock_init(&glob_data->stress_lock);

	/* before starting the threads, mark all entries as free: */
	for (i = 0; i < STRESS_SIZE; i++)
		glob_data->stress[i].state = STRESS_FREE;

	/* create threads */
	odp_cunit_thread_create(run_test_stress, &thrdarg);

	/* wait for all thread endings: */
	CU_ASSERT(odp_cunit_thread_exit(&thrdarg) >= 0);

	/* release left overs: */
	for (i = 0; i < STRESS_SIZE; i++) {
		shm = glob_data->stress[i].shm;
		if ((glob_data->stress[i].state == STRESS_ALLOC) &&
		    (glob_data->stress[i].shm != ODP_SHM_INVALID)) {
			CU_ASSERT(odp_shm_lookup(glob_data->stress[i].name) ==
							shm);
			CU_ASSERT(!odp_shm_free(shm));
		}
	}

	CU_ASSERT(0 == odp_shm_free(globshm));

	/* check that no memory is left over: */
}

odp_testinfo_t shmem_suite[] = {
	ODP_TEST_INFO(shmem_test_basic),
	ODP_TEST_INFO(shmem_test_hp),
	ODP_TEST_INFO(shmem_test_max_reserve),
	ODP_TEST_INFO(shmem_test_reserve_after_fork),
	ODP_TEST_INFO(shmem_test_singleva_after_fork),
	ODP_TEST_INFO(shmem_test_stress),
	ODP_TEST_INFO_NULL,
};

odp_suiteinfo_t shmem_suites[] = {
	{"Shared Memory", NULL, NULL, shmem_suite},
	ODP_SUITE_INFO_NULL,
};

int main(int argc, char *argv[])
{
	int ret;

	/* parse common options: */
	if (odp_cunit_parse_options(argc, argv))
		return -1;

	ret = odp_cunit_register(shmem_suites);

	if (ret == 0)
		ret = odp_cunit_run();

	return ret;
}
