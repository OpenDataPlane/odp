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
#define BIG_MEM 65536
#define STRESS_SIZE 32		/* power of 2 and <=256 */
#define STRESS_RANDOM_SZ 5
#define STRESS_ITERATION 5000

#define POOL_NAME "test_pool"
#define POOL_SZ (1UL << 20)	/* 1 MBytes */
#define TEST_SZ 1000
#define SZ_1K   1024
#define BUFF_PATTERN 0xA3

typedef enum {
	STRESS_FREE, /* entry is free and can be allocated */
	STRESS_BUSY, /* entry is being processed: don't touch */
	STRESS_ALLOC /* entry is allocated  and can be freed */
} stress_state_t;

typedef struct {
	stress_state_t state;
	odpdrv_shm_t shm;
	void *address;
	uint32_t flags;
	uint32_t size;
	uint64_t align;
	uint8_t data_val;
} stress_data_t;

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

/*
 * thread part for the drvshmem_test_stress
 */
static int run_test_stress(void *arg ODP_UNUSED)
{
	odpdrv_shm_t shm;
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

	shm = odpdrv_shm_lookup_by_name(MEM_NAME);
	glob_data = odpdrv_shm_addr(shm);
	CU_ASSERT_PTR_NOT_NULL(glob_data);

	/* wait for general GO! */
	odpdrv_barrier_wait(&glob_data->test_barrier1);
	/*

	 * at each iteration: pick up a random index for
	 * glob_data->stress[index]: If the entry is free, allocated mem
	 * randomly. If it is already allocated, make checks and free it:
	 * Note that different tread cann allocate or free a given block
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
			flags = random_bytes[2] & ODPDRV_SHM_SINGLE_VA;
			align = (random_bytes[3] + 1) << 6;/* up to 16Kb */
			data  = random_bytes[4];

			shm = odpdrv_shm_reserve(NULL, size, align, flags);
			glob_data->stress[index].shm = shm;
			if (shm == ODPDRV_SHM_INVALID) { /* out of mem ? */
				odp_spinlock_lock(&glob_data->stress_lock);
				glob_data->stress[index].state = STRESS_ALLOC;
				odp_spinlock_unlock(&glob_data->stress_lock);
				continue;
			}

			address = odpdrv_shm_addr(shm);
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

			if (shm == ODPDRV_SHM_INVALID) { /* out of mem ? */
				odp_spinlock_lock(&glob_data->stress_lock);
				glob_data->stress[index].state = STRESS_FREE;
				odp_spinlock_unlock(&glob_data->stress_lock);
				continue;
			}

			CU_ASSERT(odpdrv_shm_lookup_by_handle(shm) != 0);

			address = odpdrv_shm_addr(shm);
			CU_ASSERT_PTR_NOT_NULL(address);

			align = glob_data->stress[index].align;
			if (align) {
				align = glob_data->stress[index].align;
				CU_ASSERT(((uintptr_t)address & (align - 1))
									== 0)
			}

			flags = glob_data->stress[index].flags;
			if (flags & ODPDRV_SHM_SINGLE_VA)
				CU_ASSERT(glob_data->stress[index].address ==
							address)

			/* check that data is reachable and correct: */
			data = glob_data->stress[index].data_val;
			size = glob_data->stress[index].size;
			for (i = 0; i < size; i += 256) {
				CU_ASSERT(address[i] == (data & 0xFF));
				data++;
			}

			if (flags & ODPDRV_SHM_SINGLE_VA) {
				CU_ASSERT(!odpdrv_shm_free_by_address(address));
			} else {
				CU_ASSERT(!odpdrv_shm_free_by_handle(shm));
			}

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
void drvshmem_test_stress(void)
{
	pthrd_arg thrdarg;
	odpdrv_shm_t shm;
	shared_test_data_t *glob_data;
	odp_cpumask_t unused;
	int base; /* number of blocks already allocated at start of test */
	uint32_t i;

	base = odpdrv_shm_print_all("Before thread tests");

	shm = odpdrv_shm_reserve(MEM_NAME, sizeof(shared_test_data_t),
				 0, ODPDRV_SHM_LOCK);
	CU_ASSERT(ODPDRV_SHM_INVALID != shm);
	glob_data = odpdrv_shm_addr(shm);
	CU_ASSERT_PTR_NOT_NULL(glob_data);

	thrdarg.numthrds = odp_cpumask_default_worker(&unused, 0);
	if (thrdarg.numthrds > MAX_WORKERS)
		thrdarg.numthrds = MAX_WORKERS;

	glob_data->nb_threads = thrdarg.numthrds;
	odpdrv_barrier_init(&glob_data->test_barrier1, thrdarg.numthrds);
	odp_spinlock_init(&glob_data->stress_lock);

	/* before starting the threads, mark all entries as free: */
	for (i = 0; i < STRESS_SIZE; i++)
		glob_data->stress[i].state = STRESS_FREE;

	/* create threads */
	odp_cunit_thread_create(run_test_stress, &thrdarg);

	/* wait for all thread endings: */
	CU_ASSERT(odp_cunit_thread_exit(&thrdarg) >= 0);

	odpdrv_shm_print_all("Middle");

	/* release left overs: */
	for (i = 0; i < STRESS_SIZE; i++) {
		shm = glob_data->stress[i].shm;
		if ((glob_data->stress[i].state == STRESS_ALLOC) &&
		    (glob_data->stress[i].shm != ODPDRV_SHM_INVALID)) {
				CU_ASSERT(odpdrv_shm_lookup_by_handle(shm) !=
							NULL);
				CU_ASSERT(!odpdrv_shm_free_by_handle(shm));
		}
	}

	CU_ASSERT(0 == odpdrv_shm_free_by_name(MEM_NAME));

	/* check that no memory is left over: */
	CU_ASSERT(odpdrv_shm_print_all("After stress tests") == base);
}

void drvshmem_test_buddy_basic(void)
{
	odpdrv_shm_pool_param_t pool_params;
	odpdrv_shm_pool_t pool, found_pool;
	uint8_t *buff;
	uint8_t *addrs[TEST_SZ];
	uint8_t length;
	int i, j;

	/* create a pool and check that it can be looked up */
	pool_params.pool_size = POOL_SZ;
	pool_params.min_alloc = 1;
	pool_params.max_alloc = POOL_SZ;
	pool = odpdrv_shm_pool_create(POOL_NAME, &pool_params);
	found_pool = odpdrv_shm_pool_lookup(POOL_NAME);
	CU_ASSERT(found_pool == pool);

	/* alloc a 1k buffer, filling its contents: */
	buff = odpdrv_shm_pool_alloc(pool, SZ_1K);
	CU_ASSERT_PTR_NOT_NULL(buff);
	for (i = 0; i < SZ_1K; i++)
		buff[i] = BUFF_PATTERN;
	odpdrv_shm_pool_print("buddy test: 1K reserved", pool);

	/* alloc as many buffer a possible on increseasing sz */
	for (i = 0; i < TEST_SZ; i++) {
		length = i * 16;
		addrs[i] = odpdrv_shm_pool_alloc(pool, length);
		/* if alloc was success, fill buffer for later check */
		if (addrs[i]) {
			for (j = 0; j < length; j++)
				addrs[i][j] = (uint8_t)(length & 0xFF);
		}
	}
	odpdrv_shm_pool_print("buddy test: after many mallocs", pool);

	/* release every 3rth buffer, checking contents: */
	for (i = 0; i < TEST_SZ; i += 3) {
		/* if buffer was allocated, check the pattern in it */
		if (addrs[i]) {
			length = i * 16;
			for (j = 0; j < length; j++)
				CU_ASSERT(addrs[i][j] ==
					  (uint8_t)(length & 0xFF));
		}
		odpdrv_shm_pool_free(pool, addrs[i]);
	}
	odpdrv_shm_pool_print("buddy test: after 1/3 free:", pool);

	/* realloc them:*/
	for (i = 0; i < TEST_SZ; i += 3) {
		length = i * 16;
		addrs[i] = odpdrv_shm_pool_alloc(pool, length);
		/* if alloc was success, fill buffer for later check */
		if (addrs[i]) {
			for (j = 0; j < length; j++)
				addrs[i][j] = (uint8_t)(length & 0xFF);
		}
	}
	odpdrv_shm_pool_print("buddy test: after realloc:", pool);

	/* free all (except buff), checking contents: */
	for (i = 0; i < TEST_SZ; i++) {
		/* if buffer was allocated, check the pattern in it */
		if (addrs[i]) {
			length = i * 16;
			for (j = 0; j < length; j++)
				CU_ASSERT(addrs[i][j] ==
					  (uint8_t)(length & 0xFF))
		}
		odpdrv_shm_pool_free(pool, addrs[i]);
	}
	odpdrv_shm_pool_print("buddy test: after all but 1K free:", pool);

	/* check contents of our initial 1K buffer: */
	for (i = 0; i < SZ_1K; i++)
		CU_ASSERT((buff[i] == BUFF_PATTERN))
	odpdrv_shm_pool_free(pool, buff);

	odpdrv_shm_pool_print("buddy test: after all free", pool);

	/* destroy pool: */
	odpdrv_shm_pool_destroy(pool);
}

void drvshmem_test_slab_basic(void)
{
	odpdrv_shm_pool_param_t pool_params;
	odpdrv_shm_pool_t pool, found_pool;
	uint8_t *buff;
	uint8_t *addrs[TEST_SZ];
	uint16_t length;
	int i, j;

	/* create a pool and check that it can be looked up */
	pool_params.pool_size = POOL_SZ;
	pool_params.min_alloc = SZ_1K; /* constant size will give slab */
	pool_params.max_alloc = SZ_1K;
	pool = odpdrv_shm_pool_create(POOL_NAME, &pool_params);
	found_pool = odpdrv_shm_pool_lookup(POOL_NAME);
	CU_ASSERT(found_pool == pool);

	/* alloc a 1k buffer, filling its contents: */
	buff = odpdrv_shm_pool_alloc(pool, SZ_1K);
	CU_ASSERT_PTR_NOT_NULL(buff);
	for (i = 0; i < SZ_1K; i++)
		buff[i] = BUFF_PATTERN;
	odpdrv_shm_pool_print("buddy test: 1K reserved", pool);

	/* alloc as many 1K buffer a possible */
	for (i = 0; i < TEST_SZ; i++) {
		length = SZ_1K;
		addrs[i] = odpdrv_shm_pool_alloc(pool, length);
		/* if alloc was success, fill buffer for later check */
		if (addrs[i]) {
			for (j = 0; j < length; j++)
				addrs[i][j] = (uint8_t)(length & 0xFF);
		}
	}
	odpdrv_shm_pool_print("slab test: after many mallocs", pool);

	/* release every 3rth buffer, checking contents: */
	for (i = 0; i < TEST_SZ; i += 3) {
		/* if buffer was allocated, check the pattern in it */
		if (addrs[i]) {
			length = SZ_1K;
			for (j = 0; j < length; j++)
				CU_ASSERT(addrs[i][j] ==
					  (uint8_t)(length & 0xFF));
		}
		odpdrv_shm_pool_free(pool, addrs[i]);
	}
	odpdrv_shm_pool_print("slab test: after 1/3 free:", pool);

	/* realloc them:*/
	for (i = 0; i < TEST_SZ; i += 3) {
		length = SZ_1K;
		addrs[i] = odpdrv_shm_pool_alloc(pool, length);
		/* if alloc was success, fill buffer for later check */
		if (addrs[i]) {
			for (j = 0; j < length; j++)
				addrs[i][j] = (uint8_t)(length & 0xFF);
		}
	}
	odpdrv_shm_pool_print("slab test: after realloc:", pool);

	/* free all (except buff), checking contents: */
	for (i = 0; i < TEST_SZ; i++) {
		/* if buffer was allocated, check the pattern in it */
		if (addrs[i]) {
			length = SZ_1K;
			for (j = 0; j < length; j++)
				CU_ASSERT(addrs[i][j] ==
					  (uint8_t)(length & 0xFF))
		}
		odpdrv_shm_pool_free(pool, addrs[i]);
	}
	odpdrv_shm_pool_print("slab test: after all but 1K free:", pool);

	/* check contents of our initial 1K buffer: */
	for (i = 0; i < SZ_1K; i++)
		CU_ASSERT((buff[i] == BUFF_PATTERN))
	odpdrv_shm_pool_free(pool, buff);

	odpdrv_shm_pool_print("slab test: after all free", pool);

	/* destroy pool: */
	odpdrv_shm_pool_destroy(pool);
}

odp_testinfo_t drvshmem_suite[] = {
	ODP_TEST_INFO(drvshmem_test_basic),
	ODP_TEST_INFO(drvshmem_test_reserve_after_fork),
	ODP_TEST_INFO(drvshmem_test_singleva_after_fork),
	ODP_TEST_INFO(drvshmem_test_stress),
	ODP_TEST_INFO(drvshmem_test_buddy_basic),
	ODP_TEST_INFO(drvshmem_test_slab_basic),
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
