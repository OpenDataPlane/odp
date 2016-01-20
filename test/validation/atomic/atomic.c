/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:	 BSD-3-Clause
 */

#include <malloc.h>
#include <odp.h>
#include <CUnit/Basic.h>
#include <odp_cunit_common.h>
#include <unistd.h>
#include "atomic.h"

#define VERBOSE			0
#define MAX_ITERATIONS		1000

#define ADD_SUB_CNT		5

#define CNT			10
#define U32_INIT_VAL		(1UL << 10)
#define U64_INIT_VAL		(1ULL << 33)

#define GLOBAL_SHM_NAME		"GlobalLockTest"

#define UNUSED			__attribute__((__unused__))

#define CHECK_MAX_MIN		(1 << 0)

static odp_atomic_u32_t a32u;
static odp_atomic_u64_t a64u;
static odp_atomic_u32_t a32u_min;
static odp_atomic_u32_t a32u_max;
static odp_atomic_u64_t a64u_min;
static odp_atomic_u64_t a64u_max;

typedef __volatile uint32_t volatile_u32_t;
typedef __volatile uint64_t volatile_u64_t;

typedef struct {
	/* Global variables */
	uint32_t g_num_threads;
	uint32_t g_iterations;
	uint32_t g_verbose;
	uint32_t g_max_num_cores;

	volatile_u32_t global_lock_owner;
} global_shared_mem_t;

/* Per-thread memory */
typedef struct {
	global_shared_mem_t *global_mem;

	int thread_id;
	int thread_core;

	volatile_u64_t delay_counter;
} per_thread_mem_t;

static odp_shm_t global_shm;
static global_shared_mem_t *global_mem;

/* Initialise per-thread memory */
static per_thread_mem_t *thread_init(void)
{
	global_shared_mem_t *global_mem;
	per_thread_mem_t *per_thread_mem;
	odp_shm_t global_shm;
	uint32_t per_thread_mem_len;

	per_thread_mem_len = sizeof(per_thread_mem_t);
	per_thread_mem = malloc(per_thread_mem_len);
	memset(per_thread_mem, 0, per_thread_mem_len);

	per_thread_mem->delay_counter = 1;

	per_thread_mem->thread_id = odp_thread_id();
	per_thread_mem->thread_core = odp_cpu_id();

	global_shm = odp_shm_lookup(GLOBAL_SHM_NAME);
	global_mem = odp_shm_addr(global_shm);
	CU_ASSERT_PTR_NOT_NULL(global_mem);

	per_thread_mem->global_mem = global_mem;

	return per_thread_mem;
}

static void thread_finalize(per_thread_mem_t *per_thread_mem)
{
	free(per_thread_mem);
}

static void test_atomic_inc_32(void)
{
	int i;

	for (i = 0; i < CNT; i++)
		odp_atomic_inc_u32(&a32u);
}

static void test_atomic_inc_64(void)
{
	int i;

	for (i = 0; i < CNT; i++)
		odp_atomic_inc_u64(&a64u);
}

static void test_atomic_dec_32(void)
{
	int i;

	for (i = 0; i < CNT; i++)
		odp_atomic_dec_u32(&a32u);
}

static void test_atomic_dec_64(void)
{
	int i;

	for (i = 0; i < CNT; i++)
		odp_atomic_dec_u64(&a64u);
}

static void test_atomic_fetch_inc_32(void)
{
	int i;

	for (i = 0; i < CNT; i++)
		odp_atomic_fetch_inc_u32(&a32u);
}

static void test_atomic_fetch_inc_64(void)
{
	int i;

	for (i = 0; i < CNT; i++)
		odp_atomic_fetch_inc_u64(&a64u);
}

static void test_atomic_fetch_dec_32(void)
{
	int i;

	for (i = 0; i < CNT; i++)
		odp_atomic_fetch_dec_u32(&a32u);
}

static void test_atomic_fetch_dec_64(void)
{
	int i;

	for (i = 0; i < CNT; i++)
		odp_atomic_fetch_dec_u64(&a64u);
}

static void test_atomic_add_32(void)
{
	int i;

	for (i = 0; i < CNT; i++)
		odp_atomic_add_u32(&a32u, ADD_SUB_CNT);
}

static void test_atomic_add_64(void)
{
	int i;

	for (i = 0; i < CNT; i++)
		odp_atomic_add_u64(&a64u, ADD_SUB_CNT);
}

static void test_atomic_sub_32(void)
{
	int i;

	for (i = 0; i < CNT; i++)
		odp_atomic_sub_u32(&a32u, ADD_SUB_CNT);
}

static void test_atomic_sub_64(void)
{
	int i;

	for (i = 0; i < CNT; i++)
		odp_atomic_sub_u64(&a64u, ADD_SUB_CNT);
}

static void test_atomic_fetch_add_32(void)
{
	int i;

	for (i = 0; i < CNT; i++)
		odp_atomic_fetch_add_u32(&a32u, ADD_SUB_CNT);
}

static void test_atomic_fetch_add_64(void)
{
	int i;

	for (i = 0; i < CNT; i++)
		odp_atomic_fetch_add_u64(&a64u, ADD_SUB_CNT);
}

static void test_atomic_fetch_sub_32(void)
{
	int i;

	for (i = 0; i < CNT; i++)
		odp_atomic_fetch_sub_u32(&a32u, ADD_SUB_CNT);
}

static void test_atomic_fetch_sub_64(void)
{
	int i;

	for (i = 0; i < CNT; i++)
		odp_atomic_fetch_sub_u64(&a64u, ADD_SUB_CNT);
}

static void test_atomic_min_32(void)
{
	int i;
	uint32_t tmp;

	for (i = 0; i < CNT; i++) {
		tmp = odp_atomic_fetch_dec_u32(&a32u);
		odp_atomic_min_u32(&a32u_min, tmp);
	}
}

static void test_atomic_min_64(void)
{
	int i;
	uint64_t tmp;

	for (i = 0; i < CNT; i++) {
		tmp = odp_atomic_fetch_dec_u64(&a64u);
		odp_atomic_min_u64(&a64u_min, tmp);
	}
}

static void test_atomic_max_32(void)
{
	int i;
	uint32_t tmp;

	for (i = 0; i < CNT; i++) {
		tmp = odp_atomic_fetch_inc_u32(&a32u);
		odp_atomic_max_u32(&a32u_max, tmp);
	}
}

static void test_atomic_max_64(void)
{
	int i;
	uint64_t tmp;

	for (i = 0; i < CNT; i++) {
		tmp = odp_atomic_fetch_inc_u64(&a64u);
		odp_atomic_max_u64(&a64u_max, tmp);
	}
}

static void test_atomic_inc_dec_32(void)
{
	test_atomic_inc_32();
	test_atomic_dec_32();
}

static void test_atomic_inc_dec_64(void)
{
	test_atomic_inc_64();
	test_atomic_dec_64();
}

static void test_atomic_fetch_inc_dec_32(void)
{
	test_atomic_fetch_inc_32();
	test_atomic_fetch_dec_32();
}

static void test_atomic_fetch_inc_dec_64(void)
{
	test_atomic_fetch_inc_64();
	test_atomic_fetch_dec_64();
}

static void test_atomic_add_sub_32(void)
{
	test_atomic_add_32();
	test_atomic_sub_32();
}

static void test_atomic_add_sub_64(void)
{
	test_atomic_add_64();
	test_atomic_sub_64();
}

static void test_atomic_fetch_add_sub_32(void)
{
	test_atomic_fetch_add_32();
	test_atomic_fetch_sub_32();
}

static void test_atomic_fetch_add_sub_64(void)
{
	test_atomic_fetch_add_64();
	test_atomic_fetch_sub_64();
}

static void test_atomic_max_min_32(void)
{
	test_atomic_max_32();
	test_atomic_min_32();
}

static void test_atomic_max_min_64(void)
{
	test_atomic_max_64();
	test_atomic_min_64();
}

static void test_atomic_init(void)
{
	odp_atomic_init_u32(&a32u, 0);
	odp_atomic_init_u64(&a64u, 0);
	odp_atomic_init_u32(&a32u_min, 0);
	odp_atomic_init_u32(&a32u_max, 0);
	odp_atomic_init_u64(&a64u_min, 0);
	odp_atomic_init_u64(&a64u_max, 0);
}

static void test_atomic_store(void)
{
	odp_atomic_store_u32(&a32u, U32_INIT_VAL);
	odp_atomic_store_u64(&a64u, U64_INIT_VAL);
	odp_atomic_store_u32(&a32u_min, U32_INIT_VAL);
	odp_atomic_store_u32(&a32u_max, U32_INIT_VAL);
	odp_atomic_store_u64(&a64u_min, U64_INIT_VAL);
	odp_atomic_store_u64(&a64u_max, U64_INIT_VAL);
}

static void test_atomic_validate(int check)
{
	CU_ASSERT(U32_INIT_VAL == odp_atomic_load_u32(&a32u));
	CU_ASSERT(U64_INIT_VAL == odp_atomic_load_u64(&a64u));

	if (check & CHECK_MAX_MIN) {
		CU_ASSERT(odp_atomic_load_u32(&a32u_max) >
			  odp_atomic_load_u32(&a32u_min));

		CU_ASSERT(odp_atomic_load_u64(&a64u_max) >
			  odp_atomic_load_u64(&a64u_min));
	}
}

int atomic_init(void)
{
	uint32_t workers_count, max_threads;
	int ret = 0;
	odp_cpumask_t mask;

	if (0 != odp_init_global(NULL, NULL)) {
		fprintf(stderr, "error: odp_init_global() failed.\n");
		return -1;
	}
	if (0 != odp_init_local(ODP_THREAD_CONTROL)) {
		fprintf(stderr, "error: odp_init_local() failed.\n");
		return -1;
	}

	global_shm = odp_shm_reserve(GLOBAL_SHM_NAME,
				     sizeof(global_shared_mem_t), 64,
				     ODP_SHM_SW_ONLY);
	if (ODP_SHM_INVALID == global_shm) {
		fprintf(stderr, "Unable reserve memory for global_shm\n");
		return -1;
	}

	global_mem = odp_shm_addr(global_shm);
	memset(global_mem, 0, sizeof(global_shared_mem_t));

	global_mem->g_num_threads = MAX_WORKERS;
	global_mem->g_iterations = MAX_ITERATIONS;
	global_mem->g_verbose = VERBOSE;

	workers_count = odp_cpumask_default_worker(&mask, 0);

	max_threads = (workers_count >= MAX_WORKERS) ?
			MAX_WORKERS : workers_count;

	if (max_threads < global_mem->g_num_threads) {
		printf("Requested num of threads is too large\n");
		printf("reducing from %" PRIu32 " to %" PRIu32 "\n",
		       global_mem->g_num_threads,
		       max_threads);
		global_mem->g_num_threads = max_threads;
	}

	printf("Num of threads used = %" PRIu32 "\n",
	       global_mem->g_num_threads);

	return ret;
}

/* Atomic tests */
static void *test_atomic_inc_dec_thread(void *arg UNUSED)
{
	per_thread_mem_t *per_thread_mem;

	per_thread_mem = thread_init();
	test_atomic_inc_dec_32();
	test_atomic_inc_dec_64();

	thread_finalize(per_thread_mem);

	return NULL;
}

static void *test_atomic_add_sub_thread(void *arg UNUSED)
{
	per_thread_mem_t *per_thread_mem;

	per_thread_mem = thread_init();
	test_atomic_add_sub_32();
	test_atomic_add_sub_64();

	thread_finalize(per_thread_mem);

	return NULL;
}

static void *test_atomic_fetch_inc_dec_thread(void *arg UNUSED)
{
	per_thread_mem_t *per_thread_mem;

	per_thread_mem = thread_init();
	test_atomic_fetch_inc_dec_32();
	test_atomic_fetch_inc_dec_64();

	thread_finalize(per_thread_mem);

	return NULL;
}

static void *test_atomic_fetch_add_sub_thread(void *arg UNUSED)
{
	per_thread_mem_t *per_thread_mem;

	per_thread_mem = thread_init();
	test_atomic_fetch_add_sub_32();
	test_atomic_fetch_add_sub_64();

	thread_finalize(per_thread_mem);

	return NULL;
}

static void *test_atomic_max_min_thread(void *arg UNUSED)
{
	per_thread_mem_t *per_thread_mem;

	per_thread_mem = thread_init();
	test_atomic_max_min_32();
	test_atomic_max_min_64();

	thread_finalize(per_thread_mem);

	return NULL;
}

static void test_atomic_functional(void *func_ptr(void *), int check)
{
	pthrd_arg arg;

	arg.numthrds = global_mem->g_num_threads;
	test_atomic_init();
	test_atomic_store();
	odp_cunit_thread_create(func_ptr, &arg);
	odp_cunit_thread_exit(&arg);
	test_atomic_validate(check);
}

void atomic_test_atomic_inc_dec(void)
{
	test_atomic_functional(test_atomic_inc_dec_thread, 0);
}

void atomic_test_atomic_add_sub(void)
{
	test_atomic_functional(test_atomic_add_sub_thread, 0);
}

void atomic_test_atomic_fetch_inc_dec(void)
{
	test_atomic_functional(test_atomic_fetch_inc_dec_thread, 0);
}

void atomic_test_atomic_fetch_add_sub(void)
{
	test_atomic_functional(test_atomic_fetch_add_sub_thread, 0);
}

void synchronizers_test_atomic_max_min(void)
{
	test_atomic_functional(test_atomic_max_min_thread, CHECK_MAX_MIN);
}

odp_testinfo_t atomic_suite_atomic[] = {
	ODP_TEST_INFO(atomic_test_atomic_inc_dec),
	ODP_TEST_INFO(atomic_test_atomic_add_sub),
	ODP_TEST_INFO(atomic_test_atomic_fetch_inc_dec),
	ODP_TEST_INFO(atomic_test_atomic_fetch_add_sub),
	ODP_TEST_INFO(synchronizers_test_atomic_max_min),
	ODP_TEST_INFO_NULL,
};

odp_suiteinfo_t atomic_suites[] = {
	{"atomic", NULL, NULL,
		atomic_suite_atomic},
	ODP_SUITE_INFO_NULL
};

int atomic_main(void)
{
	int ret;

	odp_cunit_register_global_init(atomic_init);

	ret = odp_cunit_register(atomic_suites);

	if (ret == 0)
		ret = odp_cunit_run();

	return ret;
}
