/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_debug.h>
#include "odp_common.h"
#include "odp_atomic_test.h"

/**
 * add_sub_cnt could be any valid value
 * so to excercise explicit atomic_add/sub
 * ops. For now using 5..
 */
#define ADD_SUB_CNT	5

/**
 * Test basic atomic operation like
 * add/sub/increment/decrement operation.
 */
void test_atomic_basic(void)
{
	unsigned int i;

	for (i = 0; i < CNT; i++)
		odp_atomic_inc_int(&a16);
	for (i = 0; i < CNT; i++)
		odp_atomic_dec_int(&a16);
	for (i = 0; i < (CNT / ADD_SUB_CNT); i++)
		odp_atomic_fetch_add_int(&a16, ADD_SUB_CNT);
	for (i = 0; i < (CNT / ADD_SUB_CNT); i++)
		odp_atomic_fetch_sub_int(&a16, ADD_SUB_CNT);

	for (i = 0; i < CNT; i++)
		odp_atomic_inc_u32(&a32);
	for (i = 0; i < CNT; i++)
		odp_atomic_dec_u32(&a32);
	for (i = 0; i < (CNT / ADD_SUB_CNT); i++)
		odp_atomic_fetch_add_u32(&a32, ADD_SUB_CNT);
	for (i = 0; i < (CNT / ADD_SUB_CNT); i++)
		odp_atomic_fetch_sub_u32(&a32, ADD_SUB_CNT);

	for (i = 0; i < CNT; i++)
		odp_atomic_inc_u64(&a64);
	for (i = 0; i < CNT; i++)
		odp_atomic_dec_u64(&a64);
	for (i = 0; i < (CNT / ADD_SUB_CNT); i++)
		odp_atomic_fetch_add_u64(&a64, ADD_SUB_CNT);
	for (i = 0; i < (CNT / ADD_SUB_CNT); i++)
		odp_atomic_fetch_sub_u64(&a64, ADD_SUB_CNT);
}

void test_atomic_init(void)
{
	odp_atomic_init_int(&a16);
	odp_atomic_init_u32(&a32);
	odp_atomic_init_u64(&a64);
}

void test_atomic_store(void)
{
	odp_atomic_store_int(&a16, 1UL << 10);
	odp_atomic_store_u32(&a32, 1UL << 10);
	odp_atomic_store_u64(&a64, 1ULL << 33);
}

int test_atomic_validate(void)
{
	if (odp_atomic_load_int(&a16) != 1UL << 10) {
		ODP_ERR("Atomic int usual functions failed\n");
		return -1;
	}

	if (odp_atomic_load_u32(&a32) != 1UL << 10) {
		ODP_ERR("Atomic u32 usual functions failed\n");
		return -1;
	}

	if (odp_atomic_load_u64(&a64) != 1ULL << 33) {
		ODP_ERR("Atomic u64 usual functions failed\n");
		return -1;
	}

	printf("Validation successful\n");

	return 0;
}

static void *run_thread(void *arg)
{
	pthrd_arg *parg = (pthrd_arg *)arg;
	int thr;

	thr = odp_thread_id();

	printf("Thread %i starts\n", thr);

	switch (parg->testcase) {
	case ODP_ATOMIC_TEST:
		printf("test atomic basic ops add/sub/inc/dec\n");
		test_atomic_basic();
		break;
	default:
		ODP_ERR("Invalid test case [%d]\n", parg->testcase);
	}
	fflush(NULL);

	return parg;
}

int main(int argc ODP_UNUSED, char *argv[] ODP_UNUSED)
{
	pthrd_arg thrdarg;

	if (odp_test_global_init() != 0)
		return -1;
	odp_print_system_info();

	test_atomic_init();
	test_atomic_store();

	thrdarg.testcase = ODP_ATOMIC_TEST;
	odp_test_thread_create(run_thread, &thrdarg);

	odp_test_thread_exit();

	test_atomic_validate();

	return 0;
}
