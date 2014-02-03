/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <string.h>
#include <sys/time.h>
#include <odp_debug.h>
#include "odp_common.h"
#include "odp_atomic_test.h"

struct timeval tv0[MAX_WORKERS], tv1[MAX_WORKERS];

static void usage(void)
{
	printf("\n./odp_atomic -t <testcase> -n <num of pthread>,\n\n"
	"\t<testcase> is\n"
		"\t\t1 - Test mix(does inc,dec,add,sub on 32/64 bit)\n"
		"\t\t2 - Test inc dec of signed word\n"
		"\t\t3 - Test add sub of signed word\n"
		"\t\t4 - Test inc dec of unsigned word\n"
		"\t\t5 - Test add sub of unsigned word\n"
		"\t\t6 - Test inc dec of double word\n"
		"\t\t7 - Test add sub of double word\n"
	"\t<num of pthread> is optional\n"
		"\t\t<1 - 31> - no of pthreads to start\n"
		"\t\tif user doesn't specify this option, then\n"
		"\t\tno of pthreads created is equivalent to no of cores\n"
		"\t\tavailable in the system\n"
	"\tExample usage:\n"
	"\t\t./odp_atomic -t 2\n"
	"\t\t./odp_atomic -t 3 -n 12\n");
}

void test_atomic_inc_32(void)
{
	int i;

	for (i = 0; i < CNT; i++)
		odp_atomic_inc_int(&a32);
}

void test_atomic_inc_u32(void)
{
	int i;

	for (i = 0; i < CNT; i++)
		odp_atomic_inc_u32(&a32u);
}

void test_atomic_inc_64(void)
{
	int i;

	for (i = 0; i < CNT; i++)
		odp_atomic_inc_u64(&a64u);
}

void test_atomic_dec_32(void)
{
	int i;

	for (i = 0; i < CNT; i++)
		odp_atomic_dec_int(&a32);
}

void test_atomic_dec_u32(void)
{
	int i;

	for (i = 0; i < CNT; i++)
		odp_atomic_dec_u32(&a32u);
}

void test_atomic_dec_64(void)
{
	int i;

	for (i = 0; i < CNT; i++)
		odp_atomic_dec_u64(&a64u);
}

void test_atomic_add_32(void)
{
	int i;

	for (i = 0; i < (CNT / ADD_SUB_CNT); i++)
		odp_atomic_fetch_add_int(&a32, ADD_SUB_CNT);
}

void test_atomic_add_u32(void)
{
	int i;

	for (i = 0; i < (CNT / ADD_SUB_CNT); i++)
		odp_atomic_fetch_add_u32(&a32u, ADD_SUB_CNT);
}

void test_atomic_add_64(void)
{
	int i;

	for (i = 0; i < (CNT / ADD_SUB_CNT); i++)
		odp_atomic_fetch_add_u64(&a64u, ADD_SUB_CNT);
}

void test_atomic_sub_32(void)
{
	int i;

	for (i = 0; i < (CNT / ADD_SUB_CNT); i++)
		odp_atomic_fetch_sub_int(&a32, ADD_SUB_CNT);
}

void test_atomic_sub_u32(void)
{
	int i;

	for (i = 0; i < (CNT / ADD_SUB_CNT); i++)
		odp_atomic_fetch_sub_u32(&a32u, ADD_SUB_CNT);
}

void test_atomic_sub_64(void)
{
	int i;

	for (i = 0; i < (CNT / ADD_SUB_CNT); i++)
		odp_atomic_fetch_sub_u64(&a64u, ADD_SUB_CNT);
}

void test_atomic_inc_dec_32(void)
{
	test_atomic_inc_32();
	test_atomic_dec_32();
}

void test_atomic_add_sub_32(void)
{
	test_atomic_add_32();
	test_atomic_sub_32();
}

void test_atomic_inc_dec_u32(void)
{
	test_atomic_inc_u32();
	test_atomic_dec_u32();
}

void test_atomic_add_sub_u32(void)
{
	test_atomic_add_u32();
	test_atomic_sub_u32();
}

void test_atomic_inc_dec_64(void)
{
	test_atomic_inc_64();
	test_atomic_dec_64();
}

void test_atomic_add_sub_64(void)
{
	test_atomic_add_64();
	test_atomic_sub_64();
}

/**
 * Test basic atomic operation like
 * add/sub/increment/decrement operation.
 */
void test_atomic_basic(void)
{
	test_atomic_inc_32();
	test_atomic_dec_32();
	test_atomic_add_32();
	test_atomic_sub_32();

	test_atomic_inc_u32();
	test_atomic_dec_u32();
	test_atomic_add_u32();
	test_atomic_sub_u32();

	test_atomic_inc_64();
	test_atomic_dec_64();
	test_atomic_add_64();
	test_atomic_sub_64();
}

void test_atomic_init(void)
{
	odp_atomic_init_int(&a32);
	odp_atomic_init_u32(&a32u);
	odp_atomic_init_u64(&a64u);
}

void test_atomic_store(void)
{
	odp_atomic_store_int(&a32, S32_INIT_VAL);
	odp_atomic_store_u32(&a32u, U32_INIT_VAL);
	odp_atomic_store_u64(&a64u, U64_INIT_VAL);
}

int test_atomic_validate(void)
{
	if (odp_atomic_load_int(&a32) != S32_INIT_VAL) {
		ODP_ERR("Atomic signed 32 usual functions failed\n");
		return -1;
	}

	if (odp_atomic_load_u32(&a32u) != U32_INIT_VAL) {
		ODP_ERR("Atomic u32 usual functions failed\n");
		return -1;
	}

	if (odp_atomic_load_u64(&a64u) != U64_INIT_VAL) {
		ODP_ERR("Atomic u64 usual functions failed\n");
		return -1;
	}

	ODP_DBG("Validation successful\n");

	return 0;
}

static void *run_thread(void *arg)
{
	pthrd_arg *parg = (pthrd_arg *)arg;
	int thr;

	thr = odp_thread_id();

	ODP_DBG("Thread %i starts\n", thr);

	odp_atomic_inc_int(&numthrds);

	/* Wait here until all pthreads are created */
	while (*(volatile int *)&numthrds < parg->numthrds)
		;

	gettimeofday(&tv0[thr], 0);

	switch (parg->testcase) {
	case TEST_MIX:
		test_atomic_basic();
		break;
	case TEST_INC_DEC_S32:
		test_atomic_inc_dec_32();
		break;
	case TEST_ADD_SUB_S32:
		test_atomic_add_sub_32();
		break;
	case TEST_INC_DEC_U32:
		test_atomic_inc_dec_u32();
		break;
	case TEST_ADD_SUB_U32:
		test_atomic_add_sub_u32();
		break;
	case TEST_INC_DEC_64:
		test_atomic_inc_dec_64();
		break;
	case TEST_ADD_SUB_64:
		test_atomic_add_sub_64();
		break;
	}
	gettimeofday(&tv1[thr], 0);
	fflush(NULL);

	ODP_DBG("Time taken in thread %02d to complete op is %lld usec\n", thr,
		(tv1[thr].tv_sec - tv0[thr].tv_sec) * 1000000ULL +
		(tv1[thr].tv_usec - tv0[thr].tv_usec));

	return parg;
}

int main(int argc, char *argv[])
{
	pthrd_arg thrdarg;
	int test_type, pthrdnum = 0, i = 0, cnt = argc - 1;
	char c;

	if (argc == 1 || argc % 2 == 0) {
		usage();
		goto err_exit;
	}
	if (odp_test_global_init() != 0)
		goto err_exit;
	odp_print_system_info();

	while (cnt != 0) {
		sscanf(argv[++i], "-%c", &c);
		switch (c) {
		case 't':
			sscanf(argv[++i], "%d", &test_type);
			break;
		case 'n':
			sscanf(argv[++i], "%d", &pthrdnum);
			break;
		default:
			ODP_ERR("Invalid option %c\n", c);
			usage();
			goto err_exit;
		}
		if (test_type < TEST_MIX || test_type > TEST_MAX ||
		    pthrdnum > odp_sys_core_count()) {
			usage();
			goto err_exit;
		}
		cnt -= 2;
	}
	if (pthrdnum == 0)
		pthrdnum = odp_sys_core_count();

	odp_atomic_init_int(&numthrds);
	test_atomic_init();
	test_atomic_store();

	memset(&thrdarg, 0, sizeof(pthrd_arg));
	thrdarg.testcase = test_type;
	thrdarg.numthrds = pthrdnum;
	switch (thrdarg.testcase) {
	case TEST_MIX:
		ODP_DBG("test atomic basic ops add/sub/inc/dec\n");
		break;
	case TEST_INC_DEC_S32:
		ODP_DBG("test atomic inc/dec of signed word\n");
		break;
	case TEST_ADD_SUB_S32:
		ODP_DBG("test atomic add/sub of signed word\n");
		break;
	case TEST_INC_DEC_U32:
		ODP_DBG("test atomic inc/dec of unsigned word\n");
		break;
	case TEST_ADD_SUB_U32:
		ODP_DBG("test atomic add/sub of unsigned word\n");
		break;
	case TEST_INC_DEC_64:
		ODP_DBG("test atomic inc/dec of unsigned double word\n");
		break;
	case TEST_ADD_SUB_64:
		ODP_DBG("test atomic add/sub of unsigned double word\n");
		break;
	default:
		ODP_ERR("Invalid test case [%d]\n", test_type);
		goto err_exit;
	}
	odp_test_thread_create(run_thread, &thrdarg);

	odp_test_thread_exit(&thrdarg);

	test_atomic_validate();

	return 0;

err_exit:
	return -1;
}
