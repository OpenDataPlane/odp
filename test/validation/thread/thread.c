/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp.h>
#include <odp_cunit_common.h>
#include <mask_common.h>
#include <test_debug.h>
#include "thread.h"

/* Helper macro for CU_TestInfo initialization */
#define _CU_TEST_INFO(test_func) {#test_func, test_func}

/* Test thread entry and exit synchronization barriers */
odp_barrier_t bar_entry;
odp_barrier_t bar_exit;

void thread_test_odp_cpu_id(void)
{
	(void)odp_cpu_id();
	CU_PASS();
}

void thread_test_odp_thread_id(void)
{
	(void)odp_thread_id();
	CU_PASS();
}

void thread_test_odp_thread_count(void)
{
	(void)odp_thread_count();
	CU_PASS();
}

static void *thread_func(void *arg TEST_UNUSED)
{
	/* indicate that thread has started */
	odp_barrier_wait(&bar_entry);

	CU_ASSERT(odp_thread_type() == ODP_THREAD_WORKER);

	/* wait for indication that we can exit */
	odp_barrier_wait(&bar_exit);

	return NULL;
}

void thread_test_odp_thrmask_worker(void)
{
	odp_thrmask_t mask;
	int ret;
	pthrd_arg args = { .testcase = 0, .numthrds = 1 };

	CU_ASSERT_FATAL(odp_thread_type() == ODP_THREAD_CONTROL);

	odp_barrier_init(&bar_entry, args.numthrds + 1);
	odp_barrier_init(&bar_exit,  args.numthrds + 1);

	/* should start out with 0 worker threads */
	ret = odp_thrmask_worker(&mask);
	CU_ASSERT(ret == odp_thrmask_count(&mask));
	CU_ASSERT(ret == 0);

	/* start the test thread(s) */
	ret = odp_cunit_thread_create(thread_func, &args);
	CU_ASSERT(ret == args.numthrds);

	if (ret != args.numthrds)
		return;

	/* wait for thread(s) to start */
	odp_barrier_wait(&bar_entry);

	ret = odp_thrmask_worker(&mask);
	CU_ASSERT(ret == odp_thrmask_count(&mask));
	CU_ASSERT(ret == args.numthrds);
	CU_ASSERT(ret <= ODP_CONFIG_MAX_THREADS);

	/* allow thread(s) to exit */
	odp_barrier_wait(&bar_exit);

	odp_cunit_thread_exit(&args);
}

void thread_test_odp_thrmask_control(void)
{
	odp_thrmask_t mask;
	int ret;

	CU_ASSERT(odp_thread_type() == ODP_THREAD_CONTROL);

	/* should start out with 1 worker thread */
	ret = odp_thrmask_control(&mask);
	CU_ASSERT(ret == odp_thrmask_count(&mask));
	CU_ASSERT(ret == 1);
}

CU_TestInfo thread_suite[] = {
	_CU_TEST_INFO(thread_test_odp_cpu_id),
	_CU_TEST_INFO(thread_test_odp_thread_id),
	_CU_TEST_INFO(thread_test_odp_thread_count),
	_CU_TEST_INFO(thread_test_odp_thrmask_to_from_str),
	_CU_TEST_INFO(thread_test_odp_thrmask_equal),
	_CU_TEST_INFO(thread_test_odp_thrmask_zero),
	_CU_TEST_INFO(thread_test_odp_thrmask_set),
	_CU_TEST_INFO(thread_test_odp_thrmask_clr),
	_CU_TEST_INFO(thread_test_odp_thrmask_isset),
	_CU_TEST_INFO(thread_test_odp_thrmask_count),
	_CU_TEST_INFO(thread_test_odp_thrmask_and),
	_CU_TEST_INFO(thread_test_odp_thrmask_or),
	_CU_TEST_INFO(thread_test_odp_thrmask_xor),
	_CU_TEST_INFO(thread_test_odp_thrmask_copy),
	_CU_TEST_INFO(thread_test_odp_thrmask_first),
	_CU_TEST_INFO(thread_test_odp_thrmask_last),
	_CU_TEST_INFO(thread_test_odp_thrmask_next),
	_CU_TEST_INFO(thread_test_odp_thrmask_worker),
	_CU_TEST_INFO(thread_test_odp_thrmask_control),
	CU_TEST_INFO_NULL,
};

CU_SuiteInfo thread_suites[] = {
	{"thread", NULL, NULL, NULL, NULL, thread_suite},
	CU_SUITE_INFO_NULL,
};

int thread_main(void)
{
	return odp_cunit_run(thread_suites);
}
