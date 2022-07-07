/* Copyright (c) 2015-2018, Linaro Limited
 * Copyright (c) 2022, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_api.h>
#include <odp/helper/odph_api.h>
#include <odp_cunit_common.h>
#include <mask_common.h>

#define GLOBAL_SHM_NAME		"GlobalThreadTest"

typedef struct {
	/* Test thread entry and exit synchronization barriers */
	odp_barrier_t bar_entry;
	odp_barrier_t bar_exit;

	/* Storage for thread ID assignment order test */
	int thread_id[ODP_THREAD_COUNT_MAX];
} global_shared_mem_t;

static global_shared_mem_t *global_mem;

static int thread_global_init(odp_instance_t *inst)
{
	odp_shm_t global_shm;
	odp_init_t init_param;
	odph_helper_options_t helper_options;

	if (odph_options(&helper_options)) {
		fprintf(stderr, "error: odph_options() failed.\n");
		return -1;
	}

	odp_init_param_init(&init_param);
	init_param.mem_model = helper_options.mem_model;

	if (0 != odp_init_global(inst, &init_param, NULL)) {
		fprintf(stderr, "error: odp_init_global() failed.\n");
		return -1;
	}
	if (0 != odp_init_local(*inst, ODP_THREAD_CONTROL)) {
		fprintf(stderr, "error: odp_init_local() failed.\n");
		return -1;
	}

	global_shm = odp_shm_reserve(GLOBAL_SHM_NAME,
				     sizeof(global_shared_mem_t),
				     ODP_CACHE_LINE_SIZE, 0);
	if (global_shm == ODP_SHM_INVALID) {
		fprintf(stderr, "Unable reserve memory for global_shm\n");
		return -1;
	}

	global_mem = odp_shm_addr(global_shm);
	memset(global_mem, 0, sizeof(global_shared_mem_t));

	return 0;
}

static int thread_global_term(odp_instance_t inst)
{
	odp_shm_t shm;

	shm = odp_shm_lookup(GLOBAL_SHM_NAME);
	if (0 != odp_shm_free(shm)) {
		fprintf(stderr, "error: odp_shm_free() failed.\n");
		return -1;
	}

	if (0 != odp_term_local()) {
		fprintf(stderr, "error: odp_term_local() failed.\n");
		return -1;
	}

	if (0 != odp_term_global(inst)) {
		fprintf(stderr, "error: odp_term_global() failed.\n");
		return -1;
	}

	return 0;
}

static void thread_test_odp_cpu_id(void)
{
	CU_ASSERT(odp_cpu_id() >= 0);
}

static void thread_test_odp_thread_id(void)
{
	int id = odp_thread_id();

	/* First thread which called odp_init_local() */
	CU_ASSERT(id == 0);

	CU_ASSERT(id >= 0);
	CU_ASSERT(id < odp_thread_count_max());
	CU_ASSERT(id < ODP_THREAD_COUNT_MAX);
}

static void thread_test_odp_thread_count(void)
{
	int count = odp_thread_count();

	/* One thread running */
	CU_ASSERT(count == 1);

	CU_ASSERT(count >= 1);
	CU_ASSERT(count <= odp_thread_count_max());
	CU_ASSERT(count <= ODP_THREAD_COUNT_MAX);
	CU_ASSERT(odp_thread_count_max() <= ODP_THREAD_COUNT_MAX);
}

static int thread_func(void *arg)
{
	int *id_ptr = arg;

	/* Indicate that thread has started */
	odp_barrier_wait(&global_mem->bar_entry);

	/* Record thread identifier for ID assignment order check */
	*id_ptr = odp_thread_id();

	CU_ASSERT(*id_ptr > 0);
	CU_ASSERT(*id_ptr < odp_thread_count_max());

	CU_ASSERT(odp_thread_type() == ODP_THREAD_WORKER);

	/* Wait for indication that we can exit */
	odp_barrier_wait(&global_mem->bar_exit);

	return CU_get_number_of_failures();
}

static void thread_test_odp_thrmask_worker(void)
{
	odp_thrmask_t mask;
	int ret;
	int num = odp_cpumask_default_worker(NULL, 0);

	CU_ASSERT_FATAL(num > 0);
	CU_ASSERT_FATAL(odp_thread_type() == ODP_THREAD_CONTROL);

	/* Control and worker threads may share CPUs */
	if (num > 1)
		num--;

	void *args[num];

	for (int i = 0; i < num; i++) {
		global_mem->thread_id[i] = -1;
		args[i] = &global_mem->thread_id[i];
	}

	odp_barrier_init(&global_mem->bar_entry, num + 1);
	odp_barrier_init(&global_mem->bar_exit,  num + 1);

	/* should start out with 0 worker threads */
	ret = odp_thrmask_worker(&mask);
	CU_ASSERT(ret == odp_thrmask_count(&mask));
	CU_ASSERT(ret == 0);

	/* start the test thread(s) */
	ret = odp_cunit_thread_create(num, thread_func, args, 1, 1);
	CU_ASSERT(ret == num);

	if (ret != num)
		return;

	/* wait for thread(s) to start */
	odp_barrier_wait(&global_mem->bar_entry);

	ret = odp_thrmask_worker(&mask);
	CU_ASSERT(ret == odp_thrmask_count(&mask));
	CU_ASSERT(ret == num);
	CU_ASSERT(ret <= odp_thread_count_max());

	/* allow thread(s) to exit */
	odp_barrier_wait(&global_mem->bar_exit);

	/* Thread ID 0 is used by this control thread */
	for (int i = 0; i < num; i++)
		CU_ASSERT(global_mem->thread_id[i] == i + 1);

	odp_cunit_thread_join(num);
}

static void thread_test_odp_thrmask_control(void)
{
	odp_thrmask_t mask;
	int ret;

	CU_ASSERT(odp_thread_type() == ODP_THREAD_CONTROL);

	/* should start out with 1 worker thread */
	ret = odp_thrmask_control(&mask);
	CU_ASSERT(ret == odp_thrmask_count(&mask));
	CU_ASSERT(ret == 1);
}

odp_testinfo_t thread_suite[] = {
	ODP_TEST_INFO(thread_test_odp_cpu_id),
	ODP_TEST_INFO(thread_test_odp_thread_id),
	ODP_TEST_INFO(thread_test_odp_thread_count),
	ODP_TEST_INFO(thread_test_odp_thrmask_to_from_str),
	ODP_TEST_INFO(thread_test_odp_thrmask_equal),
	ODP_TEST_INFO(thread_test_odp_thrmask_zero),
	ODP_TEST_INFO(thread_test_odp_thrmask_set),
	ODP_TEST_INFO(thread_test_odp_thrmask_clr),
	ODP_TEST_INFO(thread_test_odp_thrmask_isset),
	ODP_TEST_INFO(thread_test_odp_thrmask_count),
	ODP_TEST_INFO(thread_test_odp_thrmask_and),
	ODP_TEST_INFO(thread_test_odp_thrmask_or),
	ODP_TEST_INFO(thread_test_odp_thrmask_xor),
	ODP_TEST_INFO(thread_test_odp_thrmask_copy),
	ODP_TEST_INFO(thread_test_odp_thrmask_first),
	ODP_TEST_INFO(thread_test_odp_thrmask_last),
	ODP_TEST_INFO(thread_test_odp_thrmask_next),
	ODP_TEST_INFO(thread_test_odp_thrmask_worker),
	ODP_TEST_INFO(thread_test_odp_thrmask_control),
	ODP_TEST_INFO_NULL,
};

odp_suiteinfo_t thread_suites[] = {
	{"thread", NULL, NULL, thread_suite},
	ODP_SUITE_INFO_NULL,
};

int main(int argc, char *argv[])
{
	int ret;

	/* parse common options: */
	if (odp_cunit_parse_options(argc, argv))
		return -1;

	odp_cunit_register_global_init(thread_global_init);
	odp_cunit_register_global_term(thread_global_term);

	ret = odp_cunit_register(thread_suites);

	if (ret == 0)
		ret = odp_cunit_run();

	return ret;
}
