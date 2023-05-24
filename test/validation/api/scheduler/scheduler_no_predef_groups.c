/* Copyright (c) 2013-2018, Linaro Limited
 * Copyright (c) 2019-2021, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_api.h>
#include "odp_cunit_common.h"
#include <odp/helper/odph_api.h>

static int drain_queues(void)
{
	odp_event_t ev;
	uint64_t wait = odp_schedule_wait_time(100 * ODP_TIME_MSEC_IN_NS);
	int ret = 0;

	while ((ev = odp_schedule(NULL, wait)) != ODP_EVENT_INVALID) {
		odp_event_free(ev);
		ret++;
	}

	return ret;
}

static void scheduler_test_create_group(void)
{
	odp_thrmask_t mask;
	odp_schedule_group_t group;
	int thr_id;
	odp_pool_t pool;
	odp_pool_param_t pool_params;
	odp_queue_t queue, from;
	odp_queue_param_t qp;
	odp_buffer_t buf;
	odp_event_t ev;
	uint64_t wait_time;

	thr_id = odp_thread_id();
	odp_thrmask_zero(&mask);
	odp_thrmask_set(&mask, thr_id);

	group = odp_schedule_group_create("create_group", &mask);
	CU_ASSERT_FATAL(group != ODP_SCHED_GROUP_INVALID);

	odp_pool_param_init(&pool_params);
	pool_params.buf.size  = 100;
	pool_params.buf.num   = 2;
	pool_params.type      = ODP_POOL_BUFFER;

	pool = odp_pool_create("create_group", &pool_params);
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	odp_queue_param_init(&qp);
	qp.type        = ODP_QUEUE_TYPE_SCHED;
	qp.sched.prio  = odp_schedule_default_prio();
	qp.sched.sync  = ODP_SCHED_SYNC_ATOMIC;
	qp.sched.group = group;

	queue = odp_queue_create("create_group", &qp);
	CU_ASSERT_FATAL(queue != ODP_QUEUE_INVALID);

	buf = odp_buffer_alloc(pool);
	CU_ASSERT_FATAL(buf != ODP_BUFFER_INVALID);

	ev = odp_buffer_to_event(buf);

	CU_ASSERT_FATAL(odp_queue_enq(queue, ev) == 0);

	wait_time = odp_schedule_wait_time(100 * ODP_TIME_MSEC_IN_NS);
	ev = odp_schedule(&from, wait_time);

	CU_ASSERT(ev != ODP_EVENT_INVALID);
	CU_ASSERT(from == queue);

	if (ev != ODP_EVENT_INVALID)
		odp_event_free(ev);

	/* Free schedule context */
	drain_queues();

	CU_ASSERT_FATAL(odp_queue_destroy(queue) == 0);
	CU_ASSERT_FATAL(odp_pool_destroy(pool) == 0);
	CU_ASSERT_FATAL(odp_schedule_group_destroy(group) == 0);

	/* Run scheduler after the group has been destroyed */
	CU_ASSERT_FATAL(odp_schedule(NULL, wait_time) == ODP_EVENT_INVALID);
}

static void scheduler_test_create_max_groups(void)
{
	odp_thrmask_t mask;
	int thr_id;
	uint32_t i;
	odp_queue_param_t queue_param;
	odp_schedule_capability_t sched_capa;

	CU_ASSERT_FATAL(!odp_schedule_capability(&sched_capa));
	uint32_t max_groups = sched_capa.max_groups;
	odp_schedule_group_t group[max_groups];
	odp_queue_t queue[max_groups];

	CU_ASSERT_FATAL(max_groups > 0);
	CU_ASSERT_FATAL(sched_capa.max_queues >= sched_capa.max_groups);

	thr_id = odp_thread_id();
	odp_thrmask_zero(&mask);
	odp_thrmask_set(&mask, thr_id);

	odp_queue_param_init(&queue_param);
	queue_param.type       = ODP_QUEUE_TYPE_SCHED;
	queue_param.sched.prio = odp_schedule_default_prio();
	queue_param.sched.sync = ODP_SCHED_SYNC_ATOMIC;

	for (i = 0; i < max_groups; i++) {
		group[i] = odp_schedule_group_create("max_groups", &mask);
		if (group[i] == ODP_SCHED_GROUP_INVALID) {
			ODPH_ERR("schedule group create %u failed\n", i);
			break;
		}

		queue_param.sched.group = group[i];
		queue[i] = odp_queue_create("max_groups", &queue_param);
		CU_ASSERT_FATAL(queue[i] != ODP_QUEUE_INVALID);
	}

	CU_ASSERT(i == max_groups);
	max_groups = i;

	for (i = 0; i < max_groups; i++) {
		CU_ASSERT_FATAL(odp_queue_destroy(queue[i]) == 0);
		CU_ASSERT_FATAL(odp_schedule_group_destroy(group[i]) == 0);
	}
}

static int scheduler_suite_init(void)
{
	odp_schedule_capability_t sched_capa;
	odp_schedule_config_t sched_config;

	if (odp_schedule_capability(&sched_capa)) {
		ODPH_ERR("odp_schedule_capability() failed\n");
		return -1;
	}

	odp_schedule_config_init(&sched_config);

	/* Disable all predefined groups */
	sched_config.sched_group.all = false;
	sched_config.sched_group.control = false;
	sched_config.sched_group.worker = false;

	/* Configure the scheduler. All test cases share the config. */
	if (odp_schedule_config(&sched_config)) {
		ODPH_ERR("odp_schedule_config() failed\n");
		return -1;
	}

	return 0;
}

static int scheduler_suite_term(void)
{
	if (odp_cunit_print_inactive())
		return -1;

	return 0;
}

/* Default scheduler config */
odp_testinfo_t scheduler_suite[] = {
	ODP_TEST_INFO(scheduler_test_create_group),
	ODP_TEST_INFO(scheduler_test_create_max_groups),
	ODP_TEST_INFO_NULL,
};

odp_suiteinfo_t scheduler_suites[] = {
	{"Scheduler no predefined groups",
	 scheduler_suite_init, scheduler_suite_term, scheduler_suite
	},
	ODP_SUITE_INFO_NULL,
};

static int global_init(odp_instance_t *inst)
{
	odp_init_t init_param;
	odph_helper_options_t helper_options;

	if (odph_options(&helper_options)) {
		ODPH_ERR("odph_options() failed.\n");
		return -1;
	}

	odp_init_param_init(&init_param);
	init_param.mem_model = helper_options.mem_model;

	if (odp_init_global(inst, &init_param, NULL)) {
		ODPH_ERR("odp_init_global() failed.\n");
		return -1;
	}

	if (odp_init_local(*inst, ODP_THREAD_CONTROL)) {
		ODPH_ERR("odp_init_local() failed.\n");
		return -1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	int ret;

	/* parse common options: */
	if (odp_cunit_parse_options(argc, argv))
		return -1;

	odp_cunit_register_global_init(global_init);
	ret = odp_cunit_register(scheduler_suites);

	if (ret == 0)
		ret = odp_cunit_run();

	return ret;
}
