/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2025 Nokia
 */

#include <odp_api.h>
#include <odp/helper/odph_api.h>

#include "odp_cunit_common.h"

static struct {
	const uint32_t num_groups;
	int min_prio;
	const uint32_t num_prios;
	int min_g_prio;
	uint32_t num_g_prios;
	odp_bool_t are_groups_constrained;
	odp_bool_t are_prios_constrained;
} test_info = { 4U, 0, 2U, 0, 0U, false, false };

static int are_groups_constrained(void)
{
	return test_info.are_groups_constrained ? ODP_TEST_ACTIVE : ODP_TEST_INACTIVE;
}

static void schedule_config_limits_max_groups(void)
{
	odp_thrmask_t mask;
	odp_schedule_group_t group1, group2;

	odp_thrmask_zero(&mask);
	odp_thrmask_set(&mask, odp_thread_id());
	group1 = odp_schedule_group_create(NULL, &mask);

	CU_ASSERT_FATAL(group1 != ODP_SCHED_GROUP_INVALID);

	group2 = odp_schedule_group_create(NULL, &mask);

	CU_ASSERT_FATAL(group2 == ODP_SCHED_GROUP_INVALID);
	CU_ASSERT_FATAL(odp_schedule_group_destroy(group1) == 0);
}

static int are_prios_constrained(void)
{
	return test_info.are_prios_constrained ? ODP_TEST_ACTIVE : ODP_TEST_INACTIVE;
}

static void check_group_prios(odp_schedule_group_t group)
{
	odp_schedule_group_info_t info;

	CU_ASSERT_FATAL(odp_schedule_group_info(group, &info) == 0);
	CU_ASSERT(info.num == (int)test_info.num_g_prios);

	for (int i = 0; i < info.num; ++i)
		CU_ASSERT(info.level[i] == test_info.min_g_prio + i);
}

static void schedule_config_limits_max_prios(void)
{
	const int min_prio = odp_schedule_min_prio(), max_prio = odp_schedule_max_prio(),
	def_prio = odp_schedule_default_prio(), num_prio = odp_schedule_num_prio();

	CU_ASSERT(num_prio == (int)test_info.num_prios);
	CU_ASSERT(min_prio == test_info.min_prio);
	CU_ASSERT(max_prio == min_prio + num_prio - 1);
	CU_ASSERT(def_prio >= min_prio && def_prio <= max_prio);

	check_group_prios(ODP_SCHED_GROUP_ALL);
	check_group_prios(ODP_SCHED_GROUP_WORKER);
	check_group_prios(ODP_SCHED_GROUP_CONTROL);
}

static void schedule_group_param_limits_group_prios(void)
{
	odp_thrmask_t mask;
	odp_schedule_group_param_t param;
	odp_schedule_group_t group;

	odp_thrmask_zero(&mask);
	odp_thrmask_set(&mask, odp_thread_id());
	odp_schedule_group_param_init(&param);

	for (uint32_t i = 0U; i < test_info.num_g_prios; ++i)
		param.prio.level[i] = test_info.min_g_prio + i;

	param.prio.num = test_info.num_g_prios;
	group = odp_schedule_group_create_2(NULL, &mask, &param);

	CU_ASSERT_FATAL(group != ODP_SCHED_GROUP_INVALID);

	check_group_prios(group);

	CU_ASSERT_FATAL(odp_schedule_group_destroy(group) == 0);
}

static int suite_init(void)
{
	odp_schedule_capability_t capa;
	odp_schedule_config_t config;

	if (odp_schedule_capability(&capa) < 0) {
		ODPH_ERR("Scheduler capability query failed\n");
		return -1;
	}

	odp_schedule_config_init(&config);

	/* Group count will be limited if it is feasible to limit it. */
	if (config.num_groups > test_info.num_groups) {
		config.num_groups = test_info.num_groups;
		test_info.are_groups_constrained = true;
	}

	/* Prio count will be limited if it is feasible to limit it. */
	if (config.prio.num > test_info.num_prios) {
		config.prio.num = test_info.num_prios;
		test_info.min_prio = capa.min_prio + 1;
		config.prio.min = test_info.min_prio;
		test_info.min_g_prio = test_info.min_prio + 1;
		test_info.num_g_prios = test_info.num_prios - 1;
		test_info.are_prios_constrained = true;
	}

	if (test_info.are_prios_constrained) {
		for (uint32_t i = 0U; i < test_info.num_g_prios; ++i)
			config.sched_group.all_param.prio.level[i] = test_info.min_g_prio + i;

		config.sched_group.all_param.prio.num = test_info.num_g_prios;

		for (uint32_t i = 0U; i < test_info.num_g_prios; ++i)
			config.sched_group.worker_param.prio.level[i] = test_info.min_g_prio + i;

		config.sched_group.worker_param.prio.num = test_info.num_g_prios;

		for (uint32_t i = 0U; i < test_info.num_g_prios; ++i)
			config.sched_group.control_param.prio.level[i] = test_info.min_g_prio + i;

		config.sched_group.control_param.prio.num = test_info.num_g_prios;
	}

	if (odp_schedule_config(&config) < 0) {
		ODPH_ERR("Scheduler configuration failed\n");
		return -1;
	}

	return 0;
}

static int suite_term(void)
{
	return odp_cunit_print_inactive();
}

odp_testinfo_t suite[] = {
	ODP_TEST_INFO_CONDITIONAL(schedule_config_limits_max_groups, are_groups_constrained),
	ODP_TEST_INFO_CONDITIONAL(schedule_config_limits_max_prios, are_prios_constrained),
	ODP_TEST_INFO_CONDITIONAL(schedule_group_param_limits_group_prios, are_prios_constrained),
	ODP_TEST_INFO_NULL,
};

odp_suiteinfo_t suites[] = {
	{ "Scheduler group and prio config", suite_init, suite_term, suite },
	ODP_SUITE_INFO_NULL,
};

static int global_init(odp_instance_t *inst)
{
	odp_init_t init_param;
	odph_helper_options_t helper_options;

	if (odph_options(&helper_options) == -1) {
		ODPH_ERR("Helper option parsing failed\n");
		return -1;
	}

	odp_init_param_init(&init_param);
	init_param.mem_model = helper_options.mem_model;

	if (odp_init_global(inst, &init_param, NULL)) {
		ODPH_ERR("ODP global initialization failed\n");
		return -1;
	}

	if (odp_init_local(*inst, ODP_THREAD_CONTROL)) {
		ODPH_ERR("ODP local initialization failed\n");
		return -1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	int ret;

	if (odp_cunit_parse_options(&argc, argv))
		return -1;

	odp_cunit_register_global_init(global_init);
	ret = odp_cunit_register(suites);

	if (ret == 0)
		ret = odp_cunit_run();

	return ret;
}
