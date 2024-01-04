/* Copyright (c) 2015-2018, Linaro Limited
 * Copyright (c) 2021-2022, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_api.h>

#include "odp_cunit_common.h"
#include "mask_common.h"

static int cpumask_max_count(void)
{
	odp_cpumask_t mask;

	odp_cpumask_setall(&mask);

	return odp_cpumask_count(&mask);
}

static void cpumask_test_odp_cpumask_def_control(void)
{
	odp_cpumask_t mask;
	int num, count, all;
	int max = cpumask_max_count();
	int request = 7;

	CU_ASSERT_FATAL(max > 1);

	if (request > max)
		request = max - 1;

	all = odp_cpumask_default_control(&mask, 0);
	num = all;
	count = odp_cpumask_count(&mask);

	CU_ASSERT(num > 0);
	CU_ASSERT(num == count);
	CU_ASSERT(num <= max);

	num = odp_cpumask_default_control(&mask, max);
	count = odp_cpumask_count(&mask);

	CU_ASSERT(num > 0);
	CU_ASSERT(num == count);
	CU_ASSERT(num <= max);
	CU_ASSERT(num == all);

	num = odp_cpumask_default_control(&mask, 1);
	count = odp_cpumask_count(&mask);

	CU_ASSERT(num == 1);
	CU_ASSERT(num == count);

	num = odp_cpumask_default_control(&mask, request);
	count = odp_cpumask_count(&mask);

	CU_ASSERT(num > 0);
	CU_ASSERT(num <= request);
	CU_ASSERT(num == count);

	CU_ASSERT(odp_cpumask_default_control(NULL, request) == num);
	CU_ASSERT(odp_cpumask_default_control(NULL, 0) == all);
	CU_ASSERT(odp_cpumask_default_control(NULL, 1) == 1);
}

static void cpumask_test_odp_cpumask_def_worker(void)
{
	odp_cpumask_t mask;
	int num, count, all;
	int max = cpumask_max_count();
	int request = 7;

	CU_ASSERT_FATAL(max > 1);

	if (request > max)
		request = max - 1;

	all = odp_cpumask_default_worker(&mask, 0);
	num = all;
	count = odp_cpumask_count(&mask);

	CU_ASSERT(num > 0);
	CU_ASSERT(num == count);
	CU_ASSERT(num <= max);

	num = odp_cpumask_default_worker(&mask, max);
	count = odp_cpumask_count(&mask);

	CU_ASSERT(num > 0);
	CU_ASSERT(num == count);
	CU_ASSERT(num <= max);
	CU_ASSERT(num == all);

	num = odp_cpumask_default_worker(&mask, 1);
	count = odp_cpumask_count(&mask);

	CU_ASSERT(num == 1);
	CU_ASSERT(num == count);

	num = odp_cpumask_default_worker(&mask, request);
	count = odp_cpumask_count(&mask);

	CU_ASSERT(num > 0);
	CU_ASSERT(num <= request);
	CU_ASSERT(num == count);

	CU_ASSERT(odp_cpumask_default_worker(NULL, request) == num);
	CU_ASSERT(odp_cpumask_default_worker(NULL, 0) == all);
	CU_ASSERT(odp_cpumask_default_worker(NULL, 1) == 1);
}

static void cpumask_test_odp_cpumask_def(void)
{
	odp_cpumask_t mask, all_mask, overlap;
	int count, all, num_worker, num_control, request;
	int max = cpumask_max_count();
	int cpu_count = odp_cpu_count();

	all = odp_cpumask_all_available(&all_mask);
	count = odp_cpumask_count(&all_mask);

	CU_ASSERT_FATAL(cpu_count > 0);
	CU_ASSERT_FATAL(all > 0);
	CU_ASSERT(all == cpu_count);
	CU_ASSERT(all <= max);
	CU_ASSERT(all == count);

	request = all - 1;
	if (request == 0)
		request = 1;

	num_worker = odp_cpumask_default_worker(&mask, request);
	count = odp_cpumask_count(&mask);
	CU_ASSERT(num_worker > 0);
	CU_ASSERT(num_worker <= request);
	CU_ASSERT(num_worker == count);

	/* Check that CPUs are in the all CPUs mask */
	odp_cpumask_zero(&overlap);
	odp_cpumask_and(&overlap, &mask, &all_mask);
	CU_ASSERT(odp_cpumask_count(&overlap) == num_worker);

	num_control = odp_cpumask_default_control(&mask, 1);
	count = odp_cpumask_count(&mask);
	CU_ASSERT(num_control == 1);
	CU_ASSERT(num_control == count);

	odp_cpumask_zero(&overlap);
	odp_cpumask_and(&overlap, &mask, &all_mask);
	CU_ASSERT(odp_cpumask_count(&overlap) == num_control);

	CU_ASSERT(odp_cpumask_default_worker(NULL, request) == num_worker);
	CU_ASSERT(odp_cpumask_default_worker(NULL, 0) <= all);
	CU_ASSERT(odp_cpumask_default_control(NULL, 0) <= all);
}

odp_testinfo_t cpumask_suite[] = {
	ODP_TEST_INFO(cpumask_test_odp_cpumask_to_from_str),
	ODP_TEST_INFO(cpumask_test_odp_cpumask_equal),
	ODP_TEST_INFO(cpumask_test_odp_cpumask_zero),
	ODP_TEST_INFO(cpumask_test_odp_cpumask_set),
	ODP_TEST_INFO(cpumask_test_odp_cpumask_clr),
	ODP_TEST_INFO(cpumask_test_odp_cpumask_isset),
	ODP_TEST_INFO(cpumask_test_odp_cpumask_count),
	ODP_TEST_INFO(cpumask_test_odp_cpumask_and),
	ODP_TEST_INFO(cpumask_test_odp_cpumask_or),
	ODP_TEST_INFO(cpumask_test_odp_cpumask_xor),
	ODP_TEST_INFO(cpumask_test_odp_cpumask_copy),
	ODP_TEST_INFO(cpumask_test_odp_cpumask_first),
	ODP_TEST_INFO(cpumask_test_odp_cpumask_last),
	ODP_TEST_INFO(cpumask_test_odp_cpumask_next),
	ODP_TEST_INFO(cpumask_test_odp_cpumask_setall),
	ODP_TEST_INFO(cpumask_test_odp_cpumask_def_control),
	ODP_TEST_INFO(cpumask_test_odp_cpumask_def_worker),
	ODP_TEST_INFO(cpumask_test_odp_cpumask_def),
	ODP_TEST_INFO_NULL,
};

odp_suiteinfo_t cpumask_suites[] = {
	{"Cpumask", NULL, NULL, cpumask_suite},
	ODP_SUITE_INFO_NULL,
};

int main(int argc, char *argv[])
{
	int ret;

	/* parse common options: */
	if (odp_cunit_parse_options(&argc, argv))
		return -1;

	ret = odp_cunit_register(cpumask_suites);

	if (ret == 0)
		ret = odp_cunit_run();

	return ret;
}
