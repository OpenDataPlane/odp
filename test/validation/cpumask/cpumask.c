/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp.h>

#include "odp_cunit_common.h"
#include "cpumask.h"
#include "mask_common.h"

/* default worker parameter to get all that may be available */
#define ALL_AVAILABLE 0

void cpumask_test_odp_cpumask_def_control(void)
{
	unsigned num;
	unsigned mask_count;
	unsigned max_cpus = mask_capacity();
	odp_cpumask_t mask;

	num = odp_cpumask_def_control(&mask, ALL_AVAILABLE);
	mask_count = odp_cpumask_count(&mask);

	CU_ASSERT(mask_count == num);
	CU_ASSERT(num > 0);
	CU_ASSERT(num <= max_cpus);
}

void cpumask_test_odp_cpumask_def_worker(void)
{
	unsigned num;
	unsigned mask_count;
	unsigned max_cpus = mask_capacity();
	odp_cpumask_t mask;

	num = odp_cpumask_def_worker(&mask, ALL_AVAILABLE);
	mask_count = odp_cpumask_count(&mask);

	CU_ASSERT(mask_count == num);
	CU_ASSERT(num > 0);
	CU_ASSERT(num <= max_cpus);
}

void cpumask_test_odp_cpumask_def(void)
{
	unsigned mask_count;
	unsigned num_worker;
	unsigned num_control;
	unsigned max_cpus = mask_capacity();
	unsigned available_cpus = odp_cpu_count();
	unsigned requested_cpus;
	odp_cpumask_t mask;

	CU_ASSERT(available_cpus <= max_cpus);

	if (available_cpus > 1)
		requested_cpus = available_cpus - 1;
	else
		requested_cpus = available_cpus;
	num_worker = odp_cpumask_def_worker(&mask, requested_cpus);
	mask_count = odp_cpumask_count(&mask);
	CU_ASSERT(mask_count == num_worker);

	num_control = odp_cpumask_def_control(&mask, 1);
	mask_count = odp_cpumask_count(&mask);
	CU_ASSERT(mask_count == num_control);

	CU_ASSERT(num_control == 1);
	CU_ASSERT(num_worker <= available_cpus);
	CU_ASSERT(num_worker > 0);
}

CU_TestInfo cpumask_suite[] = {
	_CU_TEST_INFO(cpumask_test_odp_cpumask_to_from_str),
	_CU_TEST_INFO(cpumask_test_odp_cpumask_equal),
	_CU_TEST_INFO(cpumask_test_odp_cpumask_zero),
	_CU_TEST_INFO(cpumask_test_odp_cpumask_set),
	_CU_TEST_INFO(cpumask_test_odp_cpumask_clr),
	_CU_TEST_INFO(cpumask_test_odp_cpumask_isset),
	_CU_TEST_INFO(cpumask_test_odp_cpumask_count),
	_CU_TEST_INFO(cpumask_test_odp_cpumask_and),
	_CU_TEST_INFO(cpumask_test_odp_cpumask_or),
	_CU_TEST_INFO(cpumask_test_odp_cpumask_xor),
	_CU_TEST_INFO(cpumask_test_odp_cpumask_copy),
	_CU_TEST_INFO(cpumask_test_odp_cpumask_first),
	_CU_TEST_INFO(cpumask_test_odp_cpumask_last),
	_CU_TEST_INFO(cpumask_test_odp_cpumask_next),
	_CU_TEST_INFO(cpumask_test_odp_cpumask_setall),
	_CU_TEST_INFO(cpumask_test_odp_cpumask_def_control),
	_CU_TEST_INFO(cpumask_test_odp_cpumask_def_worker),
	_CU_TEST_INFO(cpumask_test_odp_cpumask_def),
	CU_TEST_INFO_NULL,
};

CU_SuiteInfo cpumask_suites[] = {
	{"Cpumask", NULL, NULL, NULL, NULL, cpumask_suite},
	CU_SUITE_INFO_NULL,
};

int cpumask_main(void)
{
	return odp_cunit_run(cpumask_suites);
}
