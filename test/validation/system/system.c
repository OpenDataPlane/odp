/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include <ctype.h>
#include <odp.h>
#include <odp/cpumask.h>
#include "odp_cunit_common.h"
#include "test_debug.h"
#include "system.h"

void system_test_odp_version_numbers(void)
{
	int char_ok = 0;
	char version_string[128];
	char *s = version_string;

	strncpy(version_string, odp_version_api_str(),
		sizeof(version_string) - 1);

	while (*s) {
		if (isdigit((int)*s) || (strncmp(s, ".", 1) == 0)) {
			char_ok = 1;
			s++;
		} else {
			char_ok = 0;
			LOG_DBG("\nBAD VERSION=%s\n", version_string);
			break;
		}
	}
	CU_ASSERT(char_ok);
}

void system_test_odp_cpu_count(void)
{
	int cpus;

	cpus = odp_cpu_count();
	CU_ASSERT(0 < cpus);
}

void system_test_odp_sys_cache_line_size(void)
{
	uint64_t cache_size;

	cache_size = odp_sys_cache_line_size();
	CU_ASSERT(0 < cache_size);
	CU_ASSERT(ODP_CACHE_LINE_SIZE == cache_size);
}

void system_test_odp_cpu_model_str(void)
{
	char model[128];

	snprintf(model, 128, "%s", odp_cpu_model_str());
	CU_ASSERT(strlen(model) > 0);
	CU_ASSERT(strlen(model) < 127);
}

void system_test_odp_cpu_model_str_id(void)
{
	char model[128];
	odp_cpumask_t mask;
	int i, num, cpu;

	num = odp_cpumask_all_available(&mask);
	cpu = odp_cpumask_first(&mask);

	for (i = 0; i < num; i++) {
		snprintf(model, 128, "%s", odp_cpu_model_str_id(cpu));
		CU_ASSERT(strlen(model) > 0);
		CU_ASSERT(strlen(model) < 127);
		cpu = odp_cpumask_next(&mask, cpu);
	}
}

void system_test_odp_sys_page_size(void)
{
	uint64_t page;

	page = odp_sys_page_size();
	CU_ASSERT(0 < page);
	CU_ASSERT(ODP_PAGE_SIZE == page);
}

void system_test_odp_sys_huge_page_size(void)
{
	uint64_t page;

	page = odp_sys_huge_page_size();
	CU_ASSERT(0 < page);
}

void system_test_odp_cpu_hz(void)
{
	uint64_t hz;

	hz = odp_cpu_hz();
	CU_ASSERT(0 < hz);
}

void system_test_odp_cpu_hz_id(void)
{
	uint64_t hz;
	odp_cpumask_t mask;
	int i, num, cpu;

	num = odp_cpumask_all_available(&mask);
	cpu = odp_cpumask_first(&mask);

	for (i = 0; i < num; i++) {
		hz = odp_cpu_hz_id(cpu);
		CU_ASSERT(0 < hz);
		cpu = odp_cpumask_next(&mask, cpu);
	}
}

void system_test_odp_cpu_hz_max(void)
{
	uint64_t hz;

	hz = odp_cpu_hz_max();
	CU_ASSERT(0 < hz);
}

void system_test_odp_cpu_hz_max_id(void)
{
	uint64_t hz;
	odp_cpumask_t mask;
	int i, num, cpu;

	num = odp_cpumask_all_available(&mask);
	cpu = odp_cpumask_first(&mask);

	for (i = 0; i < num; i++) {
		hz = odp_cpu_hz_max_id(cpu);
		CU_ASSERT(0 < hz);
		cpu = odp_cpumask_next(&mask, cpu);
	}
}

CU_TestInfo system_suite[] = {
	_CU_TEST_INFO(system_test_odp_version_numbers),
	_CU_TEST_INFO(system_test_odp_cpu_count),
	_CU_TEST_INFO(system_test_odp_sys_cache_line_size),
	_CU_TEST_INFO(system_test_odp_cpu_model_str),
	_CU_TEST_INFO(system_test_odp_cpu_model_str_id),
	_CU_TEST_INFO(system_test_odp_sys_page_size),
	_CU_TEST_INFO(system_test_odp_sys_huge_page_size),
	_CU_TEST_INFO(system_test_odp_cpu_hz),
	_CU_TEST_INFO(system_test_odp_cpu_hz_id),
	_CU_TEST_INFO(system_test_odp_cpu_hz_max),
	_CU_TEST_INFO(system_test_odp_cpu_hz_max_id),
	CU_TEST_INFO_NULL,
};

CU_SuiteInfo system_suites[] = {
	{"System Info", NULL, NULL, NULL, NULL, system_suite},
	CU_SUITE_INFO_NULL,
};

int system_main(void)
{
	return odp_cunit_run(system_suites);
}
