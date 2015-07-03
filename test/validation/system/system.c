/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include <ctype.h>
#include <odp.h>
#include "odp_cunit_common.h"
#include "test_debug.h"

static void test_odp_version_numbers(void)
{
	int char_ok;
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

static void test_odp_cpu_count(void)
{
	int cpus;

	cpus = odp_cpu_count();
	CU_ASSERT(0 < cpus);
}

static void test_odp_sys_cache_line_size(void)
{
	uint64_t cache_size;

	cache_size = odp_sys_cache_line_size();
	CU_ASSERT(0 < cache_size);
	CU_ASSERT(ODP_CACHE_LINE_SIZE == cache_size);
}

static void test_odp_sys_cpu_model_str(void)
{
	char model[128];

	snprintf(model, 128, "%s", odp_sys_cpu_model_str());
	CU_ASSERT(strlen(model) > 0);
	CU_ASSERT(strlen(model) < 127);
}

static void test_odp_sys_page_size(void)
{
	uint64_t page;

	page = odp_sys_page_size();
	CU_ASSERT(0 < page);
	CU_ASSERT(ODP_PAGE_SIZE == page);
}

static void test_odp_sys_huge_page_size(void)
{
	uint64_t page;

	page = odp_sys_huge_page_size();
	CU_ASSERT(0 < page);
}

static void test_odp_sys_cpu_hz(void)
{
	uint64_t hz;

	hz = odp_sys_cpu_hz();
	CU_ASSERT(0 < hz);
}

CU_TestInfo test_odp_system[] = {
	{"odp version",  test_odp_version_numbers},
	{"odp_cpu_count",  test_odp_cpu_count},
	{"odp_sys_cache_line_size",  test_odp_sys_cache_line_size},
	{"odp_sys_cpu_model_str",  test_odp_sys_cpu_model_str},
	{"odp_sys_page_size",  test_odp_sys_page_size},
	{"odp_sys_huge_page_size",  test_odp_sys_huge_page_size},
	{"odp_sys_cpu_hz",  test_odp_sys_cpu_hz},
	CU_TEST_INFO_NULL,
};

CU_SuiteInfo odp_testsuites[] = {
	{"System Info", NULL, NULL, NULL, NULL, test_odp_system},
	CU_SUITE_INFO_NULL,
};
