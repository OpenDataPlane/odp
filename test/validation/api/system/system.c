/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2015-2018 Linaro Limited
 */

#include <ctype.h>
#include <odp_api.h>
#include <odp/helper/odph_api.h>

#include "odp_cunit_common.h"
#include "test_common_macros.h"

#define PERIODS_100_MSEC  160
#define RES_TRY_NUM       10
#define PAGESZ_NUM        10

#define GIGA_HZ 1000000000ULL
#define KILO_HZ 1000ULL

/* 10 usec wait time assumes >100kHz resolution on CPU cycles counter */
#define WAIT_TIME (10 * ODP_TIME_USEC_IN_NS)

static void test_version_api_str(void)
{
	int char_ok = 0;
	char version_string[128];
	char *s = version_string;

	odph_strcpy(version_string, odp_version_api_str(),
		    sizeof(version_string));

	while (*s) {
		if (isdigit((int)*s) || (strncmp(s, ".", 1) == 0)) {
			char_ok = 1;
			s++;
		} else {
			char_ok = 0;
			ODPH_DBG("\nBAD VERSION=%s\n", version_string);
			break;
		}
	}
	CU_ASSERT(char_ok);
}

static void test_version_str(void)
{
	printf("\nAPI version:\n");
	printf("%s\n\n", odp_version_api_str());

	printf("Implementation name:\n");
	printf("%s\n\n", odp_version_impl_name());

	printf("Implementation details:\n");
	printf("%s\n\n", odp_version_impl_str());
}

static void test_version_macro(void)
{
	CU_ASSERT(ODP_VERSION_API_NUM(0, 0, 0) < ODP_VERSION_API_NUM(0, 0, 1));
	CU_ASSERT(ODP_VERSION_API_NUM(0, 0, 1) < ODP_VERSION_API_NUM(0, 1, 0));
	CU_ASSERT(ODP_VERSION_API_NUM(0, 1, 0) < ODP_VERSION_API_NUM(1, 0, 0));
	CU_ASSERT(ODP_VERSION_API_NUM(1, 90, 0) <
		  ODP_VERSION_API_NUM(1, 90, 1));

	CU_ASSERT(ODP_VERSION_API_NUM(ODP_VERSION_API_GENERATION,
				      ODP_VERSION_API_MAJOR,
				      ODP_VERSION_API_MINOR) ==
		  ODP_VERSION_API);

	CU_ASSERT(ODP_VERSION_API_NUM(ODP_VERSION_API_GENERATION,
				      ODP_VERSION_API_MAJOR, 0) <=
		  ODP_VERSION_API);

	CU_ASSERT(ODP_VERSION_API_NUM(ODP_VERSION_API_GENERATION,
				      ODP_VERSION_API_MAJOR + 1, 0) >
		  ODP_VERSION_API);
}

static void system_test_odp_sys_cache_line_size(void)
{
	uint64_t cache_size;

	cache_size = odp_sys_cache_line_size();
	CU_ASSERT(0 < cache_size);
	CU_ASSERT(0 < ODP_CACHE_LINE_SIZE);
	CU_ASSERT(TEST_CHECK_POW2(cache_size));
	CU_ASSERT(TEST_CHECK_POW2(ODP_CACHE_LINE_SIZE));
	if (ODP_CACHE_LINE_SIZE != cache_size)
		printf("WARNING: ODP_CACHE_LINE_SIZE and odp_sys_cache_line_size() not matching\n");

	CU_ASSERT(ODP_CACHE_LINE_ROUNDUP(0) == 0);
	CU_ASSERT(ODP_CACHE_LINE_ROUNDUP(1) == ODP_CACHE_LINE_SIZE);
	CU_ASSERT(ODP_CACHE_LINE_ROUNDUP(ODP_CACHE_LINE_SIZE) ==
		  ODP_CACHE_LINE_SIZE);
	CU_ASSERT(ODP_CACHE_LINE_ROUNDUP(ODP_CACHE_LINE_SIZE + 1) ==
		  2 * ODP_CACHE_LINE_SIZE);
}

static void system_test_odp_sys_page_size(void)
{
	uint64_t page;

	page = odp_sys_page_size();
	CU_ASSERT(0 < page);
	CU_ASSERT(ODP_PAGE_SIZE == page);
}

static void system_test_odp_sys_huge_page_size(void)
{
	uint64_t page;

	page = odp_sys_huge_page_size();
	if (page == 0)
		/* Not an error, but just to be sure to hit logs */
		ODPH_ERR("Huge pages do not seem to be supported\n");
	else
		CU_ASSERT(page % ODP_PAGE_SIZE == 0);
}

static void system_test_odp_sys_huge_page_size_all(void)
{
	uint64_t pagesz_tbs[PAGESZ_NUM];
	uint64_t prev_pagesz = 0;
	int num;
	int i;

	num = odp_sys_huge_page_size_all(NULL, 0);
	CU_ASSERT(num >= 0);

	num = odp_sys_huge_page_size_all(pagesz_tbs, PAGESZ_NUM);
	CU_ASSERT(num >= 0);
	for (i = 0; i < num && i < PAGESZ_NUM; i++) {
		CU_ASSERT(pagesz_tbs[i] > 0);
		CU_ASSERT(pagesz_tbs[i] > prev_pagesz);
		prev_pagesz = pagesz_tbs[i];
	}
}

static void system_test_info_print(void)
{
	printf("\n\nCalling system info print...\n");
	odp_sys_info_print();
	printf("...done. ");
}

static void system_test_config_print(void)
{
	printf("\n\nCalling system config print...\n");
	odp_sys_config_print();
	printf("...done. ");
}

static void system_test_info(void)
{
	odp_system_info_t info;
	odp_cpu_arch_t cpu_arch;

	memset(&info, 0xff, sizeof(odp_system_info_t));
	CU_ASSERT(odp_system_info(&info) == 0);
	cpu_arch = info.cpu_arch;

	memset(&info, 0, sizeof(odp_system_info_t));
	CU_ASSERT(odp_system_info(&info) == 0);

	CU_ASSERT(info.cpu_arch == cpu_arch);
	CU_ASSERT(info.cpu_arch >= ODP_CPU_ARCH_UNKNOWN && info.cpu_arch <= ODP_CPU_ARCH_X86);

	if (info.cpu_arch == ODP_CPU_ARCH_X86) {
		printf("\n        ODP_CPU_ARCH_X86\n");
		CU_ASSERT(info.cpu_isa_sw.x86 != ODP_CPU_ARCH_X86_UNKNOWN);

		if (info.cpu_isa_sw.x86 == ODP_CPU_ARCH_X86_64)
			printf("        ODP_CPU_ARCH_X86_64\n");
		else if (info.cpu_isa_sw.x86 == ODP_CPU_ARCH_X86_I686)
			printf("        ODP_CPU_ARCH_X86_I686\n");

		if (info.cpu_isa_hw.x86 != ODP_CPU_ARCH_X86_UNKNOWN)
			CU_ASSERT(info.cpu_isa_sw.x86 <= info.cpu_isa_hw.x86);
	}

	if (info.cpu_arch == ODP_CPU_ARCH_ARM) {
		printf("\n        ODP_CPU_ARCH_ARM\n");
		CU_ASSERT(info.cpu_isa_sw.arm != ODP_CPU_ARCH_ARM_UNKNOWN);

		if (info.cpu_isa_sw.arm == ODP_CPU_ARCH_ARMV6)
			printf("        ODP_CPU_ARCH_ARMV6\n");
		else if (info.cpu_isa_sw.arm == ODP_CPU_ARCH_ARMV7)
			printf("        ODP_CPU_ARCH_ARMV7\n");
		else if (info.cpu_isa_sw.arm == ODP_CPU_ARCH_ARMV8_0)
			printf("        ODP_CPU_ARCH_ARMV8_0\n");
		else if (info.cpu_isa_sw.arm == ODP_CPU_ARCH_ARMV8_1)
			printf("        ODP_CPU_ARCH_ARMV8_1\n");
		else if (info.cpu_isa_sw.arm == ODP_CPU_ARCH_ARMV8_2)
			printf("        ODP_CPU_ARCH_ARMV8_2\n");
		else if (info.cpu_isa_sw.arm == ODP_CPU_ARCH_ARMV8_3)
			printf("        ODP_CPU_ARCH_ARMV8_3\n");
		else if (info.cpu_isa_sw.arm == ODP_CPU_ARCH_ARMV8_4)
			printf("        ODP_CPU_ARCH_ARMV8_4\n");
		else if (info.cpu_isa_sw.arm == ODP_CPU_ARCH_ARMV8_5)
			printf("        ODP_CPU_ARCH_ARMV8_5\n");
		else if (info.cpu_isa_sw.arm == ODP_CPU_ARCH_ARMV8_6)
			printf("        ODP_CPU_ARCH_ARMV8_6\n");
		else if (info.cpu_isa_sw.arm == ODP_CPU_ARCH_ARMV8_7)
			printf("        ODP_CPU_ARCH_ARMV8_7\n");
		else if (info.cpu_isa_sw.arm == ODP_CPU_ARCH_ARMV8_8)
			printf("        ODP_CPU_ARCH_ARMV8_8\n");
		else if (info.cpu_isa_sw.arm == ODP_CPU_ARCH_ARMV8_9)
			printf("        ODP_CPU_ARCH_ARMV8_9\n");
		else if (info.cpu_isa_sw.arm == ODP_CPU_ARCH_ARMV9_0)
			printf("        ODP_CPU_ARCH_ARMV9_0\n");
		else if (info.cpu_isa_sw.arm == ODP_CPU_ARCH_ARMV9_1)
			printf("        ODP_CPU_ARCH_ARMV9_1\n");
		else if (info.cpu_isa_sw.arm == ODP_CPU_ARCH_ARMV9_2)
			printf("        ODP_CPU_ARCH_ARMV9_2\n");
		else if (info.cpu_isa_sw.arm == ODP_CPU_ARCH_ARMV9_3)
			printf("        ODP_CPU_ARCH_ARMV9_3\n");
		else
			CU_FAIL("Unknown CPU ISA SW ARCH found!");

		if (info.cpu_isa_hw.arm != ODP_CPU_ARCH_ARM_UNKNOWN)
			CU_ASSERT(info.cpu_isa_sw.arm <= info.cpu_isa_hw.arm);

		if (info.cpu_isa_hw.arm == ODP_CPU_ARCH_ARMV6)
			printf("        ODP_CPU_ARCH_ARMV6\n");
		else if (info.cpu_isa_hw.arm == ODP_CPU_ARCH_ARMV7)
			printf("        ODP_CPU_ARCH_ARMV7\n");
		else if (info.cpu_isa_hw.arm == ODP_CPU_ARCH_ARMV8_0)
			printf("        ODP_CPU_ARCH_ARMV8_0\n");
		else if (info.cpu_isa_hw.arm == ODP_CPU_ARCH_ARMV8_1)
			printf("        ODP_CPU_ARCH_ARMV8_1\n");
		else if (info.cpu_isa_hw.arm == ODP_CPU_ARCH_ARMV8_2)
			printf("        ODP_CPU_ARCH_ARMV8_2\n");
		else if (info.cpu_isa_hw.arm == ODP_CPU_ARCH_ARMV8_3)
			printf("        ODP_CPU_ARCH_ARMV8_3\n");
		else if (info.cpu_isa_hw.arm == ODP_CPU_ARCH_ARMV8_4)
			printf("        ODP_CPU_ARCH_ARMV8_4\n");
		else if (info.cpu_isa_hw.arm == ODP_CPU_ARCH_ARMV8_5)
			printf("        ODP_CPU_ARCH_ARMV8_5\n");
		else if (info.cpu_isa_hw.arm == ODP_CPU_ARCH_ARMV8_6)
			printf("        ODP_CPU_ARCH_ARMV8_6\n");
		else if (info.cpu_isa_hw.arm == ODP_CPU_ARCH_ARMV8_7)
			printf("        ODP_CPU_ARCH_ARMV8_7\n");
		else if (info.cpu_isa_hw.arm == ODP_CPU_ARCH_ARMV8_8)
			printf("        ODP_CPU_ARCH_ARMV8_8\n");
		else if (info.cpu_isa_hw.arm == ODP_CPU_ARCH_ARMV8_9)
			printf("        ODP_CPU_ARCH_ARMV8_9\n");
		else if (info.cpu_isa_hw.arm == ODP_CPU_ARCH_ARMV9_0)
			printf("        ODP_CPU_ARCH_ARMV9_0\n");
		else if (info.cpu_isa_hw.arm == ODP_CPU_ARCH_ARMV9_1)
			printf("        ODP_CPU_ARCH_ARMV9_1\n");
		else if (info.cpu_isa_hw.arm == ODP_CPU_ARCH_ARMV9_2)
			printf("        ODP_CPU_ARCH_ARMV9_2\n");
		else if (info.cpu_isa_hw.arm == ODP_CPU_ARCH_ARMV9_3)
			printf("        ODP_CPU_ARCH_ARMV9_3\n");
		else if (info.cpu_isa_hw.arm == ODP_CPU_ARCH_ARM_UNKNOWN)
			printf("        ODP_CPU_ARCH_ARM_UNKNOWN\n");
		else
			CU_FAIL("Unknown CPU ISA HW ARCH found!");

	}
}

static void system_test_meminfo(void)
{
	const int32_t max_num = 128;
	odp_system_meminfo_t info, info_0;
	int32_t ret, ret_0, num, i;
	odp_system_memblock_t block[max_num];

	/* Meminfo without blocks */
	ret_0 = odp_system_meminfo(&info_0, NULL, 0);
	CU_ASSERT_FATAL(ret_0 >= 0);

	ret = odp_system_meminfo(&info, block, max_num);
	CU_ASSERT_FATAL(ret >= 0);

	/* Totals should match independent of per block output */
	CU_ASSERT(ret == ret_0);
	CU_ASSERT(info_0.total_mapped == info.total_mapped);
	CU_ASSERT(info_0.total_used == info.total_used);
	CU_ASSERT(info_0.total_overhead == info.total_overhead);

	CU_ASSERT(info.total_mapped >= info.total_used);
	CU_ASSERT(info.total_used >= info.total_overhead);

	num = ret;
	if (ret > max_num)
		num = max_num;

	printf("\n\n");
	printf("System meminfo contain %i blocks, printing %i blocks:\n", ret, num);

	printf("  %s %-32s %16s %14s %14s %12s\n", "index", "name", "addr",
	       "used", "overhead", "page_size");

	for (i = 0; i < num; i++) {
		printf("  [%3i] %-32s %16" PRIxPTR " %14" PRIu64 " %14" PRIu64 " %12" PRIu64 "\n",
		       i, block[i].name, block[i].addr, block[i].used, block[i].overhead,
		       block[i].page_size);
	}

	printf("\n");
	printf("Total mapped:   %" PRIu64 "\n", info.total_mapped);
	printf("Total used:     %" PRIu64 "\n", info.total_used);
	printf("Total overhead: %" PRIu64 "\n\n", info.total_overhead);
}

odp_testinfo_t system_suite[] = {
	ODP_TEST_INFO(test_version_api_str),
	ODP_TEST_INFO(test_version_str),
	ODP_TEST_INFO(test_version_macro),
	ODP_TEST_INFO(system_test_odp_sys_cache_line_size),
	ODP_TEST_INFO(system_test_odp_sys_page_size),
	ODP_TEST_INFO(system_test_odp_sys_huge_page_size),
	ODP_TEST_INFO(system_test_odp_sys_huge_page_size_all),
	ODP_TEST_INFO(system_test_info),
	ODP_TEST_INFO(system_test_meminfo),
	ODP_TEST_INFO(system_test_info_print),
	ODP_TEST_INFO(system_test_config_print),
	ODP_TEST_INFO_NULL,
};

odp_suiteinfo_t system_suites[] = {
	{"System Info", NULL, NULL, system_suite},
	ODP_SUITE_INFO_NULL,
};

int main(int argc, char *argv[])
{
	int ret;

	/* parse common options: */
	if (odp_cunit_parse_options(&argc, argv))
		return -1;

	ret = odp_cunit_register(system_suites);

	if (ret == 0)
		ret = odp_cunit_run();

	return ret;
}
