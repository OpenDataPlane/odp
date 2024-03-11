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

	strncpy(version_string, odp_version_api_str(),
		sizeof(version_string) - 1);

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

static void system_test_odp_cpu_count(void)
{
	int cpus;

	cpus = odp_cpu_count();
	CU_ASSERT(0 < cpus);
}

static void system_test_cpu_cycles(void)
{
	uint64_t c2, c1, diff, max;

	c1 = odp_cpu_cycles();
	odp_time_wait_ns(WAIT_TIME);
	c2 = odp_cpu_cycles();

	CU_ASSERT(c2 != c1);

	max = odp_cpu_cycles_max();

	/* With 10 usec delay, diff should be small compared to the maximum.
	 * Otherwise, counter is going backwards. */
	if (c2 > c1) {
		diff = c2 - c1;
		CU_ASSERT(diff < (max - diff));
	}

	/* Same applies also when there was a wrap. */
	if (c2 < c1) {
		diff = max - c1 + c2;
		CU_ASSERT(diff < (max - diff));
	}
}

static void system_test_cpu_cycles_max(void)
{
	uint64_t c2, c1;
	uint64_t max1, max2;

	max1 = odp_cpu_cycles_max();
	odp_time_wait_ns(WAIT_TIME);
	max2 = odp_cpu_cycles_max();

	CU_ASSERT(max1 >= UINT32_MAX / 2);
	CU_ASSERT(max1 == max2);

	c1 = odp_cpu_cycles();
	odp_time_wait_ns(WAIT_TIME);
	c2 = odp_cpu_cycles();

	CU_ASSERT(c1 <= max1 && c2 <= max1);
}

static void system_test_cpu_cycles_resolution(void)
{
	int i;
	uint64_t res;
	uint64_t c2, c1, max;
	uint64_t test_cycles = odp_cpu_hz() / 100; /* CPU cycles in 10 msec */

	max = odp_cpu_cycles_max();

	res = odp_cpu_cycles_resolution();
	CU_ASSERT(res != 0);
	CU_ASSERT(res < max / 1024);

	for (i = 0; i < RES_TRY_NUM; i++) {
		c1 = odp_cpu_cycles();
		odp_time_wait_ns(10 * ODP_TIME_MSEC_IN_NS + i);
		c2 = odp_cpu_cycles();

		/* Diff may be zero with low resolution */
		if (test_cycles && test_cycles > res) {
			uint64_t diff = odp_cpu_cycles_diff(c2, c1);

			CU_ASSERT(diff >= res);
		}

	}
}

static void system_test_cpu_cycles_diff(void)
{
	uint64_t c2, c1, max;
	uint64_t tmp, diff, res;

	res = odp_cpu_cycles_resolution();
	max = odp_cpu_cycles_max();

	c1 = res;
	c2 = 2 * res;
	diff = odp_cpu_cycles_diff(c2, c1);
	CU_ASSERT(diff == res);

	c1 = odp_cpu_cycles();
	odp_time_wait_ns(WAIT_TIME);
	c2 = odp_cpu_cycles();
	diff = odp_cpu_cycles_diff(c2, c1);
	CU_ASSERT(diff > 0);
	CU_ASSERT(diff < (max - diff));

	/* check resolution for wrap */
	c1 = max - 2 * res;
	do
		c2 = odp_cpu_cycles();
	while (c1 < c2);

	diff = odp_cpu_cycles_diff(c1, c1);
	CU_ASSERT(diff == 0);

	/* wrap */
	tmp = c2 + (max - c1) + res;
	diff = odp_cpu_cycles_diff(c2, c1);
	CU_ASSERT(diff == tmp);

	/* no wrap, revert args */
	tmp = c1 - c2;
	diff = odp_cpu_cycles_diff(c1, c2);
	CU_ASSERT(diff == tmp);
}

static void system_test_cpu_cycles_long_period(void)
{
	int i;
	int periods = PERIODS_100_MSEC;
	uint64_t max_period_duration = 100 * ODP_TIME_MSEC_IN_NS + periods - 1;
	uint64_t c2, c1, c3, max;
	uint64_t tmp, diff, res;

	res = odp_cpu_cycles_resolution();
	max = odp_cpu_cycles_max();

	c3 = odp_cpu_cycles();

	CU_ASSERT(c3 <= max);
	/*
	 * If the cycle counter is not close to wrapping around during
	 * the test, then speed up the test by not trying to see the wrap
	 * around too hard. Assume cycle counter frequency of less than 10 GHz.
	 */
	CU_ASSERT(odp_cpu_hz_max() < 10ULL * ODP_TIME_SEC_IN_NS);
	if (max - c3 > 10 * periods * max_period_duration)
		periods = 10;

	printf("\n        Testing CPU cycles for %i seconds... ", periods / 10);

	for (i = 0; i < periods; i++) {
		c1 = odp_cpu_cycles();
		odp_time_wait_ns(100 * ODP_TIME_MSEC_IN_NS + i);
		c2 = odp_cpu_cycles();

		CU_ASSERT(c2 != c1);
		CU_ASSERT(c1 <= max && c2 <= max);

		if (c2 > c1)
			tmp = c2 - c1;
		else
			tmp = c2 + (max - c1) + res;

		diff = odp_cpu_cycles_diff(c2, c1);
		CU_ASSERT(diff == tmp);

		/* wrap is detected and verified */
		if (c2 < c1)
			break;
	}

	/* wrap was detected, no need to continue */
	if (i < periods) {
		printf("wrap was detected.\n");
		return;
	}

	/* wrap has to be detected if possible */
	CU_ASSERT(max > UINT32_MAX);
	CU_ASSERT((max - c3) > UINT32_MAX);

	printf("wrap was not detected.\n");
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

static void system_test_odp_cpu_model_str(void)
{
	char model[128];

	snprintf(model, 128, "%s", odp_cpu_model_str());
	CU_ASSERT(strlen(model) > 0);
	CU_ASSERT(strlen(model) < 127);
}

static void system_test_odp_cpu_model_str_id(void)
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

static int system_check_cycle_counter(void)
{
	if (odp_cpu_cycles_max() == 0) {
		printf("Cycle counter is not supported, skipping test\n");
		return ODP_TEST_INACTIVE;
	}

	return ODP_TEST_ACTIVE;
}

static int system_check_odp_cpu_hz(void)
{
	if (odp_cpu_hz() == 0) {
		printf("odp_cpu_hz() is not supported, skipping test\n");
		return ODP_TEST_INACTIVE;
	}

	return ODP_TEST_ACTIVE;
}

static void system_test_odp_cpu_hz(void)
{
	uint64_t hz = odp_cpu_hz();

	/* Test value sanity: less than 10GHz */
	CU_ASSERT(hz < 10 * GIGA_HZ);

	/* larger than 1kHz */
	CU_ASSERT(hz > 1 * KILO_HZ);
}

static int system_check_odp_cpu_hz_id(void)
{
	uint64_t hz;
	odp_cpumask_t mask;
	int i, num, cpu;

	num = odp_cpumask_all_available(&mask);
	cpu = odp_cpumask_first(&mask);

	for (i = 0; i < num; i++) {
		hz = odp_cpu_hz_id(cpu);
		if (hz == 0) {
			printf("odp_cpu_hz_id() is not supported by CPU %d, skipping test\n", cpu);
			return ODP_TEST_INACTIVE;
		}
		cpu = odp_cpumask_next(&mask, cpu);
	}

	return ODP_TEST_ACTIVE;
}

static void system_test_odp_cpu_hz_id(void)
{
	uint64_t hz;
	odp_cpumask_t mask;
	int i, num, cpu;

	num = odp_cpumask_all_available(&mask);
	cpu = odp_cpumask_first(&mask);

	for (i = 0; i < num; i++) {
		hz = odp_cpu_hz_id(cpu);
		/* Test value sanity: less than 10GHz */
		CU_ASSERT(hz < 10 * GIGA_HZ);
		/* larger than 1kHz */
		CU_ASSERT(hz > 1 * KILO_HZ);
		cpu = odp_cpumask_next(&mask, cpu);
	}
}

static int system_check_odp_cpu_hz_max(void)
{
	if (odp_cpu_hz_max() == 0) {
		printf("odp_cpu_hz_max() is not supported, skipping test\n");
		return ODP_TEST_INACTIVE;
	}
	return ODP_TEST_ACTIVE;
}

static void system_test_odp_cpu_hz_max(void)
{
	uint64_t hz = odp_cpu_hz_max();

	/* Sanity check value */
	CU_ASSERT(hz > 1 * KILO_HZ);
	CU_ASSERT(hz < 20 * GIGA_HZ);
}

static int system_check_odp_cpu_hz_max_id(void)
{
	uint64_t hz;
	odp_cpumask_t mask;
	int i, num, cpu;

	num = odp_cpumask_all_available(&mask);
	cpu = odp_cpumask_first(&mask);

	for (i = 0; i < num; i++) {
		hz = odp_cpu_hz_max_id(cpu);
		if (hz == 0) {
			printf("odp_cpu_hz_max_id() is not supported by CPU %d, skipping test\n",
			       cpu);
			return ODP_TEST_INACTIVE;
		}
		cpu = odp_cpumask_next(&mask, cpu);
	}

	return ODP_TEST_ACTIVE;
}

static void system_test_odp_cpu_hz_max_id(void)
{
	uint64_t hz;
	odp_cpumask_t mask;
	int i, num, cpu;

	num = odp_cpumask_all_available(&mask);
	cpu = odp_cpumask_first(&mask);

	for (i = 0; i < num; i++) {
		hz = odp_cpu_hz_max_id(cpu);
		/* Sanity check value */
		CU_ASSERT(hz > 1 * KILO_HZ);
		CU_ASSERT(hz < 20 * GIGA_HZ);
		cpu = odp_cpumask_next(&mask, cpu);
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
	ODP_TEST_INFO(system_test_odp_cpu_count),
	ODP_TEST_INFO(system_test_odp_sys_cache_line_size),
	ODP_TEST_INFO(system_test_odp_cpu_model_str),
	ODP_TEST_INFO(system_test_odp_cpu_model_str_id),
	ODP_TEST_INFO(system_test_odp_sys_page_size),
	ODP_TEST_INFO(system_test_odp_sys_huge_page_size),
	ODP_TEST_INFO(system_test_odp_sys_huge_page_size_all),
	ODP_TEST_INFO_CONDITIONAL(system_test_odp_cpu_hz,
				  system_check_odp_cpu_hz),
	ODP_TEST_INFO_CONDITIONAL(system_test_odp_cpu_hz_id,
				  system_check_odp_cpu_hz_id),
	ODP_TEST_INFO_CONDITIONAL(system_test_odp_cpu_hz_max,
				  system_check_odp_cpu_hz_max),
	ODP_TEST_INFO_CONDITIONAL(system_test_odp_cpu_hz_max_id,
				  system_check_odp_cpu_hz_max_id),
	ODP_TEST_INFO_CONDITIONAL(system_test_cpu_cycles,
				  system_check_cycle_counter),
	ODP_TEST_INFO_CONDITIONAL(system_test_cpu_cycles_max,
				  system_check_cycle_counter),
	ODP_TEST_INFO_CONDITIONAL(system_test_cpu_cycles_resolution,
				  system_check_cycle_counter),
	ODP_TEST_INFO_CONDITIONAL(system_test_cpu_cycles_diff,
				  system_check_cycle_counter),
	ODP_TEST_INFO_CONDITIONAL(system_test_cpu_cycles_long_period,
				  system_check_cycle_counter),
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
