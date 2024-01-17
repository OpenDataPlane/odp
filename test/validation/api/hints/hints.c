/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2024 Nokia
 */

#include <odp_api.h>
#include <odp_cunit_common.h>

#include <stdint.h>
#include <stdlib.h>

ODP_NORETURN static void test_noreturn(void)
{
	abort();
}

int test_weak(void);

ODP_WEAK_SYMBOL int test_weak(void)
{
	return 0;
}

ODP_COLD_CODE static int test_cold(void)
{
	return -1;
}

ODP_HOT_CODE static int test_hot(void)
{
	return 1;
}

ODP_PRINTF_FORMAT(2, 3)
static int test_printf_format(int level ODP_UNUSED, const char *fmt ODP_UNUSED, ...)
{
	return 0;
}

static void test_hints(void)
{
	volatile int val = 1;

	if (odp_unlikely(!val))
		test_noreturn();

	test_weak();
	test_cold();

	if (odp_likely(val))
		test_hot();

	test_printf_format(0, "test");
}

static void test_prefetch(void)
{
	const int rounds = 10;
	uint64_t data[rounds];

	for (int i = 0; i < rounds; i++)
		odp_prefetch(&data[i]);

	for (int i = 0; i < rounds; i++)
		odp_prefetch_store(&data[i]);
}

odp_testinfo_t hints_suite[] = {
	ODP_TEST_INFO(test_hints),
	ODP_TEST_INFO(test_prefetch),
	ODP_TEST_INFO_NULL,
};

odp_suiteinfo_t align_suites[] = {
	{"hints", NULL, NULL, hints_suite},
	ODP_SUITE_INFO_NULL
};

int main(int argc, char *argv[])
{
	int ret;

	/* Parse common options */
	if (odp_cunit_parse_options(&argc, argv))
		return -1;

	ret = odp_cunit_register(align_suites);

	if (ret == 0)
		ret = odp_cunit_run();

	return ret;
}
