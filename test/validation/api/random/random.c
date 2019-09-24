/* Copyright (c) 2015-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_api.h>
#include <odp_cunit_common.h>

static void random_test_get_size(void)
{
	int32_t ret;
	uint8_t buf[32];

	ret = odp_random_data(buf, sizeof(buf), ODP_RANDOM_BASIC);
	CU_ASSERT(ret == sizeof(buf));
}

static void random_test_kind(void)
{
	int32_t rc;
	uint8_t buf[4096];
	uint32_t buf_size = sizeof(buf);
	odp_random_kind_t max_kind = odp_random_max_kind();

	rc = odp_random_data(buf, buf_size, max_kind);
	CU_ASSERT(rc > 0);

	switch (max_kind) {
	case ODP_RANDOM_BASIC:
		rc = odp_random_data(buf, 4, ODP_RANDOM_CRYPTO);
		CU_ASSERT(rc < 0);
		/* Fall through */

	case ODP_RANDOM_CRYPTO:
		rc = odp_random_data(buf, 4, ODP_RANDOM_TRUE);
		CU_ASSERT(rc < 0);
		break;

	default:
		break;
	}
}

static void random_test_repeat(void)
{
	uint8_t buf1[1024];
	uint8_t buf2[1024];
	int32_t rc;
	uint64_t seed1 = 12345897;
	uint64_t seed2 = seed1;

	rc = odp_random_test_data(buf1, sizeof(buf1), &seed1);
	CU_ASSERT(rc == sizeof(buf1));

	rc = odp_random_test_data(buf2, sizeof(buf2), &seed2);
	CU_ASSERT(rc == sizeof(buf2));

	CU_ASSERT(seed1 == seed2);
	CU_ASSERT(memcmp(buf1, buf2, sizeof(buf1)) == 0);
}

odp_testinfo_t random_suite[] = {
	ODP_TEST_INFO(random_test_get_size),
	ODP_TEST_INFO(random_test_kind),
	ODP_TEST_INFO(random_test_repeat),
	ODP_TEST_INFO_NULL,
};

odp_suiteinfo_t random_suites[] = {
	{"Random", NULL, NULL, random_suite},
	ODP_SUITE_INFO_NULL,
};

int main(int argc, char *argv[])
{
	int ret;

	/* parse common options: */
	if (odp_cunit_parse_options(argc, argv))
		return -1;

	ret = odp_cunit_register(random_suites);

	if (ret == 0)
		ret = odp_cunit_run();

	return ret;
}
