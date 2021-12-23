/* Copyright (c) 2015-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_api.h>
#include <odp_cunit_common.h>

static void random_test_get_size(void)
{
	/* odp_random_data may fail to return data on every call (i.e. lack of
	 * entropy). Therefore loop with some sane loop timeout value. Note that
	 * it is not required for implementation to return data in the "timeout"
	 * amount of steps. Rather it is a way for preventing the test to loop
	 * forever.
	 * Also note that the timeout value here is chosen completely
	 * arbitrarily (although considered sane) and neither platforms or
	 * applications are not required to use it.
	 */
	int32_t ret, timeout_ns = 1 * ODP_TIME_MSEC_IN_NS, sleep_ns = 100;
	uint32_t bytes = 0;
	uint8_t buf[32];

	do {
		ret = odp_random_data(buf + bytes, sizeof(buf) - bytes,
				      ODP_RANDOM_BASIC);
		bytes += ret;
		if (ret < 0 || bytes >= sizeof(buf))
			break;
		odp_time_wait_ns(sleep_ns);
		timeout_ns -= sleep_ns;
	} while (timeout_ns > 0);

	CU_ASSERT(ret > 0);
	CU_ASSERT(bytes == (int32_t)sizeof(buf));
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

static void random_data(uint8_t *buf, uint32_t len, odp_random_kind_t kind)
{
	static uint64_t seed;

	switch (kind) {
	case ODP_RANDOM_BASIC:
	case ODP_RANDOM_CRYPTO:
	case ODP_RANDOM_TRUE:
		for (uint32_t i = 0; i < len;) {
			int32_t r = odp_random_data(buf + i, len - i, kind);

			CU_ASSERT_FATAL(r >= 0);
			i += r;
		}
		break;
	default:
		CU_ASSERT_FATAL(odp_random_test_data(buf, len, &seed) ==
				(int32_t)len);
	}
}

static void random_test_align_and_overflow(odp_random_kind_t kind)
{
	uint8_t ODP_ALIGNED_CACHE buf[64];

	for (int align = 8; align < 16; align++) {
		for (int len = 1; len <= 16; len++) {
			memset(buf, 1, sizeof(buf));
			random_data(buf + align, len, kind);
			CU_ASSERT(buf[align - 1] == 1);
			CU_ASSERT(buf[align + len] == 1);
		}
	}
}

static void random_test_align_and_overflow_test(void)
{
	random_test_align_and_overflow(-1);
}

static void random_test_align_and_overflow_basic(void)
{
	random_test_align_and_overflow(ODP_RANDOM_BASIC);
}

static void random_test_align_and_overflow_crypto(void)
{
	random_test_align_and_overflow(ODP_RANDOM_CRYPTO);
}

static void random_test_align_and_overflow_true(void)
{
	random_test_align_and_overflow(ODP_RANDOM_TRUE);
}

static int check_kind_basic(void)
{
	return odp_random_max_kind() >= ODP_RANDOM_BASIC;
}

static int check_kind_crypto(void)
{
	return odp_random_max_kind() >= ODP_RANDOM_CRYPTO;
}

static int check_kind_true(void)
{
	return odp_random_max_kind() >= ODP_RANDOM_TRUE;
}

odp_testinfo_t random_suite[] = {
	ODP_TEST_INFO(random_test_get_size),
	ODP_TEST_INFO(random_test_kind),
	ODP_TEST_INFO(random_test_repeat),
	ODP_TEST_INFO(random_test_align_and_overflow_test),
	ODP_TEST_INFO_CONDITIONAL(random_test_align_and_overflow_basic, check_kind_basic),
	ODP_TEST_INFO_CONDITIONAL(random_test_align_and_overflow_crypto, check_kind_crypto),
	ODP_TEST_INFO_CONDITIONAL(random_test_align_and_overflow_true, check_kind_true),
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
