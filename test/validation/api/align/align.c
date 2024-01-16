/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2024 Nokia
 */

#include <odp_api.h>
#include <odp_cunit_common.h>

#include <stddef.h>
#include <stdint.h>

/* Test struct without gaps */
typedef struct ODP_PACKED {
	uint8_t a;
	uint8_t b;
	uint16_t c;
	uint32_t d;
} test_type_t;

/* Test struct with gaps */
typedef struct ODP_PACKED {
	uint8_t a;
	uint16_t b;
	uint8_t c;
	uint32_t d;
} test_type_2_t;

static void test_aligned(void)
{
	uint8_t  align_2 ODP_ALIGNED(2);
	uint16_t align_4 ODP_ALIGNED(4);
	uint32_t align_8 ODP_ALIGNED(8);
	uint64_t align_16 ODP_ALIGNED(16);

	CU_ASSERT((uintptr_t)&align_2 % 2 == 0);
	CU_ASSERT((uintptr_t)&align_4 % 4 == 0);
	CU_ASSERT((uintptr_t)&align_8 % 8 == 0);
	CU_ASSERT((uintptr_t)&align_16 % 16 == 0);
}

static void test_packed(void)
{
	uint32_t offset;

	offset = 0;
	CU_ASSERT(offsetof(test_type_t, a) == offset);

	offset += sizeof(uint8_t);
	CU_ASSERT(offsetof(test_type_t, b) == offset);

	offset += sizeof(uint8_t);
	CU_ASSERT(offsetof(test_type_t, c) == offset);

	offset += sizeof(uint16_t);
	CU_ASSERT(offsetof(test_type_t, d) == offset);

	offset = 0;
	CU_ASSERT(offsetof(test_type_2_t, a) == offset);

	offset += sizeof(uint8_t);
	CU_ASSERT(offsetof(test_type_2_t, b) == offset);

	offset += sizeof(uint16_t);
	CU_ASSERT(offsetof(test_type_2_t, c) == offset);

	offset += sizeof(uint8_t);
	CU_ASSERT(offsetof(test_type_2_t, d) == offset);
}

static void test_offsetof(void)
{
	CU_ASSERT(ODP_OFFSETOF(test_type_t, a) == offsetof(test_type_t, a));
	CU_ASSERT(ODP_OFFSETOF(test_type_t, b) == offsetof(test_type_t, b));
	CU_ASSERT(ODP_OFFSETOF(test_type_t, c) == offsetof(test_type_t, c));
	CU_ASSERT(ODP_OFFSETOF(test_type_t, d) == offsetof(test_type_t, d));
	CU_ASSERT(ODP_OFFSETOF(test_type_2_t, a) == offsetof(test_type_2_t, a));
	CU_ASSERT(ODP_OFFSETOF(test_type_2_t, b) == offsetof(test_type_2_t, b));
	CU_ASSERT(ODP_OFFSETOF(test_type_2_t, c) == offsetof(test_type_2_t, c));
	CU_ASSERT(ODP_OFFSETOF(test_type_2_t, d) == offsetof(test_type_2_t, d));
}

static void test_field_sizeof(void)
{
	test_type_t tt;

	CU_ASSERT(ODP_FIELD_SIZEOF(test_type_t, a) == sizeof(tt.a));
	CU_ASSERT(ODP_FIELD_SIZEOF(test_type_t, b) == sizeof(tt.b));
	CU_ASSERT(ODP_FIELD_SIZEOF(test_type_t, c) == sizeof(tt.c));
	CU_ASSERT(ODP_FIELD_SIZEOF(test_type_t, d) == sizeof(tt.d));
}

static void test_cache_line_size(void)
{
	CU_ASSERT(ODP_CACHE_LINE_SIZE > 0);
	CU_ASSERT(ODP_CACHE_LINE_SIZE % 2 == 0);
}

static void test_page_size(void)
{
	CU_ASSERT(ODP_PAGE_SIZE > 0);
	CU_ASSERT(ODP_PAGE_SIZE % 2 == 0);
}

static void test_aligned_cache(void)
{
	uint8_t arr[123] ODP_ALIGNED_CACHE;

	CU_ASSERT((uintptr_t)arr % ODP_CACHE_LINE_SIZE == 0);
}

static void test_aligned_page(void)
{
	uint8_t arr[123] ODP_ALIGNED_PAGE;

	CU_ASSERT((uintptr_t)arr % ODP_PAGE_SIZE == 0);
}

static void test_cache_line_roundup(void)
{
	CU_ASSERT(ODP_CACHE_LINE_ROUNDUP(123) % ODP_CACHE_LINE_SIZE == 0);
	CU_ASSERT(ODP_CACHE_LINE_ROUNDUP(ODP_CACHE_LINE_SIZE) == ODP_CACHE_LINE_SIZE);
	CU_ASSERT(ODP_CACHE_LINE_ROUNDUP(0) == 0);
}

odp_testinfo_t align_suite[] = {
	ODP_TEST_INFO(test_aligned),
	ODP_TEST_INFO(test_packed),
	ODP_TEST_INFO(test_offsetof),
	ODP_TEST_INFO(test_field_sizeof),
	ODP_TEST_INFO(test_cache_line_size),
	ODP_TEST_INFO(test_page_size),
	ODP_TEST_INFO(test_aligned_cache),
	ODP_TEST_INFO(test_aligned_page),
	ODP_TEST_INFO(test_cache_line_roundup),
	ODP_TEST_INFO_NULL,
};

odp_suiteinfo_t align_suites[] = {
	{"align", NULL, NULL, align_suite},
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
