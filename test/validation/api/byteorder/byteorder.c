/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2024 Nokia
 */

#include <odp_api.h>
#include <odp_cunit_common.h>

#include <stdint.h>

static void test_defines(void)
{
	/* Endianness */
	CU_ASSERT(ODP_BIG_ENDIAN || ODP_LITTLE_ENDIAN);

	if (ODP_BIG_ENDIAN) {
		CU_ASSERT(ODP_BYTE_ORDER == ODP_BIG_ENDIAN);
		CU_ASSERT(!ODP_LITTLE_ENDIAN);
	}

	if (ODP_LITTLE_ENDIAN) {
		CU_ASSERT(ODP_BYTE_ORDER == ODP_LITTLE_ENDIAN);
		CU_ASSERT(!ODP_BIG_ENDIAN);
	}

	/* Bitfield endianness */
	CU_ASSERT(ODP_BIG_ENDIAN_BITFIELD || ODP_LITTLE_ENDIAN_BITFIELD);

	if (ODP_BIG_ENDIAN_BITFIELD) {
		CU_ASSERT(ODP_BITFIELD_ORDER == ODP_BIG_ENDIAN_BITFIELD);
		CU_ASSERT(!ODP_LITTLE_ENDIAN_BITFIELD);
	}

	if (ODP_LITTLE_ENDIAN_BITFIELD) {
		CU_ASSERT(ODP_BITFIELD_ORDER == ODP_LITTLE_ENDIAN_BITFIELD);
		CU_ASSERT(!ODP_BIG_ENDIAN_BITFIELD);
	}
}

static void test_types(void)
{
	const uint16_t u16_val = 0x1234;
	const uint32_t u32_val = 0x12345678;
	const uint64_t u64_val = 0x1234567890123456;
	const uint16_t u16_val_conv = 0x3412;
	const uint32_t u32_val_conv = 0x78563412;
	const uint64_t u64_val_conv = 0x5634129078563412;
	odp_u16be_t be16 = odp_cpu_to_be_16(u16_val);
	odp_u32be_t be32 = odp_cpu_to_be_32(u32_val);
	odp_u64be_t be64 = odp_cpu_to_be_64(u64_val);
	odp_u16le_t le16 = odp_cpu_to_le_16(u16_val);
	odp_u32le_t le32 = odp_cpu_to_le_32(u32_val);
	odp_u64le_t le64 = odp_cpu_to_le_64(u64_val);
	odp_u16sum_t sum16 = u16_val;
	odp_u32sum_t sum32 = u16_val;

	CU_ASSERT(sum16 == sum32);

	if (ODP_BIG_ENDIAN) {
		CU_ASSERT(be16 == u16_val);
		CU_ASSERT(be32 == u32_val);
		CU_ASSERT(be64 == u64_val);
		CU_ASSERT(le16 == u16_val_conv);
		CU_ASSERT(le32 == u32_val_conv);
		CU_ASSERT(le64 == u64_val_conv);
	} else {
		CU_ASSERT(le16 == u16_val);
		CU_ASSERT(le32 == u32_val);
		CU_ASSERT(le64 == u64_val);
		CU_ASSERT(be16 == u16_val_conv);
		CU_ASSERT(be32 == u32_val_conv);
		CU_ASSERT(be64 == u64_val_conv);
	}

	CU_ASSERT(odp_be_to_cpu_16(be16) == u16_val);
	CU_ASSERT(odp_be_to_cpu_32(be32) == u32_val);
	CU_ASSERT(odp_be_to_cpu_64(be64) == u64_val);
	CU_ASSERT(odp_le_to_cpu_16(le16) == u16_val);
	CU_ASSERT(odp_le_to_cpu_32(le32) == u32_val);
	CU_ASSERT(odp_le_to_cpu_64(le64) == u64_val);
}

odp_testinfo_t byteorder_suite[] = {
	ODP_TEST_INFO(test_defines),
	ODP_TEST_INFO(test_types),
	ODP_TEST_INFO_NULL,
};

odp_suiteinfo_t byteorder_suites[] = {
	{"byteorder", NULL, NULL, byteorder_suite},
	ODP_SUITE_INFO_NULL
};

int main(int argc, char *argv[])
{
	int ret;

	/* Parse common options */
	if (odp_cunit_parse_options(&argc, argv))
		return -1;

	ret = odp_cunit_register(byteorder_suites);

	if (ret == 0)
		ret = odp_cunit_run();

	return ret;
}
