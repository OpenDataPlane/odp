/* Copyright (c) 2015-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "config.h"

#include <odp_api.h>
#include <odp_cunit_common.h>

#define CRC32C_INIT 0xffffffff
#define CRC32C_XOR  0xffffffff
#define CRC32_INIT  0xffffffff
#define CRC32_XOR   0xffffffff

typedef struct hash_test_vector_t {
	const uint8_t  *data;
	uint32_t  len;

	union {
		uint32_t u32;
		uint8_t  u8[4];
	} result;

} hash_test_vector_t;

/*
 * Test vectors 0-4 from RFC 7143.
 */
static const uint8_t test_data_0[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t test_data_1[] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

static const uint8_t test_data_2[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

static const uint8_t test_data_3[] = {
	0x1f, 0x1e, 0x1d, 0x1c, 0x1b, 0x1a, 0x19, 0x18,
	0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11, 0x10,
	0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08,
	0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00
};

static const uint8_t test_data_4[] = {
	0x01, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00,
	0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x18,
	0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* Various length strings. Terminating null character is not included into
 * crc calculation. */
static const uint8_t test_data_5[] = "abcd";

static const uint8_t test_data_6[] = "abcdefgh";

static const uint8_t test_data_7[] =
	"The quick brown fox jumps over the lazy dog.";

static const uint8_t test_data_8[]  = "a";

static const uint8_t test_data_9[]  = "ab";

static const uint8_t test_data_10[] = "abc";

static const uint8_t test_data_11[] = "abcdefg";

static const uint8_t test_data_12[] = "The five boxing wizards jump quickly.";

/* String of the common "check" value. */
static const uint8_t test_data_13[] = "123456789";

static const hash_test_vector_t crc32c_test_vector[] = {
	{ .data = test_data_0,
	  .len = sizeof(test_data_0),
	  .result.u8 = {0xaa, 0x36, 0x91, 0x8a}
	},
	{ .data = test_data_1,
	  .len = sizeof(test_data_1),
	  .result.u8 = {0x43, 0xab, 0xa8, 0x62}
	},
	{ .data = test_data_2,
	  .len = sizeof(test_data_2),
	  .result.u8 = {0x4e, 0x79, 0xdd, 0x46}
	},
	{ .data = test_data_3,
	  .len = sizeof(test_data_3),
	  .result.u8 = {0x5c, 0xdb, 0x3f, 0x11}
	},
	{ .data = test_data_4,
	  .len = sizeof(test_data_4),
	  .result.u8 = {0x56, 0x3a, 0x96, 0xd9}
	},
	{ .data = test_data_5,
	  .len = sizeof(test_data_5) - 1,
	  .result.u8 = {0x31, 0x0a, 0xc8, 0x92}
	},
	{ .data = test_data_6,
	  .len = sizeof(test_data_6) - 1,
	  .result.u8 = {0xb7, 0x21, 0x94, 0x0a}
	},
	{ .data = test_data_7,
	  .len = sizeof(test_data_7) - 1,
	  .result.u8 = {0xb3, 0x97, 0x00, 0x19}
	},
	{ .data = test_data_8,
	  .len = sizeof(test_data_8) - 1,
	  .result.u8 = {0x30, 0x43, 0xd0, 0xc1}
	},
	{ .data = test_data_9,
	  .len = sizeof(test_data_9) - 1,
	  .result.u8 = {0x36, 0x29, 0xa2, 0xe2}
	},
	{ .data = test_data_10,
	  .len = sizeof(test_data_10) - 1,
	  .result.u8 = {0xb7, 0x3f, 0x4b, 0x36}
	},
	{ .data = test_data_11,
	  .len = sizeof(test_data_11) - 1,
	  .result.u8 = {0x41, 0xf4, 0x27, 0xe6}
	},
	{ .data = test_data_12,
	  .len = sizeof(test_data_12) - 1,
	  .result.u8 = {0x9a, 0x05, 0xd3, 0xde}
	},
	{ .data = test_data_13,
	  .len = sizeof(test_data_13) - 1,
	  .result.u8 = {0x83, 0x92, 0x06, 0xe3}
	}
};

static const hash_test_vector_t crc32_test_vector[] = {
	{ .data = test_data_0,
	  .len = sizeof(test_data_0),
	  .result.u8 = {0xad, 0x55, 0x0a, 0x19}
	},
	{ .data = test_data_1,
	  .len = sizeof(test_data_1),
	  .result.u8 = {0x0b, 0xab, 0x6c, 0xff}
	},
	{ .data = test_data_2,
	  .len = sizeof(test_data_2),
	  .result.u8 = {0x8a, 0x7e, 0x26, 0x91}
	},
	{ .data = test_data_3,
	  .len = sizeof(test_data_3),
	  .result.u8 = {0x72, 0xef, 0xb0, 0x9a}
	},
	{ .data = test_data_4,
	  .len = sizeof(test_data_4),
	  .result.u8 = {0x12, 0x74, 0xe1, 0x51}
	},
	{ .data = test_data_5,
	  .len = sizeof(test_data_5) - 1,
	  .result.u8 = {0x11, 0xcd, 0x82, 0xed}
	},
	{ .data = test_data_6,
	  .len = sizeof(test_data_6) - 1,
	  .result.u8 = {0x50, 0x2a, 0xef, 0xae}
	},
	{ .data = test_data_7,
	  .len = sizeof(test_data_7) - 1,
	  .result.u8 = {0xe9, 0x25, 0x90, 0x51}
	},
	{ .data = test_data_8,
	  .len = sizeof(test_data_8) - 1,
	  .result.u8 = {0x43, 0xbe, 0xb7, 0xe8}
	},
	{ .data = test_data_9,
	  .len = sizeof(test_data_9) - 1,
	  .result.u8 = {0x6d, 0x48, 0x83, 0x9e}
	},
	{ .data = test_data_10,
	  .len = sizeof(test_data_10) - 1,
	  .result.u8 = {0xc2, 0x41, 0x24, 0x35}
	},
	{ .data = test_data_11,
	  .len = sizeof(test_data_11) - 1,
	  .result.u8 = {0xa6, 0x6a, 0x2a, 0x31}
	},
	{ .data = test_data_12,
	  .len = sizeof(test_data_12) - 1,
	  .result.u8 = {0xcd, 0x2a, 0x91, 0xde}
	},
	{ .data = test_data_13,
	  .len = sizeof(test_data_13) - 1,
	  .result.u8 = {0x26, 0x39, 0xf4, 0xcb}
	}
};

static void hash_test_crc32c(void)
{
	uint32_t ret, result;
	int i;
	int num = sizeof(crc32c_test_vector) / sizeof(hash_test_vector_t);

	for (i = 0; i < num; i++) {
		ret = odp_hash_crc32c(crc32c_test_vector[i].data,
				      crc32c_test_vector[i].len,
				      CRC32C_INIT);

		result = CRC32C_XOR ^ ret;
		CU_ASSERT(result == crc32c_test_vector[i].result.u32);
	}
}

static void hash_test_crc32(void)
{
	uint32_t ret, result;
	int i;
	int num = sizeof(crc32_test_vector) / sizeof(hash_test_vector_t);

	for (i = 0; i < num; i++) {
		ret = odp_hash_crc32(crc32_test_vector[i].data,
				     crc32_test_vector[i].len,
				     CRC32_INIT);

		result = CRC32_XOR ^ ret;
		CU_ASSERT(result == crc32_test_vector[i].result.u32);
	}
}

odp_testinfo_t hash_suite[] = {
	ODP_TEST_INFO(hash_test_crc32c),
	ODP_TEST_INFO(hash_test_crc32),
	ODP_TEST_INFO_NULL,
};

odp_suiteinfo_t hash_suites[] = {
	{"Hash", NULL, NULL, hash_suite},
	ODP_SUITE_INFO_NULL
};

int main(int argc, char *argv[])
{
	int ret;

	/* parse common options: */
	if (odp_cunit_parse_options(argc, argv))
		return -1;

	ret = odp_cunit_register(hash_suites);

	if (ret == 0)
		ret = odp_cunit_run();

	return ret;
}
