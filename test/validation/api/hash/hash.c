/* Copyright (c) 2015-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_api.h>
#include <odp_cunit_common.h>

/* Commonly used CRC check string */
#define CHECK_STR   "123456789"
#define CHECK_LEN   9

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

static const uint8_t test_data_13[] = CHECK_STR;

static const hash_test_vector_t crc32c_test_vector[] = {
	{ .data = test_data_0,
	  .len = sizeof(test_data_0),
	  .result.u32 = 0x8a9136aa
	},
	{ .data = test_data_1,
	  .len = sizeof(test_data_1),
	  .result.u32 = 0x62a8ab43
	},
	{ .data = test_data_2,
	  .len = sizeof(test_data_2),
	  .result.u32 = 0x46dd794e
	},
	{ .data = test_data_3,
	  .len = sizeof(test_data_3),
	  .result.u32 = 0x113fdb5c
	},
	{ .data = test_data_4,
	  .len = sizeof(test_data_4),
	  .result.u32 = 0xd9963a56
	},
	{ .data = test_data_5,
	  .len = sizeof(test_data_5) - 1,
	  .result.u32 = 0x92c80a31
	},
	{ .data = test_data_6,
	  .len = sizeof(test_data_6) - 1,
	  .result.u32 = 0x0a9421b7
	},
	{ .data = test_data_7,
	  .len = sizeof(test_data_7) - 1,
	  .result.u32 = 0x190097b3
	},
	{ .data = test_data_8,
	  .len = sizeof(test_data_8) - 1,
	  .result.u32 = 0xc1d04330
	},
	{ .data = test_data_9,
	  .len = sizeof(test_data_9) - 1,
	  .result.u32 = 0xe2a22936
	},
	{ .data = test_data_10,
	  .len = sizeof(test_data_10) - 1,
	  .result.u32 = 0x364b3fb7
	},
	{ .data = test_data_11,
	  .len = sizeof(test_data_11) - 1,
	  .result.u32 = 0xe627f441
	},
	{ .data = test_data_12,
	  .len = sizeof(test_data_12) - 1,
	  .result.u32 = 0xded3059a
	},
	{ .data = test_data_13,
	  .len = sizeof(test_data_13) - 1,
	  .result.u32 = 0xe3069283
	}
};

static const hash_test_vector_t crc32_test_vector[] = {
	{ .data = test_data_0,
	  .len = sizeof(test_data_0),
	  .result.u32 = 0x190a55ad
	},
	{ .data = test_data_1,
	  .len = sizeof(test_data_1),
	  .result.u32 = 0xff6cab0b
	},
	{ .data = test_data_2,
	  .len = sizeof(test_data_2),
	  .result.u32 = 0x91267e8a
	},
	{ .data = test_data_3,
	  .len = sizeof(test_data_3),
	  .result.u32 = 0x9ab0ef72
	},
	{ .data = test_data_4,
	  .len = sizeof(test_data_4),
	  .result.u32 = 0x51e17412
	},
	{ .data = test_data_5,
	  .len = sizeof(test_data_5) - 1,
	  .result.u32 = 0xed82cd11
	},
	{ .data = test_data_6,
	  .len = sizeof(test_data_6) - 1,
	  .result.u32 = 0xaeef2a50
	},
	{ .data = test_data_7,
	  .len = sizeof(test_data_7) - 1,
	  .result.u32 = 0x519025e9
	},
	{ .data = test_data_8,
	  .len = sizeof(test_data_8) - 1,
	  .result.u32 = 0xe8b7be43
	},
	{ .data = test_data_9,
	  .len = sizeof(test_data_9) - 1,
	  .result.u32 = 0x9e83486d
	},
	{ .data = test_data_10,
	  .len = sizeof(test_data_10) - 1,
	  .result.u32 = 0x352441c2
	},
	{ .data = test_data_11,
	  .len = sizeof(test_data_11) - 1,
	  .result.u32 = 0x312a6aa6
	},
	{ .data = test_data_12,
	  .len = sizeof(test_data_12) - 1,
	  .result.u32 = 0xde912acd
	},
	{ .data = test_data_13,
	  .len = sizeof(test_data_13) - 1,
	  .result.u32 = 0xcbf43926
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

/*
 * Test various commonly used 32 bit CRCs. Used CRC names, parameters and
 * check values can be found e.g. here:
 * http://reveng.sourceforge.net/crc-catalogue
 */
static void hash_test_crc32_generic(void)
{
	uint64_t result_u64;
	uint32_t result_u32, result;
	int i, num;
	odp_hash_crc_param_t crc_param;

	memset(&crc_param, 0, sizeof(odp_hash_crc_param_t));
	crc_param.width       = 32;
	crc_param.xor_out     = 0;

	/* CRC-32 */
	crc_param.poly        = 0x04c11db7;
	crc_param.reflect_in  = 1;
	crc_param.reflect_out = 1;
	num = sizeof(crc32_test_vector) / sizeof(hash_test_vector_t);

	for (i = 0; i < num; i++) {
		if (odp_hash_crc_gen64(crc32_test_vector[i].data,
				       crc32_test_vector[i].len,
				       CRC32_INIT,
				       &crc_param, &result_u64)) {
			printf("CRC-32 not supported\n.");
			break;
		}

		result_u32 = CRC32_XOR ^ result_u64;
		CU_ASSERT(result_u32 == crc32_test_vector[i].result.u32);
	}

	/* CRC-32C */
	crc_param.poly        = 0x1edc6f41;
	crc_param.reflect_in  = 1;
	crc_param.reflect_out = 1;
	num = sizeof(crc32c_test_vector) / sizeof(hash_test_vector_t);

	for (i = 0; i < num; i++) {
		if (odp_hash_crc_gen64(crc32c_test_vector[i].data,
				       crc32c_test_vector[i].len,
				       CRC32C_INIT,
				       &crc_param, &result_u64)) {
			printf("CRC-32C not supported\n.");
			break;
		}

		result_u32 = CRC32C_XOR ^ result_u64;
		CU_ASSERT(result_u32 == crc32c_test_vector[i].result.u32);
	}

	/* CRC-32/AUTOSAR */
	crc_param.poly        = 0xf4acfb13;
	crc_param.reflect_in  = 1;
	crc_param.reflect_out = 1;
	result = 0x1697d06a;

	if (odp_hash_crc_gen64(CHECK_STR, CHECK_LEN, 0xffffffff,
			       &crc_param, &result_u64) == 0) {
		result_u32 = 0xffffffff ^ result_u64;
		CU_ASSERT(result_u32 == result);
	} else {
		printf("CRC-32/AUTOSAR not supported\n.");
	}

	/* CRC-32/BZIP2 */
	crc_param.poly        = 0x04c11db7;
	crc_param.reflect_in  = 0;
	crc_param.reflect_out = 0;
	result = 0xfc891918;

	if (odp_hash_crc_gen64(CHECK_STR, CHECK_LEN, 0xffffffff,
			       &crc_param, &result_u64) == 0) {
		result_u32 = 0xffffffff ^ result_u64;
		CU_ASSERT(result_u32 == result);
	} else {
		printf("CRC-32/BZIP2 not supported\n.");
	}

	/* CRC-32D */
	crc_param.poly        = 0xa833982b;
	crc_param.reflect_in  = 1;
	crc_param.reflect_out = 1;
	result = 0x87315576;

	if (odp_hash_crc_gen64(CHECK_STR, CHECK_LEN, 0xffffffff,
			       &crc_param, &result_u64) == 0) {
		result_u32 = 0xffffffff ^ result_u64;
		CU_ASSERT(result_u32 == result);
	} else {
		printf("CRC-32D not supported\n.");
	}

	/* CRC-32/MPEG-2 */
	crc_param.poly        = 0x04c11db7;
	crc_param.reflect_in  = 0;
	crc_param.reflect_out = 0;
	result = 0x0376e6e7;

	if (odp_hash_crc_gen64(CHECK_STR, CHECK_LEN, 0xffffffff,
			       &crc_param, &result_u64) == 0) {
		result_u32 = 0x0 ^ result_u64;
		CU_ASSERT(result_u32 == result);
	} else {
		printf("CRC-32/MPEG-2 not supported\n.");
	}

	/* CRC-32/POSIX */
	crc_param.poly        = 0x04c11db7;
	crc_param.reflect_in  = 0;
	crc_param.reflect_out = 0;
	result = 0x765e7680;

	if (odp_hash_crc_gen64(CHECK_STR, CHECK_LEN, 0x0,
			       &crc_param, &result_u64) == 0) {
		result_u32 = 0xffffffff ^ result_u64;
		CU_ASSERT(result_u32 == result);
	} else {
		printf("CRC-32/POSIX not supported\n.");
	}

	/* CRC-32/POSIX - with XOR parameter used */
	crc_param.xor_out = 0xffffffff;

	if (odp_hash_crc_gen64(CHECK_STR, CHECK_LEN, 0x0,
			       &crc_param, &result_u64) == 0) {
		result_u32 = result_u64;
		CU_ASSERT(result_u32 == result);
	} else {
		printf("CRC-32/POSIX (with XOR) not supported\n.");
	}

	crc_param.xor_out = 0;

	/* CRC-32Q */
	crc_param.poly        = 0x814141ab;
	crc_param.reflect_in  = 0;
	crc_param.reflect_out = 0;
	result = 0x3010bf7f;

	if (odp_hash_crc_gen64(CHECK_STR, CHECK_LEN, 0x0,
			       &crc_param, &result_u64) == 0) {
		result_u32 = 0x0 ^ result_u64;
		CU_ASSERT(result_u32 == result);
	} else {
		printf("CRC-32Q not supported\n.");
	}

	/* CRC-32/JAMCRC */
	crc_param.poly        = 0x04c11db7;
	crc_param.reflect_in  = 1;
	crc_param.reflect_out = 1;
	result = 0x340bc6d9;

	if (odp_hash_crc_gen64(CHECK_STR, CHECK_LEN, 0xffffffff,
			       &crc_param, &result_u64) == 0) {
		result_u32 = 0x0 ^ result_u64;
		CU_ASSERT(result_u32 == result);
	} else {
		printf("CRC-32/JAMCRC not supported\n.");
	}

	/* CRC-32/XFER */
	crc_param.poly        = 0x000000af;
	crc_param.reflect_in  = 0;
	crc_param.reflect_out = 0;
	result = 0xbd0be338;

	if (odp_hash_crc_gen64(CHECK_STR, CHECK_LEN, 0x0,
			       &crc_param, &result_u64) == 0) {
		result_u32 = 0x0 ^ result_u64;
		CU_ASSERT(result_u32 == result);
	} else {
		printf("CRC-32/XFER not supported\n.");
	}
}

static void hash_test_crc24_generic(void)
{
	uint64_t result_u64;
	uint32_t result_u32, result;
	odp_hash_crc_param_t crc_param;

	memset(&crc_param, 0, sizeof(odp_hash_crc_param_t));
	crc_param.width       = 24;
	crc_param.xor_out     = 0;

	/* CRC-24 */
	crc_param.poly        = 0x864cfb;
	crc_param.reflect_in  = 0;
	crc_param.reflect_out = 0;
	result = 0x21cf02;

	if (odp_hash_crc_gen64(CHECK_STR, CHECK_LEN, 0xb704ce,
			       &crc_param, &result_u64) == 0) {
		result_u32 = 0x0 ^ result_u64;
		CU_ASSERT(result_u32 == result);
	} else {
		printf("CRC-24 not supported\n.");
	}

	/* CRC-24/FLEXRAY-A */
	crc_param.poly        = 0x5d6dcb;
	crc_param.reflect_in  = 0;
	crc_param.reflect_out = 0;
	result = 0x7979bd;

	if (odp_hash_crc_gen64(CHECK_STR, CHECK_LEN, 0xfedcba,
			       &crc_param, &result_u64) == 0) {
		result_u32 = 0x0 ^ result_u64;
		CU_ASSERT(result_u32 == result);
	} else {
		printf("CRC-24/FLEXRAY-A not supported\n.");
	}

	/* CRC-24/FLEXRAY-B */
	result = 0x1f23b8;

	if (odp_hash_crc_gen64(CHECK_STR, CHECK_LEN, 0xabcdef,
			       &crc_param, &result_u64) == 0) {
		result_u32 = 0x0 ^ result_u64;
		CU_ASSERT(result_u32 == result);
	} else {
		printf("CRC-24/FLEXRAY-B not supported\n.");
	}

	/* CRC-24/INTERLAKEN */
	crc_param.poly        = 0x328b63;
	crc_param.reflect_in  = 0;
	crc_param.reflect_out = 0;
	result = 0xb4f3e6;

	if (odp_hash_crc_gen64(CHECK_STR, CHECK_LEN, 0xffffff,
			       &crc_param, &result_u64) == 0) {
		result_u32 = 0xffffff ^ result_u64;
		CU_ASSERT(result_u32 == result);
	} else {
		printf("CRC-24/INTERLAKEN not supported\n.");
	}

	/* CRC-24/LTE-A */
	crc_param.poly        = 0x864cfb;
	crc_param.reflect_in  = 0;
	crc_param.reflect_out = 0;
	result = 0xcde703;

	if (odp_hash_crc_gen64(CHECK_STR, CHECK_LEN, 0x0,
			       &crc_param, &result_u64) == 0) {
		result_u32 = 0x0 ^ result_u64;
		CU_ASSERT(result_u32 == result);
	} else {
		printf("CRC-24/LTE-A not supported\n.");
	}

	/* CRC-24/LTE-B */
	crc_param.poly        = 0x800063;
	crc_param.reflect_in  = 0;
	crc_param.reflect_out = 0;
	result = 0x23ef52;

	if (odp_hash_crc_gen64(CHECK_STR, CHECK_LEN, 0x0,
			       &crc_param, &result_u64) == 0) {
		result_u32 = 0x0 ^ result_u64;
		CU_ASSERT(result_u32 == result);
	} else {
		printf("CRC-24/LTE-B not supported\n.");
	}

	/* CRC-24/BLE */
	crc_param.poly        = 0x00065b;
	crc_param.reflect_in  = 1;
	crc_param.reflect_out = 1;
	result = 0xc25a56;

	if (odp_hash_crc_gen64(CHECK_STR, CHECK_LEN, 0x555555,
			       &crc_param, &result_u64) == 0) {
		result_u32 = 0x0 ^ result_u64;
		CU_ASSERT(result_u32 == result);
	} else {
		printf("CRC-24/BLE not supported\n.");
	}
}

static void hash_test_crc16_generic(void)
{
	uint64_t result_u64;
	uint16_t result_u16, result;
	odp_hash_crc_param_t crc_param;

	memset(&crc_param, 0, sizeof(odp_hash_crc_param_t));
	crc_param.width       = 16;
	crc_param.xor_out     = 0;

	/* CRC-16/ARC */
	crc_param.poly        = 0x8005;
	crc_param.reflect_in  = 1;
	crc_param.reflect_out = 1;
	result = 0xbb3d;

	if (odp_hash_crc_gen64(CHECK_STR, CHECK_LEN, 0x0,
			       &crc_param, &result_u64) == 0) {
		result_u16 = 0x0 ^ result_u64;
		CU_ASSERT(result_u16 == result);
	} else {
		printf("CRC-16/ARC not supported\n.");
	}

	/* CRC-16/UMTS */
	crc_param.poly        = 0x8005;
	crc_param.reflect_in  = 0;
	crc_param.reflect_out = 0;
	result = 0xfee8;

	if (odp_hash_crc_gen64(CHECK_STR, CHECK_LEN, 0x0,
			       &crc_param, &result_u64) == 0) {
		result_u16 = 0x0 ^ result_u64;
		CU_ASSERT(result_u16 == result);
	} else {
		printf("CRC-16/UMTS not supported\n.");
	}

	/* CRC-16/CDMA2000 */
	crc_param.poly        = 0xc867;
	crc_param.reflect_in  = 0;
	crc_param.reflect_out = 0;
	result = 0x4c06;

	if (odp_hash_crc_gen64(CHECK_STR, CHECK_LEN, 0xffff,
			       &crc_param, &result_u64) == 0) {
		result_u16 = 0x0 ^ result_u64;
		CU_ASSERT(result_u16 == result);
	} else {
		printf("CRC-16/CDMA2000 not supported\n.");
	}

	/* CRC-16/GENIBUS */
	crc_param.poly        = 0x1021;
	crc_param.reflect_in  = 0;
	crc_param.reflect_out = 0;
	result = 0xd64e;

	if (odp_hash_crc_gen64(CHECK_STR, CHECK_LEN, 0xffff,
			       &crc_param, &result_u64) == 0) {
		result_u16 = 0xffff ^ result_u64;
		CU_ASSERT(result_u16 == result);
	} else {
		printf("CRC-16/GENIBUS not supported\n.");
	}

	/* CRC-16/T10-DIF */
	crc_param.poly        = 0x8bb7;
	crc_param.reflect_in  = 0;
	crc_param.reflect_out = 0;
	result = 0xd0db;

	if (odp_hash_crc_gen64(CHECK_STR, CHECK_LEN, 0x0,
			       &crc_param, &result_u64) == 0) {
		result_u16 = 0x0 ^ result_u64;
		CU_ASSERT(result_u16 == result);
	} else {
		printf("CRC-16/T10-DIF not supported\n.");
	}

	/* CRC-16/USB */
	crc_param.poly        = 0x8005;
	crc_param.reflect_in  = 1;
	crc_param.reflect_out = 1;
	result = 0xb4c8;

	if (odp_hash_crc_gen64(CHECK_STR, CHECK_LEN, 0xffff,
			       &crc_param, &result_u64) == 0) {
		result_u16 = 0xffff ^ result_u64;
		CU_ASSERT(result_u16 == result);
	} else {
		printf("CRC-16/USB not supported\n.");
	}

	/* CRC-16/CCITT */
	crc_param.poly        = 0x1021;
	crc_param.reflect_in  = 1;
	crc_param.reflect_out = 1;
	result = 0x2189;

	if (odp_hash_crc_gen64(CHECK_STR, CHECK_LEN, 0x0,
			       &crc_param, &result_u64) == 0) {
		result_u16 = 0x0 ^ result_u64;
		CU_ASSERT(result_u16 == result);
	} else {
		printf("CRC-16/CCITT not supported\n.");
	}

	/* CRC-16/X-25 */
	crc_param.poly        = 0x1021;
	crc_param.reflect_in  = 1;
	crc_param.reflect_out = 1;
	result = 0x906e;

	if (odp_hash_crc_gen64(CHECK_STR, CHECK_LEN, 0xffff,
			       &crc_param, &result_u64) == 0) {
		result_u16 = 0xffff ^ result_u64;
		CU_ASSERT(result_u16 == result);
	} else {
		printf("CRC-16/X25 not supported\n.");
	}
}

odp_testinfo_t hash_suite[] = {
	ODP_TEST_INFO(hash_test_crc32c),
	ODP_TEST_INFO(hash_test_crc32),
	ODP_TEST_INFO(hash_test_crc32_generic),
	ODP_TEST_INFO(hash_test_crc24_generic),
	ODP_TEST_INFO(hash_test_crc16_generic),
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
