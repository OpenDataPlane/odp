/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2024 Nokia
 */

#include <odp_api.h>
#include <odp/helper/odph_api.h>

#include <stdio.h>
#include <stdlib.h>

static int test_pow2(void)
{
	uint32_t in[]  = {0, 1, 2, 3,  4,   0xff,   0x100,     0xfffe,     0xffff,    0x10000};
	uint32_t out[] = {0, 1, 4, 9, 16, 0xfe01, 0x10000, 0xfffc0004, 0xfffe0001, 0xffffffff};
	uint32_t num = ODPH_ARRAY_SIZE(out);
	int ret = 0;

	printf("  odph_stress_pow2_u32() ... ");

	for (uint32_t i = 0; i < num; i++)
		if (odph_stress_pow2_u32(in[i]) != out[i])
			ret++;

	if (ret)
		printf("%i tests failed\n", ret);
	else
		printf("passed\n");

	return ret;
}

static int test_log2(void)
{
	uint32_t in[]  = {0, 1, 2, 3, 4, 5, 6, 7, 8, 15, 16, 255, 256, 257, 512, 513, 1023, 1024};
	uint32_t out[] = {0, 0, 1, 1, 2, 2, 2, 2, 3,  3,  4,   7,   8,   8,   9,   9,    9,   10};
	uint32_t num = ODPH_ARRAY_SIZE(out);
	int ret = 0;

	printf("  odph_stress_log2_u32() ... ");

	for (uint32_t i = 0; i < num; i++)
		if (odph_stress_log2_u32(in[i]) != out[i])
			ret++;

	if (ret)
		printf("%i tests failed\n", ret);
	else
		printf("passed\n");

	return ret;
}

static int test_sqrt_u32(void)
{
	uint32_t in[]  = {0, 1, 2, 3, 4, 7, 8, 9, 100, 1500, 2900, 4096, 6213, 8191, 16384, 100000,
			  1000000, 4036587, 0x42c1d80, 0x8000000, 0x1fffffff, 0x2faf0800,
			  0xffffffff};
	uint32_t out[] = {0, 1, 1, 1, 2, 2, 2, 3, 10, 38, 53, 64, 78, 90, 128, 316, 1000, 2009,
			  8366, 11585, 23170, 28284, 65535};
	uint32_t num = ODPH_ARRAY_SIZE(out);
	int ret = 0;

	printf("  odph_stress_sqrt_u32() ... ");

	for (uint32_t i = 0; i < num; i++)
		if (odph_stress_sqrt_u32(in[i]) != out[i])
			ret++;

	if (ret)
		printf("%i tests failed\n", ret);
	else
		printf("passed\n");

	return ret;
}

/*
 * 32-bit floating point can represent integers between 0 and 16777216 exactly, and integers
 * between 16777216 and 33554432 in multiples of 2, etc.
 */
static int test_sqrt_f32(void)
{
	float in[]  = {0, 1, 2, 3, 4, 7, 8, 9, 100, 1500, 2900, 4096, 6213, 8191, 16384, 100000,
		       1000000, 4036587, 16777216, 33554432, 134217728, 3000000000, 4294967296};
	float out[] = {0, 1, 1, 1, 2, 2, 2, 3, 10, 38, 53, 64, 78, 90, 128, 316, 1000, 2009, 4096,
		       5792, 11585, 54772, 65536};
	uint32_t num = ODPH_ARRAY_SIZE(out);
	int ret = 0;

	printf("  odph_stress_sqrt_f32() ... ");

	for (uint32_t i = 0; i < num; i++)
		if (odph_stress_sqrt_f32(in[i]) != out[i])
			ret++;

	if (ret)
		printf("%i tests failed\n", ret);
	else
		printf("passed\n");

	return ret;
}

int main(int argc ODP_UNUSED, char *argv[] ODP_UNUSED)
{
	int ret = 0;

	printf("Running helper algorithm tests:\n");

	ret += test_pow2();
	ret += test_log2();
	ret += test_sqrt_u32();
	ret += test_sqrt_f32();

	printf("\n");

	return ret ? EXIT_FAILURE : EXIT_SUCCESS;
}
