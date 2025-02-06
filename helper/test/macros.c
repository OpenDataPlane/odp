/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2023-2025 Nokia
 */

#include <odp_api.h>
#include <odp/helper/odph_api.h>

#include <stdio.h>
#include <stdlib.h>

int main(int argc ODP_UNUSED, char *argv[] ODP_UNUSED)
{
	int a, b, tmp;
	int ret = 0;
	int arr_1[1];
	int arr_10[10];

	printf("Running helper macro tests\n");

	if (ODPH_MIN(0, 10) != 0)
		ret++;

	if (ODPH_MAX(0, 10) != 10)
		ret++;

	if (ODPH_MIN(-1, 10) != -1)
		ret++;

	if (ODPH_MAX(-1, 10) != 10)
		ret++;

	a = 0;
	b = 10;
	if (ODPH_MIN(a--, b--) != 0)
		ret++;

	a = 0;
	b = 10;
	if (ODPH_MAX(++a, ++b) != 11)
		ret++;

	if (ODPH_ARRAY_SIZE(arr_1) != 1)
		ret++;

	if (ODPH_ARRAY_SIZE(arr_10) != 10)
		ret++;

	if (ODPH_ABS(-1) != 1)
		ret++;

	if (ODPH_ABS(1) != 1)
		ret++;

	if (ODPH_ABS(0) != 0)
		ret++;

	a = -1;
	if (ODPH_ABS(a++) != 1)
		ret++;

	a = -1;
	if (ODPH_ABS(--a) != 2)
		ret++;

	if (ODPH_DIV_ROUNDUP(1, 2) != 1)
		ret++;

	a = 128;
	b = 74;
	tmp = ODPH_DIV_ROUNDUP(a += 60, b -= 10);
	if (tmp != 3)
		ret++;

	if (ODPH_ROUNDUP_MULTIPLE(24, 64) != 64)
		ret++;

	a = 128;
	b = 74;
	tmp = ODPH_ROUNDUP_MULTIPLE(a += 60, b -= 10);
	if (tmp != 192)
		ret++;

	if (!ret)
		printf("All tests passed\n");
	else
		printf("%d tests failed\n", ret);

	return ret ? EXIT_FAILURE : EXIT_SUCCESS;
}
