/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_coremask.h>
#include <odp_debug.h>

#include <stdlib.h>
#include <string.h>

#define MAX_CORE_NUM	64


void odp_coremask_from_str(const char *str, odp_coremask_t *mask)
{
	uint64_t mask_u64;

	if (strlen(str) > 18) {
		/* more than 64 bits */
		return;
	}

	mask_u64 = strtoull(str, NULL, 16);

	odp_coremask_from_u64(&mask_u64, 1, mask);
}


void odp_coremask_to_str(char *str, int len, const odp_coremask_t *mask)
{
	int ret;

	ret = snprintf(str, len, "0x%"PRIx64"", mask->_u64[0]);

	if (ret >= 0 && ret < len) {
		/* force trailing zero */
		str[len-1] = '\0';
	}
}


void odp_coremask_from_u64(const uint64_t *u64, int num, odp_coremask_t *mask)
{
	int i;

	if (num > ODP_COREMASK_SIZE_U64) {
		/* force max size */
		num = ODP_COREMASK_SIZE_U64;
	}

	for (i = 0; i < num; i++) {
		/* */
		mask->_u64[0] |= u64[i];
	}
}

void odp_coremask_set(int core, odp_coremask_t *mask)
{
	/* should not be more than 63
	 * core no. should be from 0..63= 64bit
	 */
	if (core >= MAX_CORE_NUM) {
		ODP_ERR("invalid core count\n");
		return;
	}

	mask->_u64[0] |=  (1 << core);
}

void odp_coremask_clr(int core, odp_coremask_t *mask)
{
	/* should not be more than 63
	 * core no. should be from 0..63= 64bit
	 */
	if (core >= MAX_CORE_NUM) {
		ODP_ERR("invalid core count\n");
		return;
	}

	mask->_u64[0] &= ~(1 << core);
}


int odp_coremask_isset(int core, const odp_coremask_t *mask)
{
	/* should not be more than 63
	 * core no. should be from 0..63= 64bit
	 */
	if (core >= MAX_CORE_NUM) {
		ODP_ERR("invalid core count\n");
		return -1;
	}

	return (mask->_u64[0] >> core) & 1;
}

int odp_coremask_count(const odp_coremask_t *mask)
{
	uint64_t coremask = mask->_u64[0];
	int cnt = 0;

	while (coremask != 0) {
		coremask >>= 1;
		if (coremask & 1)
			cnt++;
	}

	return cnt;
}
