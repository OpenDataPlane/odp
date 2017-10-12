/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/chksum.h>
#include <odp/api/std_types.h>

/* Simple implementation of ones complement sum.
 * Based on RFC1071 and its errata.
 */
uint16_t odp_chksum_ones_comp16(const void *p, uint32_t len)
{
	uint32_t sum = 0;
	const uint16_t *data = p;

	while (len > 1) {
		sum += *data++;
		len -= 2;
	}

	/* Add left-over byte, if any */
	if (len > 0) {
		uint16_t left_over = 0;

		*(uint8_t *)&left_over = *(const uint8_t *)data;
		sum += left_over;
	}

	/* Fold 32-bit sum to 16 bits */
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	return sum;
}
