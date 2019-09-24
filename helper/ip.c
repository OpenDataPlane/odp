/* Copyright (c) 2016-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/helper/ip.h>

#include <stdio.h>
#include <string.h>

int odph_ipv4_addr_parse(uint32_t *ip_addr, const char *str)
{
	unsigned byte[ODPH_IPV4ADDR_LEN];
	int i;

	memset(byte, 0, sizeof(byte));

	if (sscanf(str, "%u.%u.%u.%u",
		   &byte[0], &byte[1], &byte[2], &byte[3]) != ODPH_IPV4ADDR_LEN)
		return -1;

	for (i = 0; i < ODPH_IPV4ADDR_LEN; i++)
		if (byte[i] > 255)
			return -1;

	*ip_addr = byte[0] << 24 | byte[1] << 16 | byte[2] << 8 | byte[3];

	return 0;
}
