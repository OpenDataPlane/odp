/* Copyright (c) 2016-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/helper/eth.h>

#include <stdio.h>
#include <string.h>

int odph_eth_addr_parse(odph_ethaddr_t *mac, const char *str)
{
	int byte[ODPH_ETHADDR_LEN];
	int i;

	memset(byte, 0, sizeof(byte));

	if (sscanf(str, "%x:%x:%x:%x:%x:%x",
		   &byte[0], &byte[1], &byte[2],
		   &byte[3], &byte[4], &byte[5]) != ODPH_ETHADDR_LEN)
		return -1;

	for (i = 0; i < ODPH_ETHADDR_LEN; i++)
		if (byte[i] < 0 || byte[i] > 255)
			return -1;

	mac->addr[0] = byte[0];
	mac->addr[1] = byte[1];
	mac->addr[2] = byte[2];
	mac->addr[3] = byte[3];
	mac->addr[4] = byte[4];
	mac->addr[5] = byte[5];

	return 0;
}
