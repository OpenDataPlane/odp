/* Copyright (c) 2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdint.h>
#include <zlib.h>

#include <odp/api/hash.h>

uint32_t odp_hash_crc32(const void *data, uint32_t data_len, uint32_t init_val)
{
	uLong crc;

	/* Zlib function XORs input and output crc values with all ones.
	 * Cancel out XORing as ODP API does not specify it. */
	crc = crc32((uLong)(init_val ^ 0xffffffff), data, data_len);

	return crc ^ 0xffffffff;
}
