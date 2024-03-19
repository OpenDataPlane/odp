/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2018 Linaro Limited
 */

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>

#include <odp/api/hash.h>
#include <odp/api/hints.h>
#include <odp/api/rwlock.h>
#include <odp/api/shared_memory.h>

#include <odp_debug_internal.h>
#include <odp_init_internal.h>

typedef struct crc_table_t {
	uint32_t crc[256];
	uint32_t width;
	uint32_t poly;
	int      reflect;
	odp_rwlock_t rwlock;
	odp_shm_t shm;

} crc_table_t;

static crc_table_t *crc_table;

int _odp_hash_init_global(void)
{
	odp_shm_t shm;

	shm = odp_shm_reserve("_odp_hash_crc_gen", sizeof(crc_table_t),
			      ODP_CACHE_LINE_SIZE, 0);

	crc_table = odp_shm_addr(shm);

	if (crc_table == NULL) {
		_ODP_ERR("Shm reserve failed for odp_hash_crc_gen\n");
		return -1;
	}

	memset(crc_table, 0, sizeof(crc_table_t));

	crc_table->shm = shm;
	odp_rwlock_init(&crc_table->rwlock);

	return 0;
}

int _odp_hash_term_global(void)
{
	if (odp_shm_free(crc_table->shm)) {
		_ODP_ERR("Shm free failed for odp_hash_crc_gen\n");
		return -1;
	}

	return 0;
}

/* Reflect bits in a byte */
static inline uint8_t reflect_u8(uint8_t byte)
{
	uint8_t u8[8];

	u8[0] = (byte & (0x1u << 7)) >> 7;
	u8[1] = (byte & (0x1u << 6)) >> 5;
	u8[2] = (byte & (0x1u << 5)) >> 3;
	u8[3] = (byte & (0x1u << 4)) >> 1;

	u8[4] = (byte & (0x1u << 3)) << 1;
	u8[5] = (byte & (0x1u << 2)) << 3;
	u8[6] = (byte & (0x1u << 1)) << 5;
	u8[7] = (byte & 0x1u) << 7;

	return u8[0] | u8[1] | u8[2] | u8[3] | u8[4] | u8[5] | u8[6] | u8[7];
}

/* Reflect 32 bits */
static inline uint32_t reflect_u32(uint32_t u32)
{
	uint32_t r[4];

	r[0] = reflect_u8((u32 & 0xff000000u) >> 24);
	r[1] = reflect_u8((u32 & 0x00ff0000u) >> 16);
	r[2] = reflect_u8((u32 & 0x0000ff00u) >> 8);
	r[3] = reflect_u8(u32 & 0xffu);

	return (r[3] << 24) | (r[2] << 16) | (r[1] << 8) | r[0];
}

/* Reflect 24 bits */
static inline uint32_t reflect_u24(uint32_t u32)
{
	uint32_t r[4];

	r[0] = reflect_u8((u32 & 0xff0000u) >> 16);
	r[1] = reflect_u8((u32 & 0x00ff00u) >> 8);
	r[2] = reflect_u8(u32 & 0xffu);

	return (r[2] << 16) | (r[1] << 8) | r[0];
}

/* Reflect 16 bits */
static inline uint32_t reflect_u16(uint32_t u32)
{
	uint32_t r[4];

	r[0] = reflect_u8((u32 & 0xff00u) >> 8);
	r[1] = reflect_u8(u32 & 0xffu);

	return (r[1] << 8) | r[0];
}

/* Generate table for a 32/24/16 bit CRCs.
 *
 * Based on an example in RFC 1952.
 */
static inline void crc_table_gen(uint32_t poly, int reflect, int width)
{
	uint32_t i, crc, bit, shift, msb, mask;

	crc_table->width   = width;
	crc_table->poly    = poly;
	crc_table->reflect = reflect;

	shift = width - 8;
	mask  = 0xffffffffu >> (32 - width);
	msb   = 0x1u << (width - 1);

	if (reflect) {
		if (width == 32)
			poly = reflect_u32(poly);
		else if (width == 24)
			poly = reflect_u24(poly);
		else
			poly = reflect_u16(poly);
	}

	for (i = 0; i < 256; i++) {
		if (reflect) {
			crc = i;

			for (bit = 0; bit < 8; bit++) {
				if (crc & 0x1u)
					crc = poly ^ (crc >> 1);
				else
					crc = crc >> 1;
			}
		} else {
			crc = i << shift;

			for (bit = 0; bit < 8; bit++) {
				if (crc & msb)
					crc = poly ^ (crc << 1);
				else
					crc = crc << 1;
			}
		}

		crc_table->crc[i] = crc & mask;
	}
}

static inline uint32_t crc_calc(const uint8_t *data, uint32_t data_len,
				uint32_t init_val, int reflect, int width)
{
	uint32_t i, crc, shift;
	uint8_t byte;
	uint32_t mask;

	shift = width - 8;
	mask  = 0xffffffffu >> (32 - width);

	crc = init_val;

	for (i = 0; i < data_len; i++) {
		byte = data[i];

		if (reflect) {
			crc = crc_table->crc[(crc ^ byte) & 0xffu] ^ (crc >> 8);
		} else {
			crc = crc_table->crc[(crc >> shift) ^ byte] ^
					(crc << 8);
			crc = crc & mask;
		}
	}

	return crc;
}

int odp_hash_crc_gen64(const void *data_ptr, uint32_t data_len,
		       uint64_t init_val, odp_hash_crc_param_t *crc_param,
		       uint64_t *crc_out)
{
	uint32_t crc;
	int update_table;
	uint32_t poly = crc_param->poly;
	uint32_t width = crc_param->width;
	int reflect = crc_param->reflect_in;

	if (odp_unlikely(crc_param->reflect_in != crc_param->reflect_out)) {
		_ODP_ERR("Odd reflection setting not supported.\n");
		return -1;
	}

	if (odp_unlikely(width != 32 && width != 24 && width != 16)) {
		_ODP_ERR("CRC width %" PRIu32 " bits not supported.\n", width);
		return -1;
	}

	/* TODO: fix implementation of 24 bit CRC with reflection */
	if (odp_unlikely(width == 24 && reflect)) {
		_ODP_ERR("24 bit CRC with reflection not supported.\n");
		return -1;
	}

	odp_rwlock_read_lock(&crc_table->rwlock);

	update_table = (crc_table->width != width) ||
		       (crc_table->poly != poly) ||
		       (crc_table->reflect != reflect);

	/* Generate CRC table if not yet generated. */
	if (odp_unlikely(update_table)) {
		odp_rwlock_read_unlock(&crc_table->rwlock);
		odp_rwlock_write_lock(&crc_table->rwlock);

		crc_table_gen(poly, reflect, width);
	}

	crc = crc_calc(data_ptr, data_len, init_val, reflect, width);

	if (odp_unlikely(update_table))
		odp_rwlock_write_unlock(&crc_table->rwlock);
	else
		odp_rwlock_read_unlock(&crc_table->rwlock);

	if (crc_param->xor_out)
		crc = crc ^ (uint32_t)crc_param->xor_out;

	*crc_out = crc;

	return 0;
}
