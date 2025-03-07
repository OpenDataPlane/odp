/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ARM Limited
 */

#ifndef ODP_API_ABI_HASH_CRC32_H_
#define ODP_API_ABI_HASH_CRC32_H_

#include <stdint.h>

#ifdef __ARM_FEATURE_CRC32
#include <arm_acle.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

uint32_t _odp_hash_crc32_generic(const void *data, uint32_t data_len,
				 uint32_t init_val);
uint32_t _odp_hash_crc32c_generic(const void *data, uint32_t data_len,
				  uint32_t init_val);

#ifdef __ARM_FEATURE_CRC32

static inline uint32_t _odp_hash_crc32(const void *data_ptr, uint32_t data_len,
				       uint32_t init_val)
{
	uint32_t i;
	uintptr_t pd = (uintptr_t)data_ptr;

	for (i = 0; i < data_len / 8; i++) {
		init_val = __crc32d(init_val, *(const uint64_t *)pd);
		pd += 8;
	}

	if (data_len & 0x4) {
		init_val = __crc32w(init_val, *(const uint32_t *)pd);
		pd += 4;
	}

	if (data_len & 0x2) {
		init_val = __crc32h(init_val, *(const uint16_t *)pd);
		pd += 2;
	}

	if (data_len & 0x1)
		init_val = __crc32b(init_val, *(const uint8_t *)pd);

	return init_val;
}

static inline uint32_t _odp_hash_crc32c(const void *data, uint32_t data_len,
					uint32_t init_val)
{
	uint32_t i;
	uintptr_t pd = (uintptr_t)data;

	for (i = 0; i < data_len / 8; i++) {
		init_val = __crc32cd(init_val, *(const uint64_t *)pd);
		pd += 8;
	}

	if (data_len & 0x4) {
		init_val = __crc32cw(init_val, *(const uint32_t *)pd);
		pd += 4;
	}

	if (data_len & 0x2) {
		init_val = __crc32ch(init_val, *(const uint16_t *)pd);
		pd += 2;
	}

	if (data_len & 0x1)
		init_val = __crc32cb(init_val, *(const uint8_t *)pd);

	return init_val;
}

#else /* __ARM_FEATURE_CRC32 */

/*
 * Fall back to software implementation
 */

static inline uint32_t _odp_hash_crc32(const void *data, uint32_t data_len,
				       uint32_t init_val)
{
	return _odp_hash_crc32_generic(data, data_len, init_val);
}

static inline uint32_t _odp_hash_crc32c(const void *data, uint32_t data_len,
					uint32_t init_val)
{
	return _odp_hash_crc32c_generic(data, data_len, init_val);
}

#endif

#ifdef __cplusplus
}
#endif

#endif
