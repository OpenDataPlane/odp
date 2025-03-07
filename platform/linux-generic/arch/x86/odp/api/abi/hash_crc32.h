/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 Nokia
 */

#ifndef ODP_API_ABI_HASH_CRC32_H_
#define ODP_API_ABI_HASH_CRC32_H_

#include <odp/api/std_types.h>

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

uint32_t _odp_hash_crc32_generic(const void *data, uint32_t data_len,
				 uint32_t init_val);
uint32_t _odp_hash_crc32c_generic(const void *data, uint32_t data_len,
				  uint32_t init_val);

static inline uint32_t _odp_hash_crc32(const void *data, uint32_t data_len,
				       uint32_t init_val)
{
	return _odp_hash_crc32_generic(data, data_len, init_val);
}

#ifdef __SSE4_2__

static inline uint32_t _odp_hash_crc32c(const void *data, uint32_t data_len,
					uint32_t init_val)
{
	uint32_t i;
	uintptr_t pd = (uintptr_t)data;

#ifdef __x86_64__
	for (i = 0; i < data_len / 8; i++) {
		init_val = (uint32_t)__builtin_ia32_crc32di(init_val, *(const odp_una_u64_t *)pd);
		pd += 8;
	}

	if (data_len & 0x4) {
		init_val = __builtin_ia32_crc32si(init_val, *(const odp_una_u32_t *)pd);
		pd += 4;
	}
#else
	for (i = 0; i < data_len / 4; i++) {
		init_val = __builtin_ia32_crc32si(init_val, *(const odp_una_u32_t *)pd);
		pd += 4;
	}
#endif

	if (data_len & 0x2) {
		init_val = __builtin_ia32_crc32hi(init_val, *(const odp_una_u16_t *)pd);
		pd += 2;
	}

	if (data_len & 0x1)
		init_val = __builtin_ia32_crc32qi(init_val, *(const uint8_t *)pd);

	return init_val;
}

#else

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
