/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2015-2018 Linaro Limited
 */

/**
 * @file
 *
 * ODP Hash functions
 */

#ifndef ODP_API_SPEC_HASH_H_
#define ODP_API_SPEC_HASH_H_
#include <odp/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/std_types.h>

/** @defgroup odp_hash ODP HASH
 *  Hash functions.
 *  @{
 */

/**
* Calculate CRC-32
*
* Calculates CRC-32 over the data. The polynomial is 0x04c11db7.
*
* @param data       Pointer to data
* @param data_len   Data length in bytes
* @param init_val   CRC generator initialization value
*
* @return CRC32 value
*/
uint32_t odp_hash_crc32(const void *data, uint32_t data_len, uint32_t init_val);

/**
* Calculate CRC-32C
*
* Calculates CRC-32C (a.k.a. CRC-32 Castagnoli) over the data.
* The polynomial is 0x1edc6f41.
*
* @param data       Pointer to data
* @param data_len   Data length in bytes
* @param init_val   CRC generator initialization value
*
* @return CRC32C value
*/
uint32_t odp_hash_crc32c(const void *data, uint32_t data_len,
			 uint32_t init_val);

/**
* CRC parameters
*
* Supports CRCs up to 64 bits
*/
typedef struct odp_hash_crc_param_t {
	/** CRC width in bits */
	uint32_t width;
	/** Polynomial (stored in 'width' LSB bits) */
	uint64_t poly;
	/** 0: don't reflect, 1: reflect bits in input bytes */
	odp_bool_t reflect_in;
	/** 0: don't reflect, 1: reflect bits in output bytes */
	odp_bool_t reflect_out;
	/** XOR this value to CRC output (stored in 'width' LSB bits) */
	uint64_t xor_out;
} odp_hash_crc_param_t;

/**
* Calculate up to 64 bit CRC using the given parameters
*
* Calculates CRC over the data using the given parameters.
*
* @param data       Pointer to data
* @param data_len   Data length in bytes
* @param init_val   CRC generator initialization value
* @param crc_param  CRC parameters
* @param crc        Pointer for CRC output
*
* @return 0 on success, <0 on failure (e.g. not supported algorithm)
*/
int odp_hash_crc_gen64(const void *data, uint32_t data_len,
		       uint64_t init_val, odp_hash_crc_param_t *crc_param,
		       uint64_t *crc);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
