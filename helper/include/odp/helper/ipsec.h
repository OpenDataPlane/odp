/* Copyright (c) 2014-2018, Linaro Limited
 * Copyright (c) 2021, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP IPSec headers
 */

#ifndef ODPH_IPSEC_H_
#define ODPH_IPSEC_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp_api.h>

/** @addtogroup odph_header ODPH HEADER
 *  @{
 */

#define ODPH_ESPHDR_LEN      8    /**< IPSec ESP header length */
#define ODPH_ESPTRL_LEN      2    /**< IPSec ESP trailer length */
#define ODPH_AHHDR_LEN      12    /**< IPSec AH header length */

/**
 * IPSec ESP header
 */
typedef struct ODP_PACKED {
	odp_u32be_t spi;     /**< Security Parameter Index */
	odp_u32be_t seq_no;  /**< Sequence Number */
	uint8_t    iv[];     /**< Initialization vector */
} odph_esphdr_t;

/** @internal Compile time assert */
ODP_STATIC_ASSERT(sizeof(odph_esphdr_t) == ODPH_ESPHDR_LEN,
		  "ODPH_ESPHDR_T__SIZE_ERROR");

/**
 * IPSec ESP trailer
 */
typedef struct ODP_PACKED {
	uint8_t pad_len;      /**< Padding length (0-255) */
	uint8_t next_header;  /**< Next header protocol */
	uint8_t icv[];        /**< Integrity Check Value (optional) */
} odph_esptrl_t;

/** @internal Compile time assert */
ODP_STATIC_ASSERT(sizeof(odph_esptrl_t) == ODPH_ESPTRL_LEN,
		  "ODPH_ESPTRL_T__SIZE_ERROR");

/**
 * IPSec AH header
 */
typedef struct ODP_PACKED {
	uint8_t    next_header;  /**< Next header protocol */
	uint8_t    ah_len;       /**< AH header length */
	odp_u16be_t pad;         /**< Padding (must be 0) */
	odp_u32be_t spi;         /**< Security Parameter Index */
	odp_u32be_t seq_no;      /**< Sequence Number */
	uint8_t    icv[];        /**< Integrity Check Value */
} odph_ahhdr_t;

/** @internal Compile time assert */
ODP_STATIC_ASSERT(sizeof(odph_ahhdr_t) == ODPH_AHHDR_LEN,
		  "ODPH_AHHDR_T__SIZE_ERROR");

/**
 * Check IPSEC algorithm support
 *
 * Based on the capabilities exposed by the ODP implementation, check whether
 * the specified IPSEC algorithm configuration with the default ICV length
 * is supported by the implementation. The caller provides the IPSEC
 * capability structure as an argument to the helper function.
 *
 * @param      capa            IPSEC capability structure
 * @param      cipher_alg      Cipher algorithm
 * @param      cipher_key_len  Length of cipher key in bytes
 * @param      auth_alg        Authentication algorithm
 * @param      auth_key_len    Length of authentication key in bytes
 *
 * @retval 0  on success
 * @retval <0 on failure
 */
int odph_ipsec_alg_check(const odp_ipsec_capability_t *capa,
			 odp_cipher_alg_t cipher_alg,
			 uint32_t cipher_key_len,
			 odp_auth_alg_t auth_alg,
			 uint32_t auth_key_len);

/**
 * Return the default ICV length of an algorithm
 *
 * IPsec API specifies default ICV length for each authentication and
 * combined mode algorithm. This function returns the default ICV length.
 *
 * @param      auth_alg   Authentication algorithm
 *
 * @return                The default ICV length in bytes
 */
uint32_t odph_ipsec_auth_icv_len_default(odp_auth_alg_t auth_alg);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
