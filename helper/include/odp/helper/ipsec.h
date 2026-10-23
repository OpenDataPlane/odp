/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2014-2018 Linaro Limited
 * Copyright (c) 2021-2026 Nokia
 */


/**
 * @file
 *
 * ODP IPSec headers
 */

#ifndef ODPH_IPSEC_H_
#define ODPH_IPSEC_H_

#include <odp_api.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @addtogroup odph_protocols
 * @{
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

/**
 * IPSec ESP trailer
 */
typedef struct ODP_PACKED {
	uint8_t pad_len;      /**< Padding length (0-255) */
	uint8_t next_header;  /**< Next header protocol */
	uint8_t icv[];        /**< Integrity Check Value (optional) */
} odph_esptrl_t;

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

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */
ODP_STATIC_ASSERT(sizeof(odph_esphdr_t) == ODPH_ESPHDR_LEN,
		  "ODPH_ESPHDR_T__SIZE_ERROR");

ODP_STATIC_ASSERT(sizeof(odph_esptrl_t) == ODPH_ESPTRL_LEN,
		  "ODPH_ESPTRL_T__SIZE_ERROR");

ODP_STATIC_ASSERT(sizeof(odph_ahhdr_t) == ODPH_AHHDR_LEN,
		  "ODPH_AHHDR_T__SIZE_ERROR");
/** @endcond */

/**
 * Check IPsec cipher algorithm support
 *
 * Check whether the ODP implementation advertises support for the specified
 * cipher algorithm with the given key length for IPsec.
 *
 * @param      capa     Capabilities filled by odp_ipsec_capability()
 * @param      cipher   Cipher algorithm
 * @param      key_len  Length of cipher key in bytes
 *
 * @retval 0   the algorithm is supported with the key length
 * @retval <0  the algorithm is not supported with the key length
 */
int odph_ipsec_cipher_capa_check(const odp_ipsec_capability_t *capa,
				 odp_cipher_alg_t cipher,
				 uint32_t key_len);

/**
 * Check IPsec authentication algorithm support
 *
 * Check whether the ODP implementation advertises support for the specified
 * auth algorithm with the given key length and ICV length for IPsec. ICV
 * length of zero means the explicit zero ICV length here, not the default.
 *
 * @param      capa     Capabilities filled by odp_ipsec_capability()
 * @param      auth     Authentication algorithm
 * @param      key_len  Length of auth key in bytes
 * @param      icv_len  ICV length in bytes
 *
 * @retval 0   the algorithm is supported with the key and ICV lengths
 * @retval <0  the algorithm is not supported with the key and ICV lengths
 */
int odph_ipsec_auth_capa_check(const odp_ipsec_capability_t *capa,
			       odp_auth_alg_t auth,
			       uint32_t key_len,
			       uint32_t icv_len);

/**
 * Check IPsec algorithm support
 *
 * Check if the specified cipher with the specified key length is
 * supported and if the specified auth algorithm with the specified
 * key length and its default ICV length is supported.
 *
 * If the default ICV length is undefined or implementation specific,
 * this function returns a negative value, indicating no support.
 * Use odph_ipsec_cipher_capa_check() and odph_ipsec_auth_capa_check()
 * to check support with a non-default ICV length.
 *
 * A zero return value indicates that the cipher configuration and
 * the auth configuration are advertised as supported but does not
 * guarantee that they can be used in the same IPsec SA. SA creation
 * may fail in some implementations if the cipher and auth cannot
 * be combined.
 *
 * @param      capa            Capabilities filled by odp_ipsec_capability()
 * @param      cipher_alg      Cipher algorithm
 * @param      cipher_key_len  Length of cipher key in bytes
 * @param      auth_alg        Authentication algorithm
 * @param      auth_key_len    Length of authentication key in bytes
 *
 * @retval 0   configuration is supported
 * @retval <0  configuration is not supported
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
 * If the default value is undefined or implementation specific, this
 * function returns a negative value.
 *
 * @param      auth_alg   Authentication algorithm
 *
 * @retval >=0            The default ICV length in bytes
 * @retval <0             Default ICV length is not defined
 */
int odph_ipsec_auth_icv_len_default(odp_auth_alg_t auth_alg);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
