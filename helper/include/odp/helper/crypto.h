/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2026 Nokia
 */

/**
 * @file
 *
 * ODP crypto helper
 */

#ifndef ODPH_CRYPTO_H_
#define ODPH_CRYPTO_H_

#include <odp_api.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup odph_crypto ODPH CRYPTO
 * Crypto helper
 *
 * The algorithm names used by these functions are the algorithm enumeration
 * names in lower case and without the ODP_CIPHER_ALG_ or ODP_AUTH_ALG_ prefix,
 * e.g. "aes_cbc" for ODP_CIPHER_ALG_AES_CBC and "sha256_hmac" for
 * ODP_AUTH_ALG_SHA256_HMAC.
 *
 * These functions may be called before ODP initialization.
 *
 * @{
 */

/**
 * Get cipher algorithm name
 *
 * @param alg Cipher algorithm
 *
 * @return Pointer to a constant, null terminated algorithm name string
 * @retval NULL Unknown algorithm
 */
const char *odph_cipher_alg_to_str(odp_cipher_alg_t alg);

/**
 * Get cipher algorithm from name
 *
 * The name comparison is case sensitive.
 *
 * @param      str  Cipher algorithm name
 * @param[out] alg  Pointer to cipher algorithm output
 *
 * @retval 0 on success
 * @retval <0 on failure (unknown algorithm name)
 */
int odph_cipher_alg_from_str(const char *str, odp_cipher_alg_t *alg);

/**
 * Get authentication algorithm name
 *
 * @param alg Authentication algorithm
 *
 * @return Pointer to a constant, null terminated algorithm name string
 * @retval NULL Unknown algorithm
 */
const char *odph_auth_alg_to_str(odp_auth_alg_t alg);

/**
 * Get authentication algorithm from name
 *
 * The name comparison is case sensitive.
 *
 * @param      str  Authentication algorithm name
 * @param[out] alg  Pointer to authentication algorithm output
 *
 * @retval 0 on success
 * @retval <0 on failure (unknown algorithm name)
 */
int odph_auth_alg_from_str(const char *str, odp_auth_alg_t *alg);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
