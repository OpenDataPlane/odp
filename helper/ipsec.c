/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2017-2018 Linaro Limited
 * Copyright (c) 2020 Marvell
 * Copyright (c) 2021 Nokia
 */

#include <odp/helper/debug.h>
#include <odp/helper/ipsec.h>

uint32_t odph_ipsec_auth_icv_len_default(odp_auth_alg_t auth_alg)
{
	uint32_t icv_len;

	switch (auth_alg) {
	case ODP_AUTH_ALG_NULL:
		icv_len = 0;
		break;
	case ODP_AUTH_ALG_MD5_HMAC:
		icv_len = 12;
		break;
	case ODP_AUTH_ALG_SHA1_HMAC:
		icv_len = 12;
		break;
	case ODP_AUTH_ALG_SHA256_HMAC:
		icv_len = 16;
		break;
	case ODP_AUTH_ALG_SHA384_HMAC:
		icv_len = 24;
		break;
	case ODP_AUTH_ALG_SHA512_HMAC:
		icv_len = 32;
		break;
	case ODP_AUTH_ALG_AES_GCM:
		icv_len = 16;
		break;
	case ODP_AUTH_ALG_AES_GMAC:
		icv_len = 16;
		break;
	case ODP_AUTH_ALG_AES_CCM:
		icv_len = 16;
		break;
	case ODP_AUTH_ALG_AES_CMAC:
		icv_len = 12;
		break;
	case ODP_AUTH_ALG_AES_XCBC_MAC:
		icv_len = 12;
		break;
	case ODP_AUTH_ALG_CHACHA20_POLY1305:
		icv_len = 16;
		break;
	default:
		ODPH_DBG("Unsupported authentication algorithm\n");
		icv_len = 0;
		break;
	}
	return icv_len;
}

int odph_ipsec_alg_check(const odp_ipsec_capability_t *capa,
			 odp_cipher_alg_t cipher_alg,
			 uint32_t cipher_key_len,
			 odp_auth_alg_t auth_alg,
			 uint32_t auth_key_len)
{
	int i, num, max_capa;
	uint32_t default_icv_len;
	odp_bool_t found;

	/* Check whether requested cipher algorithm is supported */
	switch (cipher_alg) {
	case ODP_CIPHER_ALG_NULL:
		if (!capa->ciphers.bit.null)
			return -1;
		break;
	case ODP_CIPHER_ALG_DES:
		if (!capa->ciphers.bit.des)
			return -1;
		break;
	case ODP_CIPHER_ALG_3DES_CBC:
		if (!capa->ciphers.bit.trides_cbc)
			return -1;
		break;
	case ODP_CIPHER_ALG_AES_CBC:
		if (!capa->ciphers.bit.aes_cbc)
			return -1;
		break;
	case ODP_CIPHER_ALG_AES_CTR:
		if (!capa->ciphers.bit.aes_ctr)
			return -1;
		break;
	case ODP_CIPHER_ALG_AES_GCM:
		if (!capa->ciphers.bit.aes_gcm)
			return -1;
		break;
	case ODP_CIPHER_ALG_AES_CCM:
		if (!capa->ciphers.bit.aes_ccm)
			return -1;
		break;
	case ODP_CIPHER_ALG_CHACHA20_POLY1305:
		if (!capa->ciphers.bit.chacha20_poly1305)
			return -1;
		break;
	default:
		ODPH_DBG("Unsupported cipher algorithm\n");
		return -1;
	}

	/* Check whether requested auth algorithm is supported */
	switch (auth_alg) {
	case ODP_AUTH_ALG_NULL:
		if (!capa->auths.bit.null)
			return -1;
		break;
	case ODP_AUTH_ALG_MD5_HMAC:
		if (!capa->auths.bit.md5_hmac)
			return -1;
		break;
	case ODP_AUTH_ALG_SHA1_HMAC:
		if (!capa->auths.bit.sha1_hmac)
			return -1;
		break;
	case ODP_AUTH_ALG_SHA256_HMAC:
		if (!capa->auths.bit.sha256_hmac)
			return -1;
		break;
	case ODP_AUTH_ALG_SHA384_HMAC:
		if (!capa->auths.bit.sha384_hmac)
			return -1;
		break;
	case ODP_AUTH_ALG_SHA512_HMAC:
		if (!capa->auths.bit.sha512_hmac)
			return -1;
		break;
	case ODP_AUTH_ALG_AES_XCBC_MAC:
		if (!capa->auths.bit.aes_xcbc_mac)
			return -1;
		break;
	case ODP_AUTH_ALG_AES_GCM:
		if (!capa->auths.bit.aes_gcm)
			return -1;
		break;
	case ODP_AUTH_ALG_AES_GMAC:
		if (!capa->auths.bit.aes_gmac)
			return -1;
		break;
	case ODP_AUTH_ALG_AES_CCM:
		if (!capa->auths.bit.aes_ccm)
			return -1;
		break;
	case ODP_AUTH_ALG_AES_CMAC:
		if (!capa->auths.bit.aes_cmac)
			return -1;
		break;
	case ODP_AUTH_ALG_CHACHA20_POLY1305:
		if (!capa->auths.bit.chacha20_poly1305)
			return -1;
		break;
	default:
		ODPH_DBG("Unsupported authentication algorithm\n");
		return -1;
	}

	/* Check whether requested cipher key length is supported */
	max_capa = odp_ipsec_cipher_capability(cipher_alg, NULL, 0);
	if (max_capa <= 0)
		return -1;

	odp_ipsec_cipher_capability_t cipher_capa[max_capa];

	num = odp_ipsec_cipher_capability(cipher_alg, cipher_capa, max_capa);
	if (num <= 0) {
		ODPH_DBG("Could not get cipher capabilities\n");
		return -1;
	}

	found = false;
	for (i = 0; i < num; i++) {
		if (cipher_capa[i].key_len == cipher_key_len) {
			found = 1;
			break;
		}
	}

	if (!found) {
		ODPH_DBG("Unsupported key length\n");
		return -1;
	}

	/* Check whether requested auth key length is supported */
	max_capa = odp_ipsec_auth_capability(auth_alg, NULL, 0);
	if (max_capa <= 0)
		return max_capa;

	odp_ipsec_auth_capability_t auth_capa[max_capa];

	num = odp_ipsec_auth_capability(auth_alg, auth_capa, max_capa);
	if (num <= 0) {
		ODPH_DBG("Could not get auth capabilities\n");
		return -1;
	}

	default_icv_len = odph_ipsec_auth_icv_len_default(auth_alg);
	found = false;
	for (i = 0; i < num; i++) {
		if (auth_capa[i].key_len == auth_key_len &&
		    auth_capa[i].icv_len == default_icv_len) {
			found = 1;
			break;
		}
	}

	if (!found) {
		ODPH_DBG("Unsupported auth key length & ICV length pair\n");
		return -1;
	}

	return 0;
}
