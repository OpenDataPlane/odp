/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2026 Nokia
 */

#include <odp/helper/crypto.h>
#include <odp/helper/macros.h>

#include <string.h>

typedef struct {
	const char *name;
	odp_cipher_alg_t alg;
} cipher_name_t;

typedef struct {
	const char *name;
	odp_auth_alg_t alg;
} auth_name_t;

static const cipher_name_t cipher_names[] = {
	{ "null",		ODP_CIPHER_ALG_NULL },
	{ "des",		ODP_CIPHER_ALG_DES },
	{ "3des_cbc",		ODP_CIPHER_ALG_3DES_CBC },
	{ "3des_ecb",		ODP_CIPHER_ALG_3DES_ECB },
	{ "aes_cbc",		ODP_CIPHER_ALG_AES_CBC },
	{ "aes_ctr",		ODP_CIPHER_ALG_AES_CTR },
	{ "aes_ecb",		ODP_CIPHER_ALG_AES_ECB },
	{ "aes_cfb128",		ODP_CIPHER_ALG_AES_CFB128 },
	{ "aes_xts",		ODP_CIPHER_ALG_AES_XTS },
	{ "aes_gcm",		ODP_CIPHER_ALG_AES_GCM },
	{ "aes_ccm",		ODP_CIPHER_ALG_AES_CCM },
	{ "chacha20_poly1305",	ODP_CIPHER_ALG_CHACHA20_POLY1305 },
	{ "kasumi_f8",		ODP_CIPHER_ALG_KASUMI_F8 },
	{ "snow3g_uea2",	ODP_CIPHER_ALG_SNOW3G_UEA2 },
	{ "snow5g_nea4",	ODP_CIPHER_ALG_SNOW5G_NEA4 },
	{ "aes_eea2",		ODP_CIPHER_ALG_AES_EEA2 },
	{ "zuc_eea3",		ODP_CIPHER_ALG_ZUC_EEA3 },
	{ "zuc_nea6",		ODP_CIPHER_ALG_ZUC_NEA6 },
	{ "snow_v",		ODP_CIPHER_ALG_SNOW_V },
	{ "snow_v_gcm",		ODP_CIPHER_ALG_SNOW_V_GCM },
	{ "sm4_ecb",		ODP_CIPHER_ALG_SM4_ECB },
	{ "sm4_cbc",		ODP_CIPHER_ALG_SM4_CBC },
	{ "sm4_ctr",		ODP_CIPHER_ALG_SM4_CTR },
	{ "sm4_gcm",		ODP_CIPHER_ALG_SM4_GCM },
	{ "sm4_ccm",		ODP_CIPHER_ALG_SM4_CCM },
};

static const auth_name_t auth_names[] = {
	{ "null",		ODP_AUTH_ALG_NULL },
	{ "md5_hmac",		ODP_AUTH_ALG_MD5_HMAC },
	{ "sha1_hmac",		ODP_AUTH_ALG_SHA1_HMAC },
	{ "sha224_hmac",	ODP_AUTH_ALG_SHA224_HMAC },
	{ "sha256_hmac",	ODP_AUTH_ALG_SHA256_HMAC },
	{ "sha384_hmac",	ODP_AUTH_ALG_SHA384_HMAC },
	{ "sha512_hmac",	ODP_AUTH_ALG_SHA512_HMAC },
	{ "sha3_224_hmac",	ODP_AUTH_ALG_SHA3_224_HMAC },
	{ "sha3_256_hmac",	ODP_AUTH_ALG_SHA3_256_HMAC },
	{ "sha3_384_hmac",	ODP_AUTH_ALG_SHA3_384_HMAC },
	{ "sha3_512_hmac",	ODP_AUTH_ALG_SHA3_512_HMAC },
	{ "aes_gcm",		ODP_AUTH_ALG_AES_GCM },
	{ "aes_gmac",		ODP_AUTH_ALG_AES_GMAC },
	{ "aes_ccm",		ODP_AUTH_ALG_AES_CCM },
	{ "aes_cmac",		ODP_AUTH_ALG_AES_CMAC },
	{ "aes_xcbc_mac",	ODP_AUTH_ALG_AES_XCBC_MAC },
	{ "chacha20_poly1305",	ODP_AUTH_ALG_CHACHA20_POLY1305 },
	{ "kasumi_f9",		ODP_AUTH_ALG_KASUMI_F9 },
	{ "snow3g_uia2",	ODP_AUTH_ALG_SNOW3G_UIA2 },
	{ "snow5g_nia4",	ODP_AUTH_ALG_SNOW5G_NIA4 },
	{ "aes_eia2",		ODP_AUTH_ALG_AES_EIA2 },
	{ "zuc_eia3",		ODP_AUTH_ALG_ZUC_EIA3 },
	{ "zuc_nia6",		ODP_AUTH_ALG_ZUC_NIA6 },
	{ "snow_v_gcm",		ODP_AUTH_ALG_SNOW_V_GCM },
	{ "snow_v_gmac",	ODP_AUTH_ALG_SNOW_V_GMAC },
	{ "sm3_hmac",		ODP_AUTH_ALG_SM3_HMAC },
	{ "sm4_gcm",		ODP_AUTH_ALG_SM4_GCM },
	{ "sm4_gmac",		ODP_AUTH_ALG_SM4_GMAC },
	{ "sm4_ccm",		ODP_AUTH_ALG_SM4_CCM },
	{ "md5",		ODP_AUTH_ALG_MD5 },
	{ "sha1",		ODP_AUTH_ALG_SHA1 },
	{ "sha224",		ODP_AUTH_ALG_SHA224 },
	{ "sha256",		ODP_AUTH_ALG_SHA256 },
	{ "sha384",		ODP_AUTH_ALG_SHA384 },
	{ "sha512",		ODP_AUTH_ALG_SHA512 },
	{ "sha3_224",		ODP_AUTH_ALG_SHA3_224 },
	{ "sha3_256",		ODP_AUTH_ALG_SHA3_256 },
	{ "sha3_384",		ODP_AUTH_ALG_SHA3_384 },
	{ "sha3_512",		ODP_AUTH_ALG_SHA3_512 },
	{ "sm3",		ODP_AUTH_ALG_SM3 },
};

const char *odph_cipher_alg_to_str(odp_cipher_alg_t alg)
{
	for (size_t i = 0; i < ODPH_ARRAY_SIZE(cipher_names); i++) {
		if (cipher_names[i].alg == alg)
			return cipher_names[i].name;
	}

	return NULL;
}

int odph_cipher_alg_from_str(const char *str, odp_cipher_alg_t *alg)
{
	for (size_t i = 0; i < ODPH_ARRAY_SIZE(cipher_names); i++) {
		if (!strcmp(str, cipher_names[i].name)) {
			*alg = cipher_names[i].alg;
			return 0;
		}
	}

	return -1;
}

const char *odph_auth_alg_to_str(odp_auth_alg_t alg)
{
	for (size_t i = 0; i < ODPH_ARRAY_SIZE(auth_names); i++) {
		if (auth_names[i].alg == alg)
			return auth_names[i].name;
	}

	return NULL;
}

int odph_auth_alg_from_str(const char *str, odp_auth_alg_t *alg)
{
	for (size_t i = 0; i < ODPH_ARRAY_SIZE(auth_names); i++) {
		if (!strcmp(str, auth_names[i].name)) {
			*alg = auth_names[i].alg;
			return 0;
		}
	}

	return -1;
}
