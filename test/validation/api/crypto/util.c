/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2014-2018 Linaro Limited
 * Copyright (c) 2021-2026 Nokia
 */

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <odp_api.h>
#include <odp_cunit_common.h>
#include <odp/helper/odph_api.h>
#include "util.h"

struct suite_context_s suite_context;

const char *auth_alg_name(odp_auth_alg_t auth)
{
	switch (auth) {
	case ODP_AUTH_ALG_NULL:
		return "ODP_AUTH_ALG_NULL";
	case ODP_AUTH_ALG_MD5_HMAC:
		return "ODP_AUTH_ALG_MD5_HMAC";
	case ODP_AUTH_ALG_SHA1_HMAC:
		return "ODP_AUTH_ALG_SHA1_HMAC";
	case ODP_AUTH_ALG_SHA224_HMAC:
		return "ODP_AUTH_ALG_SHA224_HMAC";
	case ODP_AUTH_ALG_SHA256_HMAC:
		return "ODP_AUTH_ALG_SHA256_HMAC";
	case ODP_AUTH_ALG_SHA384_HMAC:
		return "ODP_AUTH_ALG_SHA384_HMAC";
	case ODP_AUTH_ALG_SHA512_HMAC:
		return "ODP_AUTH_ALG_SHA512_HMAC";
	case ODP_AUTH_ALG_SHA3_224_HMAC:
		return "ODP_AUTH_ALG_SHA3_224_HMAC";
	case ODP_AUTH_ALG_SHA3_256_HMAC:
		return "ODP_AUTH_ALG_SHA3_256_HMAC";
	case ODP_AUTH_ALG_SHA3_384_HMAC:
		return "ODP_AUTH_ALG_SHA3_384_HMAC";
	case ODP_AUTH_ALG_SHA3_512_HMAC:
		return "ODP_AUTH_ALG_SHA3_512_HMAC";
	case ODP_AUTH_ALG_AES_GCM:
		return "ODP_AUTH_ALG_AES_GCM";
	case ODP_AUTH_ALG_AES_GMAC:
		return "ODP_AUTH_ALG_AES_GMAC";
	case ODP_AUTH_ALG_AES_CCM:
		return "ODP_AUTH_ALG_AES_CCM";
	case ODP_AUTH_ALG_AES_CMAC:
		return "ODP_AUTH_ALG_AES_CMAC";
	case ODP_AUTH_ALG_AES_XCBC_MAC:
		return "ODP_AUTH_ALG_AES_XCBC_MAC";
	case ODP_AUTH_ALG_CHACHA20_POLY1305:
		return "ODP_AUTH_ALG_CHACHA20_POLY1305";
	case ODP_AUTH_ALG_KASUMI_F9:
		return "ODP_AUTH_ALG_KASUMI_F9";
	case ODP_AUTH_ALG_SNOW3G_UIA2:
		return "ODP_AUTH_ALG_SNOW3G_UIA2";
	case ODP_AUTH_ALG_SNOW5G_NIA4:
		return "ODP_AUTH_ALG_SNOW5G_NIA4";
	case ODP_AUTH_ALG_AES_EIA2:
		return "ODP_AUTH_ALG_AES_EIA2";
	case ODP_AUTH_ALG_ZUC_EIA3:
		return "ODP_AUTH_ALG_ZUC_EIA3";
	case ODP_AUTH_ALG_SNOW_V_GCM:
		return "ODP_AUTH_ALG_SNOW_V_GCM";
	case ODP_AUTH_ALG_SNOW_V_GMAC:
		return "ODP_AUTH_ALG_SNOW_V_GMAC";
	case ODP_AUTH_ALG_SM3_HMAC:
		return "ODP_AUTH_ALG_SM3_HMAC";
	case ODP_AUTH_ALG_SM4_GCM:
		return "ODP_AUTH_ALG_SM4_GCM";
	case ODP_AUTH_ALG_SM4_GMAC:
		return "ODP_AUTH_ALG_SM4_GMAC";
	case ODP_AUTH_ALG_SM4_CCM:
		return "ODP_AUTH_ALG_SM4_CCM";
	case ODP_AUTH_ALG_MD5:
		return "ODP_AUTH_ALG_MD5";
	case ODP_AUTH_ALG_SHA1:
		return "ODP_AUTH_ALG_SHA1";
	case ODP_AUTH_ALG_SHA224:
		return "ODP_AUTH_ALG_SHA224";
	case ODP_AUTH_ALG_SHA256:
		return "ODP_AUTH_ALG_SHA256";
	case ODP_AUTH_ALG_SHA384:
		return "ODP_AUTH_ALG_SHA384";
	case ODP_AUTH_ALG_SHA512:
		return "ODP_AUTH_ALG_SHA512";
	case ODP_AUTH_ALG_SHA3_224:
		return "ODP_AUTH_ALG_SHA3_224";
	case ODP_AUTH_ALG_SHA3_256:
		return "ODP_AUTH_ALG_SHA3_256";
	case ODP_AUTH_ALG_SHA3_384:
		return "ODP_AUTH_ALG_SHA3_384";
	case ODP_AUTH_ALG_SHA3_512:
		return "ODP_AUTH_ALG_SHA3_512";
	case ODP_AUTH_ALG_SM3:
		return "ODP_AUTH_ALG_SM3";
	default:
		return "Unknown";
	}
}

const char *cipher_alg_name(odp_cipher_alg_t cipher)
{
	switch (cipher) {
	case ODP_CIPHER_ALG_NULL:
		return "ODP_CIPHER_ALG_NULL";
	case ODP_CIPHER_ALG_DES:
		return "ODP_CIPHER_ALG_DES";
	case ODP_CIPHER_ALG_3DES_CBC:
		return "ODP_CIPHER_ALG_3DES_CBC";
	case ODP_CIPHER_ALG_3DES_ECB:
		return "ODP_CIPHER_ALG_3DES_ECB";
	case ODP_CIPHER_ALG_AES_CBC:
		return "ODP_CIPHER_ALG_AES_CBC";
	case ODP_CIPHER_ALG_AES_CTR:
		return "ODP_CIPHER_ALG_AES_CTR";
	case ODP_CIPHER_ALG_AES_ECB:
		return "ODP_CIPHER_ALG_AES_ECB";
	case ODP_CIPHER_ALG_AES_CFB128:
		return "ODP_CIPHER_ALG_AES_CFB128";
	case ODP_CIPHER_ALG_AES_XTS:
		return "ODP_CIPHER_ALG_AES_XTS";
	case ODP_CIPHER_ALG_AES_GCM:
		return "ODP_CIPHER_ALG_AES_GCM";
	case ODP_CIPHER_ALG_AES_CCM:
		return "ODP_CIPHER_ALG_AES_CCM";
	case ODP_CIPHER_ALG_CHACHA20_POLY1305:
		return "ODP_CIPHER_ALG_CHACHA20_POLY1305";
	case ODP_CIPHER_ALG_KASUMI_F8:
		return "ODP_CIPHER_ALG_KASUMI_F8";
	case ODP_CIPHER_ALG_SNOW3G_UEA2:
		return "ODP_CIPHER_ALG_SNOW3G_UEA2";
	case ODP_CIPHER_ALG_SNOW5G_NEA4:
		return "ODP_CIPHER_ALG_SNOW5G_NEA4";
	case ODP_CIPHER_ALG_AES_EEA2:
		return "ODP_CIPHER_ALG_AES_EEA2";
	case ODP_CIPHER_ALG_ZUC_EEA3:
		return "ODP_CIPHER_ALG_ZUC_EEA3";
	case ODP_CIPHER_ALG_SNOW_V:
		return "ODP_CIPHER_ALG_SNOW_V";
	case ODP_CIPHER_ALG_SNOW_V_GCM:
		return "ODP_CIPHER_ALG_SNOW_V_GCM";
	case ODP_CIPHER_ALG_SM4_ECB:
		return "ODP_CIPHER_ALG_SM4_ECB";
	case ODP_CIPHER_ALG_SM4_CBC:
		return "ODP_CIPHER_ALG_SM4_CBC";
	case ODP_CIPHER_ALG_SM4_CTR:
		return "ODP_CIPHER_ALG_SM4_CTR";
	case ODP_CIPHER_ALG_SM4_GCM:
		return "ODP_CIPHER_ALG_SM4_GCM";
	case ODP_CIPHER_ALG_SM4_CCM:
		return "ODP_CIPHER_ALG_SM4_CCM";
	default:
		return "Unknown";
	}
}

int check_alg_support(odp_cipher_alg_t cipher, odp_auth_alg_t auth)
{
	odp_crypto_capability_t capability;

	memset(&capability, 0, sizeof(odp_crypto_capability_t));
	if (odp_crypto_capability(&capability)) {
		ODPH_ERR("odp_crypto_capability() failed\n");
		return ODP_TEST_INACTIVE;
	}

	if (suite_context.queue != ODP_QUEUE_INVALID) {
		if (suite_context.q_type == ODP_QUEUE_TYPE_PLAIN &&
		    capability.queue_type_plain == 0)
			return ODP_TEST_INACTIVE;
		if (suite_context.q_type == ODP_QUEUE_TYPE_SCHED &&
		    capability.queue_type_sched == 0)
			return ODP_TEST_INACTIVE;
	}

	if (suite_context.op_mode == ODP_CRYPTO_SYNC &&
	    capability.sync_mode == ODP_SUPPORT_NO)
		return ODP_TEST_INACTIVE;
	if (suite_context.op_mode == ODP_CRYPTO_ASYNC &&
	    capability.async_mode == ODP_SUPPORT_NO)
		return ODP_TEST_INACTIVE;

	/* Cipher algorithms */
	switch (cipher) {
	case ODP_CIPHER_ALG_NULL:
		if (!capability.ciphers.bit.null)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_CIPHER_ALG_DES:
		if (!capability.ciphers.bit.des)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_CIPHER_ALG_3DES_CBC:
		if (!capability.ciphers.bit.trides_cbc)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_CIPHER_ALG_3DES_ECB:
		if (!capability.ciphers.bit.trides_ecb)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_CIPHER_ALG_AES_CBC:
		if (!capability.ciphers.bit.aes_cbc)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_CIPHER_ALG_AES_CTR:
		if (!capability.ciphers.bit.aes_ctr)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_CIPHER_ALG_AES_ECB:
		if (!capability.ciphers.bit.aes_ecb)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_CIPHER_ALG_AES_CFB128:
		if (!capability.ciphers.bit.aes_cfb128)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_CIPHER_ALG_AES_XTS:
		if (!capability.ciphers.bit.aes_xts)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_CIPHER_ALG_AES_GCM:
		if (!capability.ciphers.bit.aes_gcm)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_CIPHER_ALG_AES_CCM:
		if (!capability.ciphers.bit.aes_ccm)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_CIPHER_ALG_CHACHA20_POLY1305:
		if (!capability.ciphers.bit.chacha20_poly1305)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_CIPHER_ALG_KASUMI_F8:
		if (!capability.ciphers.bit.kasumi_f8)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_CIPHER_ALG_SNOW3G_UEA2:
		if (!capability.ciphers.bit.snow3g_uea2)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_CIPHER_ALG_SNOW5G_NEA4:
		if (!capability.ciphers.bit.snow5g_nea4)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_CIPHER_ALG_AES_EEA2:
		if (!capability.ciphers.bit.aes_eea2)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_CIPHER_ALG_ZUC_EEA3:
		if (!capability.ciphers.bit.zuc_eea3)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_CIPHER_ALG_SNOW_V:
		if (!capability.ciphers.bit.snow_v)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_CIPHER_ALG_SNOW_V_GCM:
		if (!capability.ciphers.bit.snow_v_gcm)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_CIPHER_ALG_SM4_ECB:
		if (!capability.ciphers.bit.sm4_ecb)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_CIPHER_ALG_SM4_CBC:
		if (!capability.ciphers.bit.sm4_cbc)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_CIPHER_ALG_SM4_CTR:
		if (!capability.ciphers.bit.sm4_ctr)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_CIPHER_ALG_SM4_GCM:
		if (!capability.ciphers.bit.sm4_gcm)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_CIPHER_ALG_SM4_CCM:
		if (!capability.ciphers.bit.sm4_ccm)
			return ODP_TEST_INACTIVE;
		break;
	default:
		ODPH_ERR("Unsupported cipher algorithm\n");
		return ODP_TEST_INACTIVE;
	}

	/* Authentication algorithms */
	switch (auth) {
	case ODP_AUTH_ALG_NULL:
		if (!capability.auths.bit.null)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_MD5_HMAC:
		if (!capability.auths.bit.md5_hmac)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_SHA1_HMAC:
		if (!capability.auths.bit.sha1_hmac)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_SHA224_HMAC:
		if (!capability.auths.bit.sha224_hmac)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_SHA256_HMAC:
		if (!capability.auths.bit.sha256_hmac)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_SHA384_HMAC:
		if (!capability.auths.bit.sha384_hmac)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_SHA512_HMAC:
		if (!capability.auths.bit.sha512_hmac)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_SHA3_224_HMAC:
		if (!capability.auths.bit.sha3_224_hmac)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_SHA3_256_HMAC:
		if (!capability.auths.bit.sha3_256_hmac)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_SHA3_384_HMAC:
		if (!capability.auths.bit.sha3_384_hmac)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_SHA3_512_HMAC:
		if (!capability.auths.bit.sha3_512_hmac)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_AES_GCM:
		if (!capability.auths.bit.aes_gcm)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_AES_GMAC:
		if (!capability.auths.bit.aes_gmac)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_AES_CCM:
		if (!capability.auths.bit.aes_ccm)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_AES_CMAC:
		if (!capability.auths.bit.aes_cmac)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_AES_XCBC_MAC:
		if (!capability.auths.bit.aes_xcbc_mac)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_CHACHA20_POLY1305:
		if (!capability.auths.bit.chacha20_poly1305)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_KASUMI_F9:
		if (!capability.auths.bit.kasumi_f9)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_SNOW3G_UIA2:
		if (!capability.auths.bit.snow3g_uia2)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_SNOW5G_NIA4:
		if (!capability.auths.bit.snow5g_nia4)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_AES_EIA2:
		if (!capability.auths.bit.aes_eia2)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_ZUC_EIA3:
		if (!capability.auths.bit.zuc_eia3)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_SNOW_V_GCM:
		if (!capability.auths.bit.snow_v_gcm)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_SNOW_V_GMAC:
		if (!capability.auths.bit.snow_v_gmac)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_SM3_HMAC:
		if (!capability.auths.bit.sm3_hmac)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_SM4_GCM:
		if (!capability.auths.bit.sm4_gcm)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_SM4_GMAC:
		if (!capability.auths.bit.sm4_gmac)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_SM4_CCM:
		if (!capability.auths.bit.sm4_ccm)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_MD5:
		if (!capability.auths.bit.md5)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_SHA1:
		if (!capability.auths.bit.sha1)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_SHA224:
		if (!capability.auths.bit.sha224)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_SHA256:
		if (!capability.auths.bit.sha256)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_SHA384:
		if (!capability.auths.bit.sha384)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_SHA512:
		if (!capability.auths.bit.sha512)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_SHA3_224:
		if (!capability.auths.bit.sha3_224)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_SHA3_256:
		if (!capability.auths.bit.sha3_256)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_SHA3_384:
		if (!capability.auths.bit.sha3_384)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_SHA3_512:
		if (!capability.auths.bit.sha3_512)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_SM3:
		if (!capability.auths.bit.sm3)
			return ODP_TEST_INACTIVE;
		break;
	default:
		ODPH_ERR("Unsupported authentication algorithm\n");
		return ODP_TEST_INACTIVE;
	}

	return ODP_TEST_ACTIVE;
}

