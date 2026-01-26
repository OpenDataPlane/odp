/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2025 Nokia
 */

#include <odp/api/crypto.h>
#include <odp/api/pool.h>
#include <odp/api/queue.h>

#include <odp_crypto_internal.h>
#include <odp_debug_internal.h>
#include <odp_string_internal.h>

#include <inttypes.h>
#include <stdint.h>

static const char *auth_alg_name(odp_auth_alg_t auth)
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
		return "unknown";
	}
}

static const char *cipher_alg_name(odp_cipher_alg_t cipher)
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
		return "unknown";
	}
}

void _odp_crypto_session_print(const char *type, uint32_t index,
			       const odp_crypto_session_param_t *param)
{
	const int max_len = 4096;
	char str[max_len];
	int len = 0;
	int n = max_len - 1;

	len += _odp_snprint(&str[len], n - len, "Crypto info\n");
	len += _odp_snprint(&str[len], n - len, "-----------\n");
	len += _odp_snprint(&str[len], n - len, "  type                      %s\n", type);
	len += _odp_snprint(&str[len], n - len, "  index                     %" PRIu32 "\n", index);
	len += _odp_snprint(&str[len], n - len, "  op                        %s\n",
			    param->op == ODP_CRYPTO_OP_ENCODE ? "ODP_CRYPTO_OP_ENCODE" :
			    "ODP_CRYPTO_OP_DECODE");
	len += _odp_snprint(&str[len], n - len, "  op_type                   %s\n",
			    param->op_type == ODP_CRYPTO_OP_TYPE_BASIC ?
				"ODP_CRYPTO_OP_TYPE_BASIC" :
			    param->op_type == ODP_CRYPTO_OP_TYPE_OOP ?
				"ODP_CRYPTO_OP_TYPE_OOP" :
			    param->op_type == ODP_CRYPTO_OP_TYPE_BASIC_AND_OOP ?
				"ODP_CRYPTO_OP_TYPE_BASIC_AND_OOP" : "unknown");
	len += _odp_snprint(&str[len], n - len, "  cipher_range_in_bits      %s\n",
			    param->cipher_range_in_bits ? "true" : "false");
	len += _odp_snprint(&str[len], n - len, "  auth_range_in_bits        %s\n",
			    param->auth_range_in_bits ? "true" : "false");
	len += _odp_snprint(&str[len], n - len, "  auth_cipher_text          %s\n",
			    param->auth_cipher_text ? "true" : "false");
	len += _odp_snprint(&str[len], n - len, "  hash_result_in_auth_range %s\n",
			    param->hash_result_in_auth_range ? "true" : "false");
	len += _odp_snprint(&str[len], n - len, "  null_crypto_enable        %s\n",
			    param->null_crypto_enable ? "true" : "false");
	len += _odp_snprint(&str[len], n - len, "  op_mode                   %s\n",
			    param->op_mode == ODP_CRYPTO_SYNC ? "ODP_CRYPTO_SYNC" :
			    "ODP_CRYPTO_ASYNC");
	len += _odp_snprint(&str[len], n - len, "  cipher_alg                %s\n",
			    cipher_alg_name(param->cipher_alg));
	len += _odp_snprint(&str[len], n - len, "  cipher_key.data           %p\n",
			    param->cipher_key.data);
	len += _odp_snprint(&str[len], n - len, "  cipher_key.length         %" PRIu32 "\n",
			    param->cipher_key.length);
	len += _odp_snprint(&str[len], n - len, "  cipher_iv_len             %" PRIu32 "\n",
			    param->cipher_iv_len);
	len += _odp_snprint(&str[len], n - len, "  auth_alg                  %s\n",
			    auth_alg_name(param->auth_alg));
	len += _odp_snprint(&str[len], n - len, "  auth_key.data             %p\n",
			    param->auth_key.data);
	len += _odp_snprint(&str[len], n - len, "  auth_key.length           %" PRIu32 "\n",
			    param->auth_key.length);
	len += _odp_snprint(&str[len], n - len, "  auth_iv_len               %" PRIu32 "\n",
			    param->auth_iv_len);
	len += _odp_snprint(&str[len], n - len, "  auth_digest_len           %" PRIu32 "\n",
			    param->auth_digest_len);
	len += _odp_snprint(&str[len], n - len, "  auth_aad_len              %" PRIu32 "\n",
			    param->auth_aad_len);
	len += _odp_snprint(&str[len], n - len, "  compl_queue               %" PRIu64 "\n",
			    odp_queue_to_u64(param->compl_queue));
	len += _odp_snprint(&str[len], n - len, "  output_pool               %" PRIu64 "\n",
			    odp_pool_to_u64(param->output_pool));
	_ODP_PRINT("%s\n", str);
}
