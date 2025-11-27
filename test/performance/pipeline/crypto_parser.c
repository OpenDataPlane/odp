/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2025 Nokia
 */

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <libconfig.h>
#include <odp_api.h>
#include <odp/helper/odph_api.h>

#include "common.h"
#include "config_parser.h"

#define CONF_STR_NAME "name"
#define CONF_STR_OP "op"
#define CONF_STR_CIPHER_ALG "chiper_alg"
#define CONF_STR_CIPHER_KEY_DATA "cipher_key_data"
#define CONF_STR_CIPHER_KEY_LEN "cipher_key_len"
#define CONF_STR_CIPHER_IV_LEN "cipher_iv_len"
#define CONF_STR_AUTH_ALG "auth_alg"
#define CONF_STR_AUTH_KEY_DATA "auth_key_data"
#define CONF_STR_AUTH_KEY_LEN "auth_key_len"
#define CONF_STR_AUTH_IV_LEN "auth_iv_len"
#define CONF_STR_AUTH_DIGEST_LEN "auth_digest_len"
#define CONF_STR_AUTH_AAD_LEN "auth_aad_len"
#define CONF_STR_COMPL_Q "compl_queue"

#define ENCODE "encode"
#define DECODE "decode"
#define CIPHER_AUTH_NULL "null"
#define CIPHER_DES "des"
#define CIPHER_3DES_CBC "3des_cbc"
#define CIPHER_3DES_ECB "3des_ecb"
#define CIPHER_AES_CBC "aes_cbc"
#define CIPHER_AES_CTR "aes_ctr"
#define CIPHER_AES_ECB "aes_ecb"
#define CIPHER_AES_CFB128 "aes_cfb128"
#define CIPHER_AES_XTS "aes_xts"
#define CIPHER_AUTH_AES_GCM "aes_gcm"
#define CIPHER_AUTH_AES_CCM "aes_ccm"
#define CIPHER_AUTH_CHACHA20_POLY1305 "chacha20_poly1305"
#define CIPHER_KASUMI_F8 "kasumi_f8"
#define CIPHER_SNOW3G_UEA2 "snow3g_uae2"
#define CIPHER_AES_EEA2 "aes_eea2"
#define CIPHER_ZUC_EEA3 "zuc_eea3"
#define CIPHER_SNOW_V "snow_v"
#define CIPHER_AUTH_SNOW_V_GCM "snow_v_gcm"
#define CIPHER_SM4_ECB "sm4_ecb"
#define CIPHER_SM4_CBC "sm4_cbc"
#define CIPHER_SM4_CTR "sm4_ctr"
#define CIPHER_AUTH_SM4_GCM "sm4_gcm"
#define CIPHER_AUTH_SM4_CCM "sm4_ccm"
#define AUTH_MD5_HMAC "md5_hmac"
#define AUTH_SHA1_HMAC "sha1_hmac"
#define AUTH_SHA224_HMAC "sha224_hmac"
#define AUTH_SHA256_HMAC "sha256_hmac"
#define AUTH_SHA384_HMAC "sha384_hmac"
#define AUTH_SHA512_HMAC "sha512_hmac"
#define AUTH_SHA3_224_HMAC "sha3_224_hmac"
#define AUTH_SHA3_256_HMAC "sha3_256_hmac"
#define AUTH_SHA3_384_HMAC "sha3_384_hmac"
#define AUTH_SHA3_512_HMAC "sha3_512_hmac"
#define AUTH_AES_GMAC "aes_gmac"
#define AUTH_AES_CMAC "aes_cmac"
#define AUTH_AES_XCBC_MAC "aed_xcbc_mac"
#define AUTH_KASUMI_F9 "kasumi_f9"
#define AUTH_SNOW3G_UIA2 "snow3g_uia2"
#define AUTH_AES_EIA2 "aes_eia2"
#define AUTH_ZUC_EIA3 "zuc_eia3"
#define AUTH_SNOW_V_GMAC "snow_v_gmac"
#define AUTH_SM3_HMAC "sm3_hmac"
#define AUTH_SM4_GMAC "sm4_gmac"
#define AUTH_MD5 "md5"
#define AUTH_SHA1 "sha1"
#define AUTH_SHA224 "sha224"
#define AUTH_SHA256 "sha256"
#define AUTH_SHA384 "sha384"
#define AUTH_SHA512 "sha512"
#define AUTH_SHA3_224 "sha3_224"
#define AUTH_SHA3_256 "sha3_256"
#define AUTH_SHA3_384 "sha3_384"
#define AUTH_SHA3_512 "sha3_512"
#define AUTH_SM3 "sm3"

typedef struct {
	char *name;
	char *queue;
	odp_crypto_session_param_t param;
	odp_crypto_session_t crypto;
} crypto_parse_t;

typedef struct {
	crypto_parse_t *cryptos;
	uint32_t num;
} crypto_parses_t;

static crypto_parses_t cryptos;

static odp_bool_t parse_crypto_entry(config_setting_t *cs, crypto_parse_t *crypto)
{
	const char *val_str;
	config_setting_t *elem;
	int num, val_i;

	crypto->crypto = ODP_CRYPTO_SESSION_INVALID;
	odp_crypto_session_param_init(&crypto->param);
	crypto->param.op_mode = ODP_CRYPTO_ASYNC;
	crypto->param.cipher_key.data = NULL;
	crypto->param.auth_key.data = NULL;
	crypto->param.output_pool = ODP_POOL_INVALID;

	if (config_setting_lookup_string(cs, CONF_STR_NAME, &val_str) == CONFIG_FALSE) {
		ODPH_ERR("No \"" CONF_STR_NAME "\" found\n");
		return false;
	}

	crypto->name = strdup(val_str);

	if (crypto->name == NULL)
		ODPH_ABORT("Error allocating memory, aborting\n");

	if (config_setting_lookup_string(cs, CONF_STR_OP, &val_str) == CONFIG_TRUE) {
		if (strcmp(val_str, ENCODE) == 0) {
			crypto->param.op = ODP_CRYPTO_OP_ENCODE;
		} else if (strcmp(val_str, DECODE) == 0)  {
			crypto->param.op = ODP_CRYPTO_OP_DECODE;
		} else {
			ODPH_ERR("No valid \"" CONF_STR_OP "\" found\n");
			return false;
		}
	}

	if (config_setting_lookup_string(cs, CONF_STR_CIPHER_ALG, &val_str) == CONFIG_TRUE) {
		if (strcmp(val_str, CIPHER_AUTH_NULL) == 0) {
			crypto->param.cipher_alg = ODP_CIPHER_ALG_NULL;
		} else if (strcmp(val_str, CIPHER_DES) == 0) {
			crypto->param.cipher_alg = ODP_CIPHER_ALG_DES;
		} else if (strcmp(val_str, CIPHER_3DES_CBC) == 0) {
			crypto->param.cipher_alg = ODP_CIPHER_ALG_3DES_CBC;
		} else if (strcmp(val_str, CIPHER_3DES_ECB) == 0) {
			crypto->param.cipher_alg = ODP_CIPHER_ALG_3DES_ECB;
		} else if (strcmp(val_str, CIPHER_AES_CBC) == 0) {
			crypto->param.cipher_alg = ODP_CIPHER_ALG_AES_CBC;
		} else if (strcmp(val_str, CIPHER_AES_ECB) == 0) {
			crypto->param.cipher_alg = ODP_CIPHER_ALG_AES_ECB;
		} else if (strcmp(val_str, CIPHER_AES_CFB128) == 0) {
			crypto->param.cipher_alg = ODP_CIPHER_ALG_AES_CFB128;
		} else if (strcmp(val_str, CIPHER_AES_XTS) == 0) {
			crypto->param.cipher_alg = ODP_CIPHER_ALG_AES_XTS;
		} else if (strcmp(val_str, CIPHER_AUTH_AES_GCM) == 0) {
			crypto->param.cipher_alg = ODP_CIPHER_ALG_AES_GCM;
		} else if (strcmp(val_str, CIPHER_AUTH_AES_CCM) == 0) {
			crypto->param.cipher_alg = ODP_CIPHER_ALG_AES_CCM;
		} else if (strcmp(val_str, CIPHER_AUTH_CHACHA20_POLY1305) == 0) {
			crypto->param.cipher_alg = ODP_CIPHER_ALG_CHACHA20_POLY1305;
		} else if (strcmp(val_str, CIPHER_KASUMI_F8) == 0) {
			crypto->param.cipher_alg = ODP_CIPHER_ALG_KASUMI_F8;
		} else if (strcmp(val_str, CIPHER_SNOW3G_UEA2) == 0) {
			crypto->param.cipher_alg = ODP_CIPHER_ALG_SNOW3G_UEA2;
		} else if (strcmp(val_str, CIPHER_AES_EEA2) == 0) {
			crypto->param.cipher_alg = ODP_CIPHER_ALG_AES_EEA2;
		} else if (strcmp(val_str, CIPHER_ZUC_EEA3) == 0) {
			crypto->param.cipher_alg = ODP_CIPHER_ALG_ZUC_EEA3;
		} else if (strcmp(val_str, CIPHER_SNOW_V) == 0) {
			crypto->param.cipher_alg = ODP_CIPHER_ALG_SNOW_V;
		} else if (strcmp(val_str, CIPHER_AUTH_SNOW_V_GCM) == 0) {
			crypto->param.cipher_alg = ODP_CIPHER_ALG_SNOW_V_GCM;
		} else if (strcmp(val_str, CIPHER_SM4_ECB) == 0) {
			crypto->param.cipher_alg = ODP_CIPHER_ALG_SM4_ECB;
		} else if (strcmp(val_str, CIPHER_SM4_CBC) == 0) {
			crypto->param.cipher_alg = ODP_CIPHER_ALG_SM4_CBC;
		} else if (strcmp(val_str, CIPHER_SM4_CTR) == 0) {
			crypto->param.cipher_alg = ODP_CIPHER_ALG_SM4_CTR;
		} else if (strcmp(val_str, CIPHER_AUTH_SM4_GCM) == 0) {
			crypto->param.cipher_alg = ODP_CIPHER_ALG_SM4_GCM;
		} else if (strcmp(val_str, CIPHER_AUTH_SM4_CCM) == 0) {
			crypto->param.cipher_alg = ODP_CIPHER_ALG_SM4_CCM;
		} else {
			ODPH_ERR("No valid \"" CONF_STR_CIPHER_ALG "\" found\n");
			return false;
		}
	}

	elem = config_setting_lookup(cs, CONF_STR_CIPHER_KEY_DATA);

	if (elem != NULL) {
		num = config_setting_length(elem);

		if (num > 0) {
			crypto->param.cipher_key.data =
				calloc(1U, num * sizeof(*crypto->param.cipher_key.data));

			if (crypto->param.cipher_key.data == NULL)
				ODPH_ABORT("Error allocating memory, aborting\n");

			for (int i = 0; i < num; ++i)
				crypto->param.cipher_key.data[i] =
					config_setting_get_int_elem(elem, i);
		}
	}

	if (config_setting_lookup_int(cs, CONF_STR_CIPHER_KEY_LEN, &val_i) == CONFIG_TRUE)
		crypto->param.cipher_key.length = val_i;

	if (config_setting_lookup_int(cs, CONF_STR_CIPHER_IV_LEN, &val_i) == CONFIG_TRUE)
		crypto->param.cipher_iv_len = val_i;

	if (config_setting_lookup_string(cs, CONF_STR_AUTH_ALG, &val_str) == CONFIG_TRUE) {
		if (strcmp(val_str, CIPHER_AUTH_NULL) == 0) {
			crypto->param.auth_alg = ODP_AUTH_ALG_NULL;
		} else if (strcmp(val_str, AUTH_MD5_HMAC) == 0) {
			crypto->param.auth_alg = ODP_AUTH_ALG_MD5_HMAC;
		} else if (strcmp(val_str, AUTH_SHA1_HMAC) == 0) {
			crypto->param.auth_alg = ODP_AUTH_ALG_SHA1_HMAC;
		} else if (strcmp(val_str, AUTH_SHA224_HMAC) == 0) {
			crypto->param.auth_alg = ODP_AUTH_ALG_SHA224_HMAC;
		} else if (strcmp(val_str, AUTH_SHA256_HMAC) == 0) {
			crypto->param.auth_alg = ODP_AUTH_ALG_SHA256_HMAC;
		} else if (strcmp(val_str, AUTH_SHA384_HMAC) == 0) {
			crypto->param.auth_alg = ODP_AUTH_ALG_SHA384_HMAC;
		} else if (strcmp(val_str, AUTH_SHA512_HMAC) == 0) {
			crypto->param.auth_alg = ODP_AUTH_ALG_SHA512_HMAC;
		} else if (strcmp(val_str, AUTH_SHA3_224_HMAC) == 0) {
			crypto->param.auth_alg = ODP_AUTH_ALG_SHA3_224_HMAC;
		} else if (strcmp(val_str, AUTH_SHA3_256_HMAC) == 0) {
			crypto->param.auth_alg = ODP_AUTH_ALG_SHA3_256_HMAC;
		} else if (strcmp(val_str, AUTH_SHA3_384_HMAC) == 0) {
			crypto->param.auth_alg = ODP_AUTH_ALG_SHA3_384_HMAC;
		} else if (strcmp(val_str, AUTH_SHA3_512_HMAC) == 0) {
			crypto->param.auth_alg = ODP_AUTH_ALG_SHA3_512_HMAC;
		} else if (strcmp(val_str, AUTH_AES_GMAC) == 0) {
			crypto->param.auth_alg = ODP_AUTH_ALG_AES_GMAC;
		} else if (strcmp(val_str, AUTH_AES_CMAC) == 0) {
			crypto->param.auth_alg = ODP_AUTH_ALG_AES_CMAC;
		} else if (strcmp(val_str, AUTH_AES_XCBC_MAC) == 0) {
			crypto->param.auth_alg = ODP_AUTH_ALG_AES_XCBC_MAC;
		} else if (strcmp(val_str, AUTH_KASUMI_F9) == 0) {
			crypto->param.auth_alg = ODP_AUTH_ALG_KASUMI_F9;
		} else if (strcmp(val_str, AUTH_SNOW3G_UIA2) == 0) {
			crypto->param.auth_alg = ODP_AUTH_ALG_SNOW3G_UIA2;
		} else if (strcmp(val_str, AUTH_AES_EIA2) == 0) {
			crypto->param.auth_alg = ODP_AUTH_ALG_AES_EIA2;
		} else if (strcmp(val_str, AUTH_ZUC_EIA3) == 0) {
			crypto->param.auth_alg = ODP_AUTH_ALG_ZUC_EIA3;
		} else if (strcmp(val_str, AUTH_SNOW_V_GMAC) == 0) {
			crypto->param.auth_alg = ODP_AUTH_ALG_SNOW_V_GMAC;
		} else if (strcmp(val_str, AUTH_SM3_HMAC) == 0) {
			crypto->param.auth_alg = ODP_AUTH_ALG_SM3_HMAC;
		} else if (strcmp(val_str, AUTH_SM4_GMAC) == 0) {
			crypto->param.auth_alg = ODP_AUTH_ALG_SM4_GMAC;
		} else if (strcmp(val_str, AUTH_MD5) == 0) {
			crypto->param.auth_alg = ODP_AUTH_ALG_MD5;
		} else if (strcmp(val_str, AUTH_SHA1) == 0) {
			crypto->param.auth_alg = ODP_AUTH_ALG_SHA1;
		} else if (strcmp(val_str, AUTH_SHA224) == 0) {
			crypto->param.auth_alg = ODP_AUTH_ALG_SHA224;
		} else if (strcmp(val_str, AUTH_SHA256) == 0) {
			crypto->param.auth_alg = ODP_AUTH_ALG_SHA256;
		} else if (strcmp(val_str, AUTH_SHA384) == 0) {
			crypto->param.auth_alg = ODP_AUTH_ALG_SHA384;
		} else if (strcmp(val_str, AUTH_SHA512) == 0) {
			crypto->param.auth_alg = ODP_AUTH_ALG_SHA512;
		} else if (strcmp(val_str, AUTH_SHA3_224) == 0) {
			crypto->param.auth_alg = ODP_AUTH_ALG_SHA3_224;
		} else if (strcmp(val_str, AUTH_SHA3_256) == 0) {
			crypto->param.auth_alg = ODP_AUTH_ALG_SHA3_256;
		} else if (strcmp(val_str, AUTH_SHA3_384) == 0) {
			crypto->param.auth_alg = ODP_AUTH_ALG_SHA3_384;
		} else if (strcmp(val_str, AUTH_SHA3_512) == 0) {
			crypto->param.auth_alg = ODP_AUTH_ALG_SHA3_512;
		} else if (strcmp(val_str, AUTH_SM3) == 0) {
			crypto->param.auth_alg = ODP_AUTH_ALG_SM3;
		} else {
			ODPH_ERR("No valid \"" CONF_STR_AUTH_ALG "\" found\n");
			return false;
		}
	}

	elem = config_setting_lookup(cs, CONF_STR_AUTH_KEY_DATA);

	if (elem != NULL) {
		num = config_setting_length(elem);

		if (num > 0) {
			crypto->param.auth_key.data =
				calloc(1U, num * sizeof(*crypto->param.auth_key.data));

			if (crypto->param.auth_key.data == NULL)
				ODPH_ABORT("Error allocating memory, aborting\n");

			for (int i = 0; i < num; ++i)
				crypto->param.auth_key.data[i] =
					config_setting_get_int_elem(elem, i);
		}
	}

	if (config_setting_lookup_int(cs, CONF_STR_AUTH_KEY_LEN, &val_i) == CONFIG_TRUE)
		crypto->param.auth_key.length = val_i;

	if (config_setting_lookup_int(cs, CONF_STR_AUTH_IV_LEN, &val_i) == CONFIG_TRUE)
		crypto->param.auth_iv_len = val_i;

	if (config_setting_lookup_int(cs, CONF_STR_AUTH_DIGEST_LEN, &val_i) == CONFIG_TRUE)
		crypto->param.auth_digest_len = val_i;

	if (config_setting_lookup_int(cs, CONF_STR_AUTH_AAD_LEN, &val_i) == CONFIG_TRUE)
		crypto->param.auth_aad_len = val_i;

	if (config_setting_lookup_string(cs, CONF_STR_COMPL_Q, &val_str) == CONFIG_FALSE) {
		ODPH_ERR("No \"" CONF_STR_COMPL_Q "\" found\n");
		return false;
	}

	crypto->queue = strdup(val_str);

	if (crypto->queue == NULL)
		ODPH_ABORT("Error allocating memory, aborting\n");

	return true;
}

static void free_crypto_entry(crypto_parse_t *crypto)
{
	free(crypto->name);
	free(crypto->queue);
	free(crypto->param.cipher_key.data);
	free(crypto->param.auth_key.data);

	if (crypto->crypto != ODP_CRYPTO_SESSION_INVALID)
		(void)odp_crypto_session_destroy(crypto->crypto);
}

static odp_bool_t crypto_parser_init(config_t *config)
{
	config_setting_t *cs, *elem;
	int num;
	crypto_parse_t *crypto;

	cs = config_lookup(config, CRYPTO_DOMAIN);

	if (cs == NULL)	{
		printf("Nothing to parse for \"" CRYPTO_DOMAIN "\" domain\n");
		return true;
	}

	num = config_setting_length(cs);

	if (num == 0) {
		ODPH_ERR("No valid \"" CRYPTO_DOMAIN "\" entries found\n");
		return false;
	}

	cryptos.cryptos = calloc(1U, num * sizeof(*cryptos.cryptos));

	if (cryptos.cryptos == NULL)
		ODPH_ABORT("Error allocating memory, aborting\n");

	for (int i = 0; i < num; ++i) {
		elem = config_setting_get_elem(cs, i);

		if (elem == NULL) {
			ODPH_ERR("Unparsable \"" CRYPTO_DOMAIN "\" entry (%d)\n", i);
			return false;
		}

		crypto = &cryptos.cryptos[cryptos.num];

		if (!parse_crypto_entry(elem, crypto)) {
			ODPH_ERR("Invalid \"" CRYPTO_DOMAIN "\" entry (%d)\n", i);
			free_crypto_entry(crypto);
			return false;
		}

		++cryptos.num;
	}

	return true;
}

static odp_bool_t crypto_parser_deploy(void)
{
	crypto_parse_t *crypto;
	odp_queue_t queue;
	odp_crypto_ses_create_err_t status;

	printf("\n*** " CRYPTO_DOMAIN " resources ***\n");

	for (uint32_t i = 0U; i < cryptos.num; ++i) {
		crypto = &cryptos.cryptos[i];
		queue = (odp_queue_t)config_parser_get(QUEUE_DOMAIN, crypto->queue);
		crypto->param.compl_queue = queue;
		(void)odp_crypto_session_create(&crypto->param, &crypto->crypto, &status);

		if (crypto->crypto == ODP_CRYPTO_SESSION_INVALID) {
			ODPH_ERR("Error creating crypto session (%s): %d\n", crypto->name, status);
			return false;
		}

		printf("\nname: %s\n"
		       "info:\n", crypto->name);
	}

	return true;
}

static void crypto_parser_destroy(void)
{
	for (uint32_t i = 0U; i < cryptos.num; ++i)
		free_crypto_entry(&cryptos.cryptos[i]);

	free(cryptos.cryptos);
}

static uintptr_t crypto_parser_get_resource(const char *resource)
{
	crypto_parse_t *parse;
	odp_crypto_session_t crypto = ODP_CRYPTO_SESSION_INVALID;

	for (uint32_t i = 0U; i < cryptos.num; ++i) {
		parse = &cryptos.cryptos[i];

		if (strcmp(parse->name, resource) != 0)
			continue;

		crypto = parse->crypto;
		break;
	}

	if (crypto == ODP_CRYPTO_SESSION_INVALID)
		ODPH_ABORT("No resource found (%s), aborting\n", resource);

	return (uintptr_t)crypto;
}

CONFIG_PARSER_AUTOREGISTER(LOW_PRIO, CRYPTO_DOMAIN, crypto_parser_init, crypto_parser_deploy, NULL,
			   crypto_parser_destroy, crypto_parser_get_resource)
