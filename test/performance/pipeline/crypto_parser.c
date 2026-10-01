/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2025-2026 Nokia
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
#define CONF_STR_CIPHER_ALG "cipher_alg"
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

	if (config_setting_lookup_string(cs, CONF_STR_CIPHER_ALG, &val_str) == CONFIG_TRUE &&
	    odph_cipher_alg_from_str(val_str, &crypto->param.cipher_alg)) {
		ODPH_ERR("No valid \"" CONF_STR_CIPHER_ALG "\" found\n");
		return false;
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

	if (config_setting_lookup_string(cs, CONF_STR_AUTH_ALG, &val_str) == CONFIG_TRUE &&
	    odph_auth_alg_from_str(val_str, &crypto->param.auth_alg)) {
		ODPH_ERR("No valid \"" CONF_STR_AUTH_ALG "\" found\n");
		return false;
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

	cs = config_lookup(config, ODP_PL_CRYPTO_DOMAIN);

	if (cs == NULL)	{
		printf("Nothing to parse for \"" ODP_PL_CRYPTO_DOMAIN "\" domain\n");
		return true;
	}

	num = config_setting_length(cs);

	if (num == 0) {
		ODPH_ERR("No valid \"" ODP_PL_CRYPTO_DOMAIN "\" entries found\n");
		return false;
	}

	cryptos.cryptos = calloc(1U, num * sizeof(*cryptos.cryptos));

	if (cryptos.cryptos == NULL)
		ODPH_ABORT("Error allocating memory, aborting\n");

	for (int i = 0; i < num; ++i) {
		elem = config_setting_get_elem(cs, i);

		if (elem == NULL) {
			ODPH_ERR("Unparsable \"" ODP_PL_CRYPTO_DOMAIN "\" entry (%d)\n", i);
			return false;
		}

		crypto = &cryptos.cryptos[cryptos.num];

		if (!parse_crypto_entry(elem, crypto)) {
			ODPH_ERR("Invalid \"" ODP_PL_CRYPTO_DOMAIN "\" entry (%d)\n", i);
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

	printf("\n*** " ODP_PL_CRYPTO_DOMAIN " resources ***\n");

	for (uint32_t i = 0U; i < cryptos.num; ++i) {
		crypto = &cryptos.cryptos[i];
		queue = (odp_queue_t)odp_pl_config_parser_get(ODP_PL_QUEUE_DOMAIN, crypto->queue);
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

CONFIG_PARSER_AUTOREGISTER(LOW_PRIO, ODP_PL_CRYPTO_DOMAIN, crypto_parser_init,
			   crypto_parser_deploy, NULL, crypto_parser_destroy,
			   crypto_parser_get_resource)
