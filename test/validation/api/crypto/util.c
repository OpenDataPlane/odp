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
	const char *name = odph_auth_alg_to_str(auth);

	return name ? name : "Unknown";
}

const char *cipher_alg_name(odp_cipher_alg_t cipher)
{
	const char *name = odph_cipher_alg_to_str(cipher);

	return name ? name : "Unknown";
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

	if (!odph_cipher_supported(&capability.ciphers, cipher) ||
	    !odph_auth_supported(&capability.auths, auth))
		return ODP_TEST_INACTIVE;

	return ODP_TEST_ACTIVE;
}

