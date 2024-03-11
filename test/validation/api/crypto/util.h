/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2014-2018 Linaro Limited
 * Copyright (c) 2021-2023 Nokia
 */

#ifndef UTIL_H
#define UTIL_H

#include <stdint.h>
#include <odp_api.h>
#include <odp_cunit_common.h>

struct suite_context_s {
	odp_crypto_op_mode_t op_mode;
	odp_pool_t pool;
	odp_queue_t queue;
	odp_queue_type_t q_type;
	odp_event_t (*compl_queue_deq)(void);
	int partial_test;
};

extern struct suite_context_s suite_context;

const char *auth_alg_name(odp_auth_alg_t auth);

const char *cipher_alg_name(odp_cipher_alg_t cipher);

/*
 * Check if given cipher and authentication algorithms are supported
 *
 * cipher      Cipher algorithm
 * auth        Authentication algorithm
 *
 * returns ODP_TEST_ACTIVE when both algorithms are supported or
 *         ODP_TEST_INACTIVE when either algorithm is not supported
 */
int check_alg_support(odp_cipher_alg_t cipher, odp_auth_alg_t auth);

static inline void fill_with_pattern(uint8_t *buf, uint32_t len)
{
	static uint8_t value;

	for (uint32_t n = 0; n < len; n++)
		buf[n] = value++;
}

#endif
