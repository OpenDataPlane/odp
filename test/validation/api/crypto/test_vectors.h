/* Copyright (c) 2014-2018, Linaro Limited
 * Copyright (c) 2021-2023, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#ifndef TEST_VECTORS_H
#define TEST_VECTORS_H

#include <odp_api.h>
#include "test_vectors_len.h"

typedef struct crypto_test_reference_s {
	uint8_t copy_previous_vector;  /* does not copy digest_length */
	odp_cipher_alg_t cipher;
	odp_auth_alg_t auth;
	uint32_t cipher_key_length;
	uint8_t cipher_key[MAX_KEY_LEN];
	uint32_t auth_key_length;
	uint8_t auth_key[MAX_KEY_LEN];
	uint32_t cipher_iv_length;
	uint8_t cipher_iv[MAX_IV_LEN];
	uint32_t auth_iv_length;
	uint8_t auth_iv[MAX_IV_LEN];
	uint32_t length;
	odp_bool_t is_length_in_bits;
	uint8_t plaintext[MAX_DATA_LEN];
	uint8_t ciphertext[MAX_DATA_LEN];
	uint32_t aad_length;
	uint8_t aad[MAX_AAD_LEN];
	uint32_t digest_length;
	uint8_t digest[MAX_DIGEST_LEN];
} crypto_test_reference_t;

ODP_STATIC_ASSERT(ODP_CIPHER_ALG_NULL == 0, "null cipher is not the default");
ODP_STATIC_ASSERT(ODP_AUTH_ALG_NULL == 0, "null auth is not the default");

/*
 * Return test data length in bytes, rounding up to full bytes.
 */
static inline uint32_t ref_length_in_bytes(const crypto_test_reference_t *ref)
{
	return ref->is_length_in_bits ? (ref->length + 7) / 8 : ref->length;
}

/*
 * Return test data length in bits
 */
static inline uint32_t ref_length_in_bits(const crypto_test_reference_t *ref)
{
	return ref->is_length_in_bits ? ref->length : 8 * ref->length;
}

static inline void init_reference(crypto_test_reference_t *ref, int size)
{
	int n;
	crypto_test_reference_t *prev = NULL;

	for (n = 0; n < size; n++) {
		if (prev && ref[n].copy_previous_vector) {
			uint32_t len;

			len = ref[n].digest_length;
			ref[n] = *prev;
			ref[n].digest_length = len;
		}
		prev = &ref[n];
	}
}

#endif
