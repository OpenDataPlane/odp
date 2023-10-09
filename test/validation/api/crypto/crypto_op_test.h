/*
 * Copyright (c) 2021-2023, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#ifndef CRYPTO_OP_TEST_H
#define CRYPTO_OP_TEST_H

#include <odp_api.h>
#include <stdint.h>
#include "test_vectors.h"

typedef struct crypto_session_t {
	odp_crypto_session_t session;
	odp_crypto_op_t op;
	odp_crypto_op_type_t op_type;
	odp_bool_t cipher_range_in_bits;
	odp_bool_t auth_range_in_bits;
	odp_bool_t null_crypto_enable;
} crypto_session_t;

typedef struct crypto_op_test_param_t {
	crypto_session_t session;
	odp_crypto_op_type_t op_type;
	int32_t oop_shift;
	crypto_test_reference_t *ref;
	odp_packet_data_range_t cipher_range;
	odp_packet_data_range_t auth_range;
	uint32_t digest_offset;
	odp_bool_t null_crypto;
	odp_bool_t adjust_segmentation;
	odp_bool_t wrong_digest;
	uint32_t first_seg_len;
	uint32_t header_len;
	uint32_t trailer_len;
} crypto_op_test_param_t;

void test_crypto_op(const crypto_op_test_param_t *param);

int crypto_op(odp_packet_t pkt_in,
	      odp_packet_t *pkt_out,
	      odp_bool_t *ok,
	      const odp_crypto_packet_op_param_t *op_params,
	      odp_crypto_op_type_t session_op_type,
	      odp_crypto_op_type_t op_type);

#endif
