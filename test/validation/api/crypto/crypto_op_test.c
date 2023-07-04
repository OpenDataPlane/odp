/* Copyright (c) 2014-2018, Linaro Limited
 * Copyright (c) 2021-2023, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include <string.h>
#include <stdlib.h>
#include <odp_api.h>
#include <odp_cunit_common.h>
#include <packet_common.h>
#include "crypto_op_test.h"
#include "util.h"

#define MAX_FAILURE_PRINTS 20

#define MAX_IGNORED_RANGES 3

/*
 * Output packet parts that we ignore since they have undefined values
 */
typedef struct ignore_t {
	uint32_t byte_offset;	/* offset to a byte which has bits to be ignored */
	uint8_t byte_mask;	/* mask of ignored bits in the byte */
	struct {
		uint32_t offset;
		uint32_t length;
	} ranges[MAX_IGNORED_RANGES]; /* byte ranges to be ignored */
	uint32_t num_ranges;
} ignore_t;

/* Add room for bytes that are not included in ref->length */
#define MAX_EXP_DATA_LEN (MAX_DATA_LEN + 200)

/*
 * Expected packet data
 */
typedef struct expected_t {
	uint8_t data[MAX_EXP_DATA_LEN];
	uint32_t len;
	ignore_t ignore;
} expected_t;

int crypto_op(odp_packet_t pkt_in,
	      odp_packet_t *pkt_out,
	      odp_bool_t *ok,
	      const odp_crypto_packet_op_param_t *op_params,
	      odp_crypto_op_type_t op_type)
{
	int rc;
	odp_event_t event;
	odp_crypto_packet_result_t result;
	odp_event_subtype_t subtype;
	odp_packet_t orig_pkt_out;

	if (op_type == ODP_CRYPTO_OP_TYPE_LEGACY)
		*pkt_out = pkt_in;
	else if (op_type == ODP_CRYPTO_OP_TYPE_BASIC)
		*pkt_out = ODP_PACKET_INVALID;
	orig_pkt_out = *pkt_out;

	if (suite_context.op_mode == ODP_CRYPTO_SYNC) {
		rc = odp_crypto_op(&pkt_in, pkt_out, op_params, 1);
		if (rc <= 0) {
			CU_FAIL("Failed odp_crypto_packet_op()");
			goto fail;
		}
	} else {
		odp_packet_t *out_param = pkt_out;

		if (op_type == ODP_CRYPTO_OP_TYPE_BASIC)
			out_param = NULL;

		rc = odp_crypto_op_enq(&pkt_in, out_param, op_params, 1);
		if (rc <= 0) {
			CU_FAIL("Failed odp_crypto_op_enq()");
			goto fail;
		}

		/* Get crypto completion event from compl_queue. */
		CU_ASSERT_FATAL(NULL != suite_context.compl_queue_deq);
		do {
			event = suite_context.compl_queue_deq();
		} while (event == ODP_EVENT_INVALID);

		CU_ASSERT(ODP_EVENT_PACKET == odp_event_type(event));
		CU_ASSERT(ODP_EVENT_PACKET_CRYPTO == odp_event_subtype(event));
		CU_ASSERT(ODP_EVENT_PACKET == odp_event_types(event, &subtype));
		CU_ASSERT(ODP_EVENT_PACKET_CRYPTO == subtype);

		*pkt_out = odp_crypto_packet_from_event(event);
	}

	if (op_type != ODP_CRYPTO_OP_TYPE_BASIC)
		CU_ASSERT(*pkt_out == orig_pkt_out);
	CU_ASSERT(ODP_EVENT_PACKET ==
		  odp_event_type(odp_packet_to_event(*pkt_out)));
	CU_ASSERT(ODP_EVENT_PACKET_CRYPTO ==
		  odp_event_subtype(odp_packet_to_event(*pkt_out)));
	CU_ASSERT(ODP_EVENT_PACKET ==
		  odp_event_types(odp_packet_to_event(*pkt_out), &subtype));
	CU_ASSERT(ODP_EVENT_PACKET_CRYPTO == subtype);
	CU_ASSERT(odp_packet_subtype(*pkt_out) == ODP_EVENT_PACKET_CRYPTO);

	rc = odp_crypto_result(&result, *pkt_out);
	if (rc < -1)
		CU_FAIL("Failed odp_crypto_result()");
	CU_ASSERT(rc == 0 || rc == -1);

	if (op_type == ODP_CRYPTO_OP_TYPE_OOP &&
	    suite_context.op_mode == ODP_CRYPTO_ASYNC)
		CU_ASSERT(result.pkt_in == pkt_in);

	*ok = (rc == 0);

#if ODP_DEPRECATED_API
	CU_ASSERT(*ok == result.ok);
#endif

	return 0;
fail:
	odp_packet_free(pkt_in);
	if (op_type == ODP_CRYPTO_OP_TYPE_OOP)
		odp_packet_free(*pkt_out);
	return -1;
}

/*
 * Try to adjust packet so that the first segment holds 'first_seg_len' bytes
 * of packet data (+ tailroom if first_seg_len is longer than the packet).
 *
 * If 'first_seg_len' is zero, do not try to add segments but make headroom
 * zero.
 *
 * Packet data bytes are not preserved.
 */
static void adjust_segments(odp_packet_t *pkt, uint32_t first_seg_len)
{
	uint32_t shift;

	shift = odp_packet_headroom(*pkt) + first_seg_len;

	if (odp_packet_extend_head(pkt, shift, NULL, NULL) < 0) {
		CU_FAIL("odp_packet_extend_head() failed\n");
		return;
	}
	if (odp_packet_trunc_tail(pkt, shift, NULL, NULL) < 0) {
		CU_FAIL("odp_packet_trunc_tail() failed\n");
		return;
	}
	/*
	 * ODP API does not seem to guarantee that we ever have a multi-segment
	 * packet at this point, but we can print a message about it.
	 */
	if (first_seg_len == 1 &&
	    first_seg_len != odp_packet_seg_len(*pkt))
		printf("Could not create a segmented packet for testing.\n");
}

static void write_header_and_trailer(odp_packet_t pkt,
				     uint32_t header_len, uint32_t trailer_len)
{
	uint32_t trailer_offset = odp_packet_len(pkt) - trailer_len;
	uint32_t max_len = header_len > trailer_len ? header_len : trailer_len;
	uint8_t buffer[max_len];
	int rc;

	fill_with_pattern(buffer, sizeof(buffer));

	rc = odp_packet_copy_from_mem(pkt, 0, header_len, buffer);
	CU_ASSERT(rc == 0);
	rc = odp_packet_copy_from_mem(pkt, trailer_offset, trailer_len, buffer);
	CU_ASSERT(rc == 0);
}

static void prepare_crypto_ranges(const crypto_op_test_param_t *param,
				  odp_packet_data_range_t *cipher_range,
				  odp_packet_data_range_t *auth_range)
{
	uint32_t c_scale = param->session.cipher_range_in_bits ? 8 : 1;
	uint32_t a_scale = param->session.auth_range_in_bits ? 8 : 1;

	*cipher_range = param->cipher_range;
	*auth_range = param->auth_range;
	cipher_range->offset += c_scale * param->header_len;
	auth_range->offset += a_scale * param->header_len;
}

static int prepare_input_packet(const crypto_op_test_param_t *param,
				odp_packet_t *pkt_in)
{
	crypto_test_reference_t *ref = param->ref;
	uint32_t reflength = ref_length_in_bytes(ref);
	odp_packet_t pkt;
	uint32_t digest_offset = param->digest_offset;
	uint32_t pkt_len;

	pkt_len = param->header_len + reflength + param->trailer_len;
	if (param->digest_offset == param->header_len + reflength)
		pkt_len += ref->digest_length;

	pkt = odp_packet_alloc(suite_context.pool, pkt_len);

	CU_ASSERT(pkt != ODP_PACKET_INVALID);
	if (pkt == ODP_PACKET_INVALID)
		return -1;

	if (param->adjust_segmentation)
		adjust_segments(&pkt, param->first_seg_len);

	write_header_and_trailer(pkt, param->header_len, param->trailer_len);

	if (param->session.op == ODP_CRYPTO_OP_ENCODE) {
		odp_packet_copy_from_mem(pkt, param->header_len,
					 reflength, ref->plaintext);
	} else {
		odp_packet_copy_from_mem(pkt, param->header_len,
					 reflength, ref->ciphertext);
		odp_packet_copy_from_mem(pkt, digest_offset,
					 ref->digest_length,
					 ref->digest);
		if (param->wrong_digest) {
			uint8_t byte = ~ref->digest[0];

			odp_packet_copy_from_mem(pkt, digest_offset, 1, &byte);
		}
	}
	*pkt_in = pkt;
	return 0;
}

static void prepare_oop_output_packet(const crypto_op_test_param_t *param,
				      odp_packet_t *pkt_out,
				      uint32_t pkt_len)
{
	uint32_t reflength = ref_length_in_bytes(param->ref);
	const uint32_t oop_extra_len = 5;
	uint32_t trl_len;
	uint32_t hdr_len;
	uint32_t oop_len;

	oop_len = pkt_len + param->oop_shift + oop_extra_len;
	*pkt_out = odp_packet_alloc(suite_context.pool, oop_len);
	CU_ASSERT_FATAL(*pkt_out != ODP_PACKET_INVALID);

	uint8_t buf[oop_len];

	memset(buf, 0x55, sizeof(buf));
	odp_packet_copy_from_mem(*pkt_out, 0, sizeof(buf), buf);

	hdr_len = param->header_len + param->oop_shift;
	trl_len = oop_len - hdr_len - reflength;

	write_header_and_trailer(*pkt_out, hdr_len, trl_len);

	/* have different metadata than in the input packet */
	memset(odp_packet_user_area(*pkt_out), 0xab,
	       odp_packet_user_area_size(*pkt_out));
}

static int is_packet_data_equal(odp_packet_t pkt_1, odp_packet_t pkt_2)
{
	uint32_t len = odp_packet_len(pkt_1);
	uint8_t buf_1[len];
	uint8_t buf_2[len];

	if (len != odp_packet_len(pkt_2) ||
	    odp_packet_copy_to_mem(pkt_1, 0, len, buf_1) ||
	    odp_packet_copy_to_mem(pkt_2, 0, len, buf_2))
		return 0;

	return !memcmp(buf_1, buf_2, len);
}

static int is_in_range(uint32_t offs, uint32_t range_offs, uint32_t range_len)
{
	return offs >= range_offs && offs < range_offs + range_len;
}

static void add_ignored_range(ignore_t *ign, uint32_t offs, uint32_t len)
{
	if (len == 0)
		return;
	CU_ASSERT_FATAL(ign->num_ranges < MAX_IGNORED_RANGES);
	ign->ranges[ign->num_ranges].offset = offs;
	ign->ranges[ign->num_ranges].length = len;
	ign->num_ranges++;
}

static void clear_ignored_data(const ignore_t *ign, uint8_t *data, uint32_t data_len)
{
	CU_ASSERT_FATAL(ign->byte_offset < data_len);
	data[ign->byte_offset] &= ~ign->byte_mask;

	for (uint32_t n = 0; n < ign->num_ranges; n++) {
		uint32_t offset = ign->ranges[n].offset;
		uint32_t length = ign->ranges[n].length;

		CU_ASSERT(offset + length <= data_len);
		memset(data + offset, 0, length);
	}
}

static void prepare_ignore_info(const crypto_op_test_param_t *param,
				uint32_t shift,
				uint32_t cipher_offset,
				uint32_t cipher_len,
				uint32_t auth_offset,
				uint32_t auth_len,
				ignore_t *ignore)
{
	memset(ignore, 0, sizeof(*ignore));

	/*
	 * Leftover bits in the last byte of the cipher range of bit mode
	 * ciphers have undefined values.
	 */
	if (param->session.cipher_range_in_bits &&
	    param->ref->cipher != ODP_CIPHER_ALG_NULL) {
		uint8_t leftover_bits = ref_length_in_bits(param->ref) % 8;

		ignore->byte_offset = cipher_offset + cipher_len - 1 + shift;
		if (leftover_bits > 0)
			ignore->byte_mask = ~(0xff << (8 - leftover_bits));
		else
			ignore->byte_mask = 0;
	}

	/*
	 * In decode sessions the bytes in the hash location have
	 * undefined values.
	 */
	if (param->ref->auth != ODP_AUTH_ALG_NULL &&
	    param->session.op == ODP_CRYPTO_OP_DECODE) {
		uint32_t offs = param->digest_offset;

		if (param->session.op_type != ODP_CRYPTO_OP_TYPE_OOP ||
		    is_in_range(offs, cipher_offset, cipher_len) ||
		    is_in_range(offs, auth_offset, auth_len)) {
			add_ignored_range(ignore,
					  param->digest_offset + shift,
					  param->ref->digest_length);
		}
	}

	/* Decrypted bytes are undefined if authentication fails. */
	if (param->session.op == ODP_CRYPTO_OP_DECODE &&
	    param->wrong_digest) {
		add_ignored_range(ignore, cipher_offset + shift, cipher_len);
		/* In OOP case, auth range may not get copied */
		if (param->session.op_type == ODP_CRYPTO_OP_TYPE_OOP)
			add_ignored_range(ignore, auth_offset + shift, auth_len);
	}
}

static void prepare_expected_data(const crypto_op_test_param_t *param,
				  const odp_packet_data_range_t *cipher_range,
				  const odp_packet_data_range_t *auth_range,
				  odp_packet_t pkt_in,
				  odp_packet_t pkt_out,
				  expected_t *ex)
{
	uint32_t digest_offset = param->digest_offset;
	uint32_t cipher_offset = cipher_range->offset;
	uint32_t cipher_len = cipher_range->length;
	uint32_t auth_offset = auth_range->offset;
	uint32_t auth_len = auth_range->length;
	const int32_t shift = param->session.op_type == ODP_CRYPTO_OP_TYPE_OOP ? param->oop_shift
									       : 0;
	const odp_packet_t base_pkt = param->session.op_type == ODP_CRYPTO_OP_TYPE_OOP ? pkt_out
										       : pkt_in;
	int rc;
	uint32_t cipher_offset_in_ref = param->cipher_range.offset;

	if (param->session.op == ODP_CRYPTO_OP_ENCODE)
		digest_offset += shift;

	if (param->session.cipher_range_in_bits) {
		cipher_offset_in_ref /= 8;
		cipher_offset /= 8;
		cipher_len = (cipher_len + 7) / 8;
	}
	if (param->session.auth_range_in_bits) {
		auth_offset /= 8;
		auth_len = (auth_len + 7) / 8;
	}
	if (param->ref->auth == ODP_AUTH_ALG_AES_GCM ||
	    param->ref->auth == ODP_AUTH_ALG_AES_CCM ||
	    param->ref->auth == ODP_AUTH_ALG_CHACHA20_POLY1305) {
		/* auth range is ignored with AEAD algorithms */
		auth_len = 0;
	}

	/* copy all data from base packet */
	ex->len = odp_packet_len(base_pkt);
	CU_ASSERT_FATAL(ex->len <= sizeof(ex->data));
	rc = odp_packet_copy_to_mem(base_pkt, 0, ex->len, ex->data);
	CU_ASSERT(rc == 0);

	if (param->session.op_type == ODP_CRYPTO_OP_TYPE_OOP && auth_len > 0) {
		/* copy auth range from input packet */
		rc = odp_packet_copy_to_mem(pkt_in, auth_offset, auth_len,
					    ex->data + auth_offset + shift);
		CU_ASSERT(rc == 0);
	}

	if (param->session.op == ODP_CRYPTO_OP_ENCODE) {
		/* copy hash first */
		memcpy(ex->data + digest_offset,
		       param->ref->digest,
		       param->ref->digest_length);
		/*
		 * Copy ciphertext, possibly overwriting hash.
		 * The other order (hash overwriting some cipher
		 * text) does not work in any real use case anyway.
		 */
		memcpy(ex->data + cipher_offset + shift,
		       param->ref->ciphertext + cipher_offset_in_ref,
		       cipher_len);
	} else {
		memcpy(ex->data + cipher_offset + shift,
		       param->ref->plaintext + cipher_offset_in_ref,
		       cipher_len);
	}

	prepare_ignore_info(param, shift,
			    cipher_offset, cipher_len,
			    auth_offset, auth_len,
			    &ex->ignore);
}

static void print_data(const char *title, uint8_t *data, uint32_t len)
{
	static uint64_t limit;

	if (limit++ > MAX_FAILURE_PRINTS)
		return;

	printf("%s\n", title);
	for (uint32_t n = 0; n < len ; n++) {
		printf(" %02x", data[n]);
		if ((n + 1) % 16 == 0)
			printf("\n");
	}
	printf("\n");
}

static void check_output_packet_data(odp_packet_t pkt, expected_t *ex)
{
	int rc;
	uint8_t pkt_data[ex->len];

	CU_ASSERT(odp_packet_len(pkt) == ex->len);
	rc = odp_packet_copy_to_mem(pkt, 0, ex->len, pkt_data);
	CU_ASSERT(rc == 0);

	clear_ignored_data(&ex->ignore, pkt_data, sizeof(pkt_data));
	clear_ignored_data(&ex->ignore, ex->data, sizeof(ex->data));

	if (memcmp(pkt_data, ex->data, ex->len)) {
		CU_FAIL("packet data does not match expected data");
		print_data("packet:", pkt_data, ex->len);
		print_data("expected:", ex->data, ex->len);
	}
}

static int is_digest_in_cipher_range(const crypto_op_test_param_t *param,
				     const odp_crypto_packet_op_param_t *op_params)
{
	/*
	 * Do not use op_params.hash_result_offset here as it refers to
	 * the output packet which (in the OOP case) might be shifted
	 * relative to the input packet.
	 */
	uint32_t d_offset = param->digest_offset;

	if (param->session.cipher_range_in_bits)
		d_offset *= 8;

	return d_offset >= op_params->cipher_range.offset &&
		d_offset < op_params->cipher_range.offset + op_params->cipher_range.length;
}

void test_crypto_op(const crypto_op_test_param_t *param)
{
	odp_bool_t ok = false;
	odp_packet_t pkt;
	odp_packet_t pkt_copy = ODP_PACKET_INVALID;
	odp_packet_t pkt_out = ODP_PACKET_INVALID;
	test_packet_md_t md_in, md_out, md_out_orig;
	expected_t expected;
	odp_crypto_packet_op_param_t op_params = {
		.session = param->session.session,
		.cipher_iv_ptr = param->ref->cipher_iv,
		.auth_iv_ptr = param->ref->auth_iv,
		.hash_result_offset = param->digest_offset,
		.aad_ptr = param->ref->aad,
		.dst_offset_shift = param->oop_shift,
	};

	/*
	 * Test detection of wrong digest value in input packet
	 * only when decoding and using non-null auth algorithm.
	 */
	if (param->wrong_digest &&
	    (param->ref->auth == ODP_AUTH_ALG_NULL ||
	     param->session.op == ODP_CRYPTO_OP_ENCODE))
		return;

	prepare_crypto_ranges(param, &op_params.cipher_range, &op_params.auth_range);
	if (prepare_input_packet(param, &pkt))
		return;

	if (param->session.op_type == ODP_CRYPTO_OP_TYPE_OOP) {
		prepare_oop_output_packet(param, &pkt_out, odp_packet_len(pkt));

		pkt_copy = odp_packet_copy(pkt, suite_context.pool);
		CU_ASSERT_FATAL(pkt_copy != ODP_PACKET_INVALID);
		test_packet_get_md(pkt_out, &md_out_orig);
	}

	prepare_expected_data(param, &op_params.cipher_range, &op_params.auth_range,
			      pkt, pkt_out, &expected);

	if (param->session.op_type == ODP_CRYPTO_OP_TYPE_OOP &&
	    param->session.op == ODP_CRYPTO_OP_ENCODE) {
		/*
		 * In this type of sessions digest offset is an offset to the output
		 * packet, so apply the shift.
		 */
		op_params.hash_result_offset += param->oop_shift;
	}

	test_packet_set_md(pkt);
	test_packet_get_md(pkt, &md_in);

	if (crypto_op(pkt, &pkt_out, &ok, &op_params, param->session.op_type))
		return;

	test_packet_get_md(pkt_out, &md_out);

	if (param->session.op_type == ODP_CRYPTO_OP_TYPE_OOP) {
		test_packet_md_t md;

		/* check that input packet has not changed */
		CU_ASSERT(is_packet_data_equal(pkt, pkt_copy));
		odp_packet_free(pkt_copy);
		test_packet_get_md(pkt, &md);
		CU_ASSERT(test_packet_is_md_equal(&md, &md_in));
		odp_packet_free(pkt);

		/* check that metadata of output packet has not changed */
		CU_ASSERT(test_packet_is_md_equal(&md_out, &md_out_orig));
	} else {
		CU_ASSERT(test_packet_is_md_equal(&md_out, &md_in));
	}

	if (param->ref->cipher != ODP_CIPHER_ALG_NULL &&
	    param->ref->auth != ODP_AUTH_ALG_NULL &&
	    is_digest_in_cipher_range(param, &op_params)) {
		/*
		 * Not all implementations support digest offset in cipher
		 * range, so allow crypto op failure without further checks
		 * in this case.
		 */
		if (!ok)
			goto out;
	}

	if (param->wrong_digest) {
		CU_ASSERT(!ok);
	} else {
		CU_ASSERT(ok);
	}

	check_output_packet_data(pkt_out, &expected);
out:
	odp_packet_free(pkt_out);
}
