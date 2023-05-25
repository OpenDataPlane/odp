/* Copyright (c) 2014-2018, Linaro Limited
 * Copyright (c) 2021-2023, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include <string.h>
#include <stdlib.h>
#include <odp_api.h>
#include <odp/helper/odph_api.h>
#include <odp_cunit_common.h>
#include <packet_common.h>
#include "test_vectors.h"

/*
 * If nonzero, run time consuming tests too.
 * Set through FULL_TEST environment variable.
 */
static int full_test;

#define MAX_FAILURE_PRINTS 20

#define PKT_POOL_NUM  64
#define PKT_POOL_LEN  1200 /* enough for a test packet and some headroom */
#define UAREA_SIZE 8

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))

struct suite_context_s {
	odp_crypto_op_mode_t op_mode;
	odp_pool_t pool;
	odp_queue_t queue;
	odp_queue_type_t q_type;
	odp_event_t (*compl_queue_deq)(void);
};

static struct suite_context_s suite_context;

static void test_defaults(uint8_t fill)
{
	odp_crypto_session_param_t param;

	memset(&param, fill, sizeof(param));
	odp_crypto_session_param_init(&param);

	CU_ASSERT_EQUAL(param.op, ODP_CRYPTO_OP_ENCODE);
	CU_ASSERT_EQUAL(param.op_type, ODP_CRYPTO_OP_TYPE_LEGACY);
	CU_ASSERT_EQUAL(param.auth_cipher_text, false);
	CU_ASSERT_EQUAL(param.op_mode, ODP_CRYPTO_SYNC);
	CU_ASSERT_EQUAL(param.cipher_alg, ODP_CIPHER_ALG_NULL);
	CU_ASSERT_EQUAL(param.cipher_iv_len, 0);
	CU_ASSERT_EQUAL(param.auth_alg, ODP_AUTH_ALG_NULL);
	CU_ASSERT_EQUAL(param.auth_iv_len, 0);
	CU_ASSERT_EQUAL(param.auth_aad_len, 0);
}

static void test_default_values(void)
{
	test_defaults(0);
	test_defaults(0xff);
}

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
	case ODP_AUTH_ALG_AES_XCBC_MAC:
		return "ODP_AUTH_ALG_AES_XCBC_MAC";
	case ODP_AUTH_ALG_AES_GCM:
		return "ODP_AUTH_ALG_AES_GCM";
	case ODP_AUTH_ALG_AES_GMAC:
		return "ODP_AUTH_ALG_AES_GMAC";
	case ODP_AUTH_ALG_AES_CCM:
		return "ODP_AUTH_ALG_AES_CCM";
	case ODP_AUTH_ALG_AES_CMAC:
		return "ODP_AUTH_ALG_AES_CMAC";
	case ODP_AUTH_ALG_CHACHA20_POLY1305:
		return "ODP_AUTH_ALG_CHACHA20_POLY1305";
	case ODP_AUTH_ALG_KASUMI_F9:
		return "ODP_AUTH_ALG_KASUMI_F9";
	case ODP_AUTH_ALG_SNOW3G_UIA2:
		return "ODP_AUTH_ALG_SNOW3G_UIA2";
	case ODP_AUTH_ALG_AES_EIA2:
		return "ODP_AUTH_ALG_AES_EIA2";
	case ODP_AUTH_ALG_ZUC_EIA3:
		return "ODP_AUTH_ALG_ZUC_EIA3";
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
	default:
		return "Unknown";
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
	case ODP_CIPHER_ALG_AES_EEA2:
		return "ODP_CIPHER_ALG_AES_EEA2";
	case ODP_CIPHER_ALG_ZUC_EEA3:
		return "ODP_CIPHER_ALG_ZUC_EEA3";
	default:
		return "Unknown";
	}
}

static int crypto_op(odp_packet_t pkt_in,
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

static void fill_with_pattern(uint8_t *buf, uint32_t len)
{
	static uint8_t value;

	for (uint32_t n = 0; n < len; n++)
		buf[n] = value++;
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

typedef struct alg_test_param_t {
	odp_crypto_session_t session;
	odp_crypto_op_t op;
	odp_crypto_op_type_t op_type;
	int32_t oop_shift;
	crypto_test_reference_t *ref;
	odp_packet_data_range_t cipher_range;
	odp_packet_data_range_t auth_range;
	uint32_t digest_offset;
	odp_bool_t is_bit_mode_cipher;
	odp_bool_t is_bit_mode_auth;
	odp_bool_t adjust_segmentation;
	odp_bool_t wrong_digest;
	uint32_t first_seg_len;
	uint32_t header_len;
	uint32_t trailer_len;
} alg_test_param_t;

static void prepare_crypto_ranges(const alg_test_param_t *param,
				  odp_packet_data_range_t *cipher_range,
				  odp_packet_data_range_t *auth_range)
{
	odp_packet_data_range_t zero_range = {.offset = 0, .length = 0};
	uint32_t c_scale = param->is_bit_mode_cipher ? 8 : 1;
	uint32_t a_scale = param->is_bit_mode_auth ? 8 : 1;

	*cipher_range = param->cipher_range;
	*auth_range = param->auth_range;
	cipher_range->offset += c_scale * param->header_len;
	auth_range->offset += a_scale * param->header_len;

	if (param->ref->cipher == ODP_CIPHER_ALG_NULL)
		*cipher_range = zero_range;
	if (param->ref->auth == ODP_AUTH_ALG_NULL)
		*auth_range = zero_range;
}

static int prepare_input_packet(const alg_test_param_t *param,
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

	if (param->op == ODP_CRYPTO_OP_ENCODE) {
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

static void prepare_oop_output_packet(const alg_test_param_t *param,
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

static void prepare_ignore_info(const alg_test_param_t *param,
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
	if (param->is_bit_mode_cipher &&
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
	    param->op == ODP_CRYPTO_OP_DECODE) {
		uint32_t offs = param->digest_offset;

		if (param->op_type != ODP_CRYPTO_OP_TYPE_OOP ||
		    is_in_range(offs, cipher_offset, cipher_len) ||
		    is_in_range(offs, auth_offset, auth_len)) {
			add_ignored_range(ignore,
					  param->digest_offset + shift,
					  param->ref->digest_length);
		}
	}

	/* Decrypted bytes are undefined if authentication fails. */
	if (param->op == ODP_CRYPTO_OP_DECODE &&
	    param->wrong_digest) {
		add_ignored_range(ignore, cipher_offset + shift, cipher_len);
		/* In OOP case, auth range may not get copied */
		if (param->op_type == ODP_CRYPTO_OP_TYPE_OOP)
			add_ignored_range(ignore, auth_offset + shift, auth_len);
	}
}

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

static void prepare_expected_data(const alg_test_param_t *param,
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
	const int32_t shift = param->op_type == ODP_CRYPTO_OP_TYPE_OOP ? param->oop_shift : 0;
	const odp_packet_t base_pkt = param->op_type == ODP_CRYPTO_OP_TYPE_OOP ? pkt_out : pkt_in;
	int rc;
	uint32_t cipher_offset_in_ref = param->cipher_range.offset;

	if (param->op == ODP_CRYPTO_OP_ENCODE)
		digest_offset += shift;

	if (param->is_bit_mode_cipher) {
		cipher_offset_in_ref /= 8;
		cipher_offset /= 8;
		cipher_len = (cipher_len + 7) / 8;
	}
	if (param->is_bit_mode_auth) {
		auth_offset /= 8;
		auth_len = (auth_len + 7) / 8;
	}
	if (param->ref->cipher == ODP_CIPHER_ALG_NULL)
		cipher_len = 0;
	if (param->ref->auth == ODP_AUTH_ALG_NULL ||
	    param->ref->auth == ODP_AUTH_ALG_AES_GCM ||
	    param->ref->auth == ODP_AUTH_ALG_AES_CCM ||
	    param->ref->auth == ODP_AUTH_ALG_CHACHA20_POLY1305) {
		/* auth range is ignored with null and AEAD algorithms */
		auth_len = 0;
	}

	/* copy all data from base packet */
	ex->len = odp_packet_len(base_pkt);
	CU_ASSERT_FATAL(ex->len <= sizeof(ex->data));
	rc = odp_packet_copy_to_mem(base_pkt, 0, ex->len, ex->data);
	CU_ASSERT(rc == 0);

	if (param->op_type == ODP_CRYPTO_OP_TYPE_OOP && auth_len > 0) {
		/* copy auth range from input packet */
		rc = odp_packet_copy_to_mem(pkt_in, auth_offset, auth_len,
					    ex->data + auth_offset + shift);
		CU_ASSERT(rc == 0);
	}

	if (param->op == ODP_CRYPTO_OP_ENCODE) {
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

static void alg_test_execute(const alg_test_param_t *param)
{
	odp_bool_t ok = false;
	odp_packet_t pkt;
	odp_packet_t pkt_copy = ODP_PACKET_INVALID;
	odp_packet_t pkt_out = ODP_PACKET_INVALID;
	test_packet_md_t md_in, md_out, md_out_orig;
	expected_t expected;
	odp_crypto_packet_op_param_t op_params = {
		.session = param->session,
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
	     param->op == ODP_CRYPTO_OP_ENCODE))
		return;

	prepare_crypto_ranges(param, &op_params.cipher_range, &op_params.auth_range);
	if (prepare_input_packet(param, &pkt))
		return;

	if (param->op_type == ODP_CRYPTO_OP_TYPE_OOP) {
		prepare_oop_output_packet(param, &pkt_out, odp_packet_len(pkt));

		pkt_copy = odp_packet_copy(pkt, suite_context.pool);
		CU_ASSERT_FATAL(pkt_copy != ODP_PACKET_INVALID);
		test_packet_get_md(pkt_out, &md_out_orig);
	}

	prepare_expected_data(param, &op_params.cipher_range, &op_params.auth_range,
			      pkt, pkt_out, &expected);

	if (param->op_type == ODP_CRYPTO_OP_TYPE_OOP &&
	    param->op == ODP_CRYPTO_OP_ENCODE) {
		/*
		 * In this type of sessions digest offset is an offset to the output
		 * packet, so apply the shift.
		 */
		op_params.hash_result_offset += param->oop_shift;
	}

	test_packet_set_md(pkt);
	test_packet_get_md(pkt, &md_in);

	if (crypto_op(pkt, &pkt_out, &ok, &op_params, param->op_type))
		return;

	test_packet_get_md(pkt_out, &md_out);

	if (param->op_type == ODP_CRYPTO_OP_TYPE_OOP) {
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
	    param->digest_offset >= op_params.cipher_range.offset &&
	    param->digest_offset < op_params.cipher_range.offset + op_params.cipher_range.length) {
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

static void print_alg_test_param(const alg_test_param_t *p)
{
	const char *cipher_mode = p->is_bit_mode_cipher ? "bit" : "byte";
	const char *auth_mode = p->is_bit_mode_auth ? "bit" : "byte";

	switch (p->op_type) {
	case ODP_CRYPTO_OP_TYPE_LEGACY:
		printf("legacy ");
		break;
	case ODP_CRYPTO_OP_TYPE_BASIC:
		printf("basic ");
		break;
	case ODP_CRYPTO_OP_TYPE_OOP:
		printf("out-of-place ");
		break;
	}
	printf("%s\n", p->op == ODP_CRYPTO_OP_ENCODE ? "encode" : "decode");

	printf("cipher: %s, %s mode\n", cipher_alg_name(p->ref->cipher), cipher_mode);
	printf("  key length: %d, iv length: %d\n",
	       p->ref->cipher_key_length, p->ref->cipher_iv_length);
	printf("  range: offset %d, length %d\n",
	       p->cipher_range.offset, p->cipher_range.length);

	printf("auth: %s, %s mode\n", auth_alg_name(p->ref->auth), auth_mode);
	printf("  key length: %d, iv length: %d\n",
	       p->ref->auth_key_length, p->ref->auth_iv_length);
	printf("  range: offset %d, length %d; aad length: %d\n",
	       p->auth_range.offset, p->auth_range.length, p->ref->aad_length);
	printf("  digest offset: %d, digest length %d\n",
	       p->digest_offset, p->ref->digest_length);

	if (p->wrong_digest)
		printf("wrong digest test\n");
	printf("header length: %d, trailer length: %d\n", p->header_len, p->trailer_len);
	if (p->adjust_segmentation)
		printf("segmentation adjusted, first_seg_len: %d\n", p->first_seg_len);
	if (p->op_type == ODP_CRYPTO_OP_TYPE_OOP)
		printf("oop_shift: %d\n", p->oop_shift);
}

static void alg_test_execute_and_print(alg_test_param_t *param)
{
	static int print_limit = MAX_FAILURE_PRINTS;
	unsigned int num = CU_get_number_of_failures();

	alg_test_execute(param);

	if (CU_get_number_of_failures() > num) {
		if (print_limit > 0) {
			printf("\nTest failed:\n");
			print_alg_test_param(param);
			printf("\n");
			print_limit--;
			if (print_limit == 0)
				printf("Suppressing further failure output\n");
		}
	}
}

static void alg_test_op(alg_test_param_t *param)
{
	int32_t oop_shifts[] = {0, 3, 130, -10};

	for (uint32_t n = 0; n < ARRAY_SIZE(oop_shifts); n++) {
		if (oop_shifts[n] != 0 &&
		    param->op_type != ODP_CRYPTO_OP_TYPE_OOP)
			continue;
		if ((int32_t)param->header_len + oop_shifts[n] < 0)
			continue;
		param->oop_shift = oop_shifts[n];

		param->wrong_digest = false;
		alg_test_execute_and_print(param);
		if (full_test)
			alg_test_execute_and_print(param); /* rerun with the same parameters */
		param->wrong_digest = true;
		alg_test_execute_and_print(param);
	}
}

static int combo_warning_shown;
static int oop_warning_shown;

typedef enum {
	HASH_NO_OVERLAP,
	HASH_OVERLAP,
} hash_test_mode_t;

typedef enum {
	AUTH_CIPHERTEXT,
	AUTH_PLAINTEXT
} alg_order_t;

static odp_crypto_session_t session_create(odp_crypto_op_t op,
					   odp_crypto_op_type_t op_type,
					   alg_order_t order,
					   crypto_test_reference_t *ref,
					   hash_test_mode_t hash_mode)
{
	odp_crypto_session_t session = ODP_CRYPTO_SESSION_INVALID;
	int rc;
	odp_crypto_ses_create_err_t status;
	odp_crypto_session_param_t ses_params;
	uint8_t cipher_key_data[ref->cipher_key_length];
	uint8_t auth_key_data[ref->auth_key_length];
	odp_crypto_key_t cipher_key = {
		.data = cipher_key_data,
		.length = ref->cipher_key_length
	};
	odp_crypto_key_t auth_key = {
		.data = auth_key_data,
		.length = ref->auth_key_length
	};

	memcpy(cipher_key_data, ref->cipher_key, ref->cipher_key_length);
	memcpy(auth_key_data, ref->auth_key, ref->auth_key_length);

	/* Create a crypto session */
	odp_crypto_session_param_init(&ses_params);
	ses_params.op = op;
	ses_params.op_type = op_type;
	ses_params.auth_cipher_text = (order == AUTH_CIPHERTEXT);
	ses_params.op_mode = suite_context.op_mode;
	ses_params.cipher_alg = ref->cipher;
	ses_params.auth_alg = ref->auth;
	ses_params.compl_queue = suite_context.queue;
	ses_params.output_pool = suite_context.pool;
	ses_params.cipher_key = cipher_key;
	ses_params.cipher_iv_len = ref->cipher_iv_length;
	ses_params.auth_iv_len = ref->auth_iv_length;
	ses_params.auth_key = auth_key;
	ses_params.auth_digest_len = ref->digest_length;
	ses_params.auth_aad_len = ref->aad_length;
	ses_params.hash_result_in_auth_range = (hash_mode == HASH_OVERLAP);
	rc = odp_crypto_session_create(&ses_params, &session, &status);

	if (rc < 0 && status == ODP_CRYPTO_SES_ERR_ALG_COMBO) {
		if (!combo_warning_shown) {
			combo_warning_shown = 1;
			printf("\n    Unsupported algorithm combination: %s, %s\n",
			       cipher_alg_name(ref->cipher),
			       auth_alg_name(ref->auth));
		}
		return ODP_CRYPTO_SESSION_INVALID;
	}

	/*
	 * Allow ODP_CRYPTO_SES_ERR_ALG_ORDER only in async op mode.
	 * In sync mode an implementation should be able to support both
	 * orders without much difficulty.
	 */
	if (rc < 0 && status == ODP_CRYPTO_SES_ERR_ALG_ORDER &&
	    ses_params.op_mode == ODP_CRYPTO_ASYNC) {
		printf("\n    Unsupported algorithm order: %s, %s, auth_cipher_text: %d\n",
		       cipher_alg_name(ref->cipher),
		       auth_alg_name(ref->auth),
		       ses_params.auth_cipher_text);
		return ODP_CRYPTO_SESSION_INVALID;
	}

	/* For now, allow out-of-place sessions not to be supported. */
	if (rc < 0 && status == ODP_CRYPTO_SES_ERR_PARAMS &&
	    op_type == ODP_CRYPTO_OP_TYPE_OOP) {
		if (!oop_warning_shown)
			printf("\n    Skipping ODP_CRYPTO_OP_TYPE_OOP tests\n");
		oop_warning_shown = 1;
		return ODP_CRYPTO_SESSION_INVALID;
	}

	CU_ASSERT_FATAL(!rc);
	CU_ASSERT(status == ODP_CRYPTO_SES_ERR_NONE);
	CU_ASSERT(odp_crypto_session_to_u64(session) !=
		  odp_crypto_session_to_u64(ODP_CRYPTO_SESSION_INVALID));

	/*
	 * Clear session creation parameters so that we might notice if
	 * the implementation still tried to use them.
	 */
	memset(cipher_key_data, 0, sizeof(cipher_key_data));
	memset(auth_key_data, 0, sizeof(auth_key_data));
	memset(&ses_params, 0, sizeof(ses_params));

	return session;
}

static void alg_test_ses(odp_crypto_op_t op,
			 odp_crypto_op_type_t op_type,
			 alg_order_t order,
			 crypto_test_reference_t *ref,
			 odp_packet_data_range_t cipher_range,
			 odp_packet_data_range_t auth_range,
			 uint32_t digest_offset,
			 odp_bool_t is_bit_mode_cipher,
			 odp_bool_t is_bit_mode_auth)
{
	unsigned int initial_num_failures = CU_get_number_of_failures();
	const uint32_t reflength = ref_length_in_bytes(ref);
	hash_test_mode_t hash_mode = HASH_NO_OVERLAP;
	odp_crypto_session_t session;
	int rc;
	uint32_t seg_len;
	uint32_t max_shift;
	alg_test_param_t test_param;

	if (digest_offset >= auth_range.offset &&
	    digest_offset < auth_range.offset + auth_range.length)
		hash_mode = HASH_OVERLAP;

	session = session_create(op, op_type, order, ref, hash_mode);
	if (session == ODP_CRYPTO_SESSION_INVALID)
		return;

	memset(&test_param, 0, sizeof(test_param));
	test_param.session = session;
	test_param.op = op;
	test_param.op_type = op_type;
	test_param.ref = ref;
	test_param.cipher_range = cipher_range;
	test_param.auth_range = auth_range;
	test_param.is_bit_mode_cipher = is_bit_mode_cipher;
	test_param.is_bit_mode_auth = is_bit_mode_auth;
	test_param.digest_offset = digest_offset;

	alg_test_op(&test_param);

	max_shift = reflength + ref->digest_length;
	seg_len = 0;

	if (!full_test &&
	    ref->cipher != ODP_CIPHER_ALG_NULL &&
	    ref->auth != ODP_AUTH_ALG_NULL) {
		/* run the loop body just once */
		seg_len = max_shift / 2;
		max_shift = seg_len;
	}

	/*
	 * Test with segmented packets with all possible segment boundaries
	 * within the packet data
	 */
	for (; seg_len <= max_shift; seg_len++) {
		/*
		 * CUnit chokes on too many assertion failures, so bail
		 * out if this test has already failed.
		 */
		if (CU_get_number_of_failures() > initial_num_failures)
			break;

		test_param.adjust_segmentation = true;
		test_param.first_seg_len = seg_len;
		test_param.header_len = 0;
		test_param.trailer_len = 0;
		test_param.digest_offset = digest_offset;
		alg_test_op(&test_param);

		/* Test partial packet crypto with odd alignment. */
		test_param.header_len = 13;
		test_param.trailer_len = 32;
		test_param.digest_offset = test_param.header_len + digest_offset;
		alg_test_op(&test_param);
	}

	rc = odp_crypto_session_destroy(session);
	CU_ASSERT(!rc);
}

static void alg_test(odp_crypto_op_t op,
		     alg_order_t order,
		     crypto_test_reference_t *ref,
		     odp_packet_data_range_t cipher_range,
		     odp_packet_data_range_t auth_range,
		     uint32_t digest_offset,
		     odp_bool_t is_bit_mode_cipher,
		     odp_bool_t is_bit_mode_auth)
{
	odp_crypto_op_type_t op_types[] = {
		ODP_CRYPTO_OP_TYPE_LEGACY,
		ODP_CRYPTO_OP_TYPE_BASIC,
		ODP_CRYPTO_OP_TYPE_OOP,
	};

	for (unsigned int n = 0; n < ARRAY_SIZE(op_types); n++) {
		alg_test_ses(op,
			     op_types[n],
			     order,
			     ref,
			     cipher_range,
			     auth_range,
			     digest_offset,
			     is_bit_mode_cipher,
			     is_bit_mode_auth);
	}
}

static odp_bool_t aad_len_ok(const odp_crypto_auth_capability_t *capa, uint32_t len)
{
	if (len < capa->aad_len.min || len > capa->aad_len.max)
		return false;

	if (len == capa->aad_len.min)
		return true;
	if (capa->aad_len.inc == 0)
		return false;

	return ((len - capa->aad_len.min) % capa->aad_len.inc) == 0;
}

static void check_alg(odp_crypto_op_t op,
		      crypto_test_reference_t *ref,
		      size_t count)
{
	int rc, i;
	const odp_cipher_alg_t cipher_alg = ref->cipher;
	const odp_auth_alg_t auth_alg = ref->auth;
	int cipher_num = odp_crypto_cipher_capability(cipher_alg, NULL, 0);
	int auth_num = odp_crypto_auth_capability(auth_alg, NULL, 0);
	odp_bool_t cipher_ok = false;
	odp_bool_t auth_ok = false;
	size_t idx;

	CU_ASSERT_FATAL(cipher_num > 0);
	CU_ASSERT_FATAL(auth_num > 0);

	init_reference(ref, count);

	odp_crypto_cipher_capability_t cipher_capa[cipher_num];
	odp_crypto_auth_capability_t auth_capa[auth_num];
	odp_bool_t cipher_tested[cipher_num];
	odp_bool_t auth_tested[auth_num];

	rc = odp_crypto_cipher_capability(cipher_alg, cipher_capa, cipher_num);
	CU_ASSERT_FATAL(rc == cipher_num);

	rc = odp_crypto_auth_capability(auth_alg, auth_capa, auth_num);
	CU_ASSERT_FATAL(rc == auth_num);

	memset(cipher_tested, 0, sizeof(cipher_tested));
	memset(auth_tested, 0, sizeof(auth_tested));

	oop_warning_shown = 0; /* allow OOP-unsupported warning again */

	for (idx = 0; idx < count; idx++) {
		int cipher_idx = -1, auth_idx = -1;
		odp_bool_t bit_mode_needed = false;
		odp_bool_t is_bit_mode_cipher = false;
		odp_bool_t is_bit_mode_auth = false;
		uint32_t digest_offs = ref_length_in_bytes(&ref[idx]);
		odp_packet_data_range_t cipher_range = {.offset = 0};
		odp_packet_data_range_t auth_range = {.offset = 0};

		if (ref_length_in_bits(&ref[idx]) % 8 != 0)
			bit_mode_needed = true;

		for (i = 0; i < cipher_num; i++) {
			if (cipher_capa[i].key_len ==
			    ref[idx].cipher_key_length &&
			    cipher_capa[i].iv_len ==
			    ref[idx].cipher_iv_length) {
				if (bit_mode_needed &&
				    cipher_alg != ODP_CIPHER_ALG_NULL &&
				    !cipher_capa[i].bit_mode)
					continue;
				cipher_idx = i;
				is_bit_mode_cipher = cipher_capa[i].bit_mode;
				break;
			}
		}

		if (cipher_idx < 0) {
			printf("\n    Unsupported: alg=%s, key_len=%" PRIu32
			       ", iv_len=%" PRIu32 "%s\n",
			       cipher_alg_name(cipher_alg),
			       ref[idx].cipher_key_length,
			       ref[idx].cipher_iv_length,
			       bit_mode_needed ? ", bit mode" : "");
			continue;
		}

		for (i = 0; i < auth_num; i++) {
			if (auth_capa[i].digest_len ==
			    ref[idx].digest_length &&
			    auth_capa[i].iv_len ==
			    ref[idx].auth_iv_length &&
			    auth_capa[i].key_len ==
			    ref[idx].auth_key_length &&
			    aad_len_ok(&auth_capa[i], ref[idx].aad_length)) {
				if (bit_mode_needed &&
				    auth_alg != ODP_AUTH_ALG_NULL &&
				    !auth_capa[i].bit_mode)
					continue;
				auth_idx = i;
				is_bit_mode_auth = auth_capa[i].bit_mode;
				break;
			}
		}

		if (auth_idx < 0) {
			printf("\n    Unsupported: alg=%s, key_len=%" PRIu32
			       ", iv_len=%" PRIu32 ", digest_len=%" PRIu32
			       "%s\n",
			       auth_alg_name(auth_alg),
			       ref[idx].auth_key_length,
			       ref[idx].auth_iv_length,
			       ref[idx].digest_length,
			       bit_mode_needed ? ", bit mode" : "");
			continue;
		}

		cipher_range.length = is_bit_mode_cipher ?
			ref_length_in_bits(&ref[idx]) :
			ref_length_in_bytes(&ref[idx]);
		auth_range.length = is_bit_mode_auth ?
			ref_length_in_bits(&ref[idx]) :
			ref_length_in_bytes(&ref[idx]);

		alg_test(op, AUTH_PLAINTEXT, &ref[idx],
			 cipher_range, auth_range, digest_offs,
			 is_bit_mode_cipher, is_bit_mode_auth);
		alg_test(op, AUTH_CIPHERTEXT, &ref[idx],
			 cipher_range, auth_range, digest_offs,
			 is_bit_mode_cipher, is_bit_mode_auth);

		cipher_tested[cipher_idx] = true;
		auth_tested[auth_idx] = true;
	}

	for (i = 0; i < cipher_num; i++) {
		cipher_ok |= cipher_tested[i];
		if (!cipher_tested[i] && cipher_alg != ODP_CIPHER_ALG_NULL)
			printf("\n    Untested: alg=%s, key_len=%" PRIu32 ", "
			       "iv_len=%" PRIu32 "%s\n",
			       cipher_alg_name(cipher_alg),
			       cipher_capa[i].key_len,
			       cipher_capa[i].iv_len,
			       cipher_capa[i].bit_mode ? ", bit mode" : "");
	}

	for (i = 0; i < auth_num; i++) {
		auth_ok |= auth_tested[i];
		if (!auth_tested[i] && auth_alg != ODP_AUTH_ALG_NULL)
			printf("\n    Untested: alg=%s, key_len=%" PRIu32 ", "
			       "digest_len=%" PRIu32 "%s\n",
			       auth_alg_name(auth_alg),
			       auth_capa[i].key_len,
			       auth_capa[i].digest_len,
			       auth_capa[i].bit_mode ? ", bit mode" : "");
	}

	/* Verify that we were able to run at least one test */
	CU_ASSERT(cipher_ok);
	CU_ASSERT(auth_ok);
}

/**
 * Check if given cipher and authentication algorithms are supported
 *
 * @param cipher      Cipher algorithm
 * @param auth        Authentication algorithm
 *
 * @retval ODP_TEST_ACTIVE when both algorithms are supported
 * @retval ODP_TEST_INACTIVE when either algorithm is not supported
 */
static int check_alg_support(odp_cipher_alg_t cipher, odp_auth_alg_t auth)
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
	case ODP_CIPHER_ALG_AES_EEA2:
		if (!capability.ciphers.bit.aes_eea2)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_CIPHER_ALG_ZUC_EEA3:
		if (!capability.ciphers.bit.zuc_eea3)
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
	case ODP_AUTH_ALG_AES_XCBC_MAC:
		if (!capability.auths.bit.aes_xcbc_mac)
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
	case ODP_AUTH_ALG_AES_EIA2:
		if (!capability.auths.bit.aes_eia2)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_ZUC_EIA3:
		if (!capability.auths.bit.zuc_eia3)
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
	default:
		ODPH_ERR("Unsupported authentication algorithm\n");
		return ODP_TEST_INACTIVE;
	}

	return ODP_TEST_ACTIVE;
}

static void test_capability(void)
{
	odp_crypto_capability_t capa = {.max_sessions = 1};
	int rc;

	rc = odp_crypto_capability(&capa);
	CU_ASSERT(!rc);
	if (capa.max_sessions > 0)
		CU_ASSERT(capa.sync_mode || capa.async_mode);
	CU_ASSERT((~capa.ciphers.all_bits & capa.hw_ciphers.all_bits) == 0);
	CU_ASSERT((~capa.auths.all_bits & capa.hw_auths.all_bits) == 0);
}

/*
 * Create a test reference, which can be used in tests where the hash
 * result is within auth_range.
 *
 * The ciphertext packet and the hash are calculated using an encode
 * operation with hash_result_offset outside the auth_range and by
 * copying the hash in the ciphertext packet.
 */
static int create_hash_test_reference(odp_auth_alg_t auth,
				      const odp_crypto_auth_capability_t *capa,
				      crypto_test_reference_t *ref,
				      uint32_t digest_offset,
				      uint8_t digest_fill)
{
	odp_crypto_session_t session;
	int rc;
	odp_packet_t pkt;
	odp_bool_t ok;
	const uint32_t auth_bytes = 100;
	uint32_t enc_digest_offset = auth_bytes;

	ref->cipher = ODP_CIPHER_ALG_NULL;
	ref->auth = auth;
	ref->auth_key_length = capa->key_len;
	ref->auth_iv_length = capa->iv_len;
	ref->digest_length = capa->digest_len;
	ref->is_length_in_bits = false;
	ref->length = auth_bytes;

	if (ref->auth_key_length > MAX_KEY_LEN ||
	    ref->auth_iv_length > MAX_IV_LEN ||
	    auth_bytes > MAX_DATA_LEN ||
	    digest_offset + ref->digest_length > MAX_DATA_LEN)
		CU_FAIL_FATAL("Internal error\n");

	fill_with_pattern(ref->auth_key, ref->auth_key_length);
	fill_with_pattern(ref->auth_iv, ref->auth_iv_length);
	fill_with_pattern(ref->plaintext, auth_bytes);

	memset(ref->plaintext + digest_offset, digest_fill, ref->digest_length);

	pkt = odp_packet_alloc(suite_context.pool, auth_bytes + ref->digest_length);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);

	rc = odp_packet_copy_from_mem(pkt, 0, auth_bytes, ref->plaintext);
	CU_ASSERT(rc == 0);

	session = session_create(ODP_CRYPTO_OP_ENCODE,
				 ODP_CRYPTO_OP_TYPE_LEGACY,
				 AUTH_PLAINTEXT, ref, HASH_NO_OVERLAP);
	if (session == ODP_CRYPTO_SESSION_INVALID)
		return -1;

	odp_crypto_packet_op_param_t op_params = {
		.session = session,
		.cipher_iv_ptr = ref->cipher_iv,
		.auth_iv_ptr = ref->auth_iv,
		.hash_result_offset = enc_digest_offset,
		.aad_ptr = ref->aad,
		.cipher_range = {.offset = 0, .length = 0},
		.auth_range = { .offset = 0,
				.length = capa->bit_mode ? auth_bytes * 8 : auth_bytes },
		.dst_offset_shift = 0,
	};
	rc = crypto_op(pkt, &pkt, &ok, &op_params, ODP_CRYPTO_OP_TYPE_LEGACY);

	CU_ASSERT(rc == 0);
	if (rc) {
		(void)odp_crypto_session_destroy(session);
		return -1;
	}
	CU_ASSERT(ok);

	rc = odp_crypto_session_destroy(session);
	CU_ASSERT(rc == 0);

	/* copy the processed packet to the ciphertext packet in ref */
	rc = odp_packet_copy_to_mem(pkt, 0, auth_bytes, ref->ciphertext);
	CU_ASSERT(rc == 0);

	/* copy the calculated digest in the ciphertext packet in ref */
	rc = odp_packet_copy_to_mem(pkt, enc_digest_offset, ref->digest_length,
				    &ref->ciphertext[digest_offset]);
	CU_ASSERT(rc == 0);

	/* copy the calculated digest the digest field in ref */
	rc = odp_packet_copy_to_mem(pkt, enc_digest_offset, ref->digest_length,
				    &ref->digest);
	CU_ASSERT(rc == 0);

	odp_packet_free(pkt);

	return 0;
}

static void test_auth_hash_in_auth_range(odp_auth_alg_t auth,
					 const odp_crypto_auth_capability_t *capa,
					 alg_order_t order)
{
	static crypto_test_reference_t ref = {.length = 0};
	uint32_t digest_offset = 13;
	const odp_packet_data_range_t cipher_range = {.offset = 0, .length = 0};
	odp_packet_data_range_t auth_range;

	if (!full_test && capa->digest_len % 4 != 0)
		return;

	/*
	 * Create test packets with auth hash in the authenticated range and
	 * zeroes in the hash location in the plaintext packet.
	 */
	if (create_hash_test_reference(auth, capa, &ref, digest_offset, 0))
		return;

	auth_range.offset = 0;
	auth_range.length = capa->bit_mode ?
		ref_length_in_bits(&ref) :
		ref_length_in_bytes(&ref);

	/*
	 * Decode the ciphertext packet.
	 *
	 * Check that auth hash verification works even if hash_result_offset
	 * is within the auth range. The ODP implementation must clear the
	 * hash bytes in the ciphertext packet before calculating the hash.
	 */
	alg_test(ODP_CRYPTO_OP_DECODE,
		 order,
		 &ref,
		 cipher_range, auth_range,
		 digest_offset,
		 false,
		 capa->bit_mode);

	/*
	 * Create test packets with auth hash in the authenticated range and
	 * ones in the hash location in the plaintext packet.
	 */
	if (create_hash_test_reference(auth, capa, &ref, digest_offset, 1))
		return;

	auth_range.offset = 0;
	auth_range.length = capa->bit_mode ?
		ref_length_in_bits(&ref) :
		ref_length_in_bytes(&ref);

	/*
	 * Encode the plaintext packet.
	 *
	 * Check that auth hash generation works even if hash_result_offset
	 * is within the auth range. The ODP implementation must not clear
	 * the hash bytes in the plaintext packet before calculating the hash.
	 */
	alg_test(ODP_CRYPTO_OP_ENCODE,
		 order,
		 &ref,
		 cipher_range, auth_range,
		 digest_offset,
		 false,
		 capa->bit_mode);
}

/*
 * Cipher algorithms that are not AEAD algorithms
 */
static odp_cipher_alg_t cipher_algs[] = {
	ODP_CIPHER_ALG_DES,
	ODP_CIPHER_ALG_3DES_CBC,
	ODP_CIPHER_ALG_3DES_ECB,
	ODP_CIPHER_ALG_AES_CBC,
	ODP_CIPHER_ALG_AES_CTR,
	ODP_CIPHER_ALG_AES_ECB,
	ODP_CIPHER_ALG_AES_CFB128,
	ODP_CIPHER_ALG_AES_XTS,
	ODP_CIPHER_ALG_KASUMI_F8,
	ODP_CIPHER_ALG_SNOW3G_UEA2,
	ODP_CIPHER_ALG_AES_EEA2,
	ODP_CIPHER_ALG_ZUC_EEA3,
};

/*
 * Authentication algorithms and hashes that use auth_range
 * parameter. AEAD algorithms are excluded.
 */
static odp_auth_alg_t auth_algs[] = {
	ODP_AUTH_ALG_MD5_HMAC,
	ODP_AUTH_ALG_SHA1_HMAC,
	ODP_AUTH_ALG_SHA224_HMAC,
	ODP_AUTH_ALG_SHA256_HMAC,
	ODP_AUTH_ALG_SHA384_HMAC,
	ODP_AUTH_ALG_SHA512_HMAC,
	ODP_AUTH_ALG_AES_GMAC,
	ODP_AUTH_ALG_AES_CMAC,
	ODP_AUTH_ALG_AES_XCBC_MAC,
	ODP_AUTH_ALG_KASUMI_F9,
	ODP_AUTH_ALG_SNOW3G_UIA2,
	ODP_AUTH_ALG_AES_EIA2,
	ODP_AUTH_ALG_ZUC_EIA3,
	ODP_AUTH_ALG_MD5,
	ODP_AUTH_ALG_SHA1,
	ODP_AUTH_ALG_SHA224,
	ODP_AUTH_ALG_SHA256,
	ODP_AUTH_ALG_SHA384,
	ODP_AUTH_ALG_SHA512,
};

static void test_auth_hashes_in_auth_range(void)
{
	for (size_t n = 0; n < ARRAY_SIZE(auth_algs); n++) {
		odp_auth_alg_t auth = auth_algs[n];
		int num;

		if (check_alg_support(ODP_CIPHER_ALG_NULL, auth) == ODP_TEST_INACTIVE)
			continue;

		num = odp_crypto_auth_capability(auth, NULL, 0);
		CU_ASSERT_FATAL(num > 0);

		odp_crypto_auth_capability_t capa[num];

		num = odp_crypto_auth_capability(auth, capa, num);

		for (int i = 0; i < num; i++) {
			test_auth_hash_in_auth_range(auth, &capa[i], AUTH_PLAINTEXT);
			test_auth_hash_in_auth_range(auth, &capa[i], AUTH_CIPHERTEXT);
		}
	}
}

/*
 * Encode ref->plaintext and save result in ref->ciphertext.
 */
static int crypto_encode_ref(crypto_test_reference_t *ref,
			     odp_packet_data_range_t cipher_range,
			     odp_packet_data_range_t auth_range,
			     uint32_t hash_result_offset)
{
	odp_packet_data_range_t zero_range = {.offset = 0, .length = 0};
	odp_packet_t pkt;
	int rc;
	odp_crypto_session_t session;
	odp_bool_t ok;

	pkt = odp_packet_alloc(suite_context.pool, ref->length);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);

	rc = odp_packet_copy_from_mem(pkt, 0, ref->length, ref->plaintext);
	CU_ASSERT(rc == 0);

	session = session_create(ODP_CRYPTO_OP_ENCODE,
				 ODP_CRYPTO_OP_TYPE_LEGACY,
				 AUTH_PLAINTEXT,
				 ref,
				 HASH_OVERLAP);

	if (session == ODP_CRYPTO_SESSION_INVALID) {
		odp_packet_free(pkt);
		return 1;
	}

	if (ref->cipher == ODP_CIPHER_ALG_NULL)
		cipher_range = zero_range;
	if (ref->auth == ODP_AUTH_ALG_NULL) {
		auth_range = zero_range;
		hash_result_offset = 0;
	}

	CU_ASSERT_FATAL(hash_result_offset + ref->digest_length <= ref->length);

	odp_crypto_packet_op_param_t op_params = {
		.session = session,
		.cipher_iv_ptr = ref->cipher_iv,
		.auth_iv_ptr = ref->auth_iv,
		.hash_result_offset = hash_result_offset,
		.aad_ptr = ref->aad,
		.cipher_range = cipher_range,
		.auth_range = auth_range,
		.dst_offset_shift = 0,
	};
	rc = crypto_op(pkt, &pkt, &ok, &op_params, ODP_CRYPTO_OP_TYPE_LEGACY);
	CU_ASSERT(rc == 0);
	if (rc) {
		(void)odp_crypto_session_destroy(session);
		return -1;
	}
	CU_ASSERT(ok);

	rc = odp_crypto_session_destroy(session);
	CU_ASSERT(rc == 0);

	rc = odp_packet_copy_to_mem(pkt, 0, ref->length, ref->ciphertext);
	CU_ASSERT(rc == 0);

	odp_packet_free(pkt);
	return 0;
}

typedef struct crypto_suite_t {
	odp_cipher_alg_t cipher;
	odp_auth_alg_t auth;
	alg_order_t order;
	const odp_crypto_cipher_capability_t *cipher_capa;
	const odp_crypto_auth_capability_t *auth_capa;
} crypto_suite_t;

/*
 * Create test reference for combined auth & cipher by doing authentication
 * and ciphering through separate ODP crypto operations.
 */
static int create_combined_ref(const crypto_suite_t *suite,
			       crypto_test_reference_t *ref,
			       odp_packet_data_range_t *cipher_range,
			       odp_packet_data_range_t *auth_range,
			       uint32_t digest_offset)
{
	uint32_t total_len;
	int rc;
	crypto_test_reference_t ref_cipher_only;
	crypto_test_reference_t ref_auth_only;
	crypto_test_reference_t *first_ref, *second_ref;

	total_len = cipher_range->offset + cipher_range->length;
	if (auth_range->offset + auth_range->length > total_len)
		total_len = auth_range->offset + auth_range->length;
	if (digest_offset + suite->auth_capa->digest_len > total_len)
		total_len = digest_offset + suite->auth_capa->digest_len;

	ref->cipher = suite->cipher;
	ref->auth = suite->auth;
	ref->cipher_key_length = suite->cipher_capa->key_len;
	ref->cipher_iv_length = suite->cipher_capa->iv_len;
	ref->auth_key_length = suite->auth_capa->key_len;
	ref->auth_iv_length = suite->auth_capa->iv_len;
	ref->digest_length = suite->auth_capa->digest_len;
	ref->aad_length = 0;
	ref->is_length_in_bits = false;
	ref->length = total_len;

	if (suite->cipher_capa->bit_mode) {
		cipher_range->offset *= 8;
		cipher_range->length *= 8;
	}
	if (suite->auth_capa->bit_mode) {
		auth_range->offset *= 8;
		auth_range->length *= 8;
	}

	if (ref->auth_key_length > MAX_KEY_LEN ||
	    ref->auth_iv_length > MAX_IV_LEN ||
	    total_len > MAX_DATA_LEN ||
	    digest_offset + ref->digest_length > MAX_DATA_LEN)
		CU_FAIL_FATAL("Internal error\n");

	fill_with_pattern(ref->cipher_key, ref->cipher_key_length);
	fill_with_pattern(ref->cipher_iv, ref->cipher_iv_length);
	fill_with_pattern(ref->auth_key, ref->auth_key_length);
	fill_with_pattern(ref->auth_iv, ref->auth_iv_length);
	fill_with_pattern(ref->plaintext, ref->length);
	memset(ref->plaintext + digest_offset, 0, ref->digest_length);

	ref_cipher_only = *ref;
	ref_cipher_only.auth = ODP_AUTH_ALG_NULL;
	ref_cipher_only.auth_key_length = 0;
	ref_cipher_only.auth_iv_length = 0;
	ref_cipher_only.aad_length = 0;
	ref_cipher_only.digest_length = 0;

	ref_auth_only = *ref;
	ref_auth_only.cipher = ODP_CIPHER_ALG_NULL;
	ref_auth_only.cipher_key_length = 0;
	ref_auth_only.cipher_iv_length = 0;

	if (suite->order == AUTH_CIPHERTEXT) {
		first_ref = &ref_cipher_only;
		second_ref = &ref_auth_only;
	} else {
		first_ref = &ref_auth_only;
		second_ref = &ref_cipher_only;
	}
	rc = crypto_encode_ref(first_ref,
			       *cipher_range, *auth_range,
			       digest_offset);
	if (rc)
		return 1;
	memcpy(second_ref->plaintext, first_ref->ciphertext, ref->length);
	rc = crypto_encode_ref(second_ref,
			       *cipher_range, *auth_range,
			       digest_offset);
	if (rc)
		return 1;
	memcpy(ref->ciphertext, second_ref->ciphertext, ref->length);
	/*
	 * These may be encrypted bytes, but that is what alg_test wants if
	 * the digest is encrypted in the input packet.
	 */
	memcpy(ref->digest, second_ref->ciphertext + digest_offset, ref->digest_length);

	return 0;
}

/*
 * Return cipher range that is at least min_len bytes long, multiple of the
 * block size and at least 3 blocks.
 */
static uint32_t get_cipher_range_len(uint32_t min_len)
{
#define MAX_BLOCK_SIZE 16
	uint32_t bs = MAX_BLOCK_SIZE;
	uint32_t len = 3 * bs;

	if (min_len > len)
		len = ((min_len + bs - 1) / bs) * bs;
	return len;
}

typedef enum range_overlap_t {
	SEPARATE_AUTH_AND_CIPHER_RANGES,
	SAME_AUTH_AND_CIPHER_RANGE,
	RANGES_PARTIALLY_OVERLAP,
	AUTH_RANGE_IN_CIPHER_RANGE,
	CIPHER_RANGE_IN_AUTH_RANGE,
} range_overlap_t;
#define NUM_RANGE_OVERLAPS 5

typedef enum hash_location_t {
	HASH_SEPARATE,
	HASH_IN_AUTH_RANGE_ONLY,
	HASH_IN_CIPHER_RANGE_ONLY,
	HASH_IN_AUTH_AND_CIPHER_RANGE,
} hash_location_t;
#define NUM_HASH_LOCATIONS 4

static int make_byte_ranges(range_overlap_t overlap,
			    hash_location_t hash_location,
			    uint32_t hash_len,
			    odp_packet_data_range_t *cipher_range,
			    odp_packet_data_range_t *auth_range,
			    uint32_t *digest_offset)
{
	const uint32_t padding = 5; /* padding between parts, could also be zero */
	const uint32_t nonzero_len = 3;
	uint32_t c_offs = 0, c_len = 0, a_offs = 0, a_len = 0, digest_offs = 0;

	switch (overlap) {
	case SEPARATE_AUTH_AND_CIPHER_RANGES:
		switch (hash_location) {
		case HASH_SEPARATE:
			/* |cccc_aaaa_dd| */
			c_offs = 0;
			c_len = get_cipher_range_len(nonzero_len);
			a_offs = c_offs + c_len + padding;
			a_len = nonzero_len;
			digest_offs = a_offs + a_len + padding;
			break;
		case HASH_IN_AUTH_RANGE_ONLY:
			/*
			 * |cccc_aaaa|
			 * |     _dd_|
			 */
			c_offs = 0;
			c_len = get_cipher_range_len(nonzero_len);
			a_offs = c_offs + c_len + padding;
			a_len = hash_len + 2 * padding;
			digest_offs = a_offs + padding;
			break;
		case HASH_IN_CIPHER_RANGE_ONLY:
			/*
			 * |cccc_aaaa|
			 * |_dd_     |
			 */
			c_offs = 0;
			c_len = get_cipher_range_len(hash_len + 2 * padding);
			a_offs = c_offs + c_len + padding;
			a_len = nonzero_len;
			digest_offs = c_offs + padding;
			break;
		case HASH_IN_AUTH_AND_CIPHER_RANGE:
			/* not possible when ranges are separate */
			return 1;
		}
		break;
	case SAME_AUTH_AND_CIPHER_RANGE:
		c_offs = 0;
		a_offs = 0;
		switch (hash_location) {
		case HASH_SEPARATE:
			/*
			 * |cccc_dd|
			 * |aaaa   |
			 */
			c_len = get_cipher_range_len(nonzero_len);
			a_len = c_len;
			digest_offs = c_len + padding;
			break;
		case HASH_IN_AUTH_RANGE_ONLY:
		case HASH_IN_CIPHER_RANGE_ONLY:
			/* not possible when ranges are the same */
			return 1;
		case HASH_IN_AUTH_AND_CIPHER_RANGE:
			/*
			 * |cccc|
			 * |aaaa|
			 * |_dd_|
			 */
			c_len = get_cipher_range_len(hash_len + 2 * padding);
			a_len = c_len;
			digest_offs = padding;
			break;
		}
		break;
	case RANGES_PARTIALLY_OVERLAP:
		a_offs = 0;
		switch (hash_location) {
		case HASH_SEPARATE:
			/*
			 * |aaaa    |
			 * | cccc_dd|
			 */
			a_len = 2 * nonzero_len;
			c_offs = nonzero_len;
			c_len = get_cipher_range_len(a_len);
			digest_offs = c_offs + c_len + padding;
			break;
		case HASH_IN_AUTH_RANGE_ONLY:
			/*
			 * |aaaaa  |
			 * |_dd_ccc|
			 */
			digest_offs = padding;
			a_len = hash_len + 2 * padding + nonzero_len;
			c_offs = hash_len + 2 * padding;
			c_len = get_cipher_range_len(2 * nonzero_len);
			break;
		case HASH_IN_CIPHER_RANGE_ONLY:
			/* PDCP case when AUTH_PLAINTEXT */
			/*
			 * |aaaadd|
			 * | ccccc|
			 */
			c_offs = nonzero_len;
			c_len = get_cipher_range_len(nonzero_len + hash_len);
			a_len = nonzero_len + c_len - hash_len;
			digest_offs = c_offs + c_len - hash_len;
			break;
		case HASH_IN_AUTH_AND_CIPHER_RANGE:
			/*
			 * |aaaaaa |
			 * | cccccc|
			 * |¨_dd_  |
			 */
			c_offs = nonzero_len;
			c_len = get_cipher_range_len(hash_len + 2 * padding + nonzero_len);
			a_len = c_offs + hash_len + 2 * padding;
			digest_offs = c_offs + padding;
			break;
		}
		break;
	case AUTH_RANGE_IN_CIPHER_RANGE:
		c_offs = 0;
		a_offs = nonzero_len;
		switch (hash_location) {
		case HASH_SEPARATE:
			/*
			 * |cccc_dd|
			 * | aa_   |
			 */
			a_len = nonzero_len;
			c_len = get_cipher_range_len(a_offs + a_len + padding);
			digest_offs = c_len + padding;
			break;
		case HASH_IN_AUTH_RANGE_ONLY:
			/* not possible since auth range is in cipher range */
			return 1;
		case HASH_IN_CIPHER_RANGE_ONLY:
			/*
			 * |ccccccc|
			 * | aa_dd_|
			 */
			a_len = nonzero_len;
			digest_offs = a_offs + a_len + padding;
			c_len = get_cipher_range_len(digest_offs + hash_len + padding);
			break;
		case HASH_IN_AUTH_AND_CIPHER_RANGE:
			/*
			 * |cccccc|
			 * | aaaa_|
			 * | _dd_ |
			 */
			a_len = /**/ hash_len + 2 * padding;
			c_len = get_cipher_range_len(a_offs + a_len + padding);
			digest_offs = a_offs + /**/ padding;
			break;
		}
		break;
	case CIPHER_RANGE_IN_AUTH_RANGE:
		a_offs = 0;
		c_offs = nonzero_len;
		switch (hash_location) {
		case HASH_SEPARATE:
			/*
			 * |aaaa_dd|
			 * | cc_   |
			 */
			c_len = get_cipher_range_len(nonzero_len);
			a_len = c_offs + c_len + padding;
			digest_offs = a_len + padding;
			break;
		case HASH_IN_AUTH_RANGE_ONLY:
			/*
			 * |aaaaaaa|
			 * | cc_dd_|
			 */
			c_len = get_cipher_range_len(nonzero_len);
			digest_offs = c_offs + c_len + padding;
			a_len = digest_offs + hash_len + padding;
			break;
		case HASH_IN_CIPHER_RANGE_ONLY:
			/* not possible since cipher range is in auth range */
			return 1;
		case HASH_IN_AUTH_AND_CIPHER_RANGE:
			/*
			 * |aaaaaa|
			 * | cccc_|
			 * | _dd_ |
			 */
			c_len = get_cipher_range_len(hash_len + 2 * padding);
			a_len = c_offs + c_len + padding;
			digest_offs = c_offs + padding;
			break;
		}
		break;
	}
	cipher_range->offset = c_offs;
	cipher_range->length = c_len;
	auth_range->offset = a_offs;
	auth_range->length = a_len;
	*digest_offset = digest_offs;
	return 0;
}

static void test_combo(const crypto_suite_t *suite,
		       range_overlap_t overlap,
		       hash_location_t location)
{
	int rc;

	odp_packet_data_range_t cipher_range = {0, 0};
	odp_packet_data_range_t auth_range = {0, 0};
	uint32_t digest_offset = 0;
	crypto_test_reference_t ref;

	rc = make_byte_ranges(overlap,
			      location,
			      suite->auth_capa->digest_len,
			      &cipher_range,
			      &auth_range,
			      &digest_offset);
	if (rc)
		return;

	rc = create_combined_ref(suite, &ref,
				 &cipher_range, &auth_range,
				 digest_offset);
	if (rc)
		return;

	alg_test(ODP_CRYPTO_OP_ENCODE,
		 suite->order,
		 &ref,
		 cipher_range, auth_range,
		 digest_offset,
		 suite->cipher_capa->bit_mode,
		 suite->auth_capa->bit_mode);

	alg_test(ODP_CRYPTO_OP_DECODE,
		 suite->order,
		 &ref,
		 cipher_range, auth_range,
		 digest_offset,
		 suite->cipher_capa->bit_mode,
		 suite->auth_capa->bit_mode);
}

/* Iterate and test different cipher/auth range and hash locations */
static void test_combo_ranges(const crypto_suite_t *suite)
{
	if (!full_test && suite->auth_capa->digest_len % 4 != 0)
		return;

	for (int overlap = 0; overlap < NUM_RANGE_OVERLAPS; overlap++)
		for (int location = 0; location < NUM_HASH_LOCATIONS; location++) {
			if (suite->order == AUTH_CIPHERTEXT &&
			    (location == HASH_IN_CIPHER_RANGE_ONLY ||
			     location == HASH_IN_AUTH_AND_CIPHER_RANGE)) {
				/*
				 * This combination ís not valid since
				 * the generated hash would overwrite some
				 * ciphertext, preventing decryption.
				 */
				continue;
			}
			test_combo(suite, overlap, location);
		}
}

/* Iterate and test all variants (key sizes etc) of an alg combo */
static void test_combo_variants(odp_cipher_alg_t cipher, odp_auth_alg_t auth)
{
	int num, num_ciphers, num_auths;

	/* ODP API says AES-GMAC can be combined with the null cipher only */
	if (auth == ODP_AUTH_ALG_AES_GMAC &&
	    cipher != ODP_CIPHER_ALG_NULL)
		return;

	if (check_alg_support(cipher, auth) == ODP_TEST_INACTIVE)
		return;

	printf("    %s, %s\n",
	       cipher_alg_name(cipher),
	       auth_alg_name(auth));

	num_ciphers = odp_crypto_cipher_capability(cipher, NULL, 0);
	num_auths = odp_crypto_auth_capability(auth, NULL, 0);
	CU_ASSERT_FATAL(num_ciphers > 0);
	CU_ASSERT_FATAL(num_auths > 0);

	odp_crypto_cipher_capability_t cipher_capa[num_ciphers];
	odp_crypto_auth_capability_t auth_capa[num_auths];

	num = odp_crypto_cipher_capability(cipher, cipher_capa, num_ciphers);
	CU_ASSERT(num == num_ciphers);
	num = odp_crypto_auth_capability(auth, auth_capa, num_auths);
	CU_ASSERT(num == num_auths);

	combo_warning_shown = 0;

	for (int n = 0; n < num_ciphers; n++)
		for (int i = 0; i < num_auths; i++) {
			crypto_suite_t suite = {.cipher = cipher,
						.auth = auth,
						.cipher_capa = &cipher_capa[n],
						.auth_capa = &auth_capa[i]};
			suite.order = AUTH_PLAINTEXT;
			test_combo_ranges(&suite);
			suite.order = AUTH_CIPHERTEXT;
			test_combo_ranges(&suite);
		}
}

static void test_all_combinations(void)
{
	printf("\n");
	for (size_t n = 0; n < ARRAY_SIZE(cipher_algs); n++)
		for (size_t i = 0; i < ARRAY_SIZE(auth_algs); i++)
			test_combo_variants(cipher_algs[n], auth_algs[i]);
}

static int check_alg_null(void)
{
	return check_alg_support(ODP_CIPHER_ALG_NULL, ODP_AUTH_ALG_NULL);
}

static void crypto_test_enc_alg_null(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  null_reference,
		  ARRAY_SIZE(null_reference));
}

static void crypto_test_dec_alg_null(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  null_reference,
		  ARRAY_SIZE(null_reference));
}

static int check_alg_3des_cbc(void)
{
	return check_alg_support(ODP_CIPHER_ALG_3DES_CBC, ODP_AUTH_ALG_NULL);
}

static void crypto_test_enc_alg_3des_cbc(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  tdes_cbc_reference,
		  ARRAY_SIZE(tdes_cbc_reference));
}

static void crypto_test_dec_alg_3des_cbc(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  tdes_cbc_reference,
		  ARRAY_SIZE(tdes_cbc_reference));
}

static int check_alg_3des_ecb(void)
{
	return check_alg_support(ODP_CIPHER_ALG_3DES_ECB, ODP_AUTH_ALG_NULL);
}

static void crypto_test_enc_alg_3des_ecb(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  tdes_ecb_reference,
		  ARRAY_SIZE(tdes_ecb_reference));
}

static void crypto_test_dec_alg_3des_ecb(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  tdes_ecb_reference,
		  ARRAY_SIZE(tdes_ecb_reference));
}

static int check_alg_chacha20_poly1305(void)
{
	return check_alg_support(ODP_CIPHER_ALG_CHACHA20_POLY1305,
				 ODP_AUTH_ALG_CHACHA20_POLY1305);
}

static void crypto_test_enc_alg_chacha20_poly1305(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  chacha20_poly1305_reference,
		  ARRAY_SIZE(chacha20_poly1305_reference));
}

static void crypto_test_dec_alg_chacha20_poly1305(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  chacha20_poly1305_reference,
		  ARRAY_SIZE(chacha20_poly1305_reference));
}

static int check_alg_aes_gcm(void)
{
	return check_alg_support(ODP_CIPHER_ALG_AES_GCM, ODP_AUTH_ALG_AES_GCM);
}

static void crypto_test_enc_alg_aes_gcm(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  aes_gcm_reference,
		  ARRAY_SIZE(aes_gcm_reference));
}

static void crypto_test_dec_alg_aes_gcm(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  aes_gcm_reference,
		  ARRAY_SIZE(aes_gcm_reference));
}

static int check_alg_aes_ccm(void)
{
	return check_alg_support(ODP_CIPHER_ALG_AES_CCM, ODP_AUTH_ALG_AES_CCM);
}

static void crypto_test_enc_alg_aes_ccm(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  aes_ccm_reference,
		  ARRAY_SIZE(aes_ccm_reference));
}

static void crypto_test_dec_alg_aes_ccm(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  aes_ccm_reference,
		  ARRAY_SIZE(aes_ccm_reference));
}

static int check_alg_aes_cbc(void)
{
	return check_alg_support(ODP_CIPHER_ALG_AES_CBC, ODP_AUTH_ALG_NULL);
}

static void crypto_test_enc_alg_aes_cbc(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  aes_cbc_reference,
		  ARRAY_SIZE(aes_cbc_reference));
}

static void crypto_test_dec_alg_aes_cbc(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  aes_cbc_reference,
		  ARRAY_SIZE(aes_cbc_reference));
}

static int check_alg_aes_ctr(void)
{
	return check_alg_support(ODP_CIPHER_ALG_AES_CTR, ODP_AUTH_ALG_NULL);
}

static void crypto_test_enc_alg_aes_ctr(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  aes_ctr_reference,
		  ARRAY_SIZE(aes_ctr_reference));
}

static void crypto_test_dec_alg_aes_ctr(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  aes_ctr_reference,
		  ARRAY_SIZE(aes_ctr_reference));
}

static int check_alg_aes_ecb(void)
{
	return check_alg_support(ODP_CIPHER_ALG_AES_ECB, ODP_AUTH_ALG_NULL);
}

static void crypto_test_enc_alg_aes_ecb(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  aes_ecb_reference,
		  ARRAY_SIZE(aes_ecb_reference));
}

static void crypto_test_dec_alg_aes_ecb(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  aes_ecb_reference,
		  ARRAY_SIZE(aes_ecb_reference));
}

static int check_alg_aes_cfb128(void)
{
	return check_alg_support(ODP_CIPHER_ALG_AES_CFB128, ODP_AUTH_ALG_NULL);
}

static void crypto_test_enc_alg_aes_cfb128(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  aes_cfb128_reference,
		  ARRAY_SIZE(aes_cfb128_reference));
}

static void crypto_test_dec_alg_aes_cfb128(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  aes_cfb128_reference,
		  ARRAY_SIZE(aes_cfb128_reference));
}

static int check_alg_aes_xts(void)
{
	return check_alg_support(ODP_CIPHER_ALG_AES_XTS, ODP_AUTH_ALG_NULL);
}

static void crypto_test_enc_alg_aes_xts(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  aes_xts_reference,
		  ARRAY_SIZE(aes_xts_reference));
}

static void crypto_test_dec_alg_aes_xts(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  aes_xts_reference,
		  ARRAY_SIZE(aes_xts_reference));
}

static int check_alg_kasumi_f8(void)
{
	return check_alg_support(ODP_CIPHER_ALG_KASUMI_F8, ODP_AUTH_ALG_NULL);
}

static void crypto_test_enc_alg_kasumi_f8(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  kasumi_f8_reference,
		  ARRAY_SIZE(kasumi_f8_reference));
}

static void crypto_test_dec_alg_kasumi_f8(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  kasumi_f8_reference,
		  ARRAY_SIZE(kasumi_f8_reference));
}

static int check_alg_snow3g_uea2(void)
{
	return check_alg_support(ODP_CIPHER_ALG_SNOW3G_UEA2, ODP_AUTH_ALG_NULL);
}

static void crypto_test_enc_alg_snow3g_uea2(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  snow3g_uea2_reference,
		  ARRAY_SIZE(snow3g_uea2_reference));
}

static void crypto_test_dec_alg_snow3g_uea2(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  snow3g_uea2_reference,
		  ARRAY_SIZE(snow3g_uea2_reference));
}

static int check_alg_aes_eea2(void)
{
	return check_alg_support(ODP_CIPHER_ALG_AES_EEA2,
				 ODP_AUTH_ALG_NULL);
}

static void crypto_test_enc_alg_aes_eea2(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  aes_eea2_reference,
		  ARRAY_SIZE(aes_eea2_reference));
}

static void crypto_test_dec_alg_aes_eea2(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  aes_eea2_reference,
		  ARRAY_SIZE(aes_eea2_reference));
}

static int check_alg_zuc_eea3(void)
{
	return check_alg_support(ODP_CIPHER_ALG_ZUC_EEA3, ODP_AUTH_ALG_NULL);
}

static void crypto_test_enc_alg_zuc_eea3(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  zuc_eea3_reference,
		  ARRAY_SIZE(zuc_eea3_reference));
}

static void crypto_test_dec_alg_zuc_eea3(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  zuc_eea3_reference,
		  ARRAY_SIZE(zuc_eea3_reference));
}

static int check_alg_hmac_md5(void)
{
	return check_alg_support(ODP_CIPHER_ALG_NULL, ODP_AUTH_ALG_MD5_HMAC);
}

static void crypto_test_gen_alg_hmac_md5(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  hmac_md5_reference,
		  ARRAY_SIZE(hmac_md5_reference));
}

static void crypto_test_check_alg_hmac_md5(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  hmac_md5_reference,
		  ARRAY_SIZE(hmac_md5_reference));
}

static int check_alg_hmac_sha1(void)
{
	return check_alg_support(ODP_CIPHER_ALG_NULL, ODP_AUTH_ALG_SHA1_HMAC);
}

static void crypto_test_gen_alg_hmac_sha1(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  hmac_sha1_reference,
		  ARRAY_SIZE(hmac_sha1_reference));
}

static void crypto_test_check_alg_hmac_sha1(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  hmac_sha1_reference,
		  ARRAY_SIZE(hmac_sha1_reference));
}

static int check_alg_hmac_sha224(void)
{
	return check_alg_support(ODP_CIPHER_ALG_NULL, ODP_AUTH_ALG_SHA224_HMAC);
}

static void crypto_test_gen_alg_hmac_sha224(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  hmac_sha224_reference,
		  ARRAY_SIZE(hmac_sha224_reference));
}

static void crypto_test_check_alg_hmac_sha224(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  hmac_sha224_reference,
		  ARRAY_SIZE(hmac_sha224_reference));
}

static int check_alg_hmac_sha256(void)
{
	return check_alg_support(ODP_CIPHER_ALG_NULL, ODP_AUTH_ALG_SHA256_HMAC);
}

static void crypto_test_gen_alg_hmac_sha256(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  hmac_sha256_reference,
		  ARRAY_SIZE(hmac_sha256_reference));
}

static void crypto_test_check_alg_hmac_sha256(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  hmac_sha256_reference,
		  ARRAY_SIZE(hmac_sha256_reference));
}

static int check_alg_hmac_sha384(void)
{
	return check_alg_support(ODP_CIPHER_ALG_NULL, ODP_AUTH_ALG_SHA384_HMAC);
}

static void crypto_test_gen_alg_hmac_sha384(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  hmac_sha384_reference,
		  ARRAY_SIZE(hmac_sha384_reference));
}

static void crypto_test_check_alg_hmac_sha384(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  hmac_sha384_reference,
		  ARRAY_SIZE(hmac_sha384_reference));
}

static int check_alg_hmac_sha512(void)
{
	return check_alg_support(ODP_CIPHER_ALG_NULL, ODP_AUTH_ALG_SHA512_HMAC);
}

static void crypto_test_gen_alg_hmac_sha512(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  hmac_sha512_reference,
		  ARRAY_SIZE(hmac_sha512_reference));
}

static void crypto_test_check_alg_hmac_sha512(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  hmac_sha512_reference,
		  ARRAY_SIZE(hmac_sha512_reference));
}

static int check_alg_aes_xcbc(void)
{
	return check_alg_support(ODP_CIPHER_ALG_NULL,
						ODP_AUTH_ALG_AES_XCBC_MAC);
}

static void crypto_test_gen_alg_aes_xcbc(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  aes_xcbc_reference,
		  ARRAY_SIZE(aes_xcbc_reference));
}

static void crypto_test_check_alg_aes_xcbc(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  aes_xcbc_reference,
		  ARRAY_SIZE(aes_xcbc_reference));
}

static int check_alg_aes_gmac(void)
{
	return check_alg_support(ODP_CIPHER_ALG_NULL, ODP_AUTH_ALG_AES_GMAC);
}

static void crypto_test_gen_alg_aes_gmac(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  aes_gmac_reference,
		  ARRAY_SIZE(aes_gmac_reference));
}

static void crypto_test_check_alg_aes_gmac(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  aes_gmac_reference,
		  ARRAY_SIZE(aes_gmac_reference));
}

static int check_alg_aes_cmac(void)
{
	return check_alg_support(ODP_CIPHER_ALG_NULL, ODP_AUTH_ALG_AES_CMAC);
}

static void crypto_test_gen_alg_aes_cmac(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  aes_cmac_reference,
		  ARRAY_SIZE(aes_cmac_reference));
}

static void crypto_test_check_alg_aes_cmac(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  aes_cmac_reference,
		  ARRAY_SIZE(aes_cmac_reference));
}

static int check_alg_kasumi_f9(void)
{
	return check_alg_support(ODP_CIPHER_ALG_NULL, ODP_AUTH_ALG_KASUMI_F9);
}

static void crypto_test_gen_alg_kasumi_f9(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  kasumi_f9_reference,
		  ARRAY_SIZE(kasumi_f9_reference));
}

static void crypto_test_check_alg_kasumi_f9(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  kasumi_f9_reference,
		  ARRAY_SIZE(kasumi_f9_reference));
}

static int check_alg_snow3g_uia2(void)
{
	return check_alg_support(ODP_CIPHER_ALG_NULL, ODP_AUTH_ALG_SNOW3G_UIA2);
}

static void crypto_test_gen_alg_snow3g_uia2(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  snow3g_uia2_reference,
		  ARRAY_SIZE(snow3g_uia2_reference));
}

static void crypto_test_check_alg_snow3g_uia2(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  snow3g_uia2_reference,
		  ARRAY_SIZE(snow3g_uia2_reference));
}

static int check_alg_aes_eia2(void)
{
	return check_alg_support(ODP_CIPHER_ALG_NULL,
				 ODP_AUTH_ALG_AES_EIA2);
}

static void crypto_test_gen_alg_aes_eia2(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  aes_eia2_reference,
		  ARRAY_SIZE(aes_eia2_reference));
}

static void crypto_test_check_alg_aes_eia2(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  aes_eia2_reference,
		  ARRAY_SIZE(aes_eia2_reference));
}

static int check_alg_zuc_eia3(void)
{
	return check_alg_support(ODP_CIPHER_ALG_NULL, ODP_AUTH_ALG_ZUC_EIA3);
}

static void crypto_test_gen_alg_zuc_eia3(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  zuc_eia3_reference,
		  ARRAY_SIZE(zuc_eia3_reference));
}

static void crypto_test_check_alg_zuc_eia3(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  zuc_eia3_reference,
		  ARRAY_SIZE(zuc_eia3_reference));
}

static int check_alg_md5(void)
{
	return check_alg_support(ODP_CIPHER_ALG_NULL, ODP_AUTH_ALG_MD5);
}

static void crypto_test_gen_alg_md5(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  md5_reference,
		  ARRAY_SIZE(md5_reference));
}

static void crypto_test_check_alg_md5(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  md5_reference,
		  ARRAY_SIZE(md5_reference));
}

static int check_alg_sha1(void)
{
	return check_alg_support(ODP_CIPHER_ALG_NULL, ODP_AUTH_ALG_SHA1);
}

static void crypto_test_gen_alg_sha1(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  sha1_reference,
		  ARRAY_SIZE(sha1_reference));
}

static void crypto_test_check_alg_sha1(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  sha1_reference,
		  ARRAY_SIZE(sha1_reference));
}

static int check_alg_sha224(void)
{
	return check_alg_support(ODP_CIPHER_ALG_NULL, ODP_AUTH_ALG_SHA224);
}

static void crypto_test_gen_alg_sha224(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  sha224_reference,
		  ARRAY_SIZE(sha224_reference));
}

static void crypto_test_check_alg_sha224(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  sha224_reference,
		  ARRAY_SIZE(sha224_reference));
}

static int check_alg_sha256(void)
{
	return check_alg_support(ODP_CIPHER_ALG_NULL, ODP_AUTH_ALG_SHA256);
}

static void crypto_test_gen_alg_sha256(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  sha256_reference,
		  ARRAY_SIZE(sha256_reference));
}

static void crypto_test_check_alg_sha256(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  sha256_reference,
		  ARRAY_SIZE(sha256_reference));
}

static int check_alg_sha384(void)
{
	return check_alg_support(ODP_CIPHER_ALG_NULL, ODP_AUTH_ALG_SHA384);
}

static void crypto_test_gen_alg_sha384(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  sha384_reference,
		  ARRAY_SIZE(sha384_reference));
}

static void crypto_test_check_alg_sha384(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  sha384_reference,
		  ARRAY_SIZE(sha384_reference));
}

static int check_alg_sha512(void)
{
	return check_alg_support(ODP_CIPHER_ALG_NULL, ODP_AUTH_ALG_SHA512);
}

static void crypto_test_gen_alg_sha512(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  sha512_reference,
		  ARRAY_SIZE(sha512_reference));
}

static void crypto_test_check_alg_sha512(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  sha512_reference,
		  ARRAY_SIZE(sha512_reference));
}

static odp_queue_t sched_compl_queue_create(void)
{
	odp_queue_param_t qparam;

	odp_queue_param_init(&qparam);
	qparam.type = ODP_QUEUE_TYPE_SCHED;
	qparam.sched.prio  = odp_schedule_default_prio();
	qparam.sched.sync  = ODP_SCHED_SYNC_PARALLEL;
	qparam.sched.group = ODP_SCHED_GROUP_ALL;

	return odp_queue_create("crypto-out", &qparam);
}

static odp_queue_t plain_compl_queue_create(void)
{
	return odp_queue_create("crypto-out", NULL);
}

static odp_event_t sched_compl_queue_deq(void)
{
	return odp_schedule(NULL, ODP_SCHED_NO_WAIT);
}

static odp_event_t plain_compl_queue_deq(void)
{
	return odp_queue_deq(suite_context.queue);
}

static int crypto_suite_packet_sync_init(void)
{
	suite_context.op_mode = ODP_CRYPTO_SYNC;

	suite_context.pool = odp_pool_lookup("packet_pool");
	if (suite_context.pool == ODP_POOL_INVALID)
		return -1;

	suite_context.queue = ODP_QUEUE_INVALID;
	return 0;
}

static int crypto_suite_packet_async_plain_init(void)
{
	odp_queue_t out_queue;

	suite_context.op_mode = ODP_CRYPTO_ASYNC;

	suite_context.pool = odp_pool_lookup("packet_pool");
	if (suite_context.pool == ODP_POOL_INVALID)
		return -1;

	out_queue = plain_compl_queue_create();
	if (ODP_QUEUE_INVALID == out_queue) {
		ODPH_ERR("Crypto outq creation failed\n");
		return -1;
	}
	suite_context.queue = out_queue;
	suite_context.q_type = ODP_QUEUE_TYPE_PLAIN;
	suite_context.compl_queue_deq = plain_compl_queue_deq;

	return 0;
}

static int crypto_suite_packet_async_sched_init(void)
{
	odp_queue_t out_queue;

	suite_context.op_mode = ODP_CRYPTO_ASYNC;

	suite_context.pool = odp_pool_lookup("packet_pool");
	if (suite_context.pool == ODP_POOL_INVALID)
		return -1;

	out_queue = sched_compl_queue_create();
	if (ODP_QUEUE_INVALID == out_queue) {
		ODPH_ERR("Crypto outq creation failed\n");
		return -1;
	}
	suite_context.queue = out_queue;
	suite_context.q_type = ODP_QUEUE_TYPE_SCHED;
	suite_context.compl_queue_deq = sched_compl_queue_deq;

	return 0;
}

static int crypto_suite_term(void)
{
	if (ODP_QUEUE_INVALID != suite_context.queue) {
		if (odp_queue_destroy(suite_context.queue))
			ODPH_ERR("Crypto outq destroy failed\n");
	} else {
		ODPH_ERR("Crypto outq not found\n");
	}

	return odp_cunit_print_inactive();
}

odp_testinfo_t crypto_suite[] = {
	ODP_TEST_INFO(test_capability),
	ODP_TEST_INFO(test_default_values),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_enc_alg_null,
				  check_alg_null),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_dec_alg_null,
				  check_alg_null),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_enc_alg_3des_cbc,
				  check_alg_3des_cbc),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_dec_alg_3des_cbc,
				  check_alg_3des_cbc),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_enc_alg_3des_ecb,
				  check_alg_3des_ecb),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_dec_alg_3des_ecb,
				  check_alg_3des_ecb),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_enc_alg_aes_cbc,
				  check_alg_aes_cbc),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_dec_alg_aes_cbc,
				  check_alg_aes_cbc),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_enc_alg_aes_ctr,
				  check_alg_aes_ctr),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_dec_alg_aes_ctr,
				  check_alg_aes_ctr),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_enc_alg_aes_ecb,
				  check_alg_aes_ecb),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_dec_alg_aes_ecb,
				  check_alg_aes_ecb),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_enc_alg_aes_cfb128,
				  check_alg_aes_cfb128),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_dec_alg_aes_cfb128,
				  check_alg_aes_cfb128),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_enc_alg_aes_xts,
				  check_alg_aes_xts),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_dec_alg_aes_xts,
				  check_alg_aes_xts),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_enc_alg_kasumi_f8,
				  check_alg_kasumi_f8),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_dec_alg_kasumi_f8,
				  check_alg_kasumi_f8),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_enc_alg_snow3g_uea2,
				  check_alg_snow3g_uea2),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_dec_alg_snow3g_uea2,
				  check_alg_snow3g_uea2),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_enc_alg_aes_eea2,
				  check_alg_aes_eea2),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_dec_alg_aes_eea2,
				  check_alg_aes_eea2),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_enc_alg_zuc_eea3,
				  check_alg_zuc_eea3),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_dec_alg_zuc_eea3,
				  check_alg_zuc_eea3),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_enc_alg_aes_gcm,
				  check_alg_aes_gcm),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_dec_alg_aes_gcm,
				  check_alg_aes_gcm),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_enc_alg_aes_ccm,
				  check_alg_aes_ccm),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_dec_alg_aes_ccm,
				  check_alg_aes_ccm),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_enc_alg_chacha20_poly1305,
				  check_alg_chacha20_poly1305),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_dec_alg_chacha20_poly1305,
				  check_alg_chacha20_poly1305),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_gen_alg_hmac_md5,
				  check_alg_hmac_md5),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_check_alg_hmac_md5,
				  check_alg_hmac_md5),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_gen_alg_hmac_sha1,
				  check_alg_hmac_sha1),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_check_alg_hmac_sha1,
				  check_alg_hmac_sha1),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_gen_alg_hmac_sha224,
				  check_alg_hmac_sha224),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_check_alg_hmac_sha224,
				  check_alg_hmac_sha224),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_gen_alg_hmac_sha256,
				  check_alg_hmac_sha256),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_check_alg_hmac_sha256,
				  check_alg_hmac_sha256),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_gen_alg_hmac_sha384,
				  check_alg_hmac_sha384),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_check_alg_hmac_sha384,
				  check_alg_hmac_sha384),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_gen_alg_hmac_sha512,
				  check_alg_hmac_sha512),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_check_alg_hmac_sha512,
				  check_alg_hmac_sha512),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_gen_alg_aes_xcbc,
				  check_alg_aes_xcbc),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_check_alg_aes_xcbc,
				  check_alg_aes_xcbc),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_gen_alg_aes_gmac,
				  check_alg_aes_gmac),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_check_alg_aes_gmac,
				  check_alg_aes_gmac),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_gen_alg_aes_cmac,
				  check_alg_aes_cmac),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_check_alg_aes_cmac,
				  check_alg_aes_cmac),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_gen_alg_kasumi_f9,
				  check_alg_kasumi_f9),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_check_alg_kasumi_f9,
				  check_alg_kasumi_f9),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_gen_alg_snow3g_uia2,
				  check_alg_snow3g_uia2),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_check_alg_snow3g_uia2,
				  check_alg_snow3g_uia2),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_gen_alg_aes_eia2,
				  check_alg_aes_eia2),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_check_alg_aes_eia2,
				  check_alg_aes_eia2),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_gen_alg_zuc_eia3,
				  check_alg_zuc_eia3),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_check_alg_zuc_eia3,
				  check_alg_zuc_eia3),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_gen_alg_md5,
				  check_alg_md5),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_check_alg_md5,
				  check_alg_md5),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_gen_alg_sha1,
				  check_alg_sha1),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_check_alg_sha1,
				  check_alg_sha1),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_gen_alg_sha224,
				  check_alg_sha224),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_check_alg_sha224,
				  check_alg_sha224),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_gen_alg_sha256,
				  check_alg_sha256),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_check_alg_sha256,
				  check_alg_sha256),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_gen_alg_sha384,
				  check_alg_sha384),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_check_alg_sha384,
				  check_alg_sha384),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_gen_alg_sha512,
				  check_alg_sha512),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_check_alg_sha512,
				  check_alg_sha512),
	ODP_TEST_INFO(test_auth_hashes_in_auth_range),
	ODP_TEST_INFO(test_all_combinations),
	ODP_TEST_INFO_NULL,
};

odp_suiteinfo_t crypto_suites[] = {
	{"odp_crypto_packet_sync_inp", crypto_suite_packet_sync_init,
	 NULL, crypto_suite},
	{"odp_crypto_packet_async_plain_inp",
	 crypto_suite_packet_async_plain_init,
	 crypto_suite_term, crypto_suite},
	{"odp_crypto_packet_async_sched_inp",
	 crypto_suite_packet_async_sched_init,
	 crypto_suite_term, crypto_suite},
	ODP_SUITE_INFO_NULL,
};

static int crypto_init(odp_instance_t *inst)
{
	odp_pool_param_t params;
	odp_pool_t pool;
	odp_pool_capability_t pool_capa;
	odp_init_t init_param;
	odph_helper_options_t helper_options;

	if (odph_options(&helper_options)) {
		ODPH_ERR("odph_options() failed\n");
		return -1;
	}

	odp_init_param_init(&init_param);
	init_param.mem_model = helper_options.mem_model;

	if (0 != odp_init_global(inst, &init_param, NULL)) {
		ODPH_ERR("odp_init_global() failed\n");
		return -1;
	}

	if (0 != odp_init_local(*inst, ODP_THREAD_CONTROL)) {
		ODPH_ERR("odp_init_local() failed\n");
		return -1;
	}

	/* Configure the scheduler. */
	if (odp_schedule_config(NULL)) {
		ODPH_ERR("odp_schedule_config() failed\n");
		return -1;
	}

	if (odp_pool_capability(&pool_capa) < 0) {
		ODPH_ERR("odp_pool_capability() failed\n");
		return -1;
	}

	odp_pool_param_init(&params);
	params.pkt.seg_len = PKT_POOL_LEN;
	params.pkt.len     = PKT_POOL_LEN;
	params.pkt.num     = PKT_POOL_NUM;
	params.type        = ODP_POOL_PACKET;

	/*
	 * Let's have a user area so that we can check that its
	 * content gets copied along with other metadata when needed.
	 */
	if (pool_capa.pkt.max_uarea_size >= UAREA_SIZE)
		params.pkt.uarea_size = UAREA_SIZE;
	else
		printf("Warning: could not request packet user area\n");

	if (pool_capa.pkt.max_seg_len &&
	    PKT_POOL_LEN > pool_capa.pkt.max_seg_len) {
		ODPH_ERR("Warning: small packet segment length\n");
		params.pkt.seg_len = pool_capa.pkt.max_seg_len;
	}

	if (pool_capa.pkt.max_len &&
	    PKT_POOL_LEN > pool_capa.pkt.max_len) {
		ODPH_ERR("Pool max packet length too small\n");
		return -1;
	}

	pool = odp_pool_create("packet_pool", &params);

	if (ODP_POOL_INVALID == pool) {
		ODPH_ERR("Packet pool creation failed\n");
		return -1;
	}

	return 0;
}

static int crypto_term(odp_instance_t inst)
{
	odp_pool_t pool;

	pool = odp_pool_lookup("packet_pool");
	if (ODP_POOL_INVALID != pool) {
		if (odp_pool_destroy(pool))
			ODPH_ERR("Packet pool destroy failed\n");
	} else {
		ODPH_ERR("Packet pool not found\n");
	}

	if (0 != odp_term_local()) {
		ODPH_ERR("odp_term_local() failed\n");
		return -1;
	}

	if (0 != odp_term_global(inst)) {
		ODPH_ERR("odp_term_global() failed\n");
		return -1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	int ret;
	char *env = getenv("FULL_TEST");

	if (env && strcmp(env, "0"))
		full_test = 1;
	printf("Test mode: %s\n", full_test ? "full" : "partial");

	/* parse common options: */
	if (odp_cunit_parse_options(argc, argv))
		return -1;

	odp_cunit_register_global_init(crypto_init);
	odp_cunit_register_global_term(crypto_term);

	ret = odp_cunit_register(crypto_suites);

	if (ret == 0)
		ret = odp_cunit_run();

	return ret;
}
