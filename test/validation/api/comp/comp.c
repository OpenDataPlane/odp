/* Copyright (c) 2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include <odp_api.h>
#include <odp_cunit_common.h>
#include "test_vectors.h"

#define TEST_NUM_PKT  64
#define TEST_PKT_LEN  (8 * 1024)

#define SEGMENTED_TEST_PKT_LEN  (16 * 1024)
#define SEGMENTED_TEST_PATTERN  0xAA

#define COMP_PACKET_POOL  "packet_pool"
#define COMP_OUT_QUEUE	  "comp-out"

struct suite_context_s {
	odp_comp_op_mode_t op_mode;
	odp_pool_t pool;
	odp_queue_t queue;
};

static struct suite_context_s suite_context;

/**
 * Check if given compression and hash algorithms are supported
 *
 * @param comp	Compression algorithm
 * @param hash	Hash algorithm
 *
 * @retval ODP_TEST_ACTIVE when both algorithms are supported
 * @retval ODP_TEST_INACTIVE when either algorithm is not supported
 */
static int check_comp_alg_support(odp_comp_alg_t comp,
				  odp_comp_hash_alg_t hash)
{
	odp_comp_capability_t capability;

	if (odp_comp_capability(&capability))
		return ODP_TEST_INACTIVE;

	if (suite_context.op_mode == ODP_COMP_OP_MODE_SYNC &&
	    capability.sync == ODP_SUPPORT_NO)
		return ODP_TEST_INACTIVE;
	if (suite_context.op_mode == ODP_COMP_OP_MODE_ASYNC &&
	    capability.async == ODP_SUPPORT_NO)
		return ODP_TEST_INACTIVE;

	/* Compression algorithms */
	switch (comp) {
	case ODP_COMP_ALG_NULL:
		if (!capability.comp_algos.bit.null)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_COMP_ALG_DEFLATE:
		if (!capability.comp_algos.bit.deflate)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_COMP_ALG_ZLIB:
		if (!capability.comp_algos.bit.zlib)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_COMP_ALG_LZS:
		if (!capability.comp_algos.bit.lzs)
			return ODP_TEST_INACTIVE;
		break;
	default:
		fprintf(stderr, "Unsupported compression algorithm\n");
		return ODP_TEST_INACTIVE;
	}

	/* Hash algorithms */
	switch (hash) {
	case ODP_COMP_HASH_ALG_NONE:
		if (!capability.hash_algos.bit.none)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_COMP_HASH_ALG_SHA1:
		if (!capability.hash_algos.bit.sha1)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_COMP_HASH_ALG_SHA256:
		if (!capability.hash_algos.bit.sha256)
			return ODP_TEST_INACTIVE;
		break;
	default:
		fprintf(stderr, "Unsupported hash algorithm\n");
		return ODP_TEST_INACTIVE;
	}

	return ODP_TEST_ACTIVE;
}

static odp_packet_t run_comp_op(odp_comp_op_t op,
				odp_comp_alg_t comp_alg,
				odp_comp_hash_alg_t hash_alg,
				odp_packet_t inpkt,
				unsigned int outtext_len)
{
	odp_comp_session_t session;
	odp_comp_capability_t capa;
	odp_comp_alg_capability_t comp_capa;
	odp_comp_hash_alg_capability_t hash_capa;
	odp_comp_session_param_t ses_params;
	odp_comp_packet_op_param_t op_params;
	odp_packet_t outpkt;
	odp_comp_packet_result_t comp_result;
	int rc;

	rc = odp_comp_capability(&capa);
	CU_ASSERT_FATAL(!rc);

	if (comp_alg == ODP_COMP_ALG_NULL &&
	    !(capa.comp_algos.bit.null))
		rc = -1;
	if (comp_alg == ODP_COMP_ALG_DEFLATE &&
	    !(capa.comp_algos.bit.deflate))
		rc = -1;
	if (comp_alg == ODP_COMP_ALG_ZLIB &&
	    !(capa.comp_algos.bit.zlib))
		rc = -1;
	if (comp_alg == ODP_COMP_ALG_LZS &&
	    !(capa.comp_algos.bit.lzs))
		rc = -1;

	CU_ASSERT(!rc);

	if (hash_alg == ODP_COMP_HASH_ALG_NONE &&
	    !(capa.hash_algos.bit.none))
		rc = -1;
	if (hash_alg == ODP_COMP_HASH_ALG_SHA1 &&
	    !(capa.hash_algos.bit.sha1))
		rc = -1;
	if (hash_alg == ODP_COMP_HASH_ALG_SHA256 &&
	    !(capa.hash_algos.bit.sha256))
		rc = -1;

	CU_ASSERT(!rc);

	rc = odp_comp_alg_capability(comp_alg, &comp_capa);
	CU_ASSERT(!rc);

	rc = odp_comp_hash_alg_capability(hash_alg, &hash_capa);
	CU_ASSERT(!rc);

	if (hash_alg == ODP_COMP_HASH_ALG_NONE &&
	    !(comp_capa.hash_algo.bit.none))
		rc = -1;
	if (hash_alg == ODP_COMP_HASH_ALG_SHA1 &&
	    !(comp_capa.hash_algo.bit.sha1))
		rc = -1;
	if (hash_alg == ODP_COMP_HASH_ALG_SHA256 &&
	    !(comp_capa.hash_algo.bit.sha256))
		rc = -1;

	CU_ASSERT(!rc);

	/* Create a compression session */
	odp_comp_session_param_init(&ses_params);
	ses_params.op = op;
	ses_params.comp_algo = comp_alg;
	ses_params.hash_algo = hash_alg;
	ses_params.compl_queue = suite_context.queue;
	ses_params.mode = suite_context.op_mode;

	session = odp_comp_session_create(&ses_params);
	CU_ASSERT_FATAL(session != ODP_COMP_SESSION_INVALID);
	CU_ASSERT(odp_comp_session_to_u64(session) !=
		odp_comp_session_to_u64(ODP_COMP_SESSION_INVALID));

	/* Allocate compression output packet */
	outpkt = odp_packet_alloc(suite_context.pool, outtext_len);
	CU_ASSERT(outpkt != ODP_PACKET_INVALID);

	op_params.out_data_range.offset = 0;
	op_params.out_data_range.length = outtext_len;
	op_params.in_data_range.offset = 0;
	op_params.in_data_range.length = odp_packet_len(inpkt);
	op_params.session = session;

	if (suite_context.op_mode == ODP_COMP_OP_MODE_SYNC) {
		rc = odp_comp_op(&inpkt, &outpkt, 1, &op_params);
		CU_ASSERT(rc >= 0);
		if (rc < 0)
			goto cleanup;
	} else {
		odp_event_t event;
		odp_packet_t packet;

		rc = odp_comp_op_enq(&inpkt, &outpkt, 1, &op_params);
		CU_ASSERT(rc == 1);
		if (rc <= 0)
			goto cleanup;
		/* Poll completion queue for results */
		do {
			event = odp_queue_deq(suite_context.queue);
		} while (event == ODP_EVENT_INVALID);
		CU_ASSERT(ODP_EVENT_PACKET == odp_event_type(event));
		CU_ASSERT(ODP_EVENT_PACKET_COMP ==
			  odp_event_subtype(event));

		packet = odp_comp_packet_from_event(event);
		CU_ASSERT(packet != ODP_PACKET_INVALID);
		CU_ASSERT(packet == outpkt);
	}

	rc = odp_comp_result(&comp_result, outpkt);
	CU_ASSERT(!rc);
	CU_ASSERT(comp_result.status == ODP_COMP_STATUS_SUCCESS);
	CU_ASSERT(comp_result.output_data_range.offset == 0);
	odp_packet_trunc_tail(&outpkt,
			      odp_packet_len(outpkt) -
			      comp_result.output_data_range.length,
			      NULL, NULL);

cleanup:

	rc = odp_comp_session_destroy(session);
	CU_ASSERT(!rc);

	if (rc < 0) {
		odp_packet_free(outpkt);
		return ODP_PACKET_INVALID;
	}

	return outpkt;
}

static void packet_cmp(odp_packet_t pkt,
		       const uint8_t *text,
		       unsigned int text_len)
{
	odp_packet_seg_t seg;
	uint32_t cmp_offset = 0, outlen = 0;
	uint32_t compare_len = 0;
	uint8_t *outdata;

	seg = odp_packet_first_seg(pkt);
	do {
		outdata = odp_packet_seg_data(pkt, seg);
		outlen = odp_packet_seg_data_len(pkt, seg);
		compare_len = outlen < (text_len - cmp_offset) ?
			outlen : (text_len - cmp_offset);

		CU_ASSERT(!memcmp(outdata,
				  text + cmp_offset, compare_len));
		cmp_offset += compare_len;
		seg = odp_packet_next_seg(pkt, seg);
	} while (seg != ODP_PACKET_SEG_INVALID && cmp_offset < text_len);
}

static void comp_decomp_alg_test(odp_comp_alg_t comp_alg,
				 odp_comp_hash_alg_t hash_alg,
				 const uint8_t *plaintext,
				 unsigned int plaintext_len)
{
	odp_packet_t decomp_outpkt, comp_outpkt, inpkt;
	int rc;

	/* Allocate compression input packet */
	inpkt = odp_packet_alloc(suite_context.pool, plaintext_len);
	CU_ASSERT(inpkt != ODP_PACKET_INVALID);

	/* copy test data in to pkt memory */
	rc = odp_packet_copy_from_mem(inpkt, 0,
				      plaintext_len, plaintext);
	CU_ASSERT_FATAL(!rc);

	comp_outpkt = run_comp_op(ODP_COMP_OP_COMPRESS,
				  comp_alg, hash_alg,
				  inpkt,
				  plaintext_len);
	if (comp_outpkt == ODP_PACKET_INVALID)
		goto clean_in;

	decomp_outpkt = run_comp_op(ODP_COMP_OP_DECOMPRESS,
				    comp_alg, hash_alg,
				    comp_outpkt,
				    plaintext_len);
	if (decomp_outpkt == ODP_PACKET_INVALID)
		goto cleanup;

	packet_cmp(decomp_outpkt, plaintext, plaintext_len);

	odp_packet_free(decomp_outpkt);

cleanup:
	odp_packet_free(comp_outpkt);
clean_in:
	odp_packet_free(inpkt);
}

static void comp_alg_test(odp_comp_alg_t comp_alg,
			  odp_comp_hash_alg_t hash_alg,
			  const uint8_t *plaintext,
			  unsigned int plaintext_len)
{
	odp_packet_t comp_outpkt, inpkt;
	int rc;

	/* Allocate compression input packet */
	inpkt = odp_packet_alloc(suite_context.pool, plaintext_len);
	CU_ASSERT(inpkt != ODP_PACKET_INVALID);

	/* copy test data in to pkt memory */
	rc = odp_packet_copy_from_mem(inpkt, 0,
				      plaintext_len, plaintext);
	CU_ASSERT_FATAL(!rc);

	comp_outpkt = run_comp_op(ODP_COMP_OP_COMPRESS,
				  comp_alg, hash_alg,
				  inpkt,
				  plaintext_len);
	if (comp_outpkt == ODP_PACKET_INVALID)
		goto clean_in;

	odp_packet_free(comp_outpkt);
clean_in:
	odp_packet_free(inpkt);
}

static void decomp_alg_test(odp_comp_alg_t comp_alg,
			    odp_comp_hash_alg_t hash_alg,
			    const uint8_t *comptext,
			    unsigned int comptext_len,
			    const uint8_t *plaintext,
			    unsigned int plaintext_len)
{
	odp_packet_t decomp_outpkt, inpkt;
	int rc;

	/* Allocate compression input packet */
	inpkt = odp_packet_alloc(suite_context.pool, comptext_len);
	CU_ASSERT(inpkt != ODP_PACKET_INVALID);

	/* copy test data in to pkt memory */
	rc = odp_packet_copy_from_mem(inpkt, 0,
				      comptext_len, comptext);
	CU_ASSERT_FATAL(!rc);

	decomp_outpkt = run_comp_op(ODP_COMP_OP_DECOMPRESS,
				    comp_alg, hash_alg,
				    inpkt,
				    plaintext_len);
	if (decomp_outpkt == ODP_PACKET_INVALID)
		goto cleanup;

	packet_cmp(decomp_outpkt, plaintext, plaintext_len);

	odp_packet_free(decomp_outpkt);
cleanup:
	odp_packet_free(inpkt);
}

static int comp_check_deflate_none(void)
{
	return check_comp_alg_support(ODP_COMP_ALG_DEFLATE,
		ODP_COMP_HASH_ALG_NONE);
}

/* Compress content using deflate algorithm */
static void comp_test_compress_alg_deflate_none(void)
{
	comp_alg_test(ODP_COMP_ALG_DEFLATE,
		      ODP_COMP_HASH_ALG_NONE,
		      plaintext, PLAIN_TEXT_SIZE);
}

/* Decompress content using deflate algorithm */
static void comp_test_decompress_alg_deflate_none(void)
{
	decomp_alg_test(ODP_COMP_ALG_DEFLATE,
			ODP_COMP_HASH_ALG_NONE,
			compressed_text_def, COMP_DEFLATE_SIZE,
			plaintext, PLAIN_TEXT_SIZE);
}

static int comp_check_zlib_none(void)
{
	return check_comp_alg_support(ODP_COMP_ALG_ZLIB,
				      ODP_COMP_HASH_ALG_NONE);
}

/* Compress content using zlib algorithm */
static void comp_test_compress_alg_zlib_none(void)
{
	comp_alg_test(ODP_COMP_ALG_ZLIB, ODP_COMP_HASH_ALG_NONE,
		      plaintext, PLAIN_TEXT_SIZE);
}

/* Decompress content using zlib algorithm */
static void comp_test_decompress_alg_zlib_none(void)
{
	decomp_alg_test(ODP_COMP_ALG_ZLIB, ODP_COMP_HASH_ALG_NONE,
			compressed_text_zlib, COMP_ZLIB_SIZE,
			plaintext, PLAIN_TEXT_SIZE);
}

/* Compress/Decompress content using deflate algorithm */
static void comp_test_comp_decomp_alg_deflate_none(void)
{
	comp_decomp_alg_test(ODP_COMP_ALG_DEFLATE,
			     ODP_COMP_HASH_ALG_NONE,
			     plaintext, PLAIN_TEXT_SIZE);
}

/* Compress/Decompress content using zlib algorithm */
static void comp_test_comp_decomp_alg_zlib_none(void)
{
	comp_decomp_alg_test(ODP_COMP_ALG_ZLIB,
			     ODP_COMP_HASH_ALG_NONE,
			     plaintext, PLAIN_TEXT_SIZE);
}

static int comp_suite_sync_init(void)
{
	suite_context.pool = odp_pool_lookup(COMP_PACKET_POOL);
	if (suite_context.pool == ODP_POOL_INVALID)
		return -1;

	suite_context.queue = ODP_QUEUE_INVALID;
	suite_context.op_mode = ODP_COMP_OP_MODE_SYNC;
	return 0;
}

static int comp_suite_async_init(void)
{
	suite_context.pool = odp_pool_lookup(COMP_PACKET_POOL);
	if (suite_context.pool == ODP_POOL_INVALID)
		return -1;
	suite_context.queue = odp_queue_lookup(COMP_OUT_QUEUE);
	if (suite_context.queue == ODP_QUEUE_INVALID)
		return -1;

	suite_context.op_mode = ODP_COMP_OP_MODE_ASYNC;
	return 0;
}

static odp_testinfo_t comp_suite[] = {
	ODP_TEST_INFO_CONDITIONAL(comp_test_compress_alg_deflate_none,
				  comp_check_deflate_none),
	ODP_TEST_INFO_CONDITIONAL(comp_test_compress_alg_zlib_none,
				  comp_check_zlib_none),
	ODP_TEST_INFO_CONDITIONAL(comp_test_decompress_alg_deflate_none,
				  comp_check_deflate_none),
	ODP_TEST_INFO_CONDITIONAL(comp_test_decompress_alg_zlib_none,
				  comp_check_zlib_none),
	ODP_TEST_INFO_CONDITIONAL(comp_test_comp_decomp_alg_deflate_none,
				  comp_check_deflate_none),
	ODP_TEST_INFO_CONDITIONAL(comp_test_comp_decomp_alg_zlib_none,
				  comp_check_zlib_none),
	ODP_TEST_INFO_NULL,
};

/* Suite names */
#define ODP_COMP_SYNC_TEST	"Comp/decomp sync test"
#define ODP_COMP_ASYNC_TEST	"Comp/decomp async test"

static odp_suiteinfo_t comp_suites[] = {
	{ODP_COMP_SYNC_TEST, comp_suite_sync_init,
	 NULL, comp_suite},
	{ODP_COMP_ASYNC_TEST, comp_suite_async_init,
	 NULL, comp_suite},
	ODP_SUITE_INFO_NULL,
};

static int comp_init(odp_instance_t *inst)
{
	odp_pool_param_t params;
	odp_pool_t pool;
	odp_queue_t out_queue;
	odp_pool_capability_t pool_capa;

	if (0 != odp_init_global(inst, NULL, NULL)) {
		fprintf(stderr, "error: odp_init_global() failed.\n");
		return -1;
	}

	if (0 != odp_init_local(*inst, ODP_THREAD_CONTROL)) {
		fprintf(stderr, "error: odp_init_local() failed.\n");
		return -1;
	}

	if (odp_pool_capability(&pool_capa) < 0) {
		fprintf(stderr, "error: odp_pool_capability() failed.\n");
		return -1;
	}

	odp_pool_param_init(&params);
	params.pkt.seg_len = TEST_PKT_LEN;
	params.pkt.len     = TEST_PKT_LEN;
	params.pkt.num     = TEST_NUM_PKT;
	params.type        = ODP_POOL_PACKET;

	if (pool_capa.pkt.max_seg_len &&
	    TEST_PKT_LEN > pool_capa.pkt.max_seg_len) {
		fprintf(stderr, "Warning: small packet segment length\n");
		params.pkt.seg_len = pool_capa.pkt.max_seg_len;
	}

	pool = odp_pool_create(COMP_PACKET_POOL, &params);
	if (ODP_POOL_INVALID == pool) {
		fprintf(stderr, "Packet pool creation failed.\n");
		return -1;
	}

	/* Queue to store compression/decompression events */
	out_queue = odp_queue_create(COMP_OUT_QUEUE, NULL);
	if (ODP_QUEUE_INVALID == out_queue) {
		fprintf(stderr, "Comp outq creation failed.\n");
		return -1;
	}

	return 0;
}

static int comp_term(odp_instance_t inst)
{
	odp_pool_t pool;
	odp_queue_t out_queue;

	out_queue = odp_queue_lookup(COMP_OUT_QUEUE);
	if (ODP_QUEUE_INVALID != out_queue) {
		if (odp_queue_destroy(out_queue))
			fprintf(stderr, "Comp outq destroy failed.\n");
	} else {
		fprintf(stderr, "Comp outq not found.\n");
	}

	pool = odp_pool_lookup(COMP_PACKET_POOL);
	if (ODP_POOL_INVALID != pool) {
		if (odp_pool_destroy(pool))
			fprintf(stderr, "Packet pool destroy failed.\n");
	} else {
		fprintf(stderr, "Packet pool not found.\n");
	}

	if (0 != odp_term_local()) {
		fprintf(stderr, "error: odp_term_local() failed.\n");
		return -1;
	}

	if (0 != odp_term_global(inst)) {
		fprintf(stderr, "error: odp_term_global() failed.\n");
		return -1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	int ret;

	/* parse common options: */
	if (odp_cunit_parse_options(argc, argv))
		return -1;

	odp_cunit_register_global_init(comp_init);
	odp_cunit_register_global_term(comp_term);

	ret = odp_cunit_register(comp_suites);

	if (ret == 0)
		ret = odp_cunit_run();

	return ret;
}
