/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

/* Test source for running compression/decompression tests
 * using deflate and zlib algorithms by generating out of space
 * errors.
 */
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <stdio.h>
#include <odp_api.h>
#include <odp/helper/linux.h>
#include <CUnit/Basic.h>
#include <odp_cunit_common.h>
#include "odp_comp_test.h"
#include "comp.h"

#define app_dbg printf

#define app_err(fmt, ...) \
	fprintf(stderr, "%s:%d:%s(): Error: " fmt, __FILE__, \
		__LINE__, __func__, ##__VA_ARGS__)

/* Maintaining these test vectors here since
 * Out of space error tests will be marked as inactive */
#define PLAIN_DATA_LEN 64
unsigned char plain_data[PLAIN_DATA_LEN] = {
	0xe6, 0xf6, 0x70, 0x1d, 0x02, 0xa1, 0xaa, 0x0c,
	0xab, 0xb2, 0x17, 0x8d, 0xa8, 0x0d, 0x5f, 0x2c,
	0x55, 0x96, 0x20, 0xe7, 0xae, 0x72, 0x95, 0xc0,
	0x7d, 0x00, 0xa2, 0xd8, 0x13, 0xc6, 0x17, 0x32,
	0xbb, 0x89, 0xec, 0xc9, 0xf7, 0x6b, 0xa7, 0x82,
	0x1e, 0x51, 0x1a, 0x02, 0x49, 0x6c, 0x71, 0x93,
	0xc4, 0x76, 0xd1, 0x49, 0xab, 0x4e, 0x9c, 0xbd,
	0x0e, 0x93, 0x82, 0x75, 0xd5, 0xaf, 0x67, 0x12
};

#define DEFLATE_DATA_LEN 7
unsigned char deflated_data[DEFLATE_DATA_LEN] = {
	0x4b, 0x4c, 0xa4, 0x0e, 0xe0, 0x02, 0x00
};

#define ZLIB_DATA_LEN  13
unsigned char zlib_data[ZLIB_DATA_LEN] = {
	0x78, 0x9c, 0x4b, 0x4c, 0xa4, 0x1a, 0xe0, 0x02,
	0x00, 0x54, 0xdf, 0x1c, 0x76
};

/* Number of test loops */
#define TEST_LOOP_COUNT  10
/* Default output size for out of space error test */
#define TEST_OUT_64BYTE  64
/* Output size for 1BYTE test */
#define TEST_OUT_1BYTE  1

typedef struct {
	const char *op;
	odp_comp_alg_t comp_algo;
	odp_comp_hash_alg_t hash_algo;
	int async;
	odp_queue_t compl_queue;
	int compress;
	uint32_t input_len;
	uint32_t output_len;
	uint32_t iteration_count;
} comp_args_t;

static int process(comp_args_t *pcargs, odp_comp_op_param_t *op_params)
{
	int ret;
	odp_event_t ev;
	odp_comp_op_result_t result;
	uint32_t total_len = 0;
	odp_packet_t out_pkt;
	odp_packet_t comp_evpkt;
	odp_packet_data_range_t *out_pkt_range;

	if (pcargs->async) {
		ret = (pcargs->compress) ?
			odp_comp_compress_enq(op_params) :
			odp_comp_decomp_enq(op_params);
		ev = odp_queue_deq(pcargs->compl_queue);
		comp_evpkt = odp_comp_packet_from_event(ev);
		ret = odp_comp_result(comp_evpkt, &result);
	} else {
		ret = (pcargs->compress) ?
			odp_comp_compress(op_params, &result) :
			odp_comp_decomp(op_params, &result);
	}
	CU_ASSERT(ret >= 0)

	CU_ASSERT(result.err != ODP_COMP_ERR_NONE);
	CU_ASSERT(result.err == ODP_COMP_ERR_OUT_OF_SPACE);

	out_pkt = result.output.pkt.packet;
	out_pkt_range = &result.output.pkt.data_range;

	total_len += out_pkt_range->length;
	/* adjust available length by number of bytes consumed */
	op_params->output.pkt.data_range.length -=
		out_pkt_range->length;

	/* increment offset by length of bytes written
	   as result of last operation
	   */
	op_params->output.pkt.data_range.offset +=
		out_pkt_range->length;
	op_params->output.pkt.packet = out_pkt;

	if (result.err == ODP_COMP_ERR_OUT_OF_SPACE)
		return ODP_COMP_ERR_OUT_OF_SPACE;

	return ret;
}

static int init(comp_args_t *pcargs, odp_comp_op_param_t *op_param)
{
	int                       ret = 0;
	odp_comp_session_t         session = ODP_COMP_SESSION_INVALID;
	odp_comp_session_param_t   params;
	odp_comp_ses_create_err_t  status;

	memset(&params, 0, sizeof(odp_comp_session_param_t));

	params.comp_algo = pcargs->comp_algo;
	params.hash_algo = pcargs->hash_algo;

	params.op = ODP_COMP_OP_COMPRESS;
	if (!pcargs->compress)
		params.op = ODP_COMP_OP_DECOMPRESS;

	params.compl_queue = ODP_QUEUE_INVALID;
	params.mode = ODP_COMP_SYNC;
	if (pcargs->async) {
		odp_queue_param_t qparam;

		odp_queue_param_init(&qparam);
		qparam.type = ODP_QUEUE_TYPE_PLAIN;
		params.compl_queue = odp_queue_create("compl_q", &qparam);
		if (params.compl_queue != ODP_QUEUE_INVALID) {
			params.mode = ODP_COMP_ASYNC;
		} else {
			app_dbg("odp_queue_create failed\n");
			params.compl_queue = ODP_QUEUE_INVALID;
		}
	}
	ret = odp_comp_session_create(&params, &session, &status);
	if (ret && status != ODP_COMP_SES_CREATE_ERR_NONE) {
		app_err("Session creation failed\n");
		return -1;
	}
	op_param->session = session;
	pcargs->compl_queue = params.compl_queue;
	return 0;
}

static int term(comp_args_t *pcargs, odp_comp_op_param_t *param)
{
	if (pcargs->async)
		odp_queue_destroy(pcargs->compl_queue);
	odp_comp_session_destroy(param->session);
	return 0;
}

void test_outof_space_error(odp_comp_alg_t comp_alg,
			    odp_comp_hash_alg_t hash_alg,
			    odp_bool_t compress,
			    odp_comp_op_mode_t mode)
{
	int                       ret;
	odp_pool_t                pkt_pool;
	odp_packet_t              pkt = ODP_PACKET_INVALID;
	uint8_t                   *data = NULL;
	odp_comp_op_param_t       op_params;
	uint32_t                  read = 0;
	int                       err = 0;
	uint32_t                  iteration;
	odp_comp_data_t *in = &op_params.input;
	odp_comp_data_t *out = &op_params.output;
	uint8_t			in_data[PLAIN_DATA_LEN];
	comp_args_t cargs;

	cargs.iteration_count = TEST_LOOP_COUNT;
	cargs.comp_algo = comp_alg;
	cargs.hash_algo = hash_alg;
	cargs.compress = compress;
	cargs.output_len = TEST_OUT_64BYTE;
	if (mode == ODP_COMP_SYNC)
		cargs.async = 0;
	else
		cargs.async = 1;

	pkt_pool = odp_pool_lookup(COMP_PACKET_POOL);
	CU_ASSERT(pkt_pool != ODP_POOL_INVALID);

	iteration = 0;

	if (cargs.compress) {
		cargs.input_len = PLAIN_DATA_LEN;
		memcpy(in_data, plain_data, cargs.input_len);
	} else {
		if (comp_alg == ODP_COMP_ALG_DEFLATE) {
			cargs.input_len = DEFLATE_DATA_LEN;
			memcpy(in_data, deflated_data, cargs.input_len);
		} else {
			cargs.input_len = ZLIB_DATA_LEN;
			memcpy(in_data, zlib_data, cargs.input_len);
		}
	}
start_again:
	ret = init(&cargs, &op_params);
	CU_ASSERT(!ret);
	if (ret < 0)
		return;

	pkt = odp_packet_alloc(pkt_pool, cargs.input_len);
	CU_ASSERT(pkt != ODP_PACKET_INVALID);
	in->pkt.packet = pkt;

	if (iteration >= (TEST_LOOP_COUNT / 2))
		cargs.output_len = TEST_OUT_1BYTE;
	pkt = odp_packet_alloc(pkt_pool, cargs.output_len);
	CU_ASSERT(pkt != ODP_PACKET_INVALID);
	out->pkt.packet = pkt;

	while (!err && iteration++ <= cargs.iteration_count) {
		read = 0;

		odp_packet_seg_t seg = odp_packet_first_seg(in->pkt.packet);

		out->pkt.data_range.offset  = 0;
		out->pkt.data_range.length = odp_packet_len(
					out->pkt.packet);
		while (!err && read < cargs.input_len) {
			if (seg == ODP_PACKET_SEG_INVALID)
				seg = odp_packet_first_seg(in->pkt.packet);

			data = odp_packet_seg_data(in->pkt.packet, seg);

			memcpy(data, in_data, cargs.input_len);

			read += cargs.input_len;

			if (read >= cargs.input_len)
				op_params.last   = 1;
			else
				op_params.last   = 0;

			in->pkt.data_range.offset  = 0;
			in->pkt.data_range.length = cargs.input_len;
			/* process current segment */
			ret = process(&cargs, &op_params);
			if (ret == ODP_COMP_ERR_OUT_OF_SPACE) {
				if (iteration == cargs.iteration_count)
					goto end;
				odp_packet_free(out->pkt.packet);
				odp_packet_free(in->pkt.packet);
				term(&cargs, &op_params);
				goto start_again;
			}
			if (ret < 0)
				err = 1;

			/* get next segment to process */
			seg = odp_packet_next_seg(in->pkt.packet, seg);
		}
	}
end:
	/* free up pkt used by operation */
	odp_packet_free(out->pkt.packet);
	odp_packet_free(in->pkt.packet);

	term(&cargs, &op_params);
}
