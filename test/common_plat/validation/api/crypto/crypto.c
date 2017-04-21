/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include <odp_api.h>
#include <odp_cunit_common.h>
#include "odp_crypto_test_inp.h"
#include "crypto.h"

#define PKT_POOL_NUM  64
#define PKT_POOL_LEN  (1 * 1024)

odp_suiteinfo_t crypto_suites[] = {
	{ODP_CRYPTO_SYNC_INP, crypto_suite_sync_init, crypto_suite_term,
	 crypto_suite},
	{ODP_CRYPTO_ASYNC_INP, crypto_suite_async_init, crypto_suite_term,
	 crypto_suite},
	ODP_SUITE_INFO_NULL,
};

int crypto_init(odp_instance_t *inst)
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
	params.pkt.seg_len = PKT_POOL_LEN;
	params.pkt.len     = PKT_POOL_LEN;
	params.pkt.num     = PKT_POOL_NUM;
	params.type        = ODP_POOL_PACKET;

	if (pool_capa.pkt.max_seg_len &&
	    PKT_POOL_LEN > pool_capa.pkt.max_seg_len) {
		fprintf(stderr, "Warning: small packet segment length\n");
		params.pkt.seg_len = pool_capa.pkt.max_seg_len;
	}

	if (pool_capa.pkt.max_len &&
	    PKT_POOL_LEN > pool_capa.pkt.max_len) {
		fprintf(stderr, "Pool max packet length too small\n");
		return -1;
	}

	pool = odp_pool_create("packet_pool", &params);

	if (ODP_POOL_INVALID == pool) {
		fprintf(stderr, "Packet pool creation failed.\n");
		return -1;
	}
	out_queue = odp_queue_create("crypto-out", NULL);
	if (ODP_QUEUE_INVALID == out_queue) {
		fprintf(stderr, "Crypto outq creation failed.\n");
		return -1;
	}

	return 0;
}

int crypto_term(odp_instance_t inst)
{
	odp_pool_t pool;
	odp_queue_t out_queue;

	out_queue = odp_queue_lookup("crypto-out");
	if (ODP_QUEUE_INVALID != out_queue) {
		if (odp_queue_destroy(out_queue))
			fprintf(stderr, "Crypto outq destroy failed.\n");
	} else {
		fprintf(stderr, "Crypto outq not found.\n");
	}

	pool = odp_pool_lookup("packet_pool");
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

int crypto_main(int argc, char *argv[])
{
	int ret;

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
