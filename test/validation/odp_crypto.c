/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include <odp.h>
#include "odp_cunit_common.h"
#include "odp_crypto_test_inp.h"

#define SHM_PKT_POOL_SIZE	(512*2048*2)
#define SHM_PKT_POOL_BUF_SIZE	(1024 * 32)

#define SHM_COMPL_POOL_SIZE	(128*1024)
#define SHM_COMPL_POOL_BUF_SIZE	128

CU_SuiteInfo odp_testsuites[] = {
	{ODP_CRYPTO_SYNC_INP, suite_sync_inp_init, NULL, NULL, NULL,
			test_array_inp},
	{ODP_CRYPTO_ASYNC_INP, suite_async_inp_init, NULL, NULL, NULL,
			test_array_inp},
	CU_SUITE_INFO_NULL,
};

int tests_global_init(void)
{
	odp_pool_param_t params;
	odp_pool_t pool;
	odp_queue_t out_queue;

	memset(&params, 0, sizeof(params));
	params.pkt.seg_len = SHM_PKT_POOL_BUF_SIZE;
	params.pkt.len     = SHM_PKT_POOL_BUF_SIZE;
	params.pkt.num     = SHM_PKT_POOL_SIZE/SHM_PKT_POOL_BUF_SIZE;
	params.type        = ODP_POOL_PACKET;

	pool = odp_pool_create("packet_pool", ODP_SHM_NULL, &params);

	if (ODP_POOL_INVALID == pool) {
		fprintf(stderr, "Packet pool creation failed.\n");
		return -1;
	}
	out_queue = odp_queue_create("crypto-out",
				     ODP_QUEUE_TYPE_POLL, NULL);
	if (ODP_QUEUE_INVALID == out_queue) {
		fprintf(stderr, "Crypto outq creation failed.\n");
		return -1;
	}

	return 0;
}

int tests_global_term(void)
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

	return 0;
}
