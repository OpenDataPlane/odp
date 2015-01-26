/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include <odp.h>
#include "odp_cunit_common.h"
#include "odp_crypto_test_async_inp.h"
#include "odp_crypto_test_sync_inp.h"
#include "odp_crypto_test_rng.h"

#define SHM_PKT_POOL_SIZE	(512*2048*2)
#define SHM_PKT_POOL_BUF_SIZE	(1024 * 32)

#define SHM_COMPL_POOL_SIZE	(128*1024)
#define SHM_COMPL_POOL_BUF_SIZE	128

CU_SuiteInfo odp_testsuites[] = {
	{ODP_CRYPTO_SYNC_INP, NULL, NULL, NULL, NULL, test_array_sync },
	{ODP_CRYPTO_ASYNC_INP, NULL, NULL, NULL, NULL, test_array_async },
	{ODP_CRYPTO_RNG, NULL, NULL, NULL, NULL, test_rng },
	CU_SUITE_INFO_NULL,
};

int tests_global_init(void)
{
	odp_pool_param_t params;
	odp_pool_t pool;
	odp_queue_t out_queue;

	params.buf.size  = SHM_PKT_POOL_BUF_SIZE;
	params.buf.align = 0;
	params.buf.num   = SHM_PKT_POOL_SIZE/SHM_PKT_POOL_BUF_SIZE;
	params.type      = ODP_POOL_PACKET;

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

	params.buf.size  = SHM_COMPL_POOL_BUF_SIZE;
	params.buf.align = 0;
	params.buf.num   = SHM_COMPL_POOL_SIZE/SHM_COMPL_POOL_BUF_SIZE;
	params.type      = ODP_POOL_BUFFER;

	pool = odp_pool_create("compl_pool", ODP_SHM_NULL, &params);

	if (ODP_POOL_INVALID == pool) {
		fprintf(stderr, "Completion pool creation failed.\n");
		return -1;
	}

	return 0;
}
