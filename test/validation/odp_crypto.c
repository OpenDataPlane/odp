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
	odp_shm_t shm;
	void *pool_base;
	odp_buffer_pool_t pool;
	odp_queue_t out_queue;

	shm = odp_shm_reserve("shm_packet_pool",
			      SHM_PKT_POOL_SIZE,
			      ODP_CACHE_LINE_SIZE, 0);

	pool_base = odp_shm_addr(shm);
	if (!pool_base) {
		fprintf(stderr, "Packet pool allocation failed.\n");
		return -1;
	}

	pool = odp_buffer_pool_create("packet_pool", pool_base,
				      SHM_PKT_POOL_SIZE,
				      SHM_PKT_POOL_BUF_SIZE,
				      ODP_CACHE_LINE_SIZE,
				      ODP_BUFFER_TYPE_PACKET);
	if (ODP_BUFFER_POOL_INVALID == pool) {
		fprintf(stderr, "Packet pool creation failed.\n");
		return -1;
	}
	out_queue = odp_queue_create("crypto-out",
				     ODP_QUEUE_TYPE_POLL, NULL);
	if (ODP_QUEUE_INVALID == out_queue) {
		fprintf(stderr, "Crypto outq creation failed.\n");
		return -1;
	}
	shm = odp_shm_reserve("shm_compl_pool",
			     SHM_COMPL_POOL_SIZE,
			     ODP_CACHE_LINE_SIZE,
			     ODP_SHM_SW_ONLY);
	pool_base = odp_shm_addr(shm);
	if (!pool_base) {
		fprintf(stderr, "Completion pool allocation failed.\n");
		return -1;
	}
	pool = odp_buffer_pool_create("compl_pool", pool_base,
				      SHM_COMPL_POOL_SIZE,
				      SHM_COMPL_POOL_BUF_SIZE,
				      ODP_CACHE_LINE_SIZE,
				      ODP_BUFFER_TYPE_RAW);
	if (ODP_BUFFER_POOL_INVALID == pool) {
		fprintf(stderr, "Completion pool creation failed.\n");
		return -1;
	}

	return 0;
}
