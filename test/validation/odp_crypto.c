/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include <odp.h>
#include "CUnit/Basic.h"
#include "CUnit/TestDB.h"
#include "odp_crypto_test_async_inp.h"
#include "odp_crypto_test_sync_inp.h"

#define SHM_PKT_POOL_SIZE	(512*2048*2)
#define SHM_PKT_POOL_BUF_SIZE	(1024 * 32)

#define SHM_COMPL_POOL_SIZE	(128*1024)
#define SHM_COMPL_POOL_BUF_SIZE	128

static int init_suite(void)
{
	printf("\tODP API version: %s\n", odp_version_api_str());
	printf("\tODP implementation version: %s\n", odp_version_impl_str());
	return 0;
}

CU_SuiteInfo suites[] = {
	{ODP_CRYPTO_SYNC_INP, init_suite, NULL, NULL, NULL, test_array_sync },
	{ODP_CRYPTO_ASYNC_INP, init_suite, NULL, NULL, NULL, test_array_async },
	CU_SUITE_INFO_NULL,
};

int main(void)
{
	odp_shm_t shm;
	void *pool_base;
	odp_buffer_pool_t pool;
	odp_queue_t out_queue;

	if (odp_init_global(NULL, NULL)) {
		printf("ODP global init failed.\n");
		return -1;
	}
	odp_init_local();

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

	printf("\tODP version: %s\n", odp_version_api_str());


	/* initialize the CUnit test registry */
	if (CUE_SUCCESS != CU_initialize_registry())
		return CU_get_error();

	/* register suites */
	CU_register_suites(suites);
	/* Run all tests using the CUnit Basic interface */
	CU_basic_set_mode(CU_BRM_VERBOSE);
	CU_basic_run_tests();
	CU_cleanup_registry();

	odp_term_local();
	odp_term_global();

	return CU_get_error();
}
