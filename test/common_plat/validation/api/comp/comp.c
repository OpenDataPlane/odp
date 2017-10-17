/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include "config.h"

#include <odp_api.h>
#include <odp_cunit_common.h>
#include "odp_comp_test.h"
#include "comp.h"

#define TEST_NUM_PKT  64
#define TEST_PKT_LEN  (8 * 1024)

odp_suiteinfo_t comp_suites[] = {
	{ODP_COMP_SYNC_TEST, comp_suite_sync_init,
	 comp_suite_term, comp_suite},
	{ODP_COMP_ASYNC_TEST, comp_suite_async_init,
	 comp_suite_term, comp_suite},
	ODP_SUITE_INFO_NULL,
};

int comp_init(odp_instance_t *inst)
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

int comp_term(odp_instance_t inst)
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

int comp_main(int argc, char *argv[])
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
