/* Copyright (c) 2016-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <odp_api.h>
#include <odp/helper/odph_api.h>

#include <odp_cunit_common.h>
#include <odp_packet_io_ring_internal.h>

#include "ring_suites.h"

static int ring_suites_init(odp_instance_t *inst)
{
	if (0 != odp_init_global(inst, NULL, NULL)) {
		ODPH_ERR("error: odp_init_global() failed.\n");
		return -1;
	}
	if (0 != odp_init_local(*inst, ODP_THREAD_CONTROL)) {
		ODPH_ERR("error: odp_init_local() failed.\n");
		return -1;
	}

	_ring_tailq_init();
	return 0;
}

static odp_testinfo_t ring_suite_basic[] = {
	ODP_TEST_INFO(ring_test_basic_create),
	ODP_TEST_INFO(ring_test_basic_burst),
	ODP_TEST_INFO(ring_test_basic_bulk),
	ODP_TEST_INFO_NULL,
};

static odp_testinfo_t ring_suite_stress[] = {
	ODP_TEST_INFO(ring_test_stress_1_1_producer_consumer),
	ODP_TEST_INFO(ring_test_stress_1_N_producer_consumer),
	ODP_TEST_INFO(ring_test_stress_N_1_producer_consumer),
	ODP_TEST_INFO(ring_test_stress_N_M_producer_consumer),
	ODP_TEST_INFO(ring_test_stress_ring_list_dump),
	ODP_TEST_INFO_NULL,
};

static odp_suiteinfo_t ring_suites[] = {
	{"ring basic", ring_test_basic_start,
		ring_test_basic_end, ring_suite_basic},
	{"ring stress", ring_test_stress_start,
		ring_test_stress_end, ring_suite_stress},
	ODP_SUITE_INFO_NULL
};

int ring_suites_main(int argc, char *argv[])
{
	int ret;

	/* let helper collect its own arguments (e.g. --odph_proc) */
	if (odp_cunit_parse_options(argc, argv))
		return -1;

	odp_cunit_register_global_init(ring_suites_init);

	ret = odp_cunit_register(ring_suites);

	if (ret == 0)
		ret = odp_cunit_run();

	return ret;
}
