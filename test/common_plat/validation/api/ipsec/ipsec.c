/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:	 BSD-3-Clause
 */

#include <odp_api.h>
#include <odp_cunit_common.h>
#include <unistd.h>

#include "ipsec.h"

void ipsec_test_capability(void)
{
	odp_ipsec_capability_t capa;

	CU_ASSERT(odp_ipsec_capability(&capa) == 0);
}

odp_testinfo_t ipsec_suite[] = {
	ODP_TEST_INFO(ipsec_test_capability),
	ODP_TEST_INFO_NULL
};

odp_suiteinfo_t ipsec_suites[] = {
	{"IPsec", NULL, NULL, ipsec_suite},
	ODP_SUITE_INFO_NULL,
};

int ipsec_main(int argc, char *argv[])
{
	int ret;

	/* parse common options: */
	if (odp_cunit_parse_options(argc, argv))
		return -1;

	ret = odp_cunit_register(ipsec_suites);

	if (ret == 0)
		ret = odp_cunit_run();

	return ret;
}
