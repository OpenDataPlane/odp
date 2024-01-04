/* Copyright (c) 2017-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "ipsec.h"

static int ipsec_async_init(odp_instance_t *inst)
{
	int rc;

	suite_context.inbound_op_mode = ODP_IPSEC_OP_MODE_ASYNC;
	suite_context.outbound_op_mode = ODP_IPSEC_OP_MODE_ASYNC;

	rc = ipsec_init(inst, ODP_IPSEC_OP_MODE_ASYNC);
	if (rc != 0)
		return rc;

	suite_context.pool = odp_pool_lookup("packet_pool");
	if (suite_context.pool == ODP_POOL_INVALID)
		return -1;

	return ipsec_config(*inst);
}

odp_suiteinfo_t ipsec_suites[] = {
	{"IPsec-plain-in", ipsec_suite_plain_init, ipsec_suite_term,
	 ipsec_in_suite},
	{"IPsec-sched-in", ipsec_suite_sched_init, ipsec_suite_term,
	 ipsec_in_suite},
	{"IPsec-plain-out", ipsec_suite_plain_init, ipsec_suite_term,
	 ipsec_out_suite},
	{"IPsec-sched-out", ipsec_suite_sched_init, ipsec_suite_term,
	 ipsec_out_suite},
	ODP_SUITE_INFO_NULL,
};

int main(int argc, char *argv[])
{
	int ret;

	/* parse common options: */
	if (odp_cunit_parse_options(&argc, argv))
		return -1;

	odp_cunit_register_global_init(ipsec_async_init);
	odp_cunit_register_global_term(ipsec_term);

	ret = odp_cunit_register(ipsec_suites);
	if (ret == 0)
		ret = odp_cunit_run();

	return ret;
}
