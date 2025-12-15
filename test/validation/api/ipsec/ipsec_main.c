/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2017-2018 Linaro Limited
 * Copyright (c) 2024-2025 Nokia
 */

#include <odp_api.h>
#include <odp_cunit_common.h>
#include "ipsec.h"

odp_suiteinfo_t ipsec_sync_suites[] = {
	{"IPsec-in",  ipsec_suite_sync_init, ipsec_suite_term, ipsec_in_suite},
	{"IPsec-out", ipsec_suite_sync_init, ipsec_suite_term, ipsec_out_suite},
	{"out-in",    ipsec_suite_sync_init, ipsec_suite_term, ipsec_out_in_suite},
	ODP_SUITE_INFO_NULL,
};

odp_suiteinfo_t ipsec_async_suites[] = {
	{"IPsec-plain-in",  ipsec_suite_plain_init, ipsec_suite_term, ipsec_in_suite},
	{"IPsec-sched-in",  ipsec_suite_sched_init, ipsec_suite_term, ipsec_in_suite},
	{"IPsec-plain-out", ipsec_suite_plain_init, ipsec_suite_term, ipsec_out_suite},
	{"IPsec-sched-out", ipsec_suite_sched_init, ipsec_suite_term, ipsec_out_suite},
	{"plain-out-in",    ipsec_suite_plain_init, ipsec_suite_term, ipsec_out_in_suite},
	{"sched-out-in",    ipsec_suite_sched_init, ipsec_suite_term, ipsec_out_in_suite},
	ODP_SUITE_INFO_NULL,
};

odp_suiteinfo_t ipsec_inline_in_suites[] = {
	{"IPsec-plain-in", ipsec_suite_plain_init, ipsec_suite_term, ipsec_in_suite},
	{"IPsec-sched-in", ipsec_suite_sched_init, ipsec_suite_term, ipsec_in_suite},
	{"plain-out-in",   ipsec_suite_plain_init, ipsec_suite_term, ipsec_out_in_suite},
	{"sched-out-in",   ipsec_suite_sched_init, ipsec_suite_term, ipsec_out_in_suite},
	ODP_SUITE_INFO_NULL,
};

odp_suiteinfo_t ipsec_inline_out_suites[] = {
	{"IPsec-plain-out", ipsec_suite_plain_init, ipsec_suite_term, ipsec_out_suite},
	{"IPsec-sched-out", ipsec_suite_sched_init, ipsec_suite_term, ipsec_out_suite},
	{"plain-out-in",    ipsec_suite_plain_init, ipsec_suite_term, ipsec_out_in_suite},
	{"sched-out-in",    ipsec_suite_sched_init, ipsec_suite_term, ipsec_out_in_suite},
	ODP_SUITE_INFO_NULL,
};

static void usage_exit(void)
{
	fprintf(stderr, "Usage: ipsec_main {sync|async|inline-in|inline-out}\n");
	exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
	char *test_mode;
	odp_suiteinfo_t *suites = NULL;
	int ret;

	if (odp_cunit_parse_options(&argc, argv))
		return EXIT_FAILURE;

	if (argc < 2)
		usage_exit();
	test_mode = argv[1];

	if ((!strcmp(test_mode, "sync"))) {
		suite_context.inbound_op_mode = ODP_IPSEC_OP_MODE_SYNC;
		suite_context.outbound_op_mode = ODP_IPSEC_OP_MODE_SYNC;
		suites = ipsec_sync_suites;
	} else if ((!strcmp(test_mode, "async"))) {
		suite_context.inbound_op_mode = ODP_IPSEC_OP_MODE_ASYNC;
		suite_context.outbound_op_mode = ODP_IPSEC_OP_MODE_ASYNC;
		suites = ipsec_async_suites;
	} else if ((!strcmp(test_mode, "inline-in"))) {
		suite_context.inbound_op_mode = ODP_IPSEC_OP_MODE_INLINE;
		suite_context.outbound_op_mode = ODP_IPSEC_OP_MODE_ASYNC;
		suites = ipsec_inline_in_suites;
	} else if ((!strcmp(test_mode, "inline-out"))) {
		suite_context.inbound_op_mode = ODP_IPSEC_OP_MODE_ASYNC;
		suite_context.outbound_op_mode = ODP_IPSEC_OP_MODE_INLINE;
		suites = ipsec_inline_out_suites;
	} else {
		usage_exit();
	}

	odp_cunit_register_global_init(ipsec_init);
	odp_cunit_register_global_term(ipsec_term);
	ret = odp_cunit_register(suites);

	if (ret == 0)
		ret = odp_cunit_run();

	return ret;
}
