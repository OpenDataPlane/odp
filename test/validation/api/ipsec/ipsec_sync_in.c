/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "config.h"

#include "ipsec.h"

int main(int argc, char *argv[])
{
	int ret;

	/* parse common options: */
	if (odp_cunit_parse_options(argc, argv))
		return -1;

	odp_cunit_register_global_init(ipsec_init);
	odp_cunit_register_global_term(ipsec_term);

	ret = odp_cunit_register(ipsec_suites);
	if (ret == 0)
		ret = odp_cunit_run();

	return ret;
}
