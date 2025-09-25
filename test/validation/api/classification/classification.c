/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2015-2018 Linaro Limited
 */

#include <odp_api.h>
#include <odp_cunit_common.h>
#include "odp_classification_testsuites.h"
#include "classification.h"

odp_suiteinfo_t classification_suites[] = {
	{ .name         = "classification basic",
	  .testinfo_tbl = classification_suite_basic,
	},
	{ .name         = "classification pmr tests",
	  .testinfo_tbl = classification_suite_pmr,
	  .init_func    = classification_suite_pmr_init,
	  .term_func    = classification_suite_pmr_term,
	},
	{ .name         = "classification tests",
	  .testinfo_tbl = classification_suite,
	  .init_func    = classification_suite_init,
	  .term_func    = classification_suite_term,
	},
	{ .name         = "classification packet vector tests",
	  .testinfo_tbl = classification_suite_pktv,
	  .init_func    = classification_suite_pktv_init,
	  .term_func    = classification_suite_pktv_term,
	},
	{ .name         = "classification event vector tests",
	  .testinfo_tbl = classification_suite_evv,
	  .init_func    = classification_suite_evv_init,
	  .term_func    = classification_suite_evv_term,
	},
	ODP_SUITE_INFO_NULL,
};

int main(int argc, char *argv[])
{
	int ret;

	/* parse common options: */
	if (odp_cunit_parse_options(&argc, argv))
		return -1;

	ret = odp_cunit_register(classification_suites);

	if (ret == 0)
		ret = odp_cunit_run();

	return ret;
}
