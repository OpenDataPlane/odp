/* Copyright (c) 2022, Nokia
 *
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_api.h>
#include <odp/helper/odph_api.h>

int main(void)
{
	odp_instance_t inst;

	if (odp_init_global(&inst, NULL, NULL)) {
		ODPH_ERR("Global init failed.\n");
		return -1;
	}

	if (odp_init_local(inst, ODP_THREAD_CONTROL)) {
		ODPH_ERR("Local init failed.\n");
		return -1;
	}

	odp_sys_info_print();
	printf("Helper library version: %s\n", odph_version_str());

	if (odp_term_local()) {
		ODPH_ERR("Local term failed.\n");
		return -1;
	}

	if (odp_term_global(inst)) {
		ODPH_ERR("Global term failed.\n");
		return -1;
	}

	return 0;
}
