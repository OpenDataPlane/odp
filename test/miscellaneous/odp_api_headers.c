/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Nokia
 */

#include <odp_api.h>
#include <odp/helper/odph_api.h>

int main(int argc ODP_UNUSED, char *argv[] ODP_UNUSED)
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
