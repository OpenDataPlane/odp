/* Copyright (c) 2021, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_api.h>
#include <odp/helper/odph_api.h>

int main(int argc, char *argv[])
{
	odp_instance_t instance;
	odph_helper_options_t helper_options;
	odp_init_t init_param;

	argc = odph_parse_options(argc, argv);
	if (odph_options(&helper_options)) {
		ODPH_ERR("Error: reading ODP helper options failed.\n");
		exit(EXIT_FAILURE);
	}

	odp_init_param_init(&init_param);
	init_param.mem_model = helper_options.mem_model;

	memset(&instance, 0, sizeof(instance));

	if (odp_init_global(&instance, NULL, NULL)) {
		ODPH_ERR("Error: ODP global init failed.\n");
		exit(EXIT_FAILURE);
	}

	if (odp_init_local(instance, ODP_THREAD_CONTROL)) {
		ODPH_ERR("Error: ODP local init failed.\n");
		exit(EXIT_FAILURE);
	}

	odph_cli_param_t cli_param;

	odph_cli_param_init(&cli_param);

	if (odph_cli_init(instance, &cli_param)) {
		ODPH_ERR("Error: odph_cli_init() failed.\n");
		exit(EXIT_FAILURE);
	}

	if (odph_cli_start()) {
		ODPH_ERR("Error: odph_cli_start() failed.\n");
		exit(EXIT_FAILURE);
	}

	if (odph_cli_stop()) {
		ODPH_ERR("Error: odph_cli_stop() failed.\n");
		exit(EXIT_FAILURE);
	}

	if (odph_cli_term()) {
		ODPH_ERR("Error: odph_cli_term() failed.\n");
		exit(EXIT_FAILURE);
	}

	if (odp_term_local()) {
		ODPH_ERR("Error: ODP local term failed.\n");
		exit(EXIT_FAILURE);
	}

	if (odp_term_global(instance)) {
		ODPH_ERR("Error: ODP global term failed.\n");
		exit(EXIT_FAILURE);
	}

	return EXIT_SUCCESS;
}
