/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2024 Nokia
 */

#include <odp_api.h>
#include <odp/helper/odph_api.h>

static int cli_server(void *arg ODP_UNUSED)
{
	if (odph_cli_run()) {
		ODPH_ERR("odph_cli_run() failed.\n");
		return -1;
	}

	return 0;
}

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

	if (odph_cli_init(&cli_param)) {
		ODPH_ERR("Error: odph_cli_init() failed.\n");
		exit(EXIT_FAILURE);
	}

	odp_cpumask_t cpumask;
	odph_thread_common_param_t thr_common;
	odph_thread_param_t thr_param;
	odph_thread_t thr_server;
	odph_thread_join_result_t res;

	if (odp_cpumask_default_control(&cpumask, 1) != 1) {
		ODPH_ERR("Failed to get default CPU mask.\n");
		exit(EXIT_FAILURE);
	}

	odph_thread_common_param_init(&thr_common);
	thr_common.instance = instance;
	thr_common.cpumask = &cpumask;

	odph_thread_param_init(&thr_param);
	thr_param.thr_type = ODP_THREAD_CONTROL;
	thr_param.start = cli_server;

	memset(&thr_server, 0, sizeof(thr_server));

	if (odph_thread_create(&thr_server, &thr_common, &thr_param, 1) != 1) {
		ODPH_ERR("Failed to create server thread.\n");
		exit(EXIT_FAILURE);
	}

	/*
	 * Wait for a bit to ensure that the server thread has time to start.
	 */
	odp_time_wait_ns(ODP_TIME_SEC_IN_NS / 10);

	if (odph_cli_stop()) {
		ODPH_ERR("Error: odph_cli_stop() failed.\n");
		exit(EXIT_FAILURE);
	}

	if (odph_thread_join_result(&thr_server, &res, 1) != 1) {
		ODPH_ERR("Error: failed to join server thread.\n");
		exit(EXIT_FAILURE);
	}

	if (res.is_sig || res.ret != 0) {
		ODPH_ERR("Error: worker thread failure%s: %d.\n", res.is_sig ? " (signaled)" : "",
			 res.ret);
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
