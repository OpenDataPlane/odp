/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2024 Nokia
 */

/**
 * @example odp_cli.c
 *
 * This example shows how to start and stop ODP CLI using the CLI helper
 * API functions. This example application can also be used to try out
 * the CLI by connecting to a running application with a telnet client.
 *
 * @cond _ODP_HIDE_FROM_DOXYGEN_
 */

#include <odp_api.h>
#include <odp/helper/odph_api.h>

#include <stdio.h>
#include <stdint.h>
#include <signal.h>

typedef struct {
	int time;
	char *addr;
	uint16_t port;
} options_t;

static void usage(const char *prog)
{
	printf("\n"
	       "Usage: %s [options]\n"
	       "\n"
	       "OPTIONS:\n"
	       "  -t, --time <sec>        Keep CLI open for <sec> seconds. (default -1 (infinite))\n"
	       "  -a, --address <addr>    Bind listening socket to IP address <addr>.\n"
	       "  -p, --port <port>       Bind listening socket to port <port>.\n"
	       "\n"
	       "ODP helper defaults are used for address and port, if the options are\n"
	       "not given.\n"
	       "\n",
	       prog);
}

static void parse_args(int argc, char *argv[], options_t *opt)
{
	static const struct option longopts[] = {
		{ "time", required_argument, NULL, 't' },
		{ "address", required_argument, NULL, 'a' },
		{ "port", required_argument, NULL, 'p' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 }
	};

	static const char *shortopts = "+t:a:p:h";

	while (1) {
		int c = getopt_long(argc, argv, shortopts, longopts, NULL);

		if (c == -1)
			break; /* No more options */

		switch (c) {
		case 't':
			opt->time = atoi(optarg);
			break;
		case 'a':
			opt->addr = optarg;
			break;
		case 'p':
			opt->port = atoi(optarg);
			break;
		default:
			usage(argv[0]);
			exit(EXIT_SUCCESS);
			break;
		}
	}

	optind = 1; /* reset 'extern optind' from the getopt lib */
}

static volatile int shutdown_sig;

static void sig_handler(int signo)
{
	(void)signo;

	shutdown_sig = 1;
}

static void my_cmd(int argc, char *argv[])
{
	odph_cli_log("%s(%d): %s\n", __FILE__, __LINE__, __func__);

	for (int i = 0; i < argc; i++)
		odph_cli_log("argv[%d]: %s\n", i, argv[i]);
}

static int cli_server(void *arg ODP_UNUSED)
{
	/* Run CLI server. */
	if (odph_cli_run()) {
		ODPH_ERR("odph_cli_run() failed.\n");
		return -1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	signal(SIGINT, sig_handler);

	odph_helper_options_t helper_options;

	/* Let helper collect its own arguments (e.g. --odph_proc) */
	argc = odph_parse_options(argc, argv);
	if (odph_options(&helper_options)) {
		ODPH_ERR("Error: reading ODP helper options failed.\n");
		exit(EXIT_FAILURE);
	}

	odp_init_t init;

	odp_init_param_init(&init);
	init.mem_model = helper_options.mem_model;

	options_t opt = {
		.time = -1,
		.addr = NULL,
		.port = 0,
	};

	parse_args(argc, argv, &opt);

	/* Initialize ODP. */

	odp_instance_t inst;

	if (odp_init_global(&inst, &init, NULL)) {
		ODPH_ERR("Global init failed.\n");
		exit(EXIT_FAILURE);
	}

	if (odp_init_local(inst, ODP_THREAD_CONTROL)) {
		ODPH_ERR("Local init failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Prepare CLI parameters. */

	odph_cli_param_t cli_param;

	odph_cli_param_init(&cli_param);

	if (opt.addr)
		cli_param.address = opt.addr;

	if (opt.port)
		cli_param.port = opt.port;

	/* Initialize CLI helper. */
	if (odph_cli_init(&cli_param)) {
		ODPH_ERR("CLI helper initialization failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Register user command. */
	if (odph_cli_register_command("my_command", my_cmd,
				      "Example user command.")) {
		ODPH_ERR("Registering user command failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Create server thread. */

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
	thr_common.instance = inst;
	thr_common.cpumask = &cpumask;

	odph_thread_param_init(&thr_param);
	thr_param.thr_type = ODP_THREAD_CONTROL;
	thr_param.start = cli_server;

	memset(&thr_server, 0, sizeof(thr_server));

	if (odph_thread_create(&thr_server, &thr_common, &thr_param, 1) != 1) {
		ODPH_ERR("Failed to create server thread.\n");
		exit(EXIT_FAILURE);
	}

	printf("CLI server started on %s:%d.\n", cli_param.address,
	       cli_param.port);

	/* Wait for the given number of seconds. */
	for (int i = 0; (opt.time < 0 || i < opt.time) && !shutdown_sig; i++)
		odp_time_wait_ns(ODP_TIME_SEC_IN_NS);

	printf("Stopping CLI server.\n");

	/* Stop CLI server. */
	if (odph_cli_stop()) {
		ODPH_ERR("CLI stop failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Wait for server thread to exit. */
	if (odph_thread_join_result(&thr_server, &res, 1) != 1) {
		ODPH_ERR("Failed to join server thread.\n");
		exit(EXIT_FAILURE);
	}

	if (res.is_sig || res.ret != 0) {
		ODPH_ERR("Worker thread failure%s: %d.\n", res.is_sig ? " (signaled)" : "",
			 res.ret);
		exit(EXIT_FAILURE);
	}

	/* Terminate CLI helper. */
	if (odph_cli_term()) {
		ODPH_ERR("CLI helper termination failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Terminate ODP. */

	if (odp_term_local()) {
		ODPH_ERR("Local term failed.\n");
		exit(EXIT_FAILURE);
	}

	if (odp_term_global(inst)) {
		ODPH_ERR("Global term failed.\n");
		exit(EXIT_FAILURE);
	}

	return 0;
}
