/* Copyright (c) 2015-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "ipc_common.h"

/** Run time in seconds */
int run_time_sec;
/** Pid of the master process */
int master_pid;

int ipc_odp_packet_send_or_free(odp_pktio_t pktio,
				odp_packet_t pkt_tbl[], int num)
{
	int ret;
	int sent = 0;
	odp_time_t start_time;
	odp_time_t end_time;
	odp_time_t wait;
	odp_pktout_queue_t pktout;
	int i;

	start_time = odp_time_local();
	wait = odp_time_local_from_ns(ODP_TIME_SEC_IN_NS);
	end_time = odp_time_sum(start_time, wait);

	if (odp_pktout_queue(pktio, &pktout, 1) != 1) {
		ODPH_ERR("no output queue\n");
		return -1;
	}

	while (sent != num) {
		ret = odp_pktout_send(pktout, &pkt_tbl[sent], num - sent);
		if (ret < 0) {
			ODPH_ERR("odp_pktout_send return %d\n", ret);
			for (i = sent; i < num; i++)
				odp_packet_free(pkt_tbl[i]);
			return -1;
		}

		sent += ret;

		if (odp_time_cmp(end_time, odp_time_local()) < 0) {
			for (i = sent; i < num; i++)
				odp_packet_free(pkt_tbl[i]);
			ODPH_ERR("Send Timeout!\n");
			return -1;
		}
	}

	return 0;
}

odp_pktio_t create_pktio(odp_pool_t pool, int master_pid)
{
	odp_pktio_param_t pktio_param;
	odp_pktio_t ipc_pktio;
	char name[30];

	odp_pktio_param_init(&pktio_param);

	if (master_pid)
		sprintf(name, TEST_IPC_PKTIO_PID_NAME, master_pid);
	else
		sprintf(name, TEST_IPC_PKTIO_NAME);

	printf("pid: %d, create IPC pktio %s\n", getpid(), name);
	ipc_pktio = odp_pktio_open(name, pool, &pktio_param);
	if (ipc_pktio == ODP_PKTIO_INVALID) {
		ODPH_ERR("Error: ipc pktio %s create failed.\n", name);
		return ODP_PKTIO_INVALID;
	}

	if (odp_pktin_queue_config(ipc_pktio, NULL)) {
		ODPH_ERR("Input queue config failed\n");
		return ODP_PKTIO_INVALID;
	}

	if (odp_pktout_queue_config(ipc_pktio, NULL)) {
		ODPH_ERR("Output queue config failed\n");
		return ODP_PKTIO_INVALID;
	}

	return ipc_pktio;
}

/**
 * Parse and store the command line arguments
 *
 * @param argc       argument count
 * @param argv[]     argument vector
 * @param appl_args  Store application arguments here
 */
void parse_args(int argc, char *argv[])
{
	int opt;
	int long_index;
	static struct option longopts[] = {
		{"time", required_argument, NULL, 't'},
		{"pid", required_argument, NULL, 'p'}, /* master process pid */
		{"help", no_argument, NULL, 'h'},     /* return 'h' */
		{NULL, 0, NULL, 0}
	};

	run_time_sec = 0; /* loop forever if time to run is 0 */
	master_pid = 0;

	while (1) {
		opt = getopt_long(argc, argv, "+t:p:h",
				  longopts, &long_index);

		if (opt == -1)
			break;	/* No more options */

		switch (opt) {
		case 't':
			run_time_sec = atoi(optarg);
			break;
		case 'p':
			master_pid = atoi(optarg);
			break;
		case 'h':
		default:
			usage(argv[0]);
			exit(EXIT_SUCCESS);
			break;
		}
	}

	optind = 1;		/* reset 'extern optind' from the getopt lib */
}

/**
 * Print system and application info
 */
void print_info(char *progname)
{
	odp_sys_info_print();

	printf("Running ODP appl: \"%s\"\n"
	       "-----------------\n"
	       "Using IF:        %s\n",
	       progname, pktio_name);
	printf("\n\n");
	fflush(NULL);
}

/**
 * Prinf usage information
 */
void usage(char *progname)
{
	printf("\n"
	       "Usage: %s OPTIONS\n"
	       "  E.g. -n ipc_name_space %s -t seconds\n"
	       "\n"
	       "OpenDataPlane odp-linux ipc test application.\n"
	       "\n"
		"Mandatory OPTIONS:\n"
	       "  -n, --ns           IPC name space ID /dev/shm/odp-<ns>-objname.\n"
	       "Optional OPTIONS\n"
	       "  -h, --help           Display help and exit.\n"
	       "  -t, --time           Time to run in seconds.\n"
	       "\n", NO_PATH(progname), NO_PATH(progname)
	    );
}
